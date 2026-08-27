//! `chaperone serve` — run the decision server (the app factory + policy
//! cache + escalation sweeper). Local default: 127.0.0.1:8400.

use chaperone_core::ledger::ChainStore;
use clap::Args;

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Listen host (default 127.0.0.1).
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Listen port (default 8400).
    #[arg(long, default_value_t = 8400)]
    pub port: u16,
    /// Redis URL for the tier-2 cache (null = tier 1 + tier 3 only).
    #[arg(long)]
    pub redis_url: Option<String>,
    /// Server mode: enforce | shadow (server-side operator config only).
    #[arg(long, default_value = "enforce")]
    pub mode: String,
    /// ungoverned_default: block (serve default) | allow.
    #[arg(long, default_value = "block")]
    pub ungoverned_default: String,
}

pub async fn run_serve(args: ServeArgs) -> i32 {
    let store = match super::open_store() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chaperone: cannot open store: {e}");
            return 1;
        }
    };
    // Genesis on first startup (flows/04: entry 0 fixed, written on first run).
    if store
        .last_entry()
        .await
        .map(|e| e.is_none())
        .unwrap_or(true)
        && let Err(e) = chaperone_core::ledger::chain::append_genesis(&store).await
    {
        eprintln!("chaperone: genesis failed: {e}");
        return 1;
    }
    let mode = match args.mode.as_str() {
        "enforce" => chaperone_core::decision::service::ServiceMode::Enforce,
        "shadow" => chaperone_core::decision::service::ServiceMode::Shadow,
        other => {
            eprintln!("chaperone: invalid mode {other:?} (enforce|shadow)");
            return 1;
        }
    };
    let ungoverned = match args.ungoverned_default.as_str() {
        "block" => chaperone_core::decision::service::UngovernedDefault::Block,
        "allow" => chaperone_core::decision::service::UngovernedDefault::Allow,
        other => {
            eprintln!("chaperone: invalid ungoverned_default {other:?} (block|allow)");
            return 1;
        }
    };

    // Policy cache: tier 1 + optional tier 2 (Redis) + tier 3 (DB).
    let provider = chaperone_core::cache::policy_cache::StorePolicyProvider::new(store.clone());
    let redis = match &args.redis_url {
        Some(url) if !url.is_empty() => {
            let client = match redis::Client::open(url.as_str()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("chaperone: bad redis_url: {e}");
                    return 1;
                }
            };
            match client.get_connection_manager().await {
                Ok(conn) => {
                    let tier = chaperone_core::cache::redis_tier::RedisTier::new(client, conn);
                    Some(std::sync::Arc::new(tier))
                }
                Err(e) => {
                    eprintln!("chaperone: redis unavailable ({e}); continuing tier 1 + tier 3");
                    None
                }
            }
        }
        _ => None,
    };
    let cache = chaperone_core::cache::policy_cache::PolicyCache::new(
        provider,
        std::sync::Arc::new(chaperone_core::clock::SystemClock),
        redis,
    );

    let state = chaperone_server::state::build_state(
        store.clone(),
        cache,
        std::sync::Arc::new(chaperone_core::clock::SystemClock),
        mode,
        ungoverned,
        900,
        vec![],
    );

    // Escalation sweeper (30s cadence; flows/03).
    let sweeper_svc = state.escalations.clone();
    chaperone_core::escalation::sweeper::spawn_sweeper(
        sweeper_svc,
        std::time::Duration::from_secs(30),
    );

    let app = chaperone_server::app_with_rate_limit(state, chaperone_server::default_rate_limit());
    let addr = format!("{}:{}", args.host, args.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chaperone: cannot bind {addr}: {e}");
            return 1;
        }
    };
    println!(
        "chaperone: serving on http://{addr} (mode={})",
        mode.as_str()
    );
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("chaperone: server error: {e}");
        return 1;
    }
    0
}
