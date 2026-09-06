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
    // Operator config: chaperone.yaml (single source of truth) + CHAPERONE_*
    // env overrides. CLI flags for mode/ungoverned_default override config.
    let config = match crate::config::load(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chaperone: bad config: {e}");
            return 1;
        }
    };
    let store = match super::open_store().await {
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
    // Startup crash-recovery (flows/04): re-verify the whole chain and refuse
    // to serve a tampered ledger. Fail-closed: no verified chain, no gate.
    match store.verify_chain().await {
        Ok(chaperone_core::ledger::verify::VerificationResult::ChainOk { entries }) => {
            eprintln!("chaperone: ledger verified ({entries} entries)");
        }
        Ok(chaperone_core::ledger::verify::VerificationResult::ChainBroken { seq, reason }) => {
            eprintln!(
                "chaperone: LEDGER TAMPERED at seq {}: {reason} — refusing to start",
                seq.map(|s| s.to_string()).unwrap_or_else(|| "?".into())
            );
            return 1;
        }
        Err(e) => {
            eprintln!("chaperone: ledger verification failed: {e}");
            return 1;
        }
    }
    // CLI flags override config/env; otherwise the config value (env-aware)
    // drives the mode. The clap defaults match the documented defaults.
    let mode_str = if args.mode != "enforce" {
        args.mode.as_str()
    } else {
        &config.mode
    };
    let mode = match mode_str {
        "enforce" => chaperone_core::decision::service::ServiceMode::Enforce,
        "shadow" => chaperone_core::decision::service::ServiceMode::Shadow,
        other => {
            eprintln!("chaperone: invalid mode {other:?} (enforce|shadow)");
            return 1;
        }
    };
    let ungoverned_str = if args.ungoverned_default != "block" {
        args.ungoverned_default.as_str()
    } else {
        &config.ungoverned_default
    };
    let ungoverned = match ungoverned_str {
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

    // Optional webhook notifier (flows/03): only wired when url + secret are set.
    let notifier: Option<std::sync::Arc<dyn chaperone_core::escalation::webhook::WebhookNotifier>> =
        match (
            config.webhook_url.as_deref(),
            config.webhook_secret.as_deref(),
        ) {
            (Some(url), Some(secret)) if !url.is_empty() => Some(std::sync::Arc::new(
                chaperone_server::webhook::HttpWebhookNotifier::new(url, secret),
            )),
            _ => None,
        };

    let state =
        chaperone_server::state::build_state_with_notifier(chaperone_server::state::StateConfig {
            store: store.clone(),
            cache,
            clock: std::sync::Arc::new(chaperone_core::clock::SystemClock),
            mode,
            ungoverned_default: ungoverned,
            escalation_ttl_seconds: 900,
            declarations: config.derived_attributes.clone(),
            notifier,
        });

    // Escalation sweeper (30s cadence; flows/03).
    let sweeper_svc = state.escalations.clone();
    chaperone_core::escalation::sweeper::spawn_sweeper(
        sweeper_svc,
        std::time::Duration::from_secs(30),
    );

    // Checkpoint daemon (flows/04 Layer 2): signed Merkle checkpoints on the
    // entry/time cadence. Unsigned dev mode unless a key path is configured.
    let signing_key = match load_signing_key(config.checkpoint_signing_key.as_deref()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("chaperone: checkpoint signing key: {e}");
            return 1;
        }
    };
    chaperone_core::storage::checkpoint_daemon::spawn_checkpoint_daemon(
        store.clone(),
        signing_key,
        config.checkpoint_interval_entries,
        config.checkpoint_interval_seconds,
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
    // Dashboard auth (flows/03 SEC-3: the inbox is NEVER unauthenticated). The
    // dev/admin key doubles as the dashboard session token — print it so the
    // operator can paste it into the dashboard's token gate.
    println!("chaperone: dashboard session token: {}", config.api_token);
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("chaperone: server error: {e}");
        return 1;
    }
    0
}

/// Load the Ed25519 checkpoint signing key from a file path (hex/base64/raw
/// 32 bytes). `None` path → unsigned dev mode (with a warning), per
/// data-model.md `checkpoint_signing_key`.
fn load_signing_key(path: Option<&str>) -> Result<Option<ed25519_dalek::SigningKey>, String> {
    match path {
        None => {
            eprintln!(
                "chaperone: checkpoint signing key unset — emitting UNSIGNED dev checkpoints"
            );
            Ok(None)
        }
        Some(p) => {
            let bytes = std::fs::read(p).map_err(|e| format!("cannot read {p}: {e}"))?;
            let key = chaperone_core::ledger::checkpoint::signing_key_from_bytes(&bytes)
                .map_err(|e| e.message)?;
            Ok(Some(key))
        }
    }
}
