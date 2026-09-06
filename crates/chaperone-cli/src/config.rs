//! `chaperone.yaml` runtime config (docs/data-model.md "Runtime config").
//!
//! This is the single source of truth for operator configuration. Env
//! overrides use the `CHAPERONE_` prefix (e.g. `CHAPERONE_DATABASE_URL`).
//! Only the documented v1 fields exist here — an implementer must not invent
//! config surface beyond this table.

use chaperone_core::engine::derive::DerivedDeclaration;
use serde::Deserialize;

/// The full v1 config schema (docs/data-model.md). Every field has a serde
/// default so a missing/partial `chaperone.yaml` still yields a valid config.
/// The schema is the complete documented surface; a field may be parsed but not
/// yet consumed by a given command while its consumer lands. Unknown fields are
/// rejected so the contract is forward-frozen.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Config {
    /// Server-side ONLY (review-4 B1): enforce | shadow.
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_database_url")]
    pub database_url: String,
    #[serde(default)]
    pub redis_url: Option<String>,
    /// cedar | reference.
    #[serde(default = "default_engine")]
    pub engine: String,
    #[serde(default = "default_host")]
    pub serve_host: String,
    #[serde(default = "default_port")]
    pub serve_port: u16,
    #[serde(default = "default_api_token")]
    pub api_token: String,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,
    #[serde(default = "default_cache_ttl_no_redis")]
    pub cache_ttl_no_redis_seconds: u64,
    #[serde(default = "default_escalation_ttl")]
    pub escalation_ttl_seconds: i64,
    #[serde(default = "default_hook_prompt_bound")]
    pub hook_prompt_bound_seconds: u64,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_secret: Option<String>,
    #[serde(default = "default_retention_days")]
    pub proposed_params_retention_days: u32,
    #[serde(default = "default_checkpoint_entries")]
    pub checkpoint_interval_entries: u64,
    #[serde(default = "default_checkpoint_seconds")]
    pub checkpoint_interval_seconds: u64,
    #[serde(default)]
    pub checkpoint_signing_key: Option<String>,
    #[serde(default)]
    pub anchor_rekor_url: Option<String>,
    #[serde(default)]
    pub anchor_tsa_url: Option<String>,
    /// block | allow.
    #[serde(default = "default_ungoverned")]
    pub ungoverned_default: String,
    #[serde(default)]
    pub derived_attributes: Vec<DerivedDeclaration>,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub policy_pack_registry: Vec<String>,
}

fn default_mode() -> String {
    "enforce".into()
}
fn default_database_url() -> String {
    "sqlite://./chaperone.db".into()
}
fn default_engine() -> String {
    "cedar".into()
}
fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8400
}
fn default_api_token() -> String {
    "dev-token".into()
}
fn default_cache_ttl() -> u64 {
    30
}
fn default_cache_ttl_no_redis() -> u64 {
    5
}
fn default_escalation_ttl() -> i64 {
    900
}
fn default_hook_prompt_bound() -> u64 {
    30
}
fn default_retention_days() -> u32 {
    30
}
fn default_checkpoint_entries() -> u64 {
    1000
}
fn default_checkpoint_seconds() -> u64 {
    300
}
fn default_ungoverned() -> String {
    "block".into()
}
fn default_max_body_bytes() -> usize {
    1024 * 1024
}

impl Default for Config {
    fn default() -> Self {
        // Env overrides for the most common fields (documented prefix).
        Config {
            mode: env_or("CHAPERONE_MODE", default_mode()),
            database_url: env_or("CHAPERONE_DATABASE_URL", default_database_url()),
            redis_url: env_opt("CHAPERONE_REDIS_URL"),
            engine: env_or("CHAPERONE_ENGINE", default_engine()),
            serve_host: env_or("CHAPERONE_SERVE_HOST", default_host()),
            serve_port: env_or("CHAPERONE_SERVE_PORT", default_port()),
            api_token: env_or("CHAPERONE_API_TOKEN", default_api_token()),
            cache_ttl_seconds: env_or("CHAPERONE_CACHE_TTL_SECONDS", default_cache_ttl()),
            cache_ttl_no_redis_seconds: env_or(
                "CHAPERONE_CACHE_TTL_NO_REDIS_SECONDS",
                default_cache_ttl_no_redis(),
            ),
            escalation_ttl_seconds: env_or(
                "CHAPERONE_ESCALATION_TTL_SECONDS",
                default_escalation_ttl(),
            ),
            hook_prompt_bound_seconds: env_or(
                "CHAPERONE_HOOK_PROMPT_BOUND_SECONDS",
                default_hook_prompt_bound(),
            ),
            webhook_url: env_opt("CHAPERONE_WEBHOOK_URL"),
            webhook_secret: env_opt("CHAPERONE_WEBHOOK_SECRET"),
            proposed_params_retention_days: env_or(
                "CHAPERONE_PROPOSED_PARAMS_RETENTION_DAYS",
                default_retention_days(),
            ),
            checkpoint_interval_entries: env_or(
                "CHAPERONE_CHECKPOINT_INTERVAL_ENTRIES",
                default_checkpoint_entries(),
            ),
            checkpoint_interval_seconds: env_or(
                "CHAPERONE_CHECKPOINT_INTERVAL_SECONDS",
                default_checkpoint_seconds(),
            ),
            checkpoint_signing_key: env_opt("CHAPERONE_CHECKPOINT_SIGNING_KEY"),
            anchor_rekor_url: env_opt("CHAPERONE_ANCHOR_REKOR_URL"),
            anchor_tsa_url: env_opt("CHAPERONE_ANCHOR_TSA_URL"),
            ungoverned_default: env_or("CHAPERONE_UNGOVERNED_DEFAULT", default_ungoverned()),
            derived_attributes: Vec::new(),
            max_body_bytes: env_or("CHAPERONE_MAX_BODY_BYTES", default_max_body_bytes()),
            policy_pack_registry: Vec::new(),
        }
    }
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Load `chaperone.yaml` from `path` (or the current directory default) and
/// merge env overrides. A missing file yields `Config::default()`.
pub fn load(path: Option<&str>) -> Result<Config, String> {
    let path = path.unwrap_or("chaperone.yaml");
    let base = Config::default();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Ok(base),
    };
    let from_file: Config = serde_yaml::from_str(&text).map_err(|e| e.to_string())?;
    // Env overrides always win over the file (documented precedence).
    Ok(merge_env(from_file))
}

/// Overlay env vars on a parsed file config (env > file). Env values that are
/// set but unparseable are ignored (the file value stands).
fn merge_env(mut c: Config) -> Config {
    if let Some(v) = env_opt("CHAPERONE_MODE") {
        c.mode = v;
    }
    if let Some(v) = env_opt("CHAPERONE_DATABASE_URL") {
        c.database_url = v;
    }
    if let Some(v) = env_opt("CHAPERONE_REDIS_URL") {
        c.redis_url = Some(v);
    }
    if let Some(v) = env_opt("CHAPERONE_ENGINE") {
        c.engine = v;
    }
    if let Some(v) = env_opt("CHAPERONE_SERVE_HOST") {
        c.serve_host = v;
    }
    if let Some(v) = env_opt("CHAPERONE_SERVE_PORT").and_then(|s| s.parse().ok()) {
        c.serve_port = v;
    }
    if let Some(v) = env_opt("CHAPERONE_API_TOKEN") {
        c.api_token = v;
    }
    if let Some(v) = env_opt("CHAPERONE_CACHE_TTL_SECONDS").and_then(|s| s.parse().ok()) {
        c.cache_ttl_seconds = v;
    }
    if let Some(v) = env_opt("CHAPERONE_CACHE_TTL_NO_REDIS_SECONDS").and_then(|s| s.parse().ok()) {
        c.cache_ttl_no_redis_seconds = v;
    }
    if let Some(v) = env_opt("CHAPERONE_ESCALATION_TTL_SECONDS").and_then(|s| s.parse().ok()) {
        c.escalation_ttl_seconds = v;
    }
    if let Some(v) = env_opt("CHAPERONE_HOOK_PROMPT_BOUND_SECONDS").and_then(|s| s.parse().ok()) {
        c.hook_prompt_bound_seconds = v;
    }
    if let Some(v) = env_opt("CHAPERONE_WEBHOOK_URL") {
        c.webhook_url = Some(v);
    }
    if let Some(v) = env_opt("CHAPERONE_WEBHOOK_SECRET") {
        c.webhook_secret = Some(v);
    }
    if let Some(v) =
        env_opt("CHAPERONE_PROPOSED_PARAMS_RETENTION_DAYS").and_then(|s| s.parse().ok())
    {
        c.proposed_params_retention_days = v;
    }
    if let Some(v) = env_opt("CHAPERONE_CHECKPOINT_INTERVAL_ENTRIES").and_then(|s| s.parse().ok()) {
        c.checkpoint_interval_entries = v;
    }
    if let Some(v) = env_opt("CHAPERONE_CHECKPOINT_INTERVAL_SECONDS").and_then(|s| s.parse().ok()) {
        c.checkpoint_interval_seconds = v;
    }
    if let Some(v) = env_opt("CHAPERONE_CHECKPOINT_SIGNING_KEY") {
        c.checkpoint_signing_key = Some(v);
    }
    if let Some(v) = env_opt("CHAPERONE_ANCHOR_REKOR_URL") {
        c.anchor_rekor_url = Some(v);
    }
    if let Some(v) = env_opt("CHAPERONE_ANCHOR_TSA_URL") {
        c.anchor_tsa_url = Some(v);
    }
    if let Some(v) = env_opt("CHAPERONE_UNGOVERNED_DEFAULT") {
        c.ungoverned_default = v;
    }
    if let Some(v) = env_opt("CHAPERONE_MAX_BODY_BYTES").and_then(|s| s.parse().ok()) {
        c.max_body_bytes = v;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_table() {
        let c = Config::default();
        assert_eq!(c.mode, "enforce");
        assert_eq!(c.database_url, "sqlite://./chaperone.db");
        assert_eq!(c.redis_url, None);
        assert_eq!(c.engine, "cedar");
        assert_eq!(c.serve_host, "127.0.0.1");
        assert_eq!(c.serve_port, 8400);
        assert_eq!(c.api_token, "dev-token");
        assert_eq!(c.cache_ttl_seconds, 30);
        assert_eq!(c.cache_ttl_no_redis_seconds, 5);
        assert_eq!(c.escalation_ttl_seconds, 900);
        assert_eq!(c.hook_prompt_bound_seconds, 30);
        assert_eq!(c.proposed_params_retention_days, 30);
        assert_eq!(c.checkpoint_interval_entries, 1000);
        assert_eq!(c.checkpoint_interval_seconds, 300);
        assert_eq!(c.ungoverned_default, "block");
        assert!(c.derived_attributes.is_empty());
        assert_eq!(c.max_body_bytes, 1024 * 1024);
    }

    #[test]
    fn parses_derived_attributes_from_yaml() {
        let yaml = r#"
mode: enforce
derived_attributes:
  - id: agent_daily_total_amount
    kind: ledger_sum
    window_seconds: 86400
    tool: stripe.refunds.create
    param_path: amount
    same_agent: true
  - id: hourly_delete_count
    kind: ledger_count
    window_seconds: 3600
    tool: fs.write
    param_path: ""
"#;
        let c: Config = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(c.derived_attributes.len(), 2);
        assert_eq!(c.derived_attributes[0].id, "agent_daily_total_amount");
        assert_eq!(
            c.derived_attributes[0].kind,
            chaperone_core::engine::derive::DerivedKind::LedgerSum
        );
        assert_eq!(c.derived_attributes[1].id, "hourly_delete_count");
    }

    #[test]
    fn rejects_unknown_config_fields() {
        let yaml = "made_up_field: true\n";
        let err = serde_yaml::from_str::<Config>(yaml).expect_err("unknown field must be rejected");
        assert!(err.to_string().contains("made_up_field"));
    }
}
