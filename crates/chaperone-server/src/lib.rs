//! Chaperone server library.
//!
//! axum app factory + routes, consumed by the `chaperone serve` subcommand
//! (docs/repo-layout.md). Exactly one binary ships: `chaperone` (chaperone-cli).
//!
//! Wire contracts are FROZEN (docs/api-contracts.md): unknown fields rejected,
//! verdicts are in-band HTTP 200, gate failures are HTTP errors (a 4xx/5xx is
//! never a verdict — interceptors treat it as fail-closed).

pub mod auth;
pub mod error;
pub mod rate_limit;
pub mod routes;
pub mod state;

pub use state::AppState;

/// Build the axum router (the app factory). Routes are exactly the frozen set
/// from docs/api-contracts.md:
///   POST /v1/decisions · GET /v1/policies · GET /v1/policies/{id} ·
///   GET /v1/policies/{id}/versions · GET /v1/policies/{id}/versions/{v} ·
///   POST /v1/policies/{id}/activate · GET /v1/escalations ·
///   GET /v1/escalations/{id} · POST /v1/escalations/{id}/resolve ·
///   GET /v1/ledger/entries · GET /v1/ledger/verify · GET /v1/ledger/prove ·
///   GET /v1/ledger/checkpoints · /healthz · /metrics · /ws/decisions
pub fn app(state: AppState) -> axum::Router {
    axum::Router::new()
        .route(
            "/v1/decisions",
            axum::routing::post(routes::decisions::decide),
        )
        .route(
            "/v1/policies",
            axum::routing::get(routes::policies::list_policies),
        )
        .route(
            "/v1/policies/{id}",
            axum::routing::get(routes::policies::get_policy),
        )
        .route(
            "/v1/policies/{id}/versions",
            axum::routing::get(routes::policies::list_versions),
        )
        .route(
            "/v1/policies/{id}/versions/{version}",
            axum::routing::get(routes::policies::get_version),
        )
        .route(
            "/v1/policies/{id}/activate",
            axum::routing::post(routes::policies::activate_policy),
        )
        .route(
            "/v1/escalations",
            axum::routing::get(routes::escalations::list_escalations),
        )
        .route(
            "/v1/escalations/{id}",
            axum::routing::get(routes::escalations::get_escalation),
        )
        .route(
            "/v1/escalations/{id}/resolve",
            axum::routing::post(routes::escalations::resolve_escalation),
        )
        .route(
            "/v1/ledger/entries",
            axum::routing::get(routes::ledger::list_entries),
        )
        .route(
            "/v1/ledger/verify",
            axum::routing::get(routes::ledger::verify),
        )
        .route(
            "/v1/ledger/prove",
            axum::routing::get(routes::ledger::prove),
        )
        .route(
            "/v1/ledger/checkpoints",
            axum::routing::get(routes::ledger::checkpoints),
        )
        .route(
            "/v1/ledger/checkpoints/{id}",
            axum::routing::get(routes::ledger::checkpoint),
        )
        .route("/healthz", axum::routing::get(routes::health::healthz))
        .route("/metrics", axum::routing::get(routes::health::metrics))
        .with_state(state)
}

/// The default per-key rate-limit config (burst 1000, 300/sec sustained —
/// scalability-targets node ceiling).
pub fn default_rate_limit() -> rate_limit::RateLimitConfig {
    rate_limit::RateLimitConfig::default()
}

/// Build the router with the per-key rate limiter applied as a tower layer
/// (flows/02 invariant 10). `config` controls the ceiling; the limiter is
/// shared so the layer state persists across requests.
pub fn app_with_rate_limit(state: AppState, config: rate_limit::RateLimitConfig) -> axum::Router {
    let limiter = rate_limit::RateLimiter::new();
    let layer = rate_limit::RateLimitLayer::new(limiter, config);
    app(state).layer(layer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use chaperone_core::clock::SystemClock;
    use chaperone_core::decision::service::ServiceMode;
    use chaperone_core::storage::store::Store;
    use http_body_util::BodyExt;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Build a test app over a real in-memory sqlite store with a seeded
    /// agent + api key + an active policy. Returns (router, store, state).
    async fn test_app() -> (axum::Router, Store, AppState) {
        let store = Store::open_sqlite("sqlite::memory:")
            .await
            .expect("in-memory store");
        // Seed genesis, agent, admin key, and an active policy.
        chaperone_core::ledger::chain::append_genesis(&store)
            .await
            .expect("genesis");
        store
            .upsert_agent_identity(&chaperone_core::storage::store::AgentIdentityRow {
                agent_id: "agent_support_09".into(),
                name: "Support".into(),
                role: "support".into(),
                spiffe_id: None,
                tenant_id: None,
                max_delegation_depth: 1,
                is_active: true,
                created_at: "2026-08-25T00:00:00Z".into(),
            })
            .await
            .expect("agent");
        store
            .insert_api_key(&chaperone_core::storage::store::ApiKeyRow {
                key_hash: auth::hash_key("dev-token"),
                agent_id: Some("agent_support_09".into()),
                is_admin: false,
                created_at: "2026-08-25T00:00:00Z".into(),
                last_used_at: None,
                expires_at: None,
                revoked_at: None,
            })
            .await
            .expect("key");
        // Active policy (allow ≤200, escalate 100..1000, block >1000).
        store
            .upsert_policy("pol_refunds", "Refunds", None)
            .await
            .expect("policy shell");
        let ir = json!({
            "ir_version": "1",
            "policy_id": "pol_refunds",
            "version": 1,
            "description": "refund policy",
            "rules": [
                {
                    "rule_id": "r-allow-small",
                    "description": "allow <= 200",
                    "effect": "allow",
                    "target": {"tools": ["stripe.refunds.create"]},
                    "condition": {"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}}
                },
                {
                    "rule_id": "r-escalate-mid",
                    "description": "escalate 100..1000",
                    "effect": "escalate",
                    "target": {"tools": ["stripe.refunds.create"]},
                    "condition": {"op": "gte", "left": {"param": "amount"}, "right": {"value": 100}}
                },
                {
                    "rule_id": "r-block-large",
                    "description": "block > 1000",
                    "effect": "block",
                    "target": {"tools": ["stripe.refunds.create"]},
                    "condition": {"op": "gt", "left": {"param": "amount"}, "right": {"value": 1000}}
                }
            ]
        });
        let cedar_text = chaperone_core::engine::cedar_compile::to_cedar(
            &serde_json::from_value(ir.clone()).expect("ir"),
        )
        .expect("cedar")
        .into_iter()
        .map(|c| c.text)
        .collect::<Vec<_>>()
        .join("\n");
        let policy_hash =
            chaperone_core::canonical::sha256_hex(&chaperone_core::canonical::canonical_dumps(&ir));
        store
            .insert_policy_version(&chaperone_core::storage::store::PolicyVersionRow {
                policy_id: "pol_refunds".into(),
                version: 1,
                status: "active".into(),
                raw_sop_text: None,
                ir_json: ir.to_string(),
                cedar_text,
                policy_hash,
                conflict_report: None,
                test_report: None,
                compiler_model: None,
                created_by: Some("test".into()),
                approved_by: Some("admin".into()),
                created_at: "2026-08-25T00:00:00Z".into(),
                activated_at: None,
            })
            .await
            .expect("policy version");

        let cache = chaperone_core::cache::policy_cache::PolicyCache::new(
            chaperone_core::cache::policy_cache::StorePolicyProvider::new(store.clone()),
            Arc::new(SystemClock),
            None,
        );
        let state = state::build_state(
            store.clone(),
            cache,
            Arc::new(SystemClock),
            ServiceMode::Enforce,
            chaperone_core::decision::service::UngovernedDefault::Block,
            900,
            vec![],
        );
        (app(state.clone()), store, state)
    }

    fn decision_body(amount: i64) -> serde_json::Value {
        json!({
            "request_id": format!("req_{}", amount),
            "agent_id": "agent_support_09",
            "tool": "stripe.refunds.create",
            "params": {"amount": amount},
            "context": {
                "session_id": null,
                "surface": "claude_code",
                "delegation_depth": 0,
                "request_time": "2026-08-25T14:00:00Z"
            },
            "escalation_id": null
        })
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // --- happy paths -------------------------------------------------------

    #[tokio::test]
    async fn decisions_endpoint_allow() {
        let (app, _store, _state) = test_app().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/decisions")
                    .header("authorization", "Bearer dev-token")
                    .header("content-type", "application/json")
                    .body(Body::from(decision_body(50).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["decision"], "ALLOW");
        assert_eq!(v["reason_code"], "RULE_MATCH");
        assert_eq!(v["policy_id"], "pol_refunds");
        assert_eq!(v["entry_seq"], 1, "genesis(0) + decision(1)");
    }

    #[tokio::test]
    async fn decisions_endpoint_escalate_creates_ticket() {
        let (app, store, _state) = test_app().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/decisions")
                    .header("authorization", "Bearer dev-token")
                    .header("content-type", "application/json")
                    .body(Body::from(decision_body(450).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["decision"], "ESCALATE");
        let esc_id = v["escalation_id"].as_str().expect("ticket id").to_string();
        assert!(esc_id.starts_with("esc_"));
        assert!(v["escalation_expires_at"].is_string());
        // The ticket row exists.
        let row = store.get_escalation(&esc_id).await.unwrap().expect("row");
        assert_eq!(row.status, "pending");
        assert_eq!(
            row.decision_entry_seq,
            Some(v["entry_seq"].as_u64().unwrap() as i64)
        );
    }

    #[tokio::test]
    async fn decisions_endpoint_block() {
        let (app, _store, _state) = test_app().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/decisions")
                    .header("authorization", "Bearer dev-token")
                    .header("content-type", "application/json")
                    .body(Body::from(decision_body(5000).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["decision"], "BLOCK");
        assert_eq!(v["reason_code"], "RULE_MATCH");
    }

    // --- failure paths (a 4xx/5xx is never a verdict) ----------------------

    #[tokio::test]
    async fn unknown_key_401() {
        let (app, _store, _state) = test_app().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/decisions")
                    .header("authorization", "Bearer wrong-token")
                    .header("content-type", "application/json")
                    .body(Body::from(decision_body(150).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let v = body_json(resp).await;
        assert_eq!(v["error"]["code"], "AGENT_KEY_UNKNOWN");
    }

    #[tokio::test]
    async fn missing_key_401() {
        let (app, _store, _state) = test_app().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/decisions")
                    .header("content-type", "application/json")
                    .body(Body::from(decision_body(150).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_request_422() {
        let (app, _store, _state) = test_app().await;
        // An unknown field (e.g. a client-supplied "mode") is rejected.
        let mut body = decision_body(150);
        body["mode"] = json!("shadow");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/decisions")
                    .header("authorization", "Bearer dev-token")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let v = body_json(resp).await;
        assert_eq!(v["error"]["code"], "MALFORMED_REQUEST");
    }

    #[tokio::test]
    async fn healthz_ok() {
        let (app, _store, _state) = test_app().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ledger_verify_endpoint() {
        let (app, _store, _state) = test_app().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/ledger/verify")
                    .header("authorization", "Bearer dev-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["status"], "ok");
        assert_eq!(v["entries"], 1, "genesis only");
    }

    #[tokio::test]
    async fn ledger_verify_requires_auth() {
        let (app, _store, _state) = test_app().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/ledger/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// The per-key rate limiter: a burst of 2 allows 2 then 429s the third,
    /// with the RATE_LIMITED body + retry-after header (flows/02 invariant 10).
    #[tokio::test]
    async fn rate_limited_429() {
        // Rebuild the app with the rate-limit layer at a tight config.
        let (_app, _store, state) = test_app().await;
        let config = crate::rate_limit::RateLimitConfig {
            burst: 2,
            per_second: 1,
        };
        let app = app_with_rate_limit(state, config);

        let req = || {
            Request::builder()
                .method("POST")
                .uri("/v1/decisions")
                .header("authorization", "Bearer dev-token")
                .header("content-type", "application/json")
                .body(Body::from(decision_body(50).to_string()))
                .unwrap()
        };
        // First two pass (burst), third is limited.
        let r1 = app.clone().oneshot(req()).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = app.clone().oneshot(req()).await.unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
        let r3 = app.clone().oneshot(req()).await.unwrap();
        assert_eq!(r3.status(), StatusCode::TOO_MANY_REQUESTS);
        let v = body_json(r3).await;
        assert_eq!(v["error"]["code"], "RATE_LIMITED");
        assert!(
            v["error"]["detail"]["retry_after_seconds"]
                .as_u64()
                .unwrap()
                >= 1
        );
    }
}
