//! `chaperone gateway --upstream <url> --port <port>` — the MCP
//! streamable-HTTP gateway (flows/06). The org-wide chokepoint: one reverse
//! proxy in front of every MCP server governs every tool call under one policy
//! set, one inbox, one ledger.
//!
//! Authorization is decided IN-PROCESS (the same PolicyCache + DecisionService
//! graph `serve` builds), so agent identity is pinned to the API key
//! server-side (review-4 B3) — no env override, no request-supplied agent_id.
//! The body is deserialized once for tools/call (correctness-safe; the
//! `needs_params` fast path that skips parsing is a later optimization and is
//! deliberately not wired here — parsing is never wrong, just slightly slower).
//!
//! Verdict mapping (flows/06):
//!   ALLOW    → forward to upstream, stream the response back untouched
//!   BLOCK    → JSON-RPC error -32050 {policy_id, rule_ids, entry_seq}
//!   ESCALATE → MRTR InputRequiredResult with a SIGNED requestState (HMAC over
//!              canonical JSON of {escalation_id, expires_at, params_binding_hash,
//!              agent_id} — Law 4, review-4 B2). Retry verifies HMAC → the
//!              decision service consumes the escalation (single-use, params-bound).
//!
//! Non-tools/call methods (initialize, tools/list, resources) pass through.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chaperone_core::cache::policy_cache::{PolicyCache, StorePolicyProvider};
use chaperone_core::decision::service::{ServiceMode, UngovernedDefault};
use chaperone_core::ledger::ChainStore;
use chaperone_core::models::decision::{Decision, DecisionRequest, RequestContext, Surface};
use chaperone_core::storage::store::Store;
use chaperone_server::auth;
use chaperone_server::state::{DecisionServiceType, StateConfig, build_state};
use clap::Args;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;

#[derive(Args, Debug)]
pub struct GatewayArgs {
    /// The upstream MCP server URL.
    #[arg(long)]
    pub upstream: String,
    /// Listen port (default 8500).
    #[arg(long, default_value_t = 8500)]
    pub port: u16,
    /// The requestState HMAC root secret (CHAPERONE_GATEWAY_SECRET).
    #[arg(long, env = "CHAPERONE_GATEWAY_SECRET", default_value = "dev-secret")]
    pub secret: String,
    /// Max buffered request body bytes (default 1 MiB, fail-closed on oversize).
    #[arg(long, env = "CHAPERONE_MAX_BODY_BYTES", default_value_t = 1024 * 1024)]
    pub max_body_bytes: usize,
}

/// Sign a requestState: HMAC-SHA256 over the CANONICAL JSON of the tuple
/// {escalation_id, expires_at, params_binding_hash, agent_id} (flows/06,
/// review-4 B2: never ‖-concatenation). Returns base64.
pub fn sign_request_state(
    secret: &str,
    escalation_id: &str,
    expires_at: &str,
    params_binding_hash: &str,
    agent_id: &str,
) -> String {
    let payload = serde_json::json!({
        "escalation_id": escalation_id,
        "expires_at": expires_at,
        "params_binding_hash": params_binding_hash,
        "agent_id": agent_id,
    });
    let canonical = chaperone_core::canonical::canonical_dumps(&payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(canonical.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Verify a signed requestState. Returns true on a valid signature.
pub fn verify_request_state(
    secret: &str,
    signature: &str,
    escalation_id: &str,
    expires_at: &str,
    params_binding_hash: &str,
    agent_id: &str,
) -> bool {
    let expected = sign_request_state(
        secret,
        escalation_id,
        expires_at,
        params_binding_hash,
        agent_id,
    );
    // Constant-time compare via hmac::Mac::verify_slice.
    let sig = match base64::engine::general_purpose::STANDARD.decode(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(
        chaperone_core::canonical::canonical_dumps(&serde_json::json!({
            "escalation_id": escalation_id,
            "expires_at": expires_at,
            "params_binding_hash": params_binding_hash,
            "agent_id": agent_id,
        }))
        .as_bytes(),
    );
    mac.verify_slice(&sig).is_ok() && signature == expected
}

/// The signed requestState the gateway returns on ESCALATE. Serialized as JSON
/// so the retry can echo it opaquely and the gateway can re-derive + verify.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RequestState {
    escalation_id: String,
    expires_at: String,
    params_binding_hash: String,
    agent_id: String,
    sig: String,
}

impl RequestState {
    fn sign(
        secret: &str,
        escalation_id: &str,
        expires_at: &str,
        params_binding_hash: &str,
        agent_id: &str,
    ) -> Self {
        let sig = sign_request_state(
            secret,
            escalation_id,
            expires_at,
            params_binding_hash,
            agent_id,
        );
        RequestState {
            escalation_id: escalation_id.to_string(),
            expires_at: expires_at.to_string(),
            params_binding_hash: params_binding_hash.to_string(),
            agent_id: agent_id.to_string(),
            sig,
        }
    }

    fn verify(&self, secret: &str) -> bool {
        verify_request_state(
            secret,
            &self.sig,
            &self.escalation_id,
            &self.expires_at,
            &self.params_binding_hash,
            &self.agent_id,
        )
    }

    fn to_string_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Shared gateway state (cheap to clone: Store + Arc handles).
#[derive(Clone)]
struct GatewayState {
    decisions: Arc<DecisionServiceType>,
    store: Store,
    upstream: reqwest::Client,
    upstream_url: String,
    secret: String,
}

pub async fn run_gateway(args: GatewayArgs) -> i32 {
    let store = match super::open_store().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chaperone: cannot open store: {e}");
            return 1;
        }
    };
    // Genesis on first startup.
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
    // Startup crash-recovery: refuse to serve a tampered ledger.
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

    // In-process policy cache + decision service (the serve graph).
    let provider = StorePolicyProvider::new(store.clone());
    let cache = PolicyCache::new(provider, Arc::new(chaperone_core::clock::SystemClock), None);
    let state = build_state(StateConfig {
        store: store.clone(),
        cache,
        clock: Arc::new(chaperone_core::clock::SystemClock),
        mode: ServiceMode::Enforce,
        ungoverned_default: UngovernedDefault::Block,
        escalation_ttl_seconds: 900,
        declarations: vec![],
        notifier: None,
    });

    let upstream = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chaperone: cannot build upstream client: {e}");
            return 1;
        }
    };

    let gw_state = GatewayState {
        decisions: state.decisions.clone(),
        store,
        upstream,
        upstream_url: args.upstream.trim_end_matches('/').to_string(),
        secret: args.secret,
    };

    let app = axum::Router::new()
        .fallback(proxy_handler)
        .with_state(gw_state)
        .layer(axum::extract::DefaultBodyLimit::max(args.max_body_bytes));

    let addr = format!("127.0.0.1:{}", args.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chaperone: cannot bind {addr}: {e}");
            return 1;
        }
    };
    println!(
        "chaperone: gateway on http://{addr} → {} (in-process authorization)",
        args.upstream
    );
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("chaperone: gateway error: {e}");
        return 1;
    }
    0
}

/// The single gateway handler: passthrough for non-tools/call, authorization
/// for tools/call.
async fn proxy_handler(
    State(state): State<GatewayState>,
    method: Method,
    uri: axum::extract::OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let mcp_method = headers
        .get("mcp-method")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mcp_name = headers
        .get("mcp-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Non-tools/call methods pass through untouched (flows/06 step 4): the
    // gateway adds AuthZ, never replaces AuthN — OAuth is transparent.
    if mcp_method != "tools/call" {
        return forward_upstream(&state, &method, &headers, &body, uri.path()).await;
    }

    // tools/call: identity is PINNED to the authenticated API key (review-4 B3).
    let principal = match auth::authenticate(&state.store, auth::bearer_header(&headers)).await {
        Ok(p) => p,
        Err(b) => return *b,
    };
    let Some(agent_id) = principal.agent_id else {
        // A key with no bound agent cannot act through the gateway (B3).
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32050, "message": "gateway key is not bound to an agent"}
            })),
        )
            .into_response();
    };

    // tools/call: parse the JSON-RPC envelope to get id + params.
    let body_bytes = body.as_ref();
    let envelope: serde_json::Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(_) => return jsonrpc_error(-32700, "parse error", serde_json::Value::Null, None),
    };
    let id = envelope
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let tool = if !mcp_name.is_empty() {
        mcp_name.to_string()
    } else {
        envelope["params"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    let params = envelope
        .get("params")
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    // A retry carries a signed requestState (MRTR). Verify it and extract the
    // escalation_id; the decision service then re-checks approved/unconsumed/
    // params-bound (single-use enforced server-side).
    let escalation_id = if let Some(rs) = envelope
        .get("_meta")
        .and_then(|m| m.get("request_state"))
        .cloned()
    {
        match serde_json::from_value::<RequestState>(rs) {
            Ok(r) if r.verify(&state.secret) => Some(r.escalation_id),
            _ => {
                return jsonrpc_error(
                    -32050,
                    "invalid or expired requestState",
                    serde_json::Value::Null,
                    Some(id),
                );
            }
        }
    } else {
        None
    };

    // Build the decision request (request_id + request_time at the boundary).
    let request = DecisionRequest {
        request_id: format!("gateway_{}", uuid::Uuid::new_v4().simple()),
        agent_id: agent_id.clone(),
        tool,
        params,
        context: RequestContext {
            session_id: None,
            surface: Surface::McpGateway,
            delegation_depth: 0,
            request_time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        },
        escalation_id,
    };

    let env = state.decisions.decide(&request).await;
    match env.error {
        Some(chaperone_core::decision::service::DecisionError::LedgerUnavailable(msg)) => {
            return jsonrpc_error(
                -32050,
                &format!("ledger unavailable: {msg}"),
                serde_json::Value::Null,
                Some(id),
            );
        }
        Some(chaperone_core::decision::service::DecisionError::PolicyUnavailable(msg)) => {
            return jsonrpc_error(
                -32050,
                &format!("policy unavailable: {msg}"),
                serde_json::Value::Null,
                Some(id),
            );
        }
        Some(e) => {
            return jsonrpc_error(-32050, &e.to_string(), serde_json::Value::Null, Some(id));
        }
        None => {}
    }

    let resp = env.response;
    match resp.decision {
        Decision::Allow => forward_upstream(&state, &method, &headers, &body, uri.path()).await,
        Decision::Block => {
            let data = serde_json::json!({
                "policy_id": resp.policy_id,
                "rule_ids": resp.determining_rule_ids,
                "entry_seq": resp.entry_seq,
            });
            jsonrpc_error(
                -32050,
                &format!("blocked by policy ({:?})", resp.reason_code),
                data,
                Some(id),
            )
        }
        Decision::Escalate => {
            let esc_id = resp.escalation_id.unwrap_or_default();
            let expires = resp.escalation_expires_at.unwrap_or_default();
            // params_binding_hash = canonical hash of params (retry binding).
            let binding = chaperone_core::canonical::sha256_hex(
                &chaperone_core::canonical::canonical_dumps(&request.params),
            );
            let request_state =
                RequestState::sign(&state.secret, &esc_id, &expires, &binding, &agent_id);
            let result = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "resultType": "input_required",
                    "requestState": request_state.to_string_value(),
                }
            });
            (StatusCode::OK, axum::Json(result)).into_response()
        }
        // Shadow verdicts never occur in gateway mode (enforce only).
        other => jsonrpc_error(
            -32050,
            &format!("unexpected verdict {other:?}"),
            serde_json::Value::Null,
            Some(id),
        ),
    }
}

/// Forward a request to the upstream MCP server and stream the response back.
async fn forward_upstream(
    state: &GatewayState,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
    path: &str,
) -> Response {
    let url = format!("{}{}", state.upstream_url, path);
    let mut req = state
        .upstream
        .request(method.clone(), &url)
        .body(body.to_vec());
    // Copy safe headers (skip hop-by-hop + auth — the gateway re-auths upstream).
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("authorization")
            || n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        req = req.header(n, value.as_bytes());
    }
    match req.send().await {
        Ok(mut upstream_resp) => {
            let status = upstream_resp.status();
            // Take headers BEFORE consuming the body stream (bytes_stream
            // takes ownership of the response).
            let resp_headers = std::mem::take(upstream_resp.headers_mut());
            let stream = upstream_resp.bytes_stream();
            let body = Body::from_stream(stream);
            let mut builder = axum::response::Response::builder().status(status);
            for (name, value) in resp_headers.iter() {
                let n = name.as_str();
                if n.eq_ignore_ascii_case("connection")
                    || n.eq_ignore_ascii_case("transfer-encoding")
                    || n.eq_ignore_ascii_case("content-length")
                {
                    continue;
                }
                builder = builder.header(n, value.as_bytes());
            }
            builder
                .body(body)
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY).into_response())
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            format!("chaperone: upstream unreachable: {e}"),
        )
            .into_response(),
    }
}

/// A JSON-RPC 2.0 error envelope (flows/06: BLOCK → -32050).
fn jsonrpc_error(
    code: i64,
    message: &str,
    data: serde_json::Value,
    id: Option<serde_json::Value>,
) -> Response {
    let id = id.unwrap_or(serde_json::Value::Null);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message, "data": data }
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;

    /// Build a GatewayState over an in-memory sqlite store with genesis, a
    /// bound agent + key, and an active allow/block/escalate policy.
    async fn test_state() -> GatewayState {
        let store = Store::open_sqlite("sqlite::memory:").await.expect("store");
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
                key_hash: chaperone_server::auth::hash_key("dev-token"),
                agent_id: Some("agent_support_09".into()),
                is_admin: false,
                created_at: "2026-08-25T00:00:00Z".into(),
                last_used_at: None,
                expires_at: None,
                revoked_at: None,
            })
            .await
            .expect("key");
        store
            .upsert_policy("pol_refunds", "Refunds", None)
            .await
            .expect("shell");
        let ir = serde_json::json!({
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
            .expect("version");

        let provider = StorePolicyProvider::new(store.clone());
        let cache = PolicyCache::new(provider, Arc::new(chaperone_core::clock::SystemClock), None);
        let app_state = build_state(StateConfig {
            store: store.clone(),
            cache,
            clock: Arc::new(chaperone_core::clock::SystemClock),
            mode: ServiceMode::Enforce,
            ungoverned_default: UngovernedDefault::Block,
            escalation_ttl_seconds: 900,
            declarations: vec![],
            notifier: None,
        });
        GatewayState {
            decisions: app_state.decisions.clone(),
            store,
            upstream: reqwest::Client::new(),
            upstream_url: "http://127.0.0.1:1".to_string(), // never reached in BLOCK/ESCALATE tests
            secret: "test-secret".to_string(),
        }
    }

    /// Build a tools/call JSON-RPC request with a bound-agent bearer key.
    fn tools_call(amount: i64) -> Request<Body> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "stripe.refunds.create", "arguments": {"amount": amount}}
        });
        Request::builder()
            .method("POST")
            .uri("/")
            .header("authorization", "Bearer dev-token")
            .header("mcp-method", "tools/call")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    #[tokio::test]
    async fn block_returns_jsonrpc_error_with_ledger_ref() {
        let state = test_state().await;
        let resp = proxy_handler(
            State(state.clone()),
            Method::POST,
            axum::extract::OriginalUri(axum::http::Uri::from_static("/")),
            headers_of(&tools_call(5000)),
            axum::body::Bytes::from(
                serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "stripe.refunds.create", "arguments": {"amount": 5000}}
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["error"]["code"], -32050);
        assert_eq!(v["error"]["data"]["policy_id"], "pol_refunds");
        assert!(v["error"]["data"]["entry_seq"].as_u64().unwrap() >= 1);
        // The decision was ledgered.
        assert!(state.store.last_entry().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn escalate_returns_input_required_with_signed_state() {
        let state = test_state().await;
        let resp = proxy_handler(
            State(state.clone()),
            Method::POST,
            axum::extract::OriginalUri(axum::http::Uri::from_static("/")),
            headers_of(&tools_call(450)),
            axum::body::Bytes::from(
                serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "stripe.refunds.create", "arguments": {"amount": 450}}
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["result"]["resultType"], "input_required");
        let rs: RequestState =
            serde_json::from_value(v["result"]["requestState"].clone()).expect("requestState");
        assert!(rs.verify("test-secret"));
        assert!(rs.escalation_id.starts_with("esc_"));
    }

    #[tokio::test]
    async fn non_tools_call_passes_through_without_auth_check() {
        // A non-tools/call method forwards to upstream (the upstream is
        // unreachable here, so we get 502 — but NOT a JSON-RPC block).
        let state = test_state().await;
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("mcp-method", "initialize")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = proxy_handler(
            State(state.clone()),
            Method::POST,
            axum::extract::OriginalUri(axum::http::Uri::from_static("/")),
            headers_of(&req),
            axum::body::Bytes::from(body.to_string()),
        )
        .await;
        // Forwarding to an unreachable upstream → 502, NOT a policy verdict.
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    fn headers_of(req: &Request<Body>) -> HeaderMap {
        req.headers().clone()
    }

    #[test]
    fn request_state_sign_and_verify() {
        let secret = "root-secret";
        let sig = sign_request_state(secret, "esc_1", "2026-08-25T14:15:00Z", "abc123", "agent_1");
        assert!(!sig.is_empty());
        assert!(verify_request_state(
            secret,
            &sig,
            "esc_1",
            "2026-08-25T14:15:00Z",
            "abc123",
            "agent_1"
        ));
    }

    #[test]
    fn request_state_tamper_rejected() {
        let secret = "root-secret";
        let sig = sign_request_state(secret, "esc_1", "2026-08-25T14:15:00Z", "abc123", "agent_1");
        assert!(!verify_request_state(
            secret,
            &sig,
            "esc_1",
            "2026-08-25T14:15:00Z",
            "CHANGED",
            "agent_1"
        ));
        assert!(!verify_request_state(
            "other-secret",
            &sig,
            "esc_1",
            "2026-08-25T14:15:00Z",
            "abc123",
            "agent_1"
        ));
        assert!(!verify_request_state(
            secret,
            "!!!",
            "esc_1",
            "2026-08-25T14:15:00Z",
            "abc123",
            "agent_1"
        ));
    }

    #[test]
    fn canonical_payload_not_concatenated() {
        let s1 = sign_request_state("k", "ab", "c", "d", "e");
        let s2 = sign_request_state("k", "a", "bc", "d", "e");
        assert_ne!(s1, s2, "no ‖-concatenation ambiguity");
    }

    #[test]
    fn request_state_composite_roundtrip() {
        let secret = "root";
        let rs = RequestState::sign(secret, "esc_1", "2026-08-25T14:15:00Z", "abc", "agent_1");
        assert!(rs.verify(secret));
        assert!(!rs.verify("wrong"));
        // Serialize → deserialize → still verifies (opaque echo on retry).
        let json = rs.to_string_value();
        let back: RequestState = serde_json::from_value(json).unwrap();
        assert!(back.verify(secret));
        assert_eq!(back.escalation_id, "esc_1");
    }
}
