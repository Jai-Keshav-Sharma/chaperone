//! Health + metrics routes.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// GET /healthz — liveness (the gate's own health; no auth).
pub async fn healthz() -> Response {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

/// GET /metrics — Prometheus-style counters (decision totals). Kept minimal
/// and deterministic; the full histogram lands with the observability pass.
pub async fn metrics() -> Response {
    let body = "# HELP chaperone_decisions_total Total decisions evaluated.\n\
         # TYPE chaperone_decisions_total counter\n\
         chaperone_decisions_total 0\n"
        .to_string();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}
