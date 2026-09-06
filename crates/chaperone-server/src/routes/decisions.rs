//! POST /v1/decisions — the hot path (flows/02). Verdicts are IN-BAND (HTTP
//! 200); gate failures (ledger/policy) are HTTP errors, never decisions.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chaperone_core::models::decision::DecisionRequest;
use chaperone_core::models::errors::ErrorCode;

use crate::auth;
use crate::error;
use crate::state::AppState;

/// POST /v1/decisions
pub async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let principal = match auth::authenticate(&state.store, auth::bearer_header(&headers)).await {
        Ok(p) => p,
        Err(b) => return *b,
    };
    // Agent identity is PINNED to the authenticated key (review-4 B3): a
    // non-admin key cannot act for another agent.
    let request: DecisionRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return error::malformed(format!("invalid decision request: {e}")),
    };
    if !principal.is_admin && principal.agent_id.as_deref() != Some(request.agent_id.as_str()) {
        // A non-admin key cannot act for another agent (B3 identity pinning).
        return error::gate_error(
            StatusCode::FORBIDDEN,
            ErrorCode::AgentKeyUnknown,
            "key is not bound to this agent",
        );
    }

    let env = state.decisions.decide(&request).await;
    match env.error {
        Some(chaperone_core::decision::service::DecisionError::LedgerUnavailable(msg)) => {
            // Ledger write failed → 503 (no verdict returned; Law 1).
            error::ledger_unavailable(msg)
        }
        Some(chaperone_core::decision::service::DecisionError::PolicyUnavailable(msg)) => {
            error::gate_error(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::PolicyNotFound,
                msg,
            )
        }
        Some(e) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::MalformedRequest,
            e.to_string(),
        ),
        None => {
            // Successful verdict → observability + live stream (flows/02/08).
            crate::state::observe_decision(&state, &env.response);
            (StatusCode::OK, Json(env.response)).into_response()
        }
    }
}
