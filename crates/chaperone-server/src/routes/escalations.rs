//! Escalation inbox routes (docs/api-contracts.md + flows/03): list pending,
//! get one, resolve (approve/deny) — 409 if not pending.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::auth;
use crate::error;
use crate::state::AppState;

/// GET /v1/escalations?status=pending — the inbox.
pub async fn list_escalations(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(b) = auth::authenticate(&state.store, auth::bearer_header(&headers)).await {
        return *b;
    }
    match state.store.list_pending_escalations().await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(_) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::PolicyNotFound,
            "list failed",
        ),
    }
}

/// GET /v1/escalations/{id}
pub async fn get_escalation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth::authenticate(&state.store, auth::bearer_header(&headers)).await {
        return *b;
    }
    match state.store.get_escalation(&id).await {
        Ok(Some(row)) => (StatusCode::OK, Json(row)).into_response(),
        _ => error::not_found(format!("escalation {id}")),
    }
}

/// POST /v1/escalations/{id}/resolve {resolution, resolver, note}
#[derive(Deserialize)]
pub struct ResolveBody {
    pub resolution: String, // "approve" | "deny"
    #[serde(default)]
    pub resolver: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

pub async fn resolve_escalation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Json<ResolveBody>,
) -> Response {
    let principal = match auth::authenticate(&state.store, auth::bearer_header(&headers)).await {
        Ok(p) => p,
        Err(b) => return *b,
    };
    if !principal.is_admin {
        return error::gate_error(
            StatusCode::FORBIDDEN,
            chaperone_core::models::errors::ErrorCode::AgentKeyUnknown,
            "admin key required",
        );
    }
    let status = match body.resolution.as_str() {
        "approve" => "approved",
        "deny" => "denied",
        _ => return error::malformed("resolution must be approve or deny"),
    };
    match state
        .store
        .resolve_escalation(
            &id,
            status,
            body.resolver.as_deref(),
            body.note.as_deref(),
            None,
        )
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"resolved": status})),
        )
            .into_response(),
        Err(chaperone_core::storage::store::StoreError::NotFound(_)) => {
            // 409: not pending (flows/03: concurrent resolution loser → 409).
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "escalation not pending"})),
            )
                .into_response()
        }
        Err(_) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::PolicyNotFound,
            "resolve failed",
        ),
    }
}

/// POST /v1/escalations/expire — manually expire overdue pending escalations
/// (flows/03 "manual POST /v1/escalations/expire for deterministic tests").
pub async fn expire_escalations(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let principal = match auth::authenticate(&state.store, auth::bearer_header(&headers)).await {
        Ok(p) => p,
        Err(b) => return *b,
    };
    if !principal.is_admin {
        return error::gate_error(
            StatusCode::FORBIDDEN,
            chaperone_core::models::errors::ErrorCode::AgentKeyUnknown,
            "admin key required",
        );
    }
    // Sweep through the escalation service (append-then-mark: each expiry
    // appends an ESCALATION_RESOLVED(EXPIRED) ledger entry before the row flips).
    match state.escalations.sweep_due().await {
        Ok(expired) => (
            StatusCode::OK,
            Json(serde_json::json!({"expired": expired})),
        )
            .into_response(),
        Err(_) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::PolicyNotFound,
            "expire failed",
        ),
    }
}
