//! Policy admin routes (docs/api-contracts.md frozen paths).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::auth;
use crate::error;
use crate::state::AppState;

/// GET /v1/policies — list policy shells.
#[derive(Serialize)]
pub struct PolicyShell {
    pub policy_id: String,
    pub name: String,
    pub active_version: Option<i64>,
}

async fn auth_ok(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    auth::authenticate(&state.store, auth::bearer_header(headers))
        .await
        .map(|_| ())
}

pub async fn list_policies(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.list_policies().await {
        Ok(rows) => {
            let out: Vec<PolicyShell> = rows
                .into_iter()
                .map(|r| PolicyShell {
                    policy_id: r.policy_id,
                    name: r.name,
                    active_version: r.active_version,
                })
                .collect();
            (StatusCode::OK, Json(out)).into_response()
        }
        Err(_) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::PolicyNotFound,
            "list failed",
        ),
    }
}

/// GET /v1/policies/{id} — the active policy.
pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.get_active_policy(&id).await {
        Ok(Some(row)) => (StatusCode::OK, Json(row)).into_response(),
        _ => error::not_found(format!("policy {id}")),
    }
}

/// GET /v1/policies/{id}/versions — all versions of a policy.
pub async fn list_versions(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.list_policy_versions(&id).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(_) => error::not_found(format!("policy {id}")),
    }
}

/// GET /v1/policies/{id}/versions/{version}
pub async fn get_version(
    State(state): State<AppState>,
    Path((id, version)): Path<(String, i64)>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.get_policy_version(&id, version).await {
        Ok(Some(row)) => (StatusCode::OK, Json(row)).into_response(),
        _ => error::not_found(format!("policy {id} v{version}")),
    }
}

/// POST /v1/policies/{id}/activate {version} — activate a version (admin).
#[derive(serde::Deserialize)]
pub struct ActivateBody {
    pub version: i64,
}

pub async fn activate_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Json<ActivateBody>,
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
    match state.store.activate_policy_version(&id, body.version).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"activated": true}))).into_response(),
        Err(_) => error::not_found(format!("policy {id} v{}", body.version)),
    }
}
