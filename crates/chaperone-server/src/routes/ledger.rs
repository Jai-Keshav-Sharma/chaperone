//! Ledger routes (docs/api-contracts.md): entries, verify, prove, checkpoints.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::error;
use crate::state::AppState;

async fn auth_ok(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    auth::authenticate(&state.store, auth::bearer_header(headers))
        .await
        .map(|_| ())
}

/// GET /v1/ledger/entries?after_seq=N — paginated history.
#[derive(Deserialize)]
pub struct EntriesQuery {
    pub after_seq: Option<u64>,
    pub limit: Option<u64>,
}

#[derive(Serialize)]
pub struct LedgerPage {
    pub entries: Vec<chaperone_core::models::ledger::LedgerEntry>,
    pub next_after_seq: Option<u64>,
}

pub async fn list_entries(
    State(state): State<AppState>,
    Query(q): Query<EntriesQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    let after = q.after_seq.unwrap_or(0);
    let limit = q.limit.unwrap_or(100).min(1000);
    match state.store.list_ledger_entries(after, limit).await {
        Ok(entries) => {
            let next = entries.last().map(|e| e.entry_seq + 1);
            (
                StatusCode::OK,
                Json(LedgerPage {
                    entries,
                    next_after_seq: next,
                }),
            )
                .into_response()
        }
        Err(_) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::LedgerUnavailable,
            "ledger read failed",
        ),
    }
}

/// GET /v1/ledger/verify — chain verification.
#[derive(Serialize)]
pub struct VerifyResult {
    pub status: String, // "ok" | "broken"
    pub entries: u64,
    pub broken_at: Option<u64>,
    pub reason: Option<String>,
}

pub async fn verify(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.all_ledger_entries().await {
        Ok(entries) => {
            let result = chaperone_core::ledger::verify::verify_chain(&entries);
            let out = match &result {
                chaperone_core::ledger::verify::VerificationResult::ChainOk { .. } => {
                    VerifyResult {
                        status: "ok".into(),
                        entries: entries.len() as u64,
                        broken_at: None,
                        reason: None,
                    }
                }
                chaperone_core::ledger::verify::VerificationResult::ChainBroken { seq, reason } => {
                    VerifyResult {
                        status: "broken".into(),
                        entries: entries.len() as u64,
                        broken_at: *seq,
                        reason: Some(reason.clone()),
                    }
                }
            };
            (StatusCode::OK, Json(out)).into_response()
        }
        Err(_) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::LedgerUnavailable,
            "ledger read failed",
        ),
    }
}

/// GET /v1/ledger/prove?seq=N — an inclusion proof bundle.
#[derive(Deserialize)]
pub struct ProveQuery {
    pub seq: u64,
}

pub async fn prove(
    State(state): State<AppState>,
    Query(q): Query<ProveQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.prove_entry(q.seq).await {
        Ok(Some(bundle)) => (StatusCode::OK, Json(bundle)).into_response(),
        _ => error::not_found(format!("ledger seq {}", q.seq)),
    }
}

/// GET /v1/ledger/checkpoints — the checkpoint list (latest first).
pub async fn checkpoints(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.list_checkpoints().await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(_) => error::gate_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            chaperone_core::models::errors::ErrorCode::LedgerUnavailable,
            "checkpoint read failed",
        ),
    }
}

/// GET /v1/ledger/checkpoints/{id}
pub async fn checkpoint(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    if let Err(b) = auth_ok(&state, &headers).await {
        return *b;
    }
    match state.store.get_checkpoint(id).await {
        Ok(Some(row)) => (StatusCode::OK, Json(row)).into_response(),
        _ => error::not_found(format!("checkpoint {id}")),
    }
}
