//! Bearer-token auth (docs/flows/02: static bearer API keys, SHA-256 hashed at
//! rest; agent keys != admin keys). The key hash is looked up in the DB; an
//! unknown key is a 401 (AGENT_KEY_UNKNOWN) — never a verdict.

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chaperone_core::models::errors::{ApiError, ErrorBody, ErrorCode};
use chaperone_core::storage::store::{ApiKeyRow, Store};
use sha2::{Digest, Sha256};

/// The authenticated principal extracted from the bearer token.
#[derive(Debug, Clone)]
pub struct Principal {
    pub key_hash: String,
    pub agent_id: Option<String>,
    pub is_admin: bool,
}

/// Hash a bearer key (the only way keys are stored/compared — plaintext never
/// persists; sha256 hex, 64 chars).
pub fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The 401 response for a missing/unknown/revoked/expired key.
pub fn unauthorized() -> Response {
    let body = ErrorBody {
        error: ApiError {
            code: ErrorCode::AgentKeyUnknown,
            message: "unknown or invalid API key".to_string(),
            detail: serde_json::Value::Null,
        },
    };
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

/// Authenticate a bearer key against the store (called from handlers).
/// Returns the principal, or the 401 response. Fail-closed: any DB error is
/// treated as an unknown key.
pub async fn authenticate(
    store: &Store,
    auth_header: Option<&str>,
) -> Result<Principal, Box<Response>> {
    let key = auth_header
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .filter(|k| !k.is_empty())
        .ok_or_else(|| Box::new(unauthorized()))?;
    let hash = hash_key(key);
    let row: Option<ApiKeyRow> = store
        .get_api_key(&hash)
        .await
        .map_err(|_| Box::new(unauthorized()))?;
    let row = row.ok_or_else(|| Box::new(unauthorized()))?;
    // Revoked or expired keys are rejected (fail-closed).
    if row.revoked_at.is_some() {
        return Err(Box::new(unauthorized()));
    }
    if let Some(exp) = &row.expires_at
        && let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp)
        && exp_dt < chrono::Utc::now()
    {
        return Err(Box::new(unauthorized()));
    }
    Ok(Principal {
        key_hash: row.key_hash.clone(),
        agent_id: row.agent_id.clone(),
        is_admin: row.is_admin,
    })
}

/// Extract the Authorization header value from a request.
pub fn bearer_header(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}
