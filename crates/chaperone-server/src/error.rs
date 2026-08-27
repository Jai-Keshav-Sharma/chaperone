//! Error mapping (docs/api-contracts.md): a 4xx/5xx is never a verdict —
//! it is a gate failure the interceptor treats as fail-closed BLOCK.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chaperone_core::models::errors::{ApiError, ErrorBody, ErrorCode};

/// The canonical error-body builder.
pub fn error_body(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        error: ApiError {
            code,
            message: message.into(),
            detail: serde_json::Value::Null,
        },
    }
}

/// An HTTP gate failure (never a verdict).
pub fn gate_error(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Response {
    (status, Json(error_body(code, message))).into_response()
}

/// 401 — unknown API key.
pub fn unauthorized() -> Response {
    gate_error(
        StatusCode::UNAUTHORIZED,
        ErrorCode::AgentKeyUnknown,
        "unknown or invalid API key",
    )
}

/// 404 — policy/escalation not found.
pub fn not_found(message: impl Into<String>) -> Response {
    gate_error(StatusCode::NOT_FOUND, ErrorCode::PolicyNotFound, message)
}

/// 422 — malformed request (unknown fields / bad body).
pub fn malformed(message: impl Into<String>) -> Response {
    gate_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::MalformedRequest,
        message,
    )
}

/// 429 — per-key rate ceiling exceeded.
pub fn rate_limited(retry_after_seconds: u64) -> Response {
    let body = ErrorBody {
        error: ApiError {
            code: ErrorCode::RateLimited,
            message: "rate ceiling exceeded".to_string(),
            detail: serde_json::json!({ "retry_after_seconds": retry_after_seconds }),
        },
    };
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", retry_after_seconds.to_string())],
        Json(body),
    )
        .into_response()
}

/// 503 — ledger unavailable (the decision path's fail-closed gate failure).
pub fn ledger_unavailable(message: impl Into<String>) -> Response {
    gate_error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::LedgerUnavailable,
        message,
    )
}
