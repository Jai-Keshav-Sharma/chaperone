use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// HTTP-level error codes (docs/api-contracts.md error model). A non-2xx from
/// the decision endpoint is a gate FAILURE — never itself a decision;
/// interceptors treat it as BLOCK (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    PolicyNotFound,
    LedgerUnavailable,
    AgentKeyUnknown,
    MalformedRequest,
    RateLimited,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub detail: Value,
}

/// The wire error envelope: {"error": {code, message, detail}}.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: ApiError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body_roundtrip() {
        let json = r#"{
            "error": {
                "code": "RATE_LIMITED",
                "message": "rate ceiling exceeded",
                "detail": {"retry_after_seconds": 5}
            }
        }"#;
        let body: ErrorBody = serde_json::from_str(json).expect("parse");
        assert_eq!(body.error.code, ErrorCode::RateLimited);
        assert_eq!(body.error.detail["retry_after_seconds"], 5);
        let back = serde_json::to_string(&body).expect("serialize");
        let reparsed: ErrorBody = serde_json::from_str(&back).expect("reparse");
        assert_eq!(body, reparsed);
    }
}
