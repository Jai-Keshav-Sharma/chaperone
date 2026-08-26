use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::reason_code::ReasonCode;

/// The verdict on an evaluated action. WOULD_* values appear only in shadow
/// mode (flows/08): same evaluation, same ledger, interceptor always proceeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Block,
    Escalate,
    WouldAllow,
    WouldBlock,
    WouldEscalate,
}

/// The trusted-boundary derived surface (flows/02 invariant 8): computed by the
/// hook/gateway, never accepted from agent-controlled payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    ClaudeCode,
    Cursor,
    McpGateway,
    McpShim,
    Sdk,
}

/// DecisionRequest.context — frozen wire contract (docs/api-contracts.md).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    /// PASS-THROUGH for logging/correlation only; never affects decisions in v1.
    #[serde(default)]
    pub session_id: Option<String>,
    pub surface: Surface,
    pub delegation_depth: u32,
    /// RFC3339 UTC, boundary-computed, ledgered (Law 6 determinism).
    pub request_time: String,
}

/// Interceptor → decision service. Frozen wire contract: unknown fields are
/// rejected; there is NO mode field (shadow/enforce is server-side operator
/// config — an agent cannot self-exempt).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    /// UUIDv4, interceptor-generated; idempotency key.
    pub request_id: String,
    pub agent_id: String,
    /// Universal tool namespace (flows/05).
    pub tool: String,
    /// Arbitrary JSON; engine reads it only via param-path operands.
    pub params: Value,
    pub context: RequestContext,
    /// Set only when re-submitting after approval (Flow 3 consumption).
    #[serde(default)]
    pub escalation_id: Option<String>,
}

/// Trace operand kinds — `param | context | value | derived` (api-contracts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OperandKind {
    Param,
    Context,
    Value,
    Derived,
}

/// One referenced operand PATH in a rule trace — NEVER a value (Law 9 redaction).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceOperand {
    pub path: String,
    pub kind: OperandKind,
}

/// One per rule, in evaluation order (api-contracts decision trace shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceEntry {
    pub rule_id: String,
    pub matched: bool,
    /// Present when the rule evaluated a condition; operand paths only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operands: Option<Vec<TraceOperand>>,
    /// Eval-error traces carry the error code instead of raw values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Decision service → interceptor. Frozen wire contract. The ledger entry
/// exists BEFORE this response is returned (append-then-respond, Law 3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionResponse {
    pub decision: Decision,
    pub reason_code: ReasonCode,
    pub determining_rule_ids: Vec<String>,
    /// "__none__" when no policy applies.
    pub policy_id: String,
    pub policy_version: u32,
    /// sha256(canonical_json(ir_json)) — pins the decision to exact policy bytes.
    pub policy_hash: String,
    /// Ledger refs; the synchronous append happened first.
    pub entry_seq: u64,
    pub entry_hash: String,
    /// Set when decision == ESCALATE.
    #[serde(default)]
    pub escalation_id: Option<String>,
    /// RFC3339, set when decision == ESCALATE.
    #[serde(default)]
    pub escalation_expires_at: Option<String>,
    /// REDACTED trace: rule ids, match booleans, operand paths only.
    #[serde(default)]
    pub trace: Vec<TraceEntry>,
    /// Derived attributes (budgets/velocity) used in evaluation.
    #[serde(default)]
    pub derived_context: Value,
    pub evaluation_latency_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_JSON: &str = r#"{
        "request_id": "req_7f3a2b1c",
        "agent_id": "agent_support_09",
        "tool": "stripe.refunds.create",
        "params": {"amount": 150, "customer_id": "cus_123"},
        "context": {
            "session_id": "s-42",
            "surface": "claude_code",
            "delegation_depth": 0,
            "request_time": "2026-08-25T14:00:00Z"
        },
        "escalation_id": null
    }"#;

    #[test]
    fn roundtrip_decision_request() {
        let req: DecisionRequest = serde_json::from_str(REQUEST_JSON).expect("parse");
        assert_eq!(req.request_id, "req_7f3a2b1c");
        assert_eq!(req.agent_id, "agent_support_09");
        assert_eq!(req.tool, "stripe.refunds.create");
        assert_eq!(req.params["amount"], 150);
        assert_eq!(req.context.session_id.as_deref(), Some("s-42"));
        assert_eq!(req.context.surface, Surface::ClaudeCode);
        assert_eq!(req.context.delegation_depth, 0);
        assert_eq!(req.context.request_time, "2026-08-25T14:00:00Z");
        assert_eq!(req.escalation_id, None);
        let back = serde_json::to_string(&req).expect("serialize");
        let reparsed: DecisionRequest = serde_json::from_str(&back).expect("reparse");
        assert_eq!(req, reparsed);
    }

    #[test]
    fn reject_unknown_field() {
        let with_mode =
            REQUEST_JSON.replace("\"request_id\"", "\"mode\": \"shadow\", \"request_id\"");
        let err =
            serde_json::from_str::<DecisionRequest>(&with_mode).expect_err("mode must be rejected");
        assert!(err.to_string().contains("unknown field"), "got: {err}");

        let bad_context = REQUEST_JSON.replace(
            "\"session_id\": \"s-42\"",
            "\"session_id\": \"s-42\", \"agent_supplied\": true",
        );
        let err = serde_json::from_str::<DecisionRequest>(&bad_context)
            .expect_err("unknown context field must be rejected");
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    const RESPONSE_JSON: &str = r#"{
        "decision": "ALLOW",
        "reason_code": "RULE_MATCH",
        "determining_rule_ids": ["r-allow-small"],
        "policy_id": "pol_refunds",
        "policy_version": 3,
        "policy_hash": "8f2a4e6c1b9d0f3a7c5e2d8b4a6f0c1e3d5b7a9f2c4e6d8b0a1c3e5f7d9b2a4c6",
        "entry_seq": 14921,
        "entry_hash": "c41d9e7b2a5f8d0c3e6b1a4f7d9c2e5b8a0d3f6c1b4e7a9d2c5f8b0e3a6d9c1f4",
        "escalation_id": null,
        "escalation_expires_at": null,
        "trace": [{"rule_id":"r-allow-small","matched":true}],
        "derived_context": {"agent_daily_total_amount": 350.0},
        "evaluation_latency_ms": 4.1
    }"#;

    #[test]
    fn roundtrip_decision_response() {
        let resp: DecisionResponse = serde_json::from_str(RESPONSE_JSON).expect("parse");
        assert_eq!(resp.decision, Decision::Allow);
        assert_eq!(resp.reason_code, ReasonCode::RuleMatch);
        assert_eq!(resp.determining_rule_ids, vec!["r-allow-small".to_string()]);
        assert_eq!(resp.policy_id, "pol_refunds");
        assert_eq!(resp.policy_version, 3);
        assert_eq!(resp.entry_seq, 14921);
        assert_eq!(resp.escalation_id, None);
        assert_eq!(resp.escalation_expires_at, None);
        assert_eq!(resp.trace.len(), 1);
        assert_eq!(resp.trace[0].rule_id, "r-allow-small");
        assert!(resp.trace[0].matched);
        assert!(resp.trace[0].operands.is_none());
        assert!(resp.trace[0].error.is_none());
        assert_eq!(resp.derived_context["agent_daily_total_amount"], 350.0);
        let back = serde_json::to_string(&resp).expect("serialize");
        let reparsed: DecisionResponse = serde_json::from_str(&back).expect("reparse");
        assert_eq!(resp, reparsed);
    }

    #[test]
    fn roundtrip_escalate_response_with_trace_operands() {
        let json = r#"{
            "decision": "ESCALATE",
            "reason_code": "RULE_MATCH",
            "determining_rule_ids": ["r-escalate-mid"],
            "policy_id": "pol_refunds",
            "policy_version": 3,
            "policy_hash": "8f2a4e6c1b9d0f3a7c5e2d8b4a6f0c1e3d5b7a9f2c4e6d8b0a1c3e5f7d9b2a4c6",
            "entry_seq": 14921,
            "entry_hash": "c41d9e7b2a5f8d0c3e6b1a4f7d9c2e5b8a0d3f6c1b4e7a9d2c5f8b0e3a6d9c1f4",
            "escalation_id": "esc_9f4c2b71",
            "escalation_expires_at": "2026-08-25T14:15:00Z",
            "trace": [
                {"rule_id": "r-block-flagged", "matched": false},
                {"rule_id": "r-escalate-mid", "matched": true,
                 "operands": [{"path": "params.amount", "kind": "param"},
                              {"path": "context.surface", "kind": "context"}]},
                {"rule_id": "r-x", "matched": false,
                 "error": "EVAL_ERROR_MISSING_PARAM",
                 "operands": [{"path": "params.amount", "kind": "param"}]}
            ],
            "derived_context": {},
            "evaluation_latency_ms": 3.2
        }"#;
        let resp: DecisionResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.decision, Decision::Escalate);
        assert_eq!(resp.escalation_id.as_deref(), Some("esc_9f4c2b71"));
        assert_eq!(
            resp.escalation_expires_at.as_deref(),
            Some("2026-08-25T14:15:00Z")
        );
        assert_eq!(resp.trace.len(), 3);
        let mid = &resp.trace[1];
        let ops = mid.operands.as_ref().expect("operands present");
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].path, "params.amount");
        assert_eq!(ops[0].kind, OperandKind::Param);
        assert_eq!(ops[1].kind, OperandKind::Context);
        assert_eq!(
            resp.trace[2].error.as_deref(),
            Some("EVAL_ERROR_MISSING_PARAM")
        );
        let back = serde_json::to_string(&resp).expect("serialize");
        let reparsed: DecisionResponse = serde_json::from_str(&back).expect("reparse");
        assert_eq!(resp, reparsed);
    }

    #[test]
    fn reject_unknown_response_field() {
        let with_unknown =
            RESPONSE_JSON.replace("\"decision\"", "\"mode\": \"shadow\", \"decision\"");
        let err = serde_json::from_str::<DecisionResponse>(&with_unknown)
            .expect_err("unknown response field must be rejected");
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }
}
