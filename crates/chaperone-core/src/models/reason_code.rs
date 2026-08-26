use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The closed reason-code enum — unified, incl. the ESCALATION_* family
/// (docs/api-contracts.md). These are VERDICTS (in-band, HTTP 200); gate
/// failures are HTTP errors, never reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    /// A determining rule matched (allow or block).
    RuleMatch,
    /// No determining rule matched → default deny.
    DefaultDeny,
    /// Tool governed by no active policy; ungoverned_default: block.
    NoPolicy,
    /// No active policy; ungoverned_default: allow; loudly ledgered.
    UngovernedAllow,
    /// Missing param / type mismatch → immediate block (never skip the rule).
    EvalError,
    /// agent_id not registered (ledgered).
    AgentUnknown,
    /// Agent registered but inactive (ledgered).
    AgentInactive,
    /// Policy store unreachable → block.
    FailClosedPolicyUnavailable,
    /// Ledger write failed → no verdict returned (503).
    FailClosedLedgerUnavailable,
    /// Interceptor synthesized block (timeout/5xx/malformed).
    FailClosedGateUnreachable,
    /// Per-key rate ceiling exceeded (429; a limited call is a non-forward).
    RateLimited,
    /// Retry with approved escalation_id → allow.
    EscalationApproved,
    /// Escalation was denied.
    EscalationDenied,
    /// Escalation expired (auto-deny; silence always means deny).
    EscalationExpired,
    /// Retry params differ from the approved params_binding_hash.
    EscalationParamsMismatch,
    /// Escalation already used (single-use).
    EscalationAlreadyConsumed,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [&str; 16] = [
        "RULE_MATCH",
        "DEFAULT_DENY",
        "NO_POLICY",
        "UNGOVERNED_ALLOW",
        "EVAL_ERROR",
        "AGENT_UNKNOWN",
        "AGENT_INACTIVE",
        "FAIL_CLOSED_POLICY_UNAVAILABLE",
        "FAIL_CLOSED_LEDGER_UNAVAILABLE",
        "FAIL_CLOSED_GATE_UNREACHABLE",
        "RATE_LIMITED",
        "ESCALATION_APPROVED",
        "ESCALATION_DENIED",
        "ESCALATION_EXPIRED",
        "ESCALATION_PARAMS_MISMATCH",
        "ESCALATION_ALREADY_CONSUMED",
    ];

    #[test]
    fn enum_complete() {
        for name in ALL {
            let rc: ReasonCode = serde_json::from_str(&format!("\"{name}\"")).expect("deserialize");
            assert_eq!(
                serde_json::to_string(&rc).expect("serialize"),
                format!("\"{name}\"")
            );
        }
    }
}
