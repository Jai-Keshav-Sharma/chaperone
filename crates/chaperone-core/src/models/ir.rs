use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Rule effects: allow | block | escalate (docs/policy-ir.md decision semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Block,
    Escalate,
}

/// Weekday names for time_between conditions (closed set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

/// Condition operands: {"param": path} · {"context": field} · {"value": v}.
/// Untagged: the three fields are disjoint, so matching is unambiguous.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Operand {
    /// Dot path into tool params, e.g. "amount" or "customer.id".
    Param { param: String },
    /// "request_time" | "surface" | "delegation_depth" | "derived.<attr>".
    Context { context: String },
    /// Literal: number, string, bool, array...
    Value { value: JsonValue },
}

/// Condition nodes — the CLOSED op set, tagged by "op" (docs/policy-ir.md).
/// Unknown ops or fields are rejected at parse time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum ConditionNode {
    #[serde(rename = "and")]
    And { args: Vec<ConditionNode> },
    #[serde(rename = "or")]
    Or { args: Vec<ConditionNode> },
    /// Takes exactly one arg (validated in ir::validate, Phase 3).
    #[serde(rename = "not")]
    Not { args: Vec<ConditionNode> },
    #[serde(rename = "eq")]
    Eq { left: Operand, right: Operand },
    #[serde(rename = "ne")]
    Ne { left: Operand, right: Operand },
    #[serde(rename = "lt")]
    Lt { left: Operand, right: Operand },
    #[serde(rename = "lte")]
    Lte { left: Operand, right: Operand },
    #[serde(rename = "gt")]
    Gt { left: Operand, right: Operand },
    #[serde(rename = "gte")]
    Gte { left: Operand, right: Operand },
    #[serde(rename = "in")]
    In {
        left: Operand,
        values: Vec<JsonValue>,
    },
    #[serde(rename = "not_in")]
    NotIn {
        left: Operand,
        values: Vec<JsonValue>,
    },
    /// Anchored, backref-free regex; precompiled at policy load.
    #[serde(rename = "matches")]
    Matches { left: Operand, pattern: String },
    /// Param present and non-null.
    #[serde(rename = "exists")]
    Exists { param: String },
    /// Evaluated against context.request_time (boundary-computed, ledgered —
    /// never wall clock).
    #[serde(rename = "time_between")]
    TimeBetween {
        start: String,
        end: String,
        tz: String,
        days: Vec<Weekday>,
    },
}

/// Rule target: omitted/empty lists mean "any".
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Exact tool names or trailing-* globs; ["*"] = all.
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub agent_roles: Vec<String>,
    #[serde(default)]
    pub agent_ids: Vec<String>,
}

/// One authorization rule (docs/policy-ir.md).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub rule_id: String,
    /// Quotes/paraphrases the source SOP sentence; feeds the diff view.
    pub description: String,
    pub effect: Effect,
    pub target: Target,
    /// null = applies to every targeted call.
    #[serde(default)]
    pub condition: Option<ConditionNode>,
}

/// The Policy IR document — the single contract between the compiler and the
/// engine (docs/policy-ir.md). Strict: unknown fields rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub ir_version: String,
    pub policy_id: String,
    pub version: u32,
    pub description: String,
    pub rules: Vec<Rule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_JSON: &str = r#"{
        "ir_version": "1",
        "policy_id": "pol_refunds",
        "version": 3,
        "description": "Refund SOP for support agents",
        "rules": [
            {
                "rule_id": "r-allow-small-refund",
                "description": "\"Support agents may refund up to $200.\"",
                "effect": "allow",
                "target": {
                    "tools": ["stripe.refunds.create", "payments.*"],
                    "agent_roles": ["support"]
                },
                "condition": {
                    "op": "and",
                    "args": [
                        {"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}},
                        {"op": "gte", "left": {"param": "amount"}, "right": {"value": 0}},
                        {"op": "lt", "left": {"param": "amount"}, "right": {"value": 1000}},
                        {"op": "gt", "left": {"param": "amount"}, "right": {"value": 0}},
                        {"op": "eq", "left": {"param": "mode"}, "right": {"value": "live"}},
                        {"op": "ne", "left": {"param": "method"}, "right": {"value": "wire"}},
                        {"op": "in", "left": {"param": "currency"}, "values": ["USD", "INR"]},
                        {"op": "not_in", "left": {"context": "surface"}, "values": ["sdk"]},
                        {"op": "matches", "left": {"param": "customer_id"}, "pattern": "^cus_"},
                        {"op": "exists", "param": "customer_id"},
                        {"op": "not", "args": [{"op": "eq", "left": {"param": "test_mode"}, "right": {"value": true}}]},
                        {"op": "or", "args": [
                            {"op": "eq", "left": {"context": "surface"}, "right": {"value": "claude_code"}},
                            {"op": "eq", "left": {"context": "delegation_depth"}, "right": {"value": 0}}
                        ]},
                        {"op": "lte", "left": {"context": "derived.agent_daily_total_amount"}, "right": {"value": 1000}},
                        {"op": "time_between", "start": "09:00", "end": "17:00", "tz": "UTC",
                         "days": ["mon", "tue", "wed", "thu", "fri"]}
                    ]
                }
            },
            {
                "rule_id": "r-escalate-mid",
                "description": "Mid-size refunds escalate",
                "effect": "escalate",
                "target": {"tools": ["stripe.refunds.create"]},
                "condition": null
            },
            {
                "rule_id": "r-block-flagged",
                "description": "Flagged customers blocked",
                "effect": "block",
                "target": {"tools": ["*"]},
                "condition": {"op": "exists", "param": "flag"}
            }
        ]
    }"#;

    #[test]
    fn parse_all_ops() {
        let policy: Policy = serde_json::from_str(POLICY_JSON).expect("parse");
        assert_eq!(policy.ir_version, "1");
        assert_eq!(policy.policy_id, "pol_refunds");
        assert_eq!(policy.version, 3);
        assert_eq!(policy.rules.len(), 3);

        let allow = &policy.rules[0];
        assert_eq!(allow.effect, Effect::Allow);
        assert_eq!(
            allow.target.tools,
            vec![
                "stripe.refunds.create".to_string(),
                "payments.*".to_string()
            ]
        );
        assert_eq!(allow.target.agent_roles, vec!["support".to_string()]);
        assert!(allow.target.agent_ids.is_empty());

        let cond = allow.condition.as_ref().expect("condition present");
        let ConditionNode::And { args } = cond else {
            panic!("top op must be and");
        };
        assert_eq!(args.len(), 14);
        assert!(matches!(args[0], ConditionNode::Lte { .. }));
        assert!(matches!(args[4], ConditionNode::Eq { .. }));
        assert!(matches!(args[6], ConditionNode::In { .. }));
        assert!(matches!(args[7], ConditionNode::NotIn { .. }));
        assert!(matches!(args[8], ConditionNode::Matches { .. }));
        assert!(matches!(args[9], ConditionNode::Exists { .. }));
        assert!(matches!(args[10], ConditionNode::Not { .. }));
        assert!(matches!(args[11], ConditionNode::Or { .. }));
        assert!(matches!(args[12], ConditionNode::Lte { .. }));
        assert!(matches!(args[13], ConditionNode::TimeBetween { .. }));

        let ConditionNode::Lte { left, right } = &args[0] else {
            unreachable!()
        };
        assert!(matches!(left, Operand::Param { param } if param == "amount"));
        assert!(matches!(right, Operand::Value { value } if value == 200));

        let ConditionNode::Lte { left, .. } = &args[12] else {
            unreachable!()
        };
        assert!(matches!(
            left,
            Operand::Context { context } if context == "derived.agent_daily_total_amount"
        ));

        let ConditionNode::TimeBetween {
            start,
            end,
            tz,
            days,
        } = &args[13]
        else {
            unreachable!()
        };
        assert_eq!(start, "09:00");
        assert_eq!(end, "17:00");
        assert_eq!(tz, "UTC");
        assert_eq!(
            days,
            &vec![
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri
            ]
        );

        let escalate = &policy.rules[1];
        assert_eq!(escalate.effect, Effect::Escalate);
        assert!(escalate.condition.is_none());

        let block = &policy.rules[2];
        assert_eq!(block.effect, Effect::Block);
        assert_eq!(block.target.tools, vec!["*".to_string()]);

        let back = serde_json::to_string(&policy).expect("serialize");
        let reparsed: Policy = serde_json::from_str(&back).expect("reparse");
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn reject_unknown_op() {
        let bad = r#"{
            "ir_version": "1",
            "policy_id": "pol_x",
            "version": 1,
            "description": "bad",
            "rules": [{
                "rule_id": "r-1",
                "description": "d",
                "effect": "allow",
                "target": {"tools": ["*"]},
                "condition": {"op": "magic", "args": []}
            }]
        }"#;
        let err = serde_json::from_str::<Policy>(bad).expect_err("unknown op must be rejected");
        assert!(err.to_string().contains("unknown variant"), "got: {err}");
    }

    #[test]
    fn reject_unknown_ir_field() {
        let bad = POLICY_JSON.replace("\"ir_version\"", "\"ir_version_x\": \"9\", \"ir_version\"");
        let err =
            serde_json::from_str::<Policy>(&bad).expect_err("unknown IR field must be rejected");
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }
}
