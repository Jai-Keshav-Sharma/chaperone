use serde_json::Value as JsonValue;

use crate::ir::lint::{glob_prefix, is_glob};
use crate::models::ir::{ConditionNode, Effect, Operand, Policy, Rule, Weekday};

/// One generated Cedar policy: a stable id (mapping back to the IR rule) and
/// its deterministic policy text, plus the IR rule it implements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CedarPolicy {
    pub id: String,
    pub text: String,
    pub rule: RuleRef,
}

/// The IR rule behind one generated Cedar policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRef {
    pub policy_id: String,
    pub rule_id: String,
    pub effect: Effect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranspileError {
    pub rule_id: Option<String>,
    pub message: String,
}

impl TranspileError {
    fn new(rule_id: Option<String>, message: impl Into<String>) -> Self {
        TranspileError {
            rule_id,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for TranspileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.rule_id {
            Some(id) => write!(f, "rule {id}: {}", self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

const ACTION: &str = r#"action == Chaperone::Action::"call""#;

/// Deterministic IR→Cedar transpilation (docs/policy-ir.md Cedar section,
/// api-contracts entity model). Effects: allow→permit, block→forbid,
/// escalate→forbid+@chaperone_effect("escalate").
///
/// One Cedar policy per (rule × agent_id × tool): Cedar policy scope allows a
/// single principal/action/resource clause, so multi-target rules fan out.
/// Role targeting moves into the `when` clause (`principal.role == "support"`).
///
/// Entity vocabulary (FIXED, api-contracts): principal = Chaperone::Agent,
/// action = Chaperone::Action::"call", resource = Chaperone::Tool, context =
/// {params, request_time, surface, delegation_depth, derived}.
pub fn to_cedar(policy: &Policy) -> Result<Vec<CedarPolicy>, TranspileError> {
    let mut out = Vec::new();
    let mut combo = 0usize; // policy-global: ids stay unique even with duplicate rule ids
    for rule in &policy.rules {
        let agent_ids: Vec<String> = if rule.target.agent_ids.is_empty() {
            vec![String::new()] // bare `principal` clause
        } else {
            rule.target.agent_ids.clone()
        };
        for agent in &agent_ids {
            for tool in &rule.target.tools {
                let id = format!(
                    "{}__{}__{}",
                    sanitize_id(&policy.policy_id),
                    sanitize_id(&rule.rule_id),
                    combo
                );
                combo += 1;
                let text = transpile_rule(rule, agent, tool)?;
                out.push(CedarPolicy {
                    id,
                    text,
                    rule: RuleRef {
                        policy_id: policy.policy_id.clone(),
                        rule_id: rule.rule_id.clone(),
                        effect: rule.effect,
                    },
                });
            }
        }
    }
    Ok(out)
}

fn transpile_rule(rule: &Rule, agent_id: &str, tool: &str) -> Result<String, TranspileError> {
    let effect = match rule.effect {
        Effect::Allow => "permit",
        Effect::Block | Effect::Escalate => "forbid",
    };
    let annotation = if rule.effect == Effect::Escalate {
        "@chaperone_effect(\"escalate\")\n"
    } else {
        ""
    };

    let principal = if agent_id.is_empty() {
        "principal".to_string()
    } else {
        format!(
            r#"principal == Chaperone::Agent::"{}""#,
            escape_str(agent_id)
        )
    };

    let (resource, resource_when) = if tool == "*" {
        // ["*"] = all tools (docs/policy-ir.md) — bare resource clause.
        ("resource".to_string(), None)
    } else if is_glob(tool) {
        // Cedar's scope clause allows only `resource`, `resource == X`,
        // `resource in Y` — attribute matching moves into `when`.
        (
            "resource".to_string(),
            Some(format!(
                r#"resource.name like "{}""#,
                escape_like_literal(glob_prefix(tool))
            )),
        )
    } else {
        (
            format!(r#"resource == Chaperone::Tool::"{}""#, escape_str(tool)),
            None,
        )
    };

    let mut when_parts: Vec<String> = Vec::new();
    if let Some(glob_check) = resource_when {
        when_parts.push(glob_check);
    }
    if !rule.target.agent_roles.is_empty() {
        let roles = rule
            .target
            .agent_roles
            .iter()
            .map(|r| format!(r#"principal.role == "{}""#, escape_str(r)))
            .collect::<Vec<_>>()
            .join(" || ");
        when_parts.push(format!("({roles})"));
    }
    if let Some(cond) = &rule.condition {
        when_parts.push(format!("({})", transpile_condition(cond, rule)?));
    }

    let when = if when_parts.is_empty() {
        String::new()
    } else {
        format!("\nwhen {{\n    {}\n}}", when_parts.join(" && "))
    };

    Ok(format!(
        "{annotation}{effect}(\n    {principal},\n    {ACTION},\n    {resource}\n){when};"
    ))
}

fn transpile_condition(node: &ConditionNode, rule: &Rule) -> Result<String, TranspileError> {
    match node {
        ConditionNode::And { args } => {
            let parts: Result<Vec<String>, _> =
                args.iter().map(|a| transpile_condition(a, rule)).collect();
            Ok(format!("({})", parts?.join(" && ")))
        }
        ConditionNode::Or { args } => {
            let parts: Result<Vec<String>, _> =
                args.iter().map(|a| transpile_condition(a, rule)).collect();
            Ok(format!("({})", parts?.join(" || ")))
        }
        ConditionNode::Not { args } => Ok(format!("!({})", transpile_condition(&args[0], rule)?)),
        ConditionNode::Eq { left, right } => Ok(format!(
            "{} == {}",
            transpile_operand(left, rule)?,
            transpile_operand(right, rule)?
        )),
        ConditionNode::Ne { left, right } => Ok(format!(
            "{} != {}",
            transpile_operand(left, rule)?,
            transpile_operand(right, rule)?
        )),
        ConditionNode::Lt { left, right } => Ok(format!(
            "{} < {}",
            transpile_operand(left, rule)?,
            transpile_operand(right, rule)?
        )),
        ConditionNode::Lte { left, right } => Ok(format!(
            "{} <= {}",
            transpile_operand(left, rule)?,
            transpile_operand(right, rule)?
        )),
        ConditionNode::Gt { left, right } => Ok(format!(
            "{} > {}",
            transpile_operand(left, rule)?,
            transpile_operand(right, rule)?
        )),
        ConditionNode::Gte { left, right } => Ok(format!(
            "{} >= {}",
            transpile_operand(left, rule)?,
            transpile_operand(right, rule)?
        )),
        ConditionNode::In { left, values } => {
            // Cedar's `in` is for the ENTITY hierarchy; set membership uses
            // `.contains()` (probe-verified TypeError otherwise).
            let vals: Result<Vec<String>, _> = values.iter().map(transpile_literal).collect();
            Ok(format!(
                "[{}].contains({})",
                vals?.join(", "),
                transpile_operand(left, rule)?
            ))
        }
        ConditionNode::NotIn { left, values } => {
            let vals: Result<Vec<String>, _> = values.iter().map(transpile_literal).collect();
            Ok(format!(
                "!([{}].contains({}))",
                vals?.join(", "),
                transpile_operand(left, rule)?
            ))
        }
        ConditionNode::Matches { left, pattern } => {
            let interior = &pattern[1..pattern.len() - 1];
            Ok(format!(
                "{} like \"{}\"",
                transpile_operand(left, rule)?,
                escape_like_literal(interior)
            ))
        }
        ConditionNode::Exists { param } => {
            // Present ⟺ non-null in the normalized context (nulls are dropped),
            // so the `has` chain is exactly the IR exists semantics. `has` on a
            // non-record intermediate errors in Cedar — matching the reference.
            let mut chain = Vec::new();
            let segments: Vec<&str> = param.split('.').collect();
            let mut acc = "context.params".to_string();
            for seg in &segments {
                if !is_identifier(seg) {
                    return Err(TranspileError::new(
                        Some(rule.rule_id.clone()),
                        format!("param path segment {seg:?} is not a Cedar identifier"),
                    ));
                }
                chain.push(format!("({acc} has \"{}\")", escape_str(seg)));
                acc = format!("{acc}.{seg}");
            }
            Ok(chain.join(" && "))
        }
        ConditionNode::TimeBetween {
            start,
            end,
            tz,
            days,
        } => {
            let key = tb_key(start, end, tz, days);
            Ok(format!("context.derived.{key} == true"))
        }
    }
}

/// Deterministic slot key for a time_between node (a valid Cedar identifier).
/// The Cedar engine precomputes one boolean per distinct key into the derived
/// record at evaluate time (same function, same inputs → same value as the
/// reference engine).
pub(crate) fn tb_key(start: &str, end: &str, tz: &str, days: &[Weekday]) -> String {
    let days: String = days
        .iter()
        .map(|d| format!("{d:?}"))
        .collect::<Vec<_>>()
        .join("");
    let tz_safe: String = tz
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "tb_{}_{}_{}_{days}",
        start.replace(':', ""),
        end.replace(':', ""),
        tz_safe
    )
}

fn transpile_operand(op: &Operand, rule: &Rule) -> Result<String, TranspileError> {
    match op {
        Operand::Param { param } => {
            let mut acc = "context.params".to_string();
            for seg in param.split('.') {
                if !is_identifier(seg) {
                    return Err(TranspileError::new(
                        Some(rule.rule_id.clone()),
                        format!("param path segment {seg:?} is not a Cedar identifier"),
                    ));
                }
                acc = format!("{acc}.{seg}");
            }
            Ok(acc)
        }
        Operand::Context { context } => {
            if let Some(attr) = context.strip_prefix("derived.") {
                if !is_identifier(attr) {
                    return Err(TranspileError::new(
                        Some(rule.rule_id.clone()),
                        format!("derived attribute {attr:?} is not a Cedar identifier"),
                    ));
                }
                Ok(format!("context.derived.{attr}"))
            } else {
                match context.as_str() {
                    "request_time" => Ok("context.request_time".to_string()),
                    "surface" => Ok("context.surface".to_string()),
                    "delegation_depth" => Ok("context.delegation_depth".to_string()),
                    _ => Err(TranspileError::new(
                        Some(rule.rule_id.clone()),
                        format!("unknown context operand {context:?}"),
                    )),
                }
            }
        }
        Operand::Value { value } => transpile_literal(value)
            .map_err(|e| TranspileError::new(Some(rule.rule_id.clone()), e.message)),
    }
}

/// Literals transpile to the engine's NORMALIZED form: numbers become
/// fixed-point Longs (×10000, probe-verified: Cedar comparisons support Long
/// only); unrepresentable numbers stay canonical strings (ordering against
/// them is then a loud type error).
fn transpile_literal(value: &JsonValue) -> Result<String, TranspileError> {
    match value {
        JsonValue::Null => Err(TranspileError::new(
            None,
            "null value operands are not supported (Cedar has no null literal)",
        )),
        JsonValue::Bool(b) => Ok(b.to_string()),
        JsonValue::Number(n) => match crate::engine::normalize_number(n) {
            JsonValue::Number(i) => Ok(i.to_string()),
            JsonValue::String(s) => Ok(format!("\"{}\"", escape_str(&s))),
            _ => unreachable!("normalize_number returns Number or String"),
        },
        JsonValue::String(s) => Ok(format!("\"{}\"", escape_str(s))),
        JsonValue::Array(items) => {
            let vals: Result<Vec<String>, _> = items.iter().map(transpile_literal).collect();
            Ok(format!("[{}]", vals?.join(", ")))
        }
        JsonValue::Object(map) => {
            let vals: Result<Vec<String>, _> = map
                .iter()
                .map(|(k, v)| Ok(format!("\"{}\": {}", escape_str(k), transpile_literal(v)?)))
                .collect();
            Ok(format!("{{ {} }}", vals?.join(", ")))
        }
    }
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Escape a string for a Cedar string literal.
fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Resolve a like-pattern interior for Cedar. Cedar `like` has NO escape
/// syntax: `*` is the only metachar, every other char is literal. The IR's
/// `\x` escapes (used to express literals like `.`) must therefore be
/// RESOLVED here — `\.` → `.` — so reference and Cedar agree (the reference's
/// like_match handles `\x` → literal x). `"` is escaped for the Cedar string
/// literal only.
fn escape_like_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next); // `\x` → literal x (Cedar: no escape syntax)
            }
        } else {
            out.push(c);
        }
    }
    out.replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ir::Policy;
    use serde_json::json;

    fn parse(v: serde_json::Value) -> Policy {
        serde_json::from_value(v).expect("fixture parses")
    }

    fn texts(policy: &Policy) -> Vec<String> {
        to_cedar(policy)
            .expect("transpile")
            .into_iter()
            .map(|p| p.text)
            .collect()
    }

    #[test]
    fn snapshot_allow_rule() {
        let policy = parse(json!({
            "ir_version": "1",
            "policy_id": "pol_refunds",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-allow-small",
                "description": "d",
                "effect": "allow",
                "target": {"tools": ["stripe.refunds.create"]},
                "condition": {"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}}
            }]
        }));
        assert_eq!(
            texts(&policy),
            vec![concat!(
                "permit(\n",
                "    principal,\n",
                "    action == Chaperone::Action::\"call\",\n",
                "    resource == Chaperone::Tool::\"stripe.refunds.create\"\n",
                ")\n",
                "when {\n",
                "    (context.params.amount <= 2000000)\n",
                "};"
            )]
        );
    }

    #[test]
    fn snapshot_escalate_annotation() {
        let policy = parse(json!({
            "ir_version": "1",
            "policy_id": "pol_refunds",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-escalate-mid",
                "description": "d",
                "effect": "escalate",
                "target": {"tools": ["stripe.refunds.create"]},
                "condition": {"op": "gte", "left": {"param": "amount"}, "right": {"value": 100}}
            }]
        }));
        assert_eq!(
            texts(&policy),
            vec![concat!(
                "@chaperone_effect(\"escalate\")\n",
                "forbid(\n",
                "    principal,\n",
                "    action == Chaperone::Action::\"call\",\n",
                "    resource == Chaperone::Tool::\"stripe.refunds.create\"\n",
                ")\n",
                "when {\n",
                "    (context.params.amount >= 1000000)\n",
                "};"
            )]
        );
    }

    #[test]
    fn snapshot_glob_roles_and_ids() {
        let policy = parse(json!({
            "ir_version": "1",
            "policy_id": "pol_x",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-glob",
                "description": "d",
                "effect": "block",
                "target": {
                    "tools": ["payments.*"],
                    "agent_roles": ["support", "admin"],
                    "agent_ids": ["agent_a"]
                },
                "condition": null
            }]
        }));
        assert_eq!(
            texts(&policy),
            vec![concat!(
                "forbid(\n",
                "    principal == Chaperone::Agent::\"agent_a\",\n",
                "    action == Chaperone::Action::\"call\",\n",
                "    resource\n",
                ")\n",
                "when {\n",
                "    resource.name like \"payments\" && (principal.role == \"support\" || principal.role == \"admin\")\n",
                "};"
            )]
        );
    }

    #[test]
    fn snapshot_star_tool_is_bare_resource() {
        let policy = parse(json!({
            "ir_version": "1",
            "policy_id": "pol_x",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-all",
                "description": "d",
                "effect": "allow",
                "target": {"tools": ["*"]},
                "condition": null
            }]
        }));
        assert_eq!(
            texts(&policy),
            vec![concat!(
                "permit(\n",
                "    principal,\n",
                "    action == Chaperone::Action::\"call\",\n",
                "    resource\n",
                ");"
            )]
        );
    }

    #[test]
    fn snapshot_ops() {
        let policy = parse(json!({
            "ir_version": "1",
            "policy_id": "pol_x",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-ops",
                "description": "d",
                "effect": "allow",
                "target": {"tools": ["fs.write"]},
                "condition": {
                    "op": "and",
                    "args": [
                        {"op": "matches", "left": {"param": "command"}, "pattern": "^rm *$"},
                        {"op": "in", "left": {"param": "currency"}, "values": ["USD", "INR"]},
                        {"op": "not_in", "left": {"param": "currency"}, "values": ["EUR"]},
                        {"op": "exists", "param": "customer.id"},
                        {"op": "eq", "left": {"context": "surface"}, "right": {"value": "claude_code"}},
                        {"op": "time_between", "start": "09:00", "end": "17:00", "tz": "UTC", "days": ["mon", "fri"]}
                    ]
                }
            }]
        }));
        assert_eq!(
            texts(&policy),
            vec![concat!(
                "permit(\n",
                "    principal,\n",
                "    action == Chaperone::Action::\"call\",\n",
                "    resource == Chaperone::Tool::\"fs.write\"\n",
                ")\n",
                "when {\n",
                "    ((context.params.command like \"rm *\" && [\"USD\", \"INR\"].contains(context.params.currency) && !([\"EUR\"].contains(context.params.currency)) && (context.params has \"customer\") && (context.params.customer has \"id\") && context.surface == \"claude_code\" && context.derived.tb_0900_1700_UTC_MonFri == true))\n",
                "};"
            )]
        );
    }

    #[test]
    fn transpile_rejects_bad_identifiers() {
        let policy = parse(json!({
            "ir_version": "1",
            "policy_id": "pol_x",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-bad",
                "description": "d",
                "effect": "allow",
                "target": {"tools": ["fs.write"]},
                "condition": {"op": "eq", "left": {"param": "customer-id"}, "right": {"value": "x"}}
            }]
        }));
        let err = to_cedar(&policy).expect_err("must fail");
        assert!(err.message.contains("not a Cedar identifier"), "got: {err}");
    }
}
