use serde_json::{Number, Value as JsonValue};

use crate::models::decision::{OperandKind, TraceEntry, TraceOperand};
use crate::models::ir::{ConditionNode, Operand, Policy, Rule};

pub mod cedar_compile;
pub mod cedar_engine;
pub mod derive;
pub mod differential;
pub mod reference;

/// Everything the engine needs to evaluate one request. Pure data — the engine
/// performs zero I/O (Law 7); the decision service assembles this at the
/// boundary (agent identity, derived context, request_time all boundary-computed).
#[derive(Debug)]
pub struct EvalRequest<'a> {
    pub agent_id: &'a str,
    pub role: &'a str,
    pub tool: &'a str,
    pub params: &'a JsonValue,
    pub surface: &'a str,
    pub delegation_depth: u32,
    /// RFC3339, boundary-computed and ledgered (Law 6: never wall clock).
    pub request_time: &'a str,
    /// Derived attributes (budgets/velocity) computed at the boundary.
    pub derived: &'a JsonValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineDecision {
    Allow,
    Block,
    Escalate,
    /// No rule targets the tool at all — the service applies the deployment's
    /// `ungoverned_default` (block → NO_POLICY, allow → UNGOVERNED_ALLOW).
    NoPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// An operand path does not exist in params/derived context.
    MissingParam(String),
    /// Operand had the wrong type for the operation (or unparseable value).
    TypeMismatch(String),
}

impl EvalError {
    pub fn code(&self) -> &'static str {
        match self {
            EvalError::MissingParam(_) => "EVAL_ERROR_MISSING_PARAM",
            EvalError::TypeMismatch(_) => "EVAL_ERROR_TYPE_MISMATCH",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EngineOutcome {
    pub decision: EngineDecision,
    /// ALL matched determining rules, sorted (docs/policy-ir.md).
    /// Empty on EVAL_ERROR, NoPolicy, and DEFAULT_DENY.
    pub determining_rule_ids: Vec<String>,
    /// REDACTED per-rule trace (Law 9) — one entry per rule, evaluation order.
    pub trace: Vec<TraceEntry>,
    /// Present when any targeted rule aborted with an eval error → BLOCK
    /// (EVAL_ERROR). Rules are never silently skipped (fail-open prevention).
    pub eval_error: Option<EvalError>,
}

/// The NORMALIZED view both engines evaluate against (docs/repo-layout law:
/// one canonical path; determinism across engines):
/// - every JSON number is rewritten to its canonical decimal string form
///   ("150" → "150.0", "150.5" → "150.5") so Cedar's `decimal()` can parse it
///   (probe-verified: decimal() accepts strings only, digits on both sides);
/// - every null is dropped (probe-verified: Cedar rejects null in context) —
///   this makes `exists` mean exactly "present and non-null".
pub(crate) struct NormalizedRequest {
    pub agent_id: String,
    pub role: String,
    pub tool: String,
    pub params: JsonValue,
    pub surface: String,
    pub delegation_depth: JsonValue,
    pub request_time: String,
    pub derived: JsonValue,
}

pub(crate) fn normalize_request(req: &EvalRequest) -> NormalizedRequest {
    NormalizedRequest {
        agent_id: req.agent_id.to_string(),
        role: req.role.to_string(),
        tool: req.tool.to_string(),
        params: normalize_for_cedar(req.params),
        surface: req.surface.to_string(),
        delegation_depth: JsonValue::Number((req.delegation_depth as i64 * NUMBER_SCALE).into()),
        request_time: req.request_time.to_string(),
        derived: normalize_for_cedar(req.derived),
    }
}

fn normalize_keep(v: &JsonValue) -> Option<JsonValue> {
    match normalize_for_cedar(v) {
        JsonValue::Null => None,
        other => Some(other),
    }
}

/// Recursively rewrite a JSON value into the engine's normalized form:
/// numbers → fixed-point Longs (×10000, exact for ≤4 fractional digits — the
/// same precision Cedar's `decimal` supports), nulls dropped (objects lose the
/// key, arrays lose the element). Numbers NOT exactly representable at that
/// scale (huge, >4 fractional digits, exponent form) stay as their canonical
/// decimal STRING — ordering comparisons on them then fail loudly in BOTH
/// engines (a type mismatch, never a silent wrong answer).
pub(crate) fn normalize_for_cedar(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Null => JsonValue::Null,
        JsonValue::Bool(b) => JsonValue::Bool(*b),
        JsonValue::Number(n) => normalize_number(n),
        JsonValue::String(s) => JsonValue::String(s.clone()),
        JsonValue::Array(items) => {
            JsonValue::Array(items.iter().filter_map(normalize_keep).collect())
        }
        JsonValue::Object(map) => JsonValue::Object(
            map.iter()
                .filter_map(|(k, v)| normalize_keep(v).map(|nv| (k.clone(), nv)))
                .collect(),
        ),
    }
}

/// Fixed-point scale: ×10_000. Cedar's own `decimal` type supports ≤4
/// fractional digits — anything representable there is representable here.
pub(crate) const NUMBER_SCALE: i64 = 10_000;

/// Canonical number → fixed-point Long, or its canonical decimal string when
/// the value is not exactly representable at the scale (checked_mul overflow,
/// >4 fractional digits, or exponent notation).
pub(crate) fn normalize_number(n: &Number) -> JsonValue {
    if let Some(i) = n.as_i64() {
        return scale_i64(i);
    }
    if let Some(u) = n.as_u64() {
        if let Ok(i) = i64::try_from(u) {
            return scale_i64(i);
        }
        return JsonValue::String(u.to_string());
    }
    let s = n.to_string(); // ryu shortest repr, e.g. "150.5", "0.1", "1e21"
    match scaled_long_from_decimal_string(&s) {
        Some(v) => JsonValue::Number(v.into()),
        None => JsonValue::String(s),
    }
}

fn scale_i64(i: i64) -> JsonValue {
    match i.checked_mul(NUMBER_SCALE) {
        Some(v) => JsonValue::Number(v.into()),
        None => JsonValue::String(i.to_string()),
    }
}

/// Parse a canonical decimal string ("150.5", "-0.25") into a fixed-point
/// Long. Returns None for exponent form, >4 fractional digits, or overflow —
/// the value then stays a string (ordering on it errors loudly).
fn scaled_long_from_decimal_string(s: &str) -> Option<i64> {
    let (neg, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (int_part, frac_part) = body.split_once('.')?;
    if int_part.is_empty() || frac_part.is_empty() || frac_part.len() > 4 {
        return None;
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let int: i64 = int_part.parse().ok()?;
    let frac: i64 = format!("{frac_part:0<4}").parse().ok()?;
    let scaled = int.checked_mul(NUMBER_SCALE)?.checked_add(frac)?;
    Some(if neg { -scaled } else { scaled })
}

/// Flow 6 fast path: does the ACTIVE policy set need the request body
/// deserialized for this tool? (docs/policy-ir.md) — true iff any rule
/// targeting the tool has a condition referencing param operands. Deliberately
/// NOT "OR has effect escalate" — escalate-always-deserialize is a gateway
/// concern, not an engine concern.
pub fn needs_params(policies: &[Policy], tool: &str) -> bool {
    policies.iter().flat_map(|p| &p.rules).any(|r| {
        r.target
            .tools
            .iter()
            .any(|t| crate::ir::lint::tool_patterns_overlap(t, tool))
            && condition_references_param(r.condition.as_ref())
    })
}

fn condition_references_param(cond: Option<&ConditionNode>) -> bool {
    match cond {
        None => false,
        Some(node) => node_has_param(node),
    }
}

fn node_has_param(node: &ConditionNode) -> bool {
    match node {
        ConditionNode::And { args } | ConditionNode::Or { args } | ConditionNode::Not { args } => {
            args.iter().any(node_has_param)
        }
        ConditionNode::Eq { left, right }
        | ConditionNode::Ne { left, right }
        | ConditionNode::Lt { left, right }
        | ConditionNode::Lte { left, right }
        | ConditionNode::Gt { left, right }
        | ConditionNode::Gte { left, right } => operand_is_param(left) || operand_is_param(right),
        ConditionNode::In { left, .. } | ConditionNode::NotIn { left, .. } => {
            operand_is_param(left)
        }
        ConditionNode::Matches { left, .. } => operand_is_param(left),
        ConditionNode::Exists { .. } => true,
        ConditionNode::TimeBetween { .. } => false,
    }
}

fn operand_is_param(op: &Operand) -> bool {
    matches!(op, Operand::Param { .. })
}

/// Collect the operand PATHS a condition references, in encounter order,
/// deduplicated — the redacted trace material (Law 9: paths, never values).
pub(crate) fn collect_operand_paths(node: &ConditionNode) -> Vec<TraceOperand> {
    let mut out: Vec<TraceOperand> = Vec::new();
    let mut seen: std::collections::HashSet<(String, OperandKind)> =
        std::collections::HashSet::new();
    walk_operands(node, &mut |path, kind| {
        if seen.insert((path.clone(), kind)) {
            out.push(TraceOperand { path, kind });
        }
    });
    out
}

fn walk_operands(node: &ConditionNode, f: &mut impl FnMut(String, OperandKind)) {
    match node {
        ConditionNode::And { args } | ConditionNode::Or { args } | ConditionNode::Not { args } => {
            for arg in args {
                walk_operands(arg, f);
            }
        }
        ConditionNode::Eq { left, right }
        | ConditionNode::Ne { left, right }
        | ConditionNode::Lt { left, right }
        | ConditionNode::Lte { left, right }
        | ConditionNode::Gt { left, right }
        | ConditionNode::Gte { left, right } => {
            emit_operand(left, f);
            emit_operand(right, f);
        }
        ConditionNode::In { left, .. } | ConditionNode::NotIn { left, .. } => emit_operand(left, f),
        ConditionNode::Matches { left, .. } => emit_operand(left, f),
        ConditionNode::Exists { param } => f(format!("params.{param}"), OperandKind::Param),
        ConditionNode::TimeBetween { .. } => {
            f("context.request_time".to_string(), OperandKind::Context);
        }
    }
}

fn emit_operand(op: &Operand, f: &mut impl FnMut(String, OperandKind)) {
    match op {
        Operand::Param { param } => f(format!("params.{param}"), OperandKind::Param),
        Operand::Context { context } => {
            if let Some(attr) = context.strip_prefix("derived.") {
                f(format!("context.derived.{attr}"), OperandKind::Derived);
            } else {
                f(format!("context.{context}"), OperandKind::Context);
            }
        }
        Operand::Value { .. } => {} // literals have no path; never appear in traces
    }
}

/// Walk a dot path into a normalized JSON value. Returns:
/// Err(MissingParam) if the path is absent or an intermediate is not a record;
/// Ok(None) if the FINAL segment is absent (exists semantics);
/// Ok(Some(v)) with the value at the path.
pub(crate) fn resolve_path<'a>(
    root: &'a JsonValue,
    path: &str,
) -> Result<Option<&'a JsonValue>, EvalError> {
    let segments: Vec<&str> = path.split('.').collect();
    let mut current = root;
    for (i, seg) in segments.iter().enumerate() {
        match current {
            JsonValue::Object(map) => match map.get(*seg) {
                Some(next) => current = next,
                None => {
                    if i == segments.len() - 1 {
                        return Ok(None);
                    }
                    return Err(EvalError::MissingParam(path.to_string()));
                }
            },
            _ => return Err(EvalError::MissingParam(path.to_string())),
        }
    }
    Ok(Some(current))
}

/// Rule-level target matching (tool + roles + agent ids). Shared by engines.
pub(crate) fn targets_match(rule: &Rule, req: &NormalizedRequest) -> bool {
    let tool_match = rule
        .target
        .tools
        .iter()
        .any(|t| crate::ir::lint::tool_patterns_overlap(t, &req.tool));
    if !tool_match {
        return false;
    }
    let role_match = rule.target.agent_roles.is_empty()
        || rule.target.agent_roles.iter().any(|r| r == &req.role);
    let id_match = rule.target.agent_ids.is_empty()
        || rule.target.agent_ids.iter().any(|i| i == &req.agent_id);
    role_match && id_match
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ir::{Effect, Policy, Rule, Target};
    use serde_json::json;

    fn pol(rules: Vec<Rule>) -> Policy {
        Policy {
            ir_version: "1".into(),
            policy_id: "pol".into(),
            version: 1,
            description: "d".into(),
            rules,
        }
    }

    fn rule(id: &str, effect: Effect, tools: Vec<&str>, cond: Option<ConditionNode>) -> Rule {
        Rule {
            rule_id: id.into(),
            description: "d".into(),
            effect,
            target: Target {
                tools: tools.into_iter().map(String::from).collect(),
                agent_roles: vec![],
                agent_ids: vec![],
            },
            condition: cond,
        }
    }

    fn lte_amount(v: i64) -> ConditionNode {
        ConditionNode::Lte {
            left: Operand::Param {
                param: "amount".into(),
            },
            right: Operand::Value { value: json!(v) },
        }
    }

    #[test]
    fn needs_params_param_rule_true() {
        let p = pol(vec![rule(
            "r1",
            Effect::Allow,
            vec!["stripe.refunds.create"],
            Some(lte_amount(200)),
        )]);
        assert!(needs_params(&[p], "stripe.refunds.create"));
    }

    #[test]
    fn needs_params_no_condition_false() {
        let p = pol(vec![rule(
            "r1",
            Effect::Allow,
            vec!["stripe.refunds.create"],
            None,
        )]);
        assert!(!needs_params(&[p], "stripe.refunds.create"));
    }

    #[test]
    fn needs_params_escalate_only_conditionless_false() {
        // Escalate-always-deserialize is a GATEWAY concern, not engine (build-plan).
        let p = pol(vec![rule(
            "r1",
            Effect::Escalate,
            vec!["stripe.refunds.create"],
            None,
        )]);
        assert!(!needs_params(&[p], "stripe.refunds.create"));
    }

    #[test]
    fn needs_params_glob_target() {
        let p = pol(vec![rule(
            "r1",
            Effect::Allow,
            vec!["payments.*"],
            Some(lte_amount(200)),
        )]);
        assert!(needs_params(
            std::slice::from_ref(&p),
            "payments.refunds.create"
        ));
        assert!(!needs_params(
            std::slice::from_ref(&p),
            "stripe.refunds.create"
        ));
    }

    #[test]
    fn needs_params_context_only_condition_false() {
        let cond = ConditionNode::Eq {
            left: Operand::Context {
                context: "surface".into(),
            },
            right: Operand::Value {
                value: json!("claude_code"),
            },
        };
        let p = pol(vec![rule("r1", Effect::Allow, vec!["fs.read"], Some(cond))]);
        assert!(!needs_params(&[p], "fs.read"));
    }

    #[test]
    fn normalize_numbers_and_nulls() {
        let v = json!({
            "amount": 150,
            "rate": 1.5,
            "flag": true,
            "name": "x",
            "nested": {"a": null, "b": 3},
            "arr": [1, null, "s"]
        });
        assert_eq!(
            normalize_for_cedar(&v),
            json!({
                "amount": 1500000,
                "rate": 15000,
                "flag": true,
                "name": "x",
                "nested": {"b": 30000},
                "arr": [10000, "s"]
            })
        );
    }

    #[test]
    fn normalize_unrepresentable_numbers_stay_strings() {
        assert_eq!(normalize_for_cedar(&json!(0.12345)), json!("0.12345"));
        assert_eq!(normalize_for_cedar(&json!(150.5)), json!(1505000));
        assert_eq!(normalize_for_cedar(&json!(-0.25)), json!(-2500));
        assert_eq!(normalize_for_cedar(&json!(-0.0)), json!(0));
        assert_eq!(normalize_for_cedar(&json!(0.1)), json!(1000));
    }

    #[test]
    fn collect_operands_dedupes() {
        let cond = ConditionNode::And {
            args: vec![
                lte_amount(200),
                ConditionNode::Eq {
                    left: Operand::Param {
                        param: "amount".into(),
                    },
                    right: Operand::Value { value: json!(200) },
                },
                ConditionNode::Eq {
                    left: Operand::Context {
                        context: "derived.agent_daily_total_amount".into(),
                    },
                    right: Operand::Value { value: json!(1000) },
                },
            ],
        };
        let ops = collect_operand_paths(&cond);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].path, "params.amount");
        assert_eq!(ops[0].kind, OperandKind::Param);
        assert_eq!(ops[1].path, "context.derived.agent_daily_total_amount");
        assert_eq!(ops[1].kind, OperandKind::Derived);
    }

    // -----------------------------------------------------------------------
    // Behavioral tests — run against BOTH engines (build-plan Phase 4).
    // -----------------------------------------------------------------------

    fn fixture_policies() -> Vec<Policy> {
        serde_json::from_value(json!([
            {
                "ir_version": "1",
                "policy_id": "pol_refunds",
                "version": 1,
                "description": "d",
                "rules": [
                    {
                        "rule_id": "r-allow-small",
                        "description": "d",
                        "effect": "allow",
                        "target": {"tools": ["stripe.refunds.create"]},
                        "condition": {"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}}
                    },
                    {
                        "rule_id": "r-escalate-mid",
                        "description": "d",
                        "effect": "escalate",
                        "target": {"tools": ["stripe.refunds.create"]},
                        "condition": {"op": "gte", "left": {"param": "amount"}, "right": {"value": 100}}
                    },
                    {
                        "rule_id": "r-block-large",
                        "description": "d",
                        "effect": "block",
                        "target": {"tools": ["stripe.refunds.create"]},
                        "condition": {"op": "gte", "left": {"param": "amount"}, "right": {"value": 1000}}
                    }
                ]
            }
        ]))
        .expect("fixture")
    }

    fn empty_derived() -> &'static JsonValue {
        Box::leak(Box::new(JsonValue::Object(Default::default())))
    }

    fn req<'a>(
        tool: &'a str,
        params: &'a JsonValue,
        agent: &'a str,
        role: &'a str,
    ) -> EvalRequest<'a> {
        EvalRequest {
            agent_id: agent,
            role,
            tool,
            params,
            surface: "claude_code",
            delegation_depth: 0,
            request_time: "2026-08-25T14:00:00Z",
            derived: empty_derived(),
        }
    }

    fn both_engines(policies: &[Policy], request: &EvalRequest) -> (EngineOutcome, EngineOutcome) {
        let reference = crate::engine::reference::evaluate_ir(policies, request);
        let engine = crate::engine::cedar_engine::CedarEngine::compile(policies).expect("compile");
        let cedar = engine.evaluate(request);
        (reference, cedar)
    }

    #[test]
    fn refund_allow_escalate_block() {
        let policies = fixture_policies();
        // Allow only when no escalate/block rule also fires.
        for amount in [0i64, 50] {
            let (r, c) = both_engines(
                &policies,
                &req(
                    "stripe.refunds.create",
                    &json!({"amount": amount}),
                    "agent_support_09",
                    "support",
                ),
            );
            assert_eq!(r.decision, EngineDecision::Allow, "amount {amount}");
            assert_eq!(c.decision, EngineDecision::Allow, "amount {amount}");
            assert_eq!(r.determining_rule_ids, vec!["r-allow-small".to_string()]);
            assert_eq!(c.determining_rule_ids, vec!["r-allow-small".to_string()]);
        }
        // Overlap 100..=200: the escalate rule ALSO fires → escalate wins
        // (policy-ir: block > escalate > allow). The lint would flag this
        // overlap as ERROR_ALLOW_ESCALATE_OVERLAP; the engine semantics are
        // still deterministic. The shadowed allow stays in the trace but is
        // not determining (matches Cedar's reason set).
        for amount in [199i64, 200, 201, 500, 999] {
            let (r, c) = both_engines(
                &policies,
                &req(
                    "stripe.refunds.create",
                    &json!({"amount": amount}),
                    "agent_support_09",
                    "support",
                ),
            );
            assert_eq!(r.decision, EngineDecision::Escalate, "amount {amount}");
            assert_eq!(c.decision, EngineDecision::Escalate, "amount {amount}");
            assert_eq!(
                r.determining_rule_ids,
                vec!["r-escalate-mid".to_string()],
                "amount {amount}"
            );
            assert_eq!(
                c.determining_rule_ids,
                vec!["r-escalate-mid".to_string()],
                "amount {amount}"
            );
            if amount <= 200 {
                assert!(
                    r.trace
                        .iter()
                        .any(|t| t.rule_id == "r-allow-small" && t.matched)
                );
            }
        }
        for amount in [1000i64, 5000] {
            let (r, c) = both_engines(
                &policies,
                &req(
                    "stripe.refunds.create",
                    &json!({"amount": amount}),
                    "agent_support_09",
                    "support",
                ),
            );
            assert_eq!(r.decision, EngineDecision::Block, "amount {amount}");
            assert_eq!(c.decision, EngineDecision::Block, "amount {amount}");
            // block wins even though the escalate rule ALSO matched — but ALL
            // matched rules are reported (policy-ir: "lists ALL matched rules").
            assert_eq!(
                r.determining_rule_ids,
                vec!["r-block-large".to_string(), "r-escalate-mid".to_string()]
            );
            assert_eq!(c.determining_rule_ids, r.determining_rule_ids);
        }
        // default deny: governed tool, no rule matches, no eval error
        let deny_pol = serde_json::from_value::<Vec<Policy>>(json!([{
            "ir_version": "1",
            "policy_id": "pol_deny",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-needs-flag",
                "description": "d",
                "effect": "block",
                "target": {"tools": ["stripe.payouts.create"]},
                "condition": {"op": "exists", "param": "flag"}
            }]
        }]))
        .expect("fixture");
        let (r, c) = both_engines(
            &deny_pol,
            &req(
                "stripe.payouts.create",
                &json!({"amount": 50}),
                "agent_support_09",
                "support",
            ),
        );
        assert_eq!(r.decision, EngineDecision::Block);
        assert_eq!(c.decision, EngineDecision::Block);
        assert!(r.determining_rule_ids.is_empty());
        assert!(c.determining_rule_ids.is_empty());
        assert!(r.eval_error.is_none());
        // ungoverned tool
        let (r, c) = both_engines(
            &policies,
            &req(
                "email.send",
                &json!({"to": "x@y.z"}),
                "agent_support_09",
                "support",
            ),
        );
        assert_eq!(r.decision, EngineDecision::NoPolicy);
        assert_eq!(c.decision, EngineDecision::NoPolicy);
    }

    #[test]
    fn missing_param_blocks() {
        let policies = fixture_policies();
        // No amount key at all → every rule errors → BLOCK(EVAL_ERROR).
        let (r, c) = both_engines(
            &policies,
            &req(
                "stripe.refunds.create",
                &json!({"customer_id": "cus_1"}),
                "agent_support_09",
                "support",
            ),
        );
        assert_eq!(r.decision, EngineDecision::Block);
        assert_eq!(c.decision, EngineDecision::Block);
        assert!(r.eval_error.is_some());
        assert!(c.eval_error.is_some());
        assert!(r.determining_rule_ids.is_empty());
        // nested missing path
        let p = serde_json::from_value::<Vec<Policy>>(json!([{
            "ir_version": "1",
            "policy_id": "pol_nested",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-nested",
                "description": "d",
                "effect": "allow",
                "target": {"tools": ["fs.read"]},
                "condition": {"op": "eq", "left": {"param": "customer.id"}, "right": {"value": "cus_1"}}
            }]
        }]))
        .expect("fixture");
        let (r, c) = both_engines(
            &p,
            &req(
                "fs.read",
                &json!({"customer": {"name": "x"}}),
                "a",
                "support",
            ),
        );
        assert_eq!(r.decision, EngineDecision::Block);
        assert_eq!(c.decision, EngineDecision::Block);
        assert!(r.eval_error.is_some());
        assert!(c.eval_error.is_some());
    }

    #[test]
    fn eval_error_never_skips() {
        // An allow rule with an erroring condition must NOT be skipped to
        // produce ALLOW — and the error must win over a matched block rule
        // too: the verdict is BLOCK(EVAL_ERROR), never a rule verdict.
        let p = serde_json::from_value::<Vec<Policy>>(json!([{
            "ir_version": "1",
            "policy_id": "pol_mix",
            "version": 1,
            "description": "d",
            "rules": [
                {
                    "rule_id": "r-allow-err",
                    "description": "d",
                    "effect": "allow",
                    "target": {"tools": ["shell.exec"]},
                    "condition": {"op": "lte", "left": {"param": "missing_path"}, "right": {"value": 5}}
                },
                {
                    "rule_id": "r-block-known",
                    "description": "d",
                    "effect": "block",
                    "target": {"tools": ["shell.exec"]},
                    "condition": {"op": "eq", "left": {"param": "cmd"}, "right": {"value": "rm"}}
                }
            ]
        }]))
        .expect("fixture");
        let (r, c) = both_engines(
            &p,
            &req("shell.exec", &json!({"cmd": "rm"}), "a", "support"),
        );
        assert_eq!(r.decision, EngineDecision::Block);
        assert_eq!(c.decision, EngineDecision::Block);
        assert!(
            r.eval_error.is_some(),
            "the allow rule's error must abort, not be skipped"
        );
        assert!(c.eval_error.is_some());
        assert!(r.determining_rule_ids.is_empty());
        // the trace must record the erroring rule
        assert!(
            r.trace
                .iter()
                .any(|t| t.rule_id == "r-allow-err" && t.error.is_some())
        );
        assert!(
            r.trace
                .iter()
                .any(|t| t.rule_id == "r-block-known" && t.matched)
        );
    }

    #[test]
    fn time_between_and_matches_and_derived() {
        let p = serde_json::from_value::<Vec<Policy>>(json!([{
            "ir_version": "1",
            "policy_id": "pol_tb",
            "version": 1,
            "description": "d",
            "rules": [
                {
                    "rule_id": "r-window",
                    "description": "d",
                    "effect": "allow",
                    "target": {"tools": ["fs.write"]},
                    "condition": {
                        "op": "and",
                        "args": [
                            {"op": "time_between", "start": "09:00", "end": "17:00", "tz": "UTC", "days": ["mon", "tue", "wed", "thu", "fri"]},
                            {"op": "matches", "left": {"param": "command"}, "pattern": "^rm *$"},
                            {"op": "lte", "left": {"context": "derived.agent_daily_total_amount"}, "right": {"value": 1000}}
                        ]
                    }
                }
            ]
        }]))
        .expect("fixture");
        // Tue 14:00 UTC, rm -rf, budget 350 → allow
        let p1 = json!({"command": "rm -rf /"});
        let d1 = json!({"agent_daily_total_amount": 350.0});
        let base1 = req("fs.write", &p1, "a", "support");
        let req1 = EvalRequest {
            derived: &d1,
            ..base1
        };
        let (r, c) = both_engines(&p, &req1);
        assert_eq!(r.decision, EngineDecision::Allow);
        assert_eq!(c.decision, EngineDecision::Allow);
        // Sunday → window closed
        let p2 = json!({"command": "rm -rf /"});
        let base2 = req("fs.write", &p2, "a", "support");
        let req2 = EvalRequest {
            request_time: "2026-08-23T10:00:00Z",
            ..base2
        };
        let (r, _) = both_engines(&p, &req2);
        assert_eq!(r.decision, EngineDecision::Block);
        // non-matching command
        let p3 = json!({"command": "ls -la"});
        let base3 = req("fs.write", &p3, "a", "support");
        let req3 = EvalRequest {
            request_time: "2026-08-25T10:00:00Z",
            ..base3
        };
        let (r, _) = both_engines(&p, &req3);
        assert_eq!(r.decision, EngineDecision::Block);
    }
}
