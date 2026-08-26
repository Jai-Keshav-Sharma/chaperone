use crate::models::ir::{ConditionNode, Operand, Policy};

/// Semantic validation of a Policy IR document — the layer ABOVE serde.
/// Serde rejects unknown fields/ops; validation rejects structurally
/// malformed-but-parseable IR (docs/policy-ir.md, build-plan Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorCode {
    UnsupportedIrVersion,
    EmptyRuleId,
    EmptyToolTarget,
    InvalidToolPattern,
    EmptyLogicalArgs,
    NotArityOne,
    EmptyParamPath,
    InvalidContextOperand,
    EmptyPattern,
    PatternNotAnchored,
    InvalidTimeFormat,
    EmptyTimezone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub code: ValidationErrorCode,
    pub rule_id: Option<String>,
    pub message: String,
}

impl ValidationError {
    fn new(code: ValidationErrorCode, rule_id: Option<String>, message: impl Into<String>) -> Self {
        ValidationError {
            code,
            rule_id,
            message: message.into(),
        }
    }
}

/// Validate a policy document. Ok(()) = structurally valid; Err = all findings
/// (collected, not early-exit — the compiler pipeline wants the full report).
pub fn validate(policy: &Policy) -> Result<(), Vec<ValidationError>> {
    let mut errs = Vec::new();
    if policy.ir_version != "1" {
        errs.push(ValidationError::new(
            ValidationErrorCode::UnsupportedIrVersion,
            None,
            format!(
                "unsupported ir_version {:?}; supported: \"1\"",
                policy.ir_version
            ),
        ));
    }
    for rule in &policy.rules {
        if rule.rule_id.is_empty() {
            errs.push(ValidationError::new(
                ValidationErrorCode::EmptyRuleId,
                Some(rule.rule_id.clone()),
                "rule_id must not be empty",
            ));
        }
        if rule.target.tools.is_empty() {
            errs.push(ValidationError::new(
                ValidationErrorCode::EmptyToolTarget,
                Some(rule.rule_id.clone()),
                "target.tools must name at least one tool",
            ));
        }
        for tool in &rule.target.tools {
            if !is_valid_tool_pattern(tool) {
                errs.push(ValidationError::new(
                    ValidationErrorCode::InvalidToolPattern,
                    Some(rule.rule_id.clone()),
                    format!("invalid tool pattern {tool:?}: exact names or trailing-* globs only"),
                ));
            }
        }
        if let Some(cond) = &rule.condition {
            validate_condition(cond, &rule.rule_id, &mut errs);
        }
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

/// Tools are "exact names or trailing-* globs" (docs/policy-ir.md): no `*`
/// anywhere except as a trailing `.*` on a star-free prefix; `["*"]` = all.
fn is_valid_tool_pattern(tool: &str) -> bool {
    if tool.is_empty() {
        return false;
    }
    if tool == "*" {
        return true;
    }
    if let Some(prefix) = tool.strip_suffix(".*") {
        !prefix.is_empty() && !prefix.contains('*')
    } else {
        !tool.contains('*')
    }
}

fn validate_condition(node: &ConditionNode, rule_id: &str, errs: &mut Vec<ValidationError>) {
    match node {
        ConditionNode::And { args } | ConditionNode::Or { args } => {
            if args.is_empty() {
                errs.push(ValidationError::new(
                    ValidationErrorCode::EmptyLogicalArgs,
                    Some(rule_id.to_string()),
                    "and/or must have at least one argument",
                ));
            }
            for arg in args {
                validate_condition(arg, rule_id, errs);
            }
        }
        ConditionNode::Not { args } => {
            if args.len() != 1 {
                errs.push(ValidationError::new(
                    ValidationErrorCode::NotArityOne,
                    Some(rule_id.to_string()),
                    "not takes exactly one argument",
                ));
            }
            for arg in args {
                validate_condition(arg, rule_id, errs);
            }
        }
        ConditionNode::Eq { left, right }
        | ConditionNode::Ne { left, right }
        | ConditionNode::Lt { left, right }
        | ConditionNode::Lte { left, right }
        | ConditionNode::Gt { left, right }
        | ConditionNode::Gte { left, right } => {
            validate_operand(left, rule_id, errs);
            validate_operand(right, rule_id, errs);
        }
        ConditionNode::In { left, .. } | ConditionNode::NotIn { left, .. } => {
            validate_operand(left, rule_id, errs);
        }
        ConditionNode::Matches { left, pattern } => {
            validate_operand(left, rule_id, errs);
            if pattern.is_empty() {
                errs.push(ValidationError::new(
                    ValidationErrorCode::EmptyPattern,
                    Some(rule_id.to_string()),
                    "matches pattern must not be empty",
                ));
            } else if !(pattern.starts_with('^') && pattern.ends_with('$')) {
                errs.push(ValidationError::new(
                    ValidationErrorCode::PatternNotAnchored,
                    Some(rule_id.to_string()),
                    format!("matches pattern {pattern:?} must be anchored (^...$)"),
                ));
            }
        }
        ConditionNode::Exists { param } => {
            if param.is_empty() {
                errs.push(ValidationError::new(
                    ValidationErrorCode::EmptyParamPath,
                    Some(rule_id.to_string()),
                    "exists param path must not be empty",
                ));
            }
        }
        ConditionNode::TimeBetween { start, end, tz, .. } => {
            if !is_hhmm(start) || !is_hhmm(end) {
                errs.push(ValidationError::new(
                    ValidationErrorCode::InvalidTimeFormat,
                    Some(rule_id.to_string()),
                    format!("time_between bounds must be HH:MM, got start={start:?} end={end:?}"),
                ));
            }
            if tz.is_empty() {
                errs.push(ValidationError::new(
                    ValidationErrorCode::EmptyTimezone,
                    Some(rule_id.to_string()),
                    "time_between tz must not be empty",
                ));
            }
        }
    }
}

fn validate_operand(op: &Operand, rule_id: &str, errs: &mut Vec<ValidationError>) {
    match op {
        Operand::Param { param } => {
            if param.is_empty() {
                errs.push(ValidationError::new(
                    ValidationErrorCode::EmptyParamPath,
                    Some(rule_id.to_string()),
                    "param operand path must not be empty",
                ));
            }
        }
        Operand::Context { context } => {
            let valid = matches!(
                context.as_str(),
                "request_time" | "surface" | "delegation_depth"
            ) || context
                .strip_prefix("derived.")
                .is_some_and(|attr| !attr.is_empty());
            if !valid {
                errs.push(ValidationError::new(
                    ValidationErrorCode::InvalidContextOperand,
                    Some(rule_id.to_string()),
                    format!(
                        "context operand {context:?} is not in the closed set \
                         (request_time | surface | delegation_depth | derived.<attr>)"
                    ),
                ));
            }
        }
        Operand::Value { .. } => {}
    }
}

/// Strict "HH:MM" clock format: 2-digit hours (00-23), colon, 2-digit minutes (00-59).
fn is_hhmm(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 5
        && b[2] == b':'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 2 || c.is_ascii_digit())
        && (b[0] - b'0') * 10 + (b[1] - b'0') <= 23
        && (b[3] - b'0') * 10 + (b[4] - b'0') <= 59
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ir::Policy;
    use serde_json::{Value, json};

    fn base() -> Value {
        json!({
            "ir_version": "1",
            "policy_id": "pol_x",
            "version": 1,
            "description": "d",
            "rules": [{
                "rule_id": "r-1",
                "description": "d",
                "effect": "allow",
                "target": {"tools": ["fs.read"]},
                "condition": null
            }]
        })
    }

    fn parse(v: Value) -> Policy {
        serde_json::from_value(v).expect("fixture parses")
    }

    #[test]
    fn valid_policy_passes() {
        assert!(validate(&parse(base())).is_ok());
    }

    #[test]
    fn unsupported_ir_version_rejected() {
        let mut v = base();
        v["ir_version"] = json!("2");
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::UnsupportedIrVersion))
        );
    }

    #[test]
    fn not_arity_one_rejected() {
        let mut v = base();
        v["rules"][0]["condition"] = json!({
            "op": "not",
            "args": [
                {"op": "eq", "left": {"param": "a"}, "right": {"value": 1}},
                {"op": "eq", "left": {"param": "b"}, "right": {"value": 2}}
            ]
        });
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::NotArityOne))
        );
    }

    #[test]
    fn empty_and_args_rejected() {
        let mut v = base();
        v["rules"][0]["condition"] = json!({"op": "and", "args": []});
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::EmptyLogicalArgs))
        );
    }

    #[test]
    fn empty_pattern_rejected() {
        let mut v = base();
        v["rules"][0]["condition"] = json!({
            "op": "matches",
            "left": {"param": "command"},
            "pattern": ""
        });
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::EmptyPattern))
        );
    }

    #[test]
    fn unanchored_pattern_rejected() {
        for pat in ["^cus_", "cus_$", "cus_"] {
            let mut v = base();
            v["rules"][0]["condition"] = json!({
                "op": "matches",
                "left": {"param": "customer_id"},
                "pattern": pat
            });
            let errs = validate(&parse(v)).expect_err("must fail");
            assert!(
                errs.iter()
                    .any(|e| matches!(e.code, ValidationErrorCode::PatternNotAnchored)),
                "pattern {pat:?} should be rejected"
            );
        }
    }

    #[test]
    fn anchored_pattern_passes() {
        let mut v = base();
        v["rules"][0]["condition"] = json!({
            "op": "matches",
            "left": {"param": "customer_id"},
            "pattern": "^cus_.*$"
        });
        assert!(validate(&parse(v)).is_ok());
    }

    #[test]
    fn bad_time_format_rejected() {
        for bad in ["9:00", "25:00", "09:60", "0900", "09:0"] {
            let mut v = base();
            v["rules"][0]["condition"] = json!({
                "op": "time_between",
                "start": bad,
                "end": "17:00",
                "tz": "UTC",
                "days": ["mon"]
            });
            let errs = validate(&parse(v)).expect_err("must fail");
            assert!(
                errs.iter()
                    .any(|e| matches!(e.code, ValidationErrorCode::InvalidTimeFormat)),
                "start {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn empty_timezone_rejected() {
        let mut v = base();
        v["rules"][0]["condition"] = json!({
            "op": "time_between",
            "start": "09:00",
            "end": "17:00",
            "tz": "",
            "days": ["mon"]
        });
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::EmptyTimezone))
        );
    }

    #[test]
    fn bad_context_operand_rejected() {
        let mut v = base();
        v["rules"][0]["condition"] = json!({
            "op": "eq",
            "left": {"context": "agent_supplied"},
            "right": {"value": "x"}
        });
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::InvalidContextOperand))
        );
    }

    #[test]
    fn derived_context_operand_passes() {
        let mut v = base();
        v["rules"][0]["condition"] = json!({
            "op": "eq",
            "left": {"context": "derived.agent_daily_total_amount"},
            "right": {"value": 100}
        });
        assert!(validate(&parse(v)).is_ok());
    }

    #[test]
    fn empty_param_path_rejected() {
        let mut v = base();
        v["rules"][0]["condition"] = json!({
            "op": "exists",
            "param": ""
        });
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::EmptyParamPath))
        );
    }

    #[test]
    fn empty_rule_id_rejected() {
        let mut v = base();
        v["rules"][0]["rule_id"] = json!("");
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::EmptyRuleId))
        );
    }

    #[test]
    fn empty_tool_target_rejected() {
        let mut v = base();
        v["rules"][0]["target"] = json!({"tools": []});
        let errs = validate(&parse(v)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| matches!(e.code, ValidationErrorCode::EmptyToolTarget))
        );
    }

    #[test]
    fn invalid_tool_pattern_rejected() {
        for bad in ["*.refunds.create", "pay.*.create", "a*b"] {
            let mut v = base();
            v["rules"][0]["target"] = json!({"tools": [bad]});
            let errs = validate(&parse(v)).expect_err("must fail");
            assert!(
                errs.iter()
                    .any(|e| matches!(e.code, ValidationErrorCode::InvalidToolPattern)),
                "tool {bad:?} should be rejected"
            );
        }
        for ok in ["stripe.refunds.create", "payments.*", "*"] {
            let mut v = base();
            v["rules"][0]["target"] = json!({"tools": [ok]});
            assert!(validate(&parse(v)).is_ok(), "tool {ok:?} should pass");
        }
    }
}
