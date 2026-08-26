use std::collections::HashSet;

use crate::models::ir::{ConditionNode, Effect, Operand, Policy, Rule, Target};
use serde_json::Value as JsonValue;

/// Static lint findings over the ACTIVE policy SET (docs/policy-ir.md).
/// Lint is pure analysis over IR bytes — it never evaluates anything (Law).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LintCode {
    DuplicateRuleId,
    NoRules,
    AllowEscalateOverlap,
    CrossPolicyConflict,
    UnreachableAllow,
    ToolUngoverned,
    BroadTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Error,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub severity: Severity,
    pub code: LintCode,
    pub policy_id: Option<String>,
    pub rule_id: Option<String>,
    pub message: String,
}

/// Run every lint check over a policy set. `known_tools` is the deployment's
/// tool registry (used by WARN_TOOL_UNGOVERNED; empty = nothing to compare).
pub fn lint(policies: &[Policy], known_tools: &[String]) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    for policy in policies {
        if policy.rules.is_empty() {
            findings.push(LintFinding {
                severity: Severity::Error,
                code: LintCode::NoRules,
                policy_id: Some(policy.policy_id.clone()),
                rule_id: None,
                message: "policy has no rules — nothing is governed".to_string(),
            });
        }

        let mut seen_ids = HashSet::new();
        for rule in &policy.rules {
            if !seen_ids.insert(rule.rule_id.as_str()) {
                findings.push(LintFinding {
                    severity: Severity::Error,
                    code: LintCode::DuplicateRuleId,
                    policy_id: Some(policy.policy_id.clone()),
                    rule_id: Some(rule.rule_id.clone()),
                    message: format!("duplicate rule_id {:?}", rule.rule_id),
                });
            }
        }

        for rule in &policy.rules {
            if rule.target.tools.iter().any(|t| is_broad_pattern(t)) {
                findings.push(LintFinding {
                    severity: Severity::Warn,
                    code: LintCode::BroadTarget,
                    policy_id: Some(policy.policy_id.clone()),
                    rule_id: Some(rule.rule_id.clone()),
                    message: "rule targets every tool (\"*\") or an over-broad pattern".to_string(),
                });
            }
        }

        for (i, a) in policy.rules.iter().enumerate() {
            for b in &policy.rules[i + 1..] {
                if a.effect == Effect::Allow
                    && b.effect == Effect::Escalate
                    && targets_overlap(&a.target, &b.target)
                    && conditions_overlap(&a.condition, &b.condition)
                {
                    findings.push(LintFinding {
                        severity: Severity::Error,
                        code: LintCode::AllowEscalateOverlap,
                        policy_id: Some(policy.policy_id.clone()),
                        rule_id: Some(a.rule_id.clone()),
                        message: format!(
                            "allow rule {:?} and escalate rule {:?} can both fire for the same call",
                            a.rule_id, b.rule_id
                        ),
                    });
                }
            }
        }
    }

    // ERROR_CROSS_POLICY_CONFLICT: allow in one policy vs block/escalate in a
    // DIFFERENT policy, jointly satisfiable — blocks activation (policy-ir).
    for (i, pa) in policies.iter().enumerate() {
        for pb in &policies[i + 1..] {
            for ra in &pa.rules {
                if ra.effect != Effect::Allow {
                    continue;
                }
                for rb in &pb.rules {
                    if !matches!(rb.effect, Effect::Block | Effect::Escalate) {
                        continue;
                    }
                    if targets_overlap(&ra.target, &rb.target)
                        && conditions_overlap(&ra.condition, &rb.condition)
                    {
                        findings.push(LintFinding {
                            severity: Severity::Error,
                            code: LintCode::CrossPolicyConflict,
                            policy_id: Some(pa.policy_id.clone()),
                            rule_id: Some(ra.rule_id.clone()),
                            message: format!(
                                "allow rule {:?} in {:?} conflicts with {:?} rule {:?} in {:?}",
                                ra.rule_id, pa.policy_id, rb.effect, rb.rule_id, pb.policy_id
                            ),
                        });
                    }
                }
            }
        }
    }

    // WARN_UNREACHABLE_ALLOW: an allow rule fully dominated by a block rule —
    // the block always preempts it, so the allow can never produce ALLOW.
    let blocks: Vec<&Rule> = policies
        .iter()
        .flat_map(|p| p.rules.iter())
        .filter(|r| r.effect == Effect::Block)
        .collect();
    for policy in policies {
        for ra in &policy.rules {
            if ra.effect != Effect::Allow {
                continue;
            }
            for rb in &blocks {
                if target_covers(&rb.target, &ra.target)
                    && condition_implies(&ra.condition, &rb.condition)
                {
                    findings.push(LintFinding {
                        severity: Severity::Warn,
                        code: LintCode::UnreachableAllow,
                        policy_id: Some(policy.policy_id.clone()),
                        rule_id: Some(ra.rule_id.clone()),
                        message: format!(
                            "allow rule {:?} is unreachable — block rule {:?} always preempts it",
                            ra.rule_id, rb.rule_id
                        ),
                    });
                    break;
                }
            }
        }
    }

    // WARN_TOOL_UNGOVERNED: a known tool no rule targets in any policy.
    for tool in known_tools {
        let governed = policies.iter().flat_map(|p| p.rules.iter()).any(|r| {
            r.target
                .tools
                .iter()
                .any(|t| tool_patterns_overlap(t, tool))
        });
        if !governed {
            findings.push(LintFinding {
                severity: Severity::Warn,
                code: LintCode::ToolUngoverned,
                policy_id: None,
                rule_id: None,
                message: format!("known tool {tool:?} is governed by no active policy"),
            });
        }
    }

    findings
}

/// A pattern is "broad" if it matches everything ("*") or contains a `*`
/// outside the legal trailing-glob position (malformed, matches nothing).
fn is_broad_pattern(t: &str) -> bool {
    t == "*" || (t.contains('*') && !is_glob(t)) || (is_glob(t) && glob_prefix(t).contains('*'))
}

fn is_glob(s: &str) -> bool {
    s.ends_with(".*")
}

fn glob_prefix(s: &str) -> &str {
    &s[..s.len() - 2]
}

/// Can two tool patterns both match some tool name?
fn tool_patterns_overlap(a: &str, b: &str) -> bool {
    if a == "*" || b == "*" {
        return true;
    }
    match (is_glob(a), is_glob(b)) {
        (false, false) => a == b,
        (true, false) => glob_matches_exact(a, b),
        (false, true) => glob_matches_exact(b, a),
        (true, true) => {
            let (pa, pb) = (glob_prefix(a), glob_prefix(b));
            pa.starts_with(pb) || pb.starts_with(pa)
        }
    }
}

fn glob_matches_exact(glob: &str, exact: &str) -> bool {
    let prefix = glob_prefix(glob);
    exact.len() > prefix.len()
        && exact.starts_with(prefix)
        && exact.as_bytes()[prefix.len()] == b'.'
}

/// Does pattern `b` match every name pattern `a` matches (b ⊇ a)?
fn tool_covers(b: &str, a: &str) -> bool {
    if b == "*" {
        return true;
    }
    if a == "*" {
        return false;
    }
    match (is_glob(b), is_glob(a)) {
        (false, false) => b == a,
        (true, false) => glob_matches_exact(b, a),
        (true, true) => glob_prefix(a).starts_with(glob_prefix(b)),
        (false, true) => false,
    }
}

fn roles_overlap(a: &[String], b: &[String]) -> bool {
    a.is_empty() || b.is_empty() || a.iter().any(|x| b.contains(x))
}

/// Do two targets overlap — some request matches both?
fn targets_overlap(a: &Target, b: &Target) -> bool {
    a.tools
        .iter()
        .any(|ta| b.tools.iter().any(|tb| tool_patterns_overlap(ta, tb)))
        && roles_overlap(&a.agent_roles, &b.agent_roles)
        && roles_overlap(&a.agent_ids, &b.agent_ids)
}

/// Does target `b` cover every request target `a` matches (b ⊇ a)?
fn target_covers(b: &Target, a: &Target) -> bool {
    a.tools
        .iter()
        .all(|ta| b.tools.iter().any(|tb| tool_covers(tb, ta)))
        && roles_cover(&b.agent_roles, &a.agent_roles)
        && roles_cover(&b.agent_ids, &a.agent_ids)
}

/// `b` covers `a`: b unrestricted (empty), or a restricted and a ⊆ b.
fn roles_cover(b: &[String], a: &[String]) -> bool {
    b.is_empty() || (!a.is_empty() && a.iter().all(|x| b.contains(x)))
}

// ---------------------------------------------------------------------------
// Condition satisfiability: DNF over atomic predicates (build-plan Phase 3:
// "bounded ~64 atoms; matches treated as always-satisfiable (conservative)").
// ---------------------------------------------------------------------------

/// One atomic predicate. `Always` = no constraint (conservative for
/// matches/exists/time_between/not/unknown); `False` = statically dead.
#[derive(Debug, Clone, PartialEq)]
enum Atom {
    False,
    Always,
    Eq {
        path: String,
        value: JsonValue,
    },
    Ne {
        path: String,
        value: JsonValue,
    },
    Lt {
        path: String,
        value: JsonValue,
    },
    Lte {
        path: String,
        value: JsonValue,
    },
    Gt {
        path: String,
        value: JsonValue,
    },
    Gte {
        path: String,
        value: JsonValue,
    },
    In {
        path: String,
        values: Vec<JsonValue>,
    },
    NotIn {
        path: String,
        values: Vec<JsonValue>,
    },
}

const DNF_CAP: usize = 64;

#[derive(Debug, Clone)]
enum OperandRef {
    Path(String),
    Constant(JsonValue),
}

fn operand_ref(op: &Operand) -> OperandRef {
    match op {
        Operand::Param { param } => OperandRef::Path(format!("param:{param}")),
        Operand::Context { context } => OperandRef::Path(format!("context:{context}")),
        Operand::Value { value } => OperandRef::Constant(value.clone()),
    }
}

/// Convert a condition to DNF: a list of disjuncts, each a conjunction of atoms.
/// None = the cap was exceeded → caller treats it as conservative (satisfiable).
fn to_dnf(node: &ConditionNode) -> Option<Vec<Vec<Atom>>> {
    match node {
        ConditionNode::And { args } => {
            let mut acc: Vec<Vec<Atom>> = vec![vec![]];
            for arg in args {
                let d = to_dnf(arg)?;
                acc = cartesian(&acc, &d)?;
            }
            Some(acc)
        }
        ConditionNode::Or { args } => {
            let mut acc = Vec::new();
            for arg in args {
                acc.extend(to_dnf(arg)?);
                if acc.len() > DNF_CAP {
                    return None;
                }
            }
            Some(acc)
        }
        ConditionNode::Not { .. } => Some(vec![vec![Atom::Always]]),
        leaf => Some(vec![vec![atom_for_leaf(leaf)]]),
    }
}

fn cartesian(a: &[Vec<Atom>], b: &[Vec<Atom>]) -> Option<Vec<Vec<Atom>>> {
    if a.is_empty() || b.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for da in a {
        for db in b {
            let mut conj = da.clone();
            conj.extend(db.iter().cloned());
            out.push(conj);
            if out.len() > DNF_CAP {
                return None;
            }
        }
    }
    Some(out)
}

fn atom_for_leaf(node: &ConditionNode) -> Atom {
    match node {
        ConditionNode::Eq { left, right } => compare_atom("eq", left, right),
        ConditionNode::Ne { left, right } => compare_atom("ne", left, right),
        ConditionNode::Lt { left, right } => compare_atom("lt", left, right),
        ConditionNode::Lte { left, right } => compare_atom("lte", left, right),
        ConditionNode::Gt { left, right } => compare_atom("gt", left, right),
        ConditionNode::Gte { left, right } => compare_atom("gte", left, right),
        ConditionNode::In { left, values } => match operand_ref(left) {
            OperandRef::Path(path) => Atom::In {
                path,
                values: values.clone(),
            },
            OperandRef::Constant(c) => {
                if values.contains(&c) {
                    Atom::Always
                } else {
                    Atom::False
                }
            }
        },
        ConditionNode::NotIn { left, values } => match operand_ref(left) {
            OperandRef::Path(path) => Atom::NotIn {
                path,
                values: values.clone(),
            },
            OperandRef::Constant(c) => {
                if values.contains(&c) {
                    Atom::False
                } else {
                    Atom::Always
                }
            }
        },
        ConditionNode::Matches { .. }
        | ConditionNode::Exists { .. }
        | ConditionNode::TimeBetween { .. } => Atom::Always,
        ConditionNode::And { .. } | ConditionNode::Or { .. } | ConditionNode::Not { .. } => {
            unreachable!("non-leaf node passed to atom_for_leaf")
        }
    }
}

fn compare_atom(kind: &str, left: &Operand, right: &Operand) -> Atom {
    match (operand_ref(left), operand_ref(right)) {
        (OperandRef::Constant(a), OperandRef::Constant(b)) => fold_compare(kind, &a, &b),
        (OperandRef::Path(_), OperandRef::Path(_)) => Atom::Always,
        (OperandRef::Path(p), OperandRef::Constant(v)) => atom(kind, p, v),
        (OperandRef::Constant(v), OperandRef::Path(p)) => atom(swapped(kind), p, v),
    }
}

/// Evaluate a comparison of two constants: Always (true) or False (dead).
/// Numeric ops accept int/float only — a type mismatch is an EVAL_ERROR at
/// runtime, i.e. the rule never matches → False.
fn fold_compare(kind: &str, a: &JsonValue, b: &JsonValue) -> Atom {
    let r = match kind {
        "eq" => a == b,
        "ne" => a != b,
        _ => match (a.as_f64(), b.as_f64()) {
            (Some(x), Some(y)) => match kind {
                "lt" => x < y,
                "lte" => x <= y,
                "gt" => x > y,
                "gte" => x >= y,
                _ => unreachable!(),
            },
            _ => return Atom::False,
        },
    };
    if r { Atom::Always } else { Atom::False }
}

fn atom(kind: &str, path: String, value: JsonValue) -> Atom {
    match kind {
        "eq" => Atom::Eq { path, value },
        "ne" => Atom::Ne { path, value },
        "lt" => Atom::Lt { path, value },
        "lte" => Atom::Lte { path, value },
        "gt" => Atom::Gt { path, value },
        "gte" => Atom::Gte { path, value },
        _ => unreachable!(),
    }
}

/// Comparison kind with left/right swapped (constant on the left side).
fn swapped(kind: &str) -> &str {
    match kind {
        "lt" => "gt",
        "lte" => "gte",
        "gt" => "lt",
        "gte" => "lte",
        other => other,
    }
}

fn path_of(a: &Atom) -> Option<&str> {
    match a {
        Atom::False | Atom::Always => None,
        Atom::Eq { path, .. }
        | Atom::Ne { path, .. }
        | Atom::Lt { path, .. }
        | Atom::Lte { path, .. }
        | Atom::Gt { path, .. }
        | Atom::Gte { path, .. }
        | Atom::In { path, .. }
        | Atom::NotIn { path, .. } => Some(path),
    }
}

fn num_cmp(x: &JsonValue, y: &JsonValue, f: impl Fn(f64, f64) -> bool) -> bool {
    match (x.as_f64(), y.as_f64()) {
        (Some(a), Some(b)) => f(a, b),
        _ => true, // non-numeric: conservative (assume satisfiable)
    }
}

/// Are two atoms jointly satisfiable? (same-path reasoning; different paths
/// are independent variables and always compatible)
fn atoms_compatible(a: &Atom, b: &Atom) -> bool {
    match (a, b) {
        (Atom::False, _) | (_, Atom::False) => false,
        (Atom::Always, _) | (_, Atom::Always) => true,
        _ => {
            let (pa, pb) = (path_of(a), path_of(b));
            if pa != pb {
                return true;
            }
            let (a, b) = if rank(a) <= rank(b) { (a, b) } else { (b, a) };
            same_path_compatible(a, b)
        }
    }
}

fn rank(a: &Atom) -> u8 {
    match a {
        Atom::False => 0,
        Atom::Always => 1,
        Atom::Eq { .. } => 2,
        Atom::Ne { .. } => 3,
        Atom::Lt { .. } => 4,
        Atom::Lte { .. } => 5,
        Atom::Gt { .. } => 6,
        Atom::Gte { .. } => 7,
        Atom::In { .. } => 8,
        Atom::NotIn { .. } => 9,
    }
}

/// Same-path pair logic. `a` has rank <= `b` (caller guarantees).
fn same_path_compatible(a: &Atom, b: &Atom) -> bool {
    match (a, b) {
        (Atom::Eq { value: va, .. }, Atom::Eq { value: vb, .. }) => va == vb,
        (Atom::Eq { value: va, .. }, Atom::Ne { value: vb, .. }) => va != vb,
        (Atom::Eq { value: v, .. }, Atom::Lt { value: ub, .. }) => num_cmp(v, ub, |x, y| x < y),
        (Atom::Eq { value: v, .. }, Atom::Lte { value: ub, .. }) => num_cmp(v, ub, |x, y| x <= y),
        (Atom::Eq { value: v, .. }, Atom::Gt { value: lb, .. }) => num_cmp(v, lb, |x, y| x > y),
        (Atom::Eq { value: v, .. }, Atom::Gte { value: lb, .. }) => num_cmp(v, lb, |x, y| x >= y),
        (Atom::Eq { value: v, .. }, Atom::In { values, .. }) => values.contains(v),
        (Atom::Eq { value: v, .. }, Atom::NotIn { values, .. }) => !values.contains(v),
        (Atom::Ne { value: v, .. }, Atom::In { values, .. }) => values.iter().any(|e| e != v),
        (Atom::Lt { value: ub, .. }, Atom::Gt { value: lb, .. }) => num_cmp(lb, ub, |x, y| x < y),
        (Atom::Lt { value: ub, .. }, Atom::Gte { value: lb, .. }) => num_cmp(lb, ub, |x, y| x < y),
        (Atom::Lte { value: ub, .. }, Atom::Gt { value: lb, .. }) => num_cmp(lb, ub, |x, y| x < y),
        (Atom::Lte { value: ub, .. }, Atom::Gte { value: lb, .. }) => {
            num_cmp(lb, ub, |x, y| x <= y)
        }
        (Atom::In { values: s1, .. }, Atom::In { values: s2, .. }) => {
            s1.iter().any(|e| s2.contains(e))
        }
        (Atom::In { values: s, .. }, Atom::NotIn { values: t, .. }) => {
            s.iter().any(|e| !t.contains(e))
        }
        _ => true, // remaining pairs: conservative (assume satisfiable)
    }
}

/// A disjunct is live iff it contains no dead atom and is internally consistent.
fn disjunct_valid(d: &[Atom]) -> bool {
    if d.contains(&Atom::False) {
        return false;
    }
    for i in 0..d.len() {
        for j in (i + 1)..d.len() {
            if !atoms_compatible(&d[i], &d[j]) {
                return false;
            }
        }
    }
    true
}

fn disjuncts_compatible(x: &[Atom], y: &[Atom]) -> bool {
    for a in x {
        for b in y {
            if !atoms_compatible(a, b) {
                return false;
            }
        }
    }
    true
}

fn dnf_of(cond: &Option<ConditionNode>) -> Vec<Vec<Atom>> {
    match cond {
        None => vec![vec![]], // no condition = the empty conjunction = true
        Some(node) => to_dnf(node).unwrap_or_else(|| vec![vec![Atom::Always]]),
    }
}

/// Can both conditions be true simultaneously (both rules fire on one call)?
fn conditions_overlap(a: &Option<ConditionNode>, b: &Option<ConditionNode>) -> bool {
    let da = dnf_of(a);
    let db = dnf_of(b);
    if da.is_empty() || db.is_empty() {
        return false;
    }
    for x in &da {
        if !disjunct_valid(x) {
            continue;
        }
        for y in &db {
            if disjunct_valid(y) && disjuncts_compatible(x, y) {
                return true;
            }
        }
    }
    false
}

/// Does condition `a` imply condition `b`? Every disjunct of `a` must be
/// covered by some disjunct of `b` (b's atoms ⊆ a's atoms — b is weaker).
fn condition_implies(a: &Option<ConditionNode>, b: &Option<ConditionNode>) -> bool {
    let da = dnf_of(a);
    let db = dnf_of(b);
    for x in &da {
        if !disjunct_valid(x) {
            continue;
        }
        let covered = db
            .iter()
            .any(|y| disjunct_valid(y) && y.iter().all(|atom| x.contains(atom)));
        if !covered {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ir::Policy;
    use serde_json::{Value, json};

    fn parse(v: Value) -> Policy {
        serde_json::from_value(v).expect("fixture parses")
    }

    fn rule(id: &str, effect: &str, tools: Value, condition: Value) -> Value {
        json!({
            "rule_id": id,
            "description": "d",
            "effect": effect,
            "target": {"tools": tools},
            "condition": condition
        })
    }

    fn policy(id: &str, rules: Vec<Value>) -> Policy {
        parse(json!({
            "ir_version": "1",
            "policy_id": id,
            "version": 1,
            "description": "d",
            "rules": rules
        }))
    }

    #[test]
    fn each_error_code_fires() {
        let pol_dup = policy(
            "pol_dup",
            vec![
                rule("r-same", "allow", json!(["fs.read"]), Value::Null),
                rule("r-same", "allow", json!(["fs.read"]), Value::Null),
            ],
        );
        let pol_empty = policy("pol_empty", vec![]);
        let pol_overlap = policy(
            "pol_overlap",
            vec![
                rule(
                    "r-allow-w",
                    "allow",
                    json!(["fs.write"]),
                    json!({"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}}),
                ),
                rule(
                    "r-esc-w",
                    "escalate",
                    json!(["fs.write"]),
                    json!({"op": "gte", "left": {"param": "amount"}, "right": {"value": 100}}),
                ),
            ],
        );
        let pol_a = policy(
            "pol_a",
            vec![rule(
                "r-allow-a",
                "allow",
                json!(["stripe.refunds.create"]),
                json!({"op": "lte", "left": {"param": "amount"}, "right": {"value": 100}}),
            )],
        );
        let pol_b = policy(
            "pol_b",
            vec![rule(
                "r-block-b",
                "block",
                json!(["stripe.refunds.create"]),
                json!({"op": "gte", "left": {"param": "amount"}, "right": {"value": 50}}),
            )],
        );
        let pol_ur = policy(
            "pol_ur",
            vec![
                rule(
                    "r-block-rm",
                    "block",
                    json!(["shell.exec"]),
                    json!({"op": "matches", "left": {"param": "command"}, "pattern": "^rm .*$"}),
                ),
                rule(
                    "r-allow-rm",
                    "allow",
                    json!(["shell.exec"]),
                    json!({"op": "matches", "left": {"param": "command"}, "pattern": "^rm -rf .*$"}),
                ),
            ],
        );
        let pol_br = policy(
            "pol_br",
            vec![rule(
                "r-all",
                "allow",
                json!(["*.refunds.create"]),
                Value::Null,
            )],
        );

        let policies = vec![
            pol_dup,
            pol_empty,
            pol_overlap,
            pol_a,
            pol_b,
            pol_ur,
            pol_br,
        ];
        let known_tools = vec![
            "stripe.refunds.create".to_string(),
            "fs.read".to_string(),
            "fs.write".to_string(),
            "shell.exec".to_string(),
            "web.fetch".to_string(),
            "email.send".to_string(),
        ];
        let findings = lint(&policies, &known_tools);

        let codes: HashSet<LintCode> = findings.iter().map(|f| f.code).collect();
        for expected in [
            LintCode::DuplicateRuleId,
            LintCode::NoRules,
            LintCode::AllowEscalateOverlap,
            LintCode::CrossPolicyConflict,
            LintCode::UnreachableAllow,
            LintCode::ToolUngoverned,
            LintCode::BroadTarget,
        ] {
            assert!(
                codes.contains(&expected),
                "missing lint code {expected:?}; got {codes:?}"
            );
        }

        assert!(
            findings.iter().any(|f| {
                f.code == LintCode::ToolUngoverned && f.message.contains("email.send")
            })
        );
        assert!(findings.iter().any(|f| {
            f.code == LintCode::DuplicateRuleId && f.rule_id.as_deref() == Some("r-same")
        }));
        assert!(
            findings
                .iter()
                .any(|f| f.code == LintCode::BroadTarget && f.rule_id.as_deref() == Some("r-all"))
        );
        assert!(findings.iter().any(|f| {
            f.code == LintCode::NoRules && f.policy_id.as_deref() == Some("pol_empty")
        }));
        assert!(findings.iter().any(|f| {
            f.code == LintCode::AllowEscalateOverlap
                && f.policy_id.as_deref() == Some("pol_overlap")
        }));
        assert!(findings.iter().any(|f| {
            f.code == LintCode::UnreachableAllow && f.rule_id.as_deref() == Some("r-allow-rm")
        }));
    }

    #[test]
    fn cross_policy_conflict_detected() {
        let pol_a = policy(
            "pol_a",
            vec![rule(
                "r-allow-a",
                "allow",
                json!(["stripe.refunds.create"]),
                json!({"op": "lte", "left": {"param": "amount"}, "right": {"value": 100}}),
            )],
        );
        let pol_b = policy(
            "pol_b",
            vec![rule(
                "r-block-b",
                "block",
                json!(["stripe.refunds.create"]),
                json!({"op": "gte", "left": {"param": "amount"}, "right": {"value": 50}}),
            )],
        );
        let pol_c = policy(
            "pol_c",
            vec![rule(
                "r-allow-c",
                "allow",
                json!(["stripe.payouts.create"]),
                json!({"op": "lte", "left": {"param": "amount"}, "right": {"value": 100}}),
            )],
        );
        let pol_d = policy(
            "pol_d",
            vec![rule(
                "r-block-d",
                "block",
                json!(["stripe.payouts.create"]),
                json!({"op": "gte", "left": {"param": "amount"}, "right": {"value": 200}}),
            )],
        );

        let findings = lint(&[pol_a, pol_b, pol_c, pol_d], &[]);
        let conflicts: Vec<_> = findings
            .iter()
            .filter(|f| f.code == LintCode::CrossPolicyConflict)
            .collect();
        assert_eq!(
            conflicts.len(),
            1,
            "only the jointly-satisfiable pair (a,b) conflicts; got {findings:?}"
        );
        assert_eq!(conflicts[0].policy_id.as_deref(), Some("pol_a"));
        assert_eq!(conflicts[0].rule_id.as_deref(), Some("r-allow-a"));
    }

    #[test]
    fn atoms_eq_neq() {
        assert!(!atoms_compatible(
            &Atom::Eq {
                path: p(),
                value: json!(50)
            },
            &Atom::Ne {
                path: p(),
                value: json!(50)
            }
        ));
        assert!(atoms_compatible(
            &Atom::Eq {
                path: p(),
                value: json!(50)
            },
            &Atom::Ne {
                path: p(),
                value: json!(60)
            }
        ));
    }

    #[test]
    fn atoms_range_bounds() {
        let gte = |v| Atom::Gte {
            path: p(),
            value: json!(v),
        };
        let gt = |v| Atom::Gt {
            path: p(),
            value: json!(v),
        };
        let lte = |v| Atom::Lte {
            path: p(),
            value: json!(v),
        };
        let lt = |v| Atom::Lt {
            path: p(),
            value: json!(v),
        };

        assert!(!atoms_compatible(&gt(200), &lt(100)));
        assert!(atoms_compatible(&gte(100), &lte(100)));
        assert!(!atoms_compatible(&gt(100), &lte(100)));
        assert!(!atoms_compatible(&gte(100), &lt(100)));
        assert!(atoms_compatible(&gt(50), &lt(100)));
        assert!(!atoms_compatible(&gt(100), &lt(100)));
        assert!(atoms_compatible(&gt(100), &lt(101)));
    }

    #[test]
    fn atoms_in_sets() {
        let a = Atom::In {
            path: p(),
            values: vec![json!(1), json!(2)],
        };
        let b = Atom::In {
            path: p(),
            values: vec![json!(3), json!(4)],
        };
        let c = Atom::In {
            path: p(),
            values: vec![json!(2), json!(3)],
        };
        assert!(!atoms_compatible(&a, &b));
        assert!(atoms_compatible(&a, &c));
        assert!(atoms_compatible(
            &Atom::Eq {
                path: p(),
                value: json!(2)
            },
            &a
        ));
        assert!(!atoms_compatible(
            &Atom::Eq {
                path: p(),
                value: json!(5)
            },
            &a
        ));
        assert!(atoms_compatible(
            &Atom::Ne {
                path: p(),
                value: json!(1)
            },
            &a
        ));
        assert!(atoms_compatible(
            &Atom::Ne {
                path: p(),
                value: json!(1)
            },
            &Atom::NotIn {
                path: p(),
                values: vec![json!(1)]
            }
        ));
    }

    #[test]
    fn atoms_different_paths_independent() {
        let a = Atom::Lt {
            path: "param:a".into(),
            value: json!(100),
        };
        let b = Atom::Gt {
            path: "param:b".into(),
            value: json!(5),
        };
        assert!(atoms_compatible(&a, &b));
    }

    fn p() -> String {
        "param:amount".to_string()
    }
}
