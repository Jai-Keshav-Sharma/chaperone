use chrono::{DateTime, Datelike, NaiveTime, Utc};
use chrono_tz::Tz;
use serde_json::Value as JsonValue;

use crate::engine::{
    EngineDecision, EngineOutcome, EvalError, EvalRequest, NormalizedRequest,
    collect_operand_paths, normalize_for_cedar, normalize_request, resolve_path, targets_match,
};
use crate::models::decision::TraceEntry;
use crate::models::ir::{ConditionNode, Effect, Operand, Policy, Weekday};

/// The pure-Rust reference evaluator: the differential-test oracle for the
/// Cedar engine AND the configured `engine: reference` fallback (docs/tech-stack).
/// Evaluates IR directly — no transpilation. Semantics MUST match the Cedar
/// path exactly; any divergence is an engine bug (build-plan guardrail).
pub fn evaluate_ir(policies: &[Policy], req: &EvalRequest) -> EngineOutcome {
    let n = normalize_request(req);
    let mut trace: Vec<TraceEntry> = Vec::new();
    let mut matched_block: Vec<String> = Vec::new();
    let mut matched_escalate: Vec<String> = Vec::new();
    let mut matched_allow: Vec<String> = Vec::new();
    let mut decision: Option<EngineDecision> = None;
    let mut eval_error: Option<EvalError> = None;
    let mut governed = false;

    for policy in policies {
        for rule in &policy.rules {
            let tool_targeted = rule
                .target
                .tools
                .iter()
                .any(|t| crate::ir::lint::tool_patterns_overlap(t, &n.tool));
            if tool_targeted {
                governed = true;
            }
            if !targets_match(rule, &n) {
                trace.push(TraceEntry {
                    rule_id: rule.rule_id.clone(),
                    matched: false,
                    operands: None,
                    error: None,
                });
                continue;
            }
            let mut entry = TraceEntry {
                rule_id: rule.rule_id.clone(),
                matched: false,
                operands: None,
                error: None,
            };
            if let Some(cond) = &rule.condition {
                entry.operands = Some(collect_operand_paths(cond));
                match eval_condition(cond, &n) {
                    Ok(true) => entry.matched = true,
                    Ok(false) => {}
                    Err(e) => {
                        entry.error = Some(e.code().to_string());
                        if eval_error.is_none() {
                            eval_error = Some(e);
                        }
                    }
                }
            } else {
                entry.matched = true;
            }
            if entry.matched {
                // block > escalate > allow (docs/policy-ir.md decision semantics)
                match rule.effect {
                    Effect::Block => {
                        matched_block.push(rule.rule_id.clone());
                        decision = Some(EngineDecision::Block);
                    }
                    Effect::Escalate => {
                        matched_escalate.push(rule.rule_id.clone());
                        if decision != Some(EngineDecision::Block) {
                            decision = Some(EngineDecision::Escalate);
                        }
                    }
                    Effect::Allow => {
                        matched_allow.push(rule.rule_id.clone());
                        if decision.is_none() {
                            decision = Some(EngineDecision::Allow);
                        }
                    }
                }
            }
            trace.push(entry);
        }
    }

    if let Some(e) = eval_error {
        return EngineOutcome {
            decision: EngineDecision::Block,
            determining_rule_ids: Vec::new(),
            trace,
            eval_error: Some(e),
        };
    }
    if !governed {
        return EngineOutcome {
            decision: EngineDecision::NoPolicy,
            determining_rule_ids: Vec::new(),
            trace,
            eval_error: None,
        };
    }
    // determining_rule_ids = the rules that DETERMINED the verdict, sorted.
    // Matched-but-losing rules (e.g. an allow shadowed by an escalate forbid)
    // stay visible in the trace but are not determining — this matches Cedar's
    // reason set exactly (forbids for Deny, permits for Allow).
    let mut determining: Vec<String> = match decision {
        Some(EngineDecision::Block) => {
            matched_block.extend(matched_escalate);
            matched_block
        }
        Some(EngineDecision::Escalate) => matched_escalate,
        Some(EngineDecision::Allow) => matched_allow,
        _ => Vec::new(), // DEFAULT_DENY
    };
    determining.sort();
    EngineOutcome {
        decision: decision.unwrap_or(EngineDecision::Block), // DEFAULT_DENY
        determining_rule_ids: determining,
        trace,
        eval_error: None,
    }
}

/// Evaluate a condition against the normalized request.
fn eval_condition(node: &ConditionNode, n: &NormalizedRequest) -> Result<bool, EvalError> {
    match node {
        ConditionNode::And { args } => {
            for a in args {
                if !eval_condition(a, n)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        ConditionNode::Or { args } => {
            for a in args {
                if eval_condition(a, n)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        ConditionNode::Not { args } => Ok(!eval_condition(&args[0], n)?),
        ConditionNode::Eq { left, right } => {
            Ok(resolve_operand(left, n)? == resolve_operand(right, n)?)
        }
        ConditionNode::Ne { left, right } => {
            Ok(resolve_operand(left, n)? != resolve_operand(right, n)?)
        }
        ConditionNode::Lt { left, right }
        | ConditionNode::Lte { left, right }
        | ConditionNode::Gt { left, right }
        | ConditionNode::Gte { left, right } => {
            let (a, b) = (resolve_operand(left, n)?, resolve_operand(right, n)?);
            numeric_compare(node, &a, &b)
        }
        ConditionNode::In { left, values } => {
            let v = resolve_operand(left, n)?;
            let norm_values: Vec<JsonValue> = values.iter().map(normalize_for_cedar).collect();
            Ok(norm_values.contains(&v))
        }
        ConditionNode::NotIn { left, values } => {
            let v = resolve_operand(left, n)?;
            let norm_values: Vec<JsonValue> = values.iter().map(normalize_for_cedar).collect();
            Ok(!norm_values.contains(&v))
        }
        ConditionNode::Matches { left, pattern } => {
            let v = resolve_operand(left, n)?;
            match v {
                JsonValue::String(s) => Ok(like_match(
                    &pattern[1..pattern.len().saturating_sub(1)],
                    s.as_str(),
                )),
                _ => Err(EvalError::TypeMismatch(format!(
                    "matches requires a string operand, got {:?}",
                    kind_of(&v)
                ))),
            }
        }
        ConditionNode::Exists { param } => Ok(exists_path(&n.params, param)?),
        ConditionNode::TimeBetween {
            start,
            end,
            tz,
            days,
        } => evaluate_time_between(start, end, tz, days, &n.request_time),
    }
}

/// Evaluate the weekday+clock-window check for time_between. Shared with the
/// Cedar engine (which precomputes per-policy slots) so both paths compute the
/// SAME value from the SAME request_time (Law 6 determinism).
/// Malformed inputs (bad request_time/tz) are ERRORS; outside the window is a
/// plain false (the condition simply does not match).
pub(crate) fn evaluate_time_between(
    start: &str,
    end: &str,
    tz: &str,
    days: &[Weekday],
    request_time: &str,
) -> Result<bool, EvalError> {
    let dt: DateTime<Utc> = DateTime::parse_from_rfc3339(request_time)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| EvalError::TypeMismatch(format!("request_time not RFC3339: {e}")))?;
    let zone: Tz = tz
        .parse()
        .map_err(|e| EvalError::TypeMismatch(format!("unknown tz {tz:?}: {e}")))?;
    let local = dt.with_timezone(&zone);
    let wd = match local.weekday() {
        chrono::Weekday::Mon => Weekday::Mon,
        chrono::Weekday::Tue => Weekday::Tue,
        chrono::Weekday::Wed => Weekday::Wed,
        chrono::Weekday::Thu => Weekday::Thu,
        chrono::Weekday::Fri => Weekday::Fri,
        chrono::Weekday::Sat => Weekday::Sat,
        chrono::Weekday::Sun => Weekday::Sun,
    };
    if !days.contains(&wd) {
        return Ok(false);
    }
    let t = local.time();
    let (h, m) = parse_hhmm(start);
    let (eh, em) = parse_hhmm(end);
    let lo = NaiveTime::from_hms_opt(h, m, 0).expect("validated HH:MM");
    let hi = NaiveTime::from_hms_opt(eh, em, 0).expect("validated HH:MM");
    Ok(t >= lo && t <= hi)
}

fn parse_hhmm(s: &str) -> (u32, u32) {
    let b = s.as_bytes();
    let h = (b[0] - b'0') as u32 * 10 + (b[1] - b'0') as u32;
    let m = (b[3] - b'0') as u32 * 10 + (b[4] - b'0') as u32;
    (h, m)
}

fn kind_of(v: &JsonValue) -> &'static str {
    match v {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "bool",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

/// Numeric comparisons operate on the normalized fixed-point Longs (×10000).
/// Both sides must be numbers — anything else (strings, bools, unrepresentable
/// values that stayed strings) is a type mismatch: loud, never silent
/// (matches Cedar: comparison supports only Long/datetime/duration).
fn numeric_compare(node: &ConditionNode, a: &JsonValue, b: &JsonValue) -> Result<bool, EvalError> {
    let (x, y) = match (a, b) {
        (JsonValue::Number(x), JsonValue::Number(y)) => {
            let x = x.as_i64().ok_or_else(|| {
                EvalError::TypeMismatch(format!("non-integer number {x:?} in comparison"))
            })?;
            let y = y.as_i64().ok_or_else(|| {
                EvalError::TypeMismatch(format!("non-integer number {y:?} in comparison"))
            })?;
            (x, y)
        }
        _ => {
            return Err(EvalError::TypeMismatch(format!(
                "numeric comparison requires numeric operands, got {} vs {}",
                kind_of(a),
                kind_of(b)
            )));
        }
    };
    Ok(match node {
        ConditionNode::Lt { .. } => x < y,
        ConditionNode::Lte { .. } => x <= y,
        ConditionNode::Gt { .. } => x > y,
        ConditionNode::Gte { .. } => x >= y,
        _ => unreachable!("non-numeric node in numeric_compare"),
    })
}

/// Cedar-like pattern matcher (the IR `matches` language, docs/policy-ir.md):
/// `*` matches any sequence (incl. empty); `\x` escapes the next char
/// literally; everything else matches literally. Full-string match.
/// Probe-verified: Cedar 4.12 `like` supports exactly this subset (no `?`, no
/// character classes), so reference and Cedar agree by construction.
pub(crate) fn like_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    fn m(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        match p[0] {
            '*' => (0..=t.len()).any(|skip| m(&p[1..], &t[skip..])),
            '\\' if p.len() >= 2 => !t.is_empty() && t[0] == p[1] && m(&p[2..], &t[1..]),
            c => !t.is_empty() && t[0] == c && m(&p[1..], &t[1..]),
        }
    }
    m(&p, &t)
}

/// exists semantics: ANY missing segment → false (like Cedar's short-circuiting
/// `has` chain); walking into a non-record → error (Cedar's `has` on a
/// non-record is a TypeError). Final presence implies non-null (normalization
/// drops nulls), so this is exactly "present and non-null".
fn exists_path(root: &JsonValue, path: &str) -> Result<bool, EvalError> {
    let mut current = root;
    for seg in path.split('.') {
        match current {
            JsonValue::Object(map) => match map.get(seg) {
                Some(next) => current = next,
                None => return Ok(false),
            },
            _ => {
                return Err(EvalError::TypeMismatch(format!(
                    "exists walked into a non-record at {seg:?}"
                )));
            }
        }
    }
    Ok(true)
}

/// Resolve an operand against the normalized request.
fn resolve_operand(op: &Operand, n: &NormalizedRequest) -> Result<JsonValue, EvalError> {
    match op {
        Operand::Param { param } => resolve_path(&n.params, param)?
            .cloned()
            .ok_or_else(|| EvalError::MissingParam(format!("params.{param}"))),
        Operand::Context { context } => {
            if let Some(attr) = context.strip_prefix("derived.") {
                resolve_path(&n.derived, attr)?
                    .cloned()
                    .ok_or_else(|| EvalError::MissingParam(format!("derived.{attr}")))
            } else {
                match context.as_str() {
                    "request_time" => Ok(JsonValue::String(n.request_time.clone())),
                    "surface" => Ok(JsonValue::String(n.surface.clone())),
                    "delegation_depth" => Ok(n.delegation_depth.clone()),
                    _ => Err(EvalError::TypeMismatch(format!(
                        "unknown context operand {context:?}"
                    ))),
                }
            }
        }
        Operand::Value { value } => Ok(normalize_for_cedar(value)),
    }
}
