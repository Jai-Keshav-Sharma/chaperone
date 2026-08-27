use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityUid, Policy as CedarPolicyAst, PolicyId,
    PolicySet, Request, RestrictedExpression,
};
use serde_json::{Value as JsonValue, json};

use crate::engine::cedar_compile::{RuleRef, TranspileError, tb_key, to_cedar};
use crate::engine::reference::{evaluate_ir, evaluate_time_between};
use crate::engine::{EngineDecision, EngineOutcome, EvalError, EvalRequest, normalize_request};
use crate::models::ir::{ConditionNode, Effect, Policy, Weekday};

/// The Cedar-backed engine (default `engine: cedar`, docs/tech-stack):
/// transpiled policies evaluated by cedar-policy — the formally verified
/// authorizer. The redacted trace and the governed/eval-error detection come
/// from the reference pass (Cedar's diagnostics only expose determining
/// policies, not per-rule results); the VERDICT always comes from Cedar.
/// Differential tests enforce the two paths agree on every input.
#[derive(Debug)]
pub struct CedarEngine {
    policies: Vec<Policy>,
    policy_set: PolicySet,
    rule_map: HashMap<String, RuleRef>,
    /// distinct time_between slots in first-seen order: (key, start, end, tz, days)
    tb_slots: Vec<(String, String, String, String, Vec<Weekday>)>,
}

impl CedarEngine {
    /// Recursively collect distinct time_between nodes (they can be nested
    /// inside and/or/not) in first-seen order — the transpiler emits
    /// `context.derived.<key> == true` for the same keys.
    fn collect_tb_slots(
        node: &ConditionNode,
        slots: &mut Vec<(String, String, String, String, Vec<Weekday>)>,
        seen: &mut HashSet<String>,
    ) {
        match node {
            ConditionNode::And { args }
            | ConditionNode::Or { args }
            | ConditionNode::Not { args } => {
                for arg in args {
                    Self::collect_tb_slots(arg, slots, seen);
                }
            }
            ConditionNode::TimeBetween {
                start,
                end,
                tz,
                days,
            } => {
                let key = tb_key(start, end, tz, days);
                if seen.insert(key.clone()) {
                    slots.push((key, start.clone(), end.clone(), tz.clone(), days.clone()));
                }
            }
            _ => {}
        }
    }
    /// Transpile + parse the whole active policy set. Fails loudly on any
    /// transpile error (a policy that cannot be compiled must not be activatable).
    pub fn compile(policies: &[Policy]) -> Result<CedarEngine, TranspileError> {
        let mut policy_set = PolicySet::new();
        let mut rule_map = HashMap::new();
        let mut tb_slots: Vec<(String, String, String, String, Vec<Weekday>)> = Vec::new();
        let mut tb_seen: HashSet<String> = HashSet::new();

        for policy in policies {
            for rule in &policy.rules {
                if let Some(cond) = &rule.condition {
                    Self::collect_tb_slots(cond, &mut tb_slots, &mut tb_seen);
                }
            }
            for cedar in to_cedar(policy)? {
                let ast = CedarPolicyAst::parse(
                    Some(PolicyId::from_str(&cedar.id).map_err(|e| TranspileError {
                        rule_id: Some(cedar.rule.rule_id.clone()),
                        message: format!("invalid policy id {:?}: {e}", cedar.id),
                    })?),
                    &cedar.text,
                )
                .map_err(|e| TranspileError {
                    rule_id: Some(cedar.rule.rule_id.clone()),
                    message: format!("transpiled policy does not parse: {e}\n---\n{}", cedar.text),
                })?;
                policy_set.add(ast).map_err(|e| TranspileError {
                    rule_id: Some(cedar.rule.rule_id.clone()),
                    message: format!("policy set add failed: {e}"),
                })?;
                rule_map.insert(cedar.id, cedar.rule);
            }
        }

        Ok(CedarEngine {
            policies: policies.to_vec(),
            policy_set,
            rule_map,
            tb_slots,
        })
    }

    pub fn evaluate(&self, req: &EvalRequest) -> EngineOutcome {
        let n = normalize_request(req);
        let reference_outcome = evaluate_ir(&self.policies, req);

        // Tool governed by no active policy → the service applies
        // ungoverned_default (NO_POLICY / UNGOVERNED_ALLOW); nothing to ask Cedar.
        if reference_outcome.decision == EngineDecision::NoPolicy {
            return reference_outcome;
        }

        // Precompute time_between slots: one boolean per distinct node, from
        // the SAME inputs as the reference engine (Law 6 determinism).
        let mut derived_with_slots = match n.derived.clone() {
            JsonValue::Object(map) => map,
            _ => serde_json::Map::new(),
        };
        for (key, start, end, tz, days) in &self.tb_slots {
            match evaluate_time_between(start, end, tz, days, &n.request_time) {
                Ok(v) => {
                    derived_with_slots.insert(key.clone(), json!(v));
                }
                Err(e) => {
                    // reference would error identically → EVAL_ERROR block
                    return EngineOutcome {
                        decision: EngineDecision::Block,
                        determining_rule_ids: Vec::new(),
                        trace: reference_outcome.trace,
                        eval_error: Some(e),
                    };
                }
            }
        }

        let context_json = json!({
            "params": n.params,
            "request_time": n.request_time,
            "surface": n.surface,
            "delegation_depth": n.delegation_depth,
            "derived": derived_with_slots,
        });
        let context = match Context::from_json_value(context_json, None) {
            Ok(c) => c,
            Err(e) => {
                return EngineOutcome {
                    decision: EngineDecision::Block,
                    determining_rule_ids: Vec::new(),
                    trace: reference_outcome.trace,
                    eval_error: Some(EvalError::TypeMismatch(format!(
                        "context build failed: {e}"
                    ))),
                };
            }
        };

        let principal_uid = entity_uid("Chaperone::Agent", &n.agent_id);
        let action_uid = entity_uid("Chaperone::Action", "call");
        let resource_uid = entity_uid("Chaperone::Tool", &n.tool);

        let agent_entity = match Entity::new(
            principal_uid.clone(),
            HashMap::from([(
                "role".to_string(),
                RestrictedExpression::from_str(&format!("\"{}\"", escape(&n.role)))
                    .expect("static"),
            )]),
            HashSet::new(),
        ) {
            Ok(e) => e,
            Err(e) => {
                return EngineOutcome {
                    decision: EngineDecision::Block,
                    determining_rule_ids: Vec::new(),
                    trace: reference_outcome.trace,
                    eval_error: Some(EvalError::TypeMismatch(format!("entity build failed: {e}"))),
                };
            }
        };
        let tool_entity = match Entity::new(
            resource_uid.clone(),
            HashMap::from([(
                "name".to_string(),
                RestrictedExpression::from_str(&format!("\"{}\"", escape(&n.tool)))
                    .expect("static"),
            )]),
            HashSet::new(),
        ) {
            Ok(e) => e,
            Err(e) => {
                return EngineOutcome {
                    decision: EngineDecision::Block,
                    determining_rule_ids: Vec::new(),
                    trace: reference_outcome.trace,
                    eval_error: Some(EvalError::TypeMismatch(format!("entity build failed: {e}"))),
                };
            }
        };
        let entities = match Entities::from_entities([agent_entity, tool_entity], None) {
            Ok(e) => e,
            Err(e) => {
                return EngineOutcome {
                    decision: EngineDecision::Block,
                    determining_rule_ids: Vec::new(),
                    trace: reference_outcome.trace,
                    eval_error: Some(EvalError::TypeMismatch(format!("entities failed: {e}"))),
                };
            }
        };

        let request = match Request::new(principal_uid, action_uid, resource_uid, context, None) {
            Ok(r) => r,
            Err(e) => {
                return EngineOutcome {
                    decision: EngineDecision::Block,
                    determining_rule_ids: Vec::new(),
                    trace: reference_outcome.trace,
                    eval_error: Some(EvalError::TypeMismatch(format!(
                        "request build failed: {e}"
                    ))),
                };
            }
        };

        let response = Authorizer::new().is_authorized(&request, &self.policy_set, &entities);

        // EVAL_ERROR doctrine: any evaluation error aborts to BLOCK. Cedar's
        // diagnostics catch what the reference might miss (and vice versa —
        // the differential suite keeps the two aligned).
        let mut cedar_error: Option<EvalError> = None;
        let mut reason_rules: Vec<&RuleRef> = Vec::new();
        for pid in response.diagnostics().reason() {
            let pid_str: &str = pid.as_ref();
            if let Some(r) = self.rule_map.get(pid_str) {
                reason_rules.push(r);
            }
        }
        let cedar_diagnostics_failed = response.diagnostics().errors().next().is_some();
        if cedar_diagnostics_failed {
            cedar_error = Some(EvalError::TypeMismatch(
                "Cedar reported evaluation errors".to_string(),
            ));
        }

        let eval_error = reference_outcome.eval_error.or(cedar_error);
        if let Some(e) = &eval_error {
            return EngineOutcome {
                decision: EngineDecision::Block,
                determining_rule_ids: Vec::new(),
                trace: reference_outcome.trace,
                eval_error: Some(e.clone()),
            };
        }

        match response.decision() {
            cedar_policy::Decision::Allow => {
                let mut ids: Vec<String> = reason_rules
                    .iter()
                    .map(|r| r.rule_id.clone())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                ids.sort();
                EngineOutcome {
                    decision: EngineDecision::Allow,
                    determining_rule_ids: ids,
                    trace: reference_outcome.trace,
                    eval_error: None,
                }
            }
            cedar_policy::Decision::Deny => {
                if reason_rules.is_empty() {
                    return EngineOutcome {
                        decision: EngineDecision::Block, // DEFAULT_DENY
                        determining_rule_ids: Vec::new(),
                        trace: reference_outcome.trace,
                        eval_error: None,
                    };
                }
                // block > escalate among determining forbids (IR semantics)
                let any_block = reason_rules.iter().any(|r| r.effect == Effect::Block);
                let mut ids: Vec<String> = reason_rules
                    .iter()
                    .map(|r| r.rule_id.clone())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                ids.sort();
                EngineOutcome {
                    decision: if any_block {
                        EngineDecision::Block
                    } else {
                        EngineDecision::Escalate
                    },
                    determining_rule_ids: ids,
                    trace: reference_outcome.trace,
                    eval_error: None,
                }
            }
        }
    }
}

fn entity_uid(entity_type: &str, id: &str) -> EntityUid {
    EntityUid::from_str(&format!(r#"{entity_type}::"{id}""#)).expect("static entity uid")
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
