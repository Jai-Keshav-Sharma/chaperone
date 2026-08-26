//! Differential testing (build-plan Phase 4): the reference evaluator and the
//! Cedar engine must agree on EVERY generated input. A mismatch is ALWAYS an
//! engine bug — fix the engine, never the test.
#![cfg(test)]

use proptest::prelude::*;
use serde_json::{Value as JsonValue, json};

use crate::engine::cedar_engine::CedarEngine;
use crate::engine::reference::evaluate_ir;
use crate::engine::{EngineOutcome, EvalRequest};
use crate::models::ir::Policy;

/// Compare outcomes semantically: verdict, determining rules, and whether an
/// eval error occurred (the precise error KIND may differ between engines
/// without changing the verdict — both abort to BLOCK(EVAL_ERROR)).
fn semantically_equal(a: &EngineOutcome, b: &EngineOutcome) -> bool {
    a.decision == b.decision
        && a.determining_rule_ids == b.determining_rule_ids
        && a.eval_error.is_some() == b.eval_error.is_some()
}

const TOOLS: &[&str] = &[
    "stripe.refunds.create",
    "stripe.payouts.create",
    "fs.write",
    "shell.exec",
    "payments.*",
    "*",
];
const REQUEST_TIMES: &[&str] = &[
    "2026-08-25T14:00:00Z", // Tue 14:00 UTC
    "2026-08-23T09:30:00Z", // Sun
    "2026-08-24T17:00:00Z", // Mon 17:00
    "2026-08-25T06:00:00Z", // Tue 06:00
    "2026-08-25T23:59:00Z", // Tue 23:59
];

fn arb_tools() -> impl Strategy<Value = Vec<String>> {
    proptest::sample::subsequence(TOOLS, 1..=2)
        .prop_map(|v| v.into_iter().map(String::from).collect::<Vec<_>>())
}

fn arb_amount() -> impl Strategy<Value = JsonValue> {
    prop_oneof![
        any::<i64>().prop_map(|v| json!(v.rem_euclid(1000))),
        proptest::num::f64::ANY
            .prop_filter("bounded decimals", |f| f.is_finite() && f.abs() < 1000.0)
            .prop_map(|f| json!(f)),
    ]
}

/// A condition leaf — every generated node stays inside the supported envelope.
fn arb_condition(depth: usize) -> impl Strategy<Value = JsonValue> {
    let amount_cmp = |op: &'static str| {
        arb_amount().prop_map(
            move |v| json!({"op": op, "left": {"param": "amount"}, "right": {"value": v}}),
        )
    };
    let leaf = prop_oneof![
        amount_cmp("lte"),
        amount_cmp("gte"),
        amount_cmp("gt"),
        Just(json!({"op": "eq", "left": {"param": "status"}, "right": {"value": "open"}})),
        Just(json!({"op": "eq", "left": {"param": "status"}, "right": {"value": "closed"}})),
        Just(json!({"op": "ne", "left": {"param": "status"}, "right": {"value": "open"}})),
        Just(json!({"op": "eq", "left": {"param": "test_mode"}, "right": {"value": true}})),
        Just(
            json!({"op": "eq", "left": {"context": "surface"}, "right": {"value": "claude_code"}})
        ),
        Just(json!({"op": "eq", "left": {"context": "surface"}, "right": {"value": "sdk"}})),
        Just(json!({"op": "lte", "left": {"context": "delegation_depth"}, "right": {"value": 1}})),
        Just(json!({"op": "in", "left": {"param": "currency"}, "values": ["USD", "INR"]})),
        Just(json!({"op": "not_in", "left": {"param": "currency"}, "values": ["USD"]})),
        proptest::sample::select(vec!["^rm *$", "^git push *$", "^ls *$", "^cus_*$"])
            .prop_map(|p| json!({"op": "matches", "left": {"param": "command"}, "pattern": p})),
        Just(json!({"op": "matches", "left": {"param": "amount"}, "pattern": "^1*$"})),
        Just(json!({"op": "exists", "param": "customer_id"})),
        Just(json!({"op": "exists", "param": "customer.id"})),
        Just(json!({"op": "eq", "left": {"param": "amount"}, "right": {"value": "abc"}})),
        Just(json!({"op": "lte", "left": {"param": "status"}, "right": {"value": 50}})),
        Just(
            json!({"op": "time_between", "start": "09:00", "end": "17:00", "tz": "UTC", "days": ["mon", "tue", "wed", "thu", "fri"]})
        ),
        Just(
            json!({"op": "time_between", "start": "09:00", "end": "17:00", "tz": "Asia/Kolkata", "days": ["sat", "sun"]})
        ),
        Just(json!({"op": "eq", "left": {"param": "amount"}, "right": {"value": 50.0}})),
        Just(json!({"op": "ne", "left": {"param": "amount"}, "right": {"value": "50.0"}})),
        Just(json!({"op": "eq", "left": {"param": "amount"}, "right": {"value": 200}})),
        Just(
            json!({"op": "eq", "left": {"context": "request_time"}, "right": {"value": "2026-08-24T14:00:00Z"}})
        ),
    ];
    if depth >= 2 {
        leaf.boxed()
    } else {
        prop_oneof![
            leaf,
            (arb_condition(depth + 1), arb_condition(depth + 1))
                .prop_map(|(a, b)| json!({"op": "and", "args": [a, b]})),
            (arb_condition(depth + 1), arb_condition(depth + 1))
                .prop_map(|(a, b)| json!({"op": "or", "args": [a, b]})),
            arb_condition(depth + 1).prop_map(|a| json!({"op": "not", "args": [a]})),
        ]
        .boxed()
    }
}

fn arb_rule(case: u64, policy_n: u64, rule_n: u64) -> impl Strategy<Value = JsonValue> {
    (
        prop_oneof![Just("allow"), Just("block"), Just("escalate")],
        arb_tools(),
        prop_oneof![
            Just(vec![]),
            Just(vec!["support".to_string()]),
            Just(vec!["support".to_string(), "admin".to_string()]),
        ],
        prop_oneof![
            Just(vec![]),
            Just(vec!["agent_a".to_string()]),
            Just(vec!["agent_a".to_string(), "agent_b".to_string()]),
        ],
        prop_oneof![Just(JsonValue::Null), arb_condition(0),],
    )
        .prop_map(move |(effect, tools, roles, ids, cond)| {
            json!({
                "rule_id": format!("r-{case}-{policy_n}-{rule_n}"),
                "description": "generated",
                "effect": effect,
                "target": {"tools": tools, "agent_roles": roles, "agent_ids": ids},
                "condition": cond,
            })
        })
}

/// n rules with unique ids.
fn arb_rule_vec(case: u64, policy_n: u64, n: u64) -> impl Strategy<Value = Vec<JsonValue>> {
    if n == 0 {
        Just(vec![]).boxed()
    } else {
        (
            arb_rule(case, policy_n, n - 1),
            arb_rule_vec(case, policy_n, n - 1),
        )
            .prop_map(|(rule, mut rest)| {
                rest.push(rule);
                rest
            })
            .boxed()
    }
}

fn arb_policy(case: u64, i: u64) -> impl Strategy<Value = Policy> {
    (1..=3u64)
        .prop_flat_map(move |n_rules| arb_rule_vec(case, i, n_rules))
        .prop_map(move |rules| {
            serde_json::from_value(json!({
                "ir_version": "1",
                "policy_id": format!("pol_{case}_{i}"),
                "version": 1,
                "description": "generated",
                "rules": rules,
            }))
            .expect("generated policy parses")
        })
}

/// n policies with unique ids.
fn arb_policy_vec(case: u64, n: u64) -> impl Strategy<Value = Vec<Policy>> {
    if n == 0 {
        Just(vec![]).boxed()
    } else {
        (arb_policy(case, n - 1), arb_policy_vec(case, n - 1))
            .prop_map(|(policy, mut rest)| {
                rest.push(policy);
                rest
            })
            .boxed()
    }
}

fn arb_policies() -> impl Strategy<Value = Vec<Policy>> {
    any::<u64>().prop_flat_map(|case| (1..=2u64).prop_flat_map(move |n| arb_policy_vec(case, n)))
}

fn arb_params() -> impl Strategy<Value = JsonValue> {
    (
        proptest::option::of(arb_amount()),
        proptest::option::of(prop_oneof![Just(json!("open")), Just(json!("closed"))]),
        proptest::option::of(prop_oneof![
            Just(json!("USD")),
            Just(json!("INR")),
            Just(json!("EUR"))
        ]),
        proptest::option::of(prop_oneof![
            Just(json!("rm -rf /")),
            Just(json!("git push origin main")),
            Just(json!("ls -la")),
        ]),
        proptest::option::of(prop_oneof![Just(json!("cus_123")), Just(json!(42))]),
        proptest::option::of(Just(json!(true))),
        proptest::option::of(Just(json!({"id": "cus_9"}))),
        proptest::option::of(Just(json!({"name": "x"}))),
        proptest::option::of(Just(json!(5))), // customer as a NUMBER
        proptest::option::of(Just(json!("abc"))),
    )
        .prop_map(
            |(
                amount,
                status,
                currency,
                command,
                customer_id,
                tm,
                customer,
                customer2,
                customer3,
                amount_str,
            )| {
                let mut params = serde_json::Map::new();
                if let Some(v) = amount {
                    params.insert("amount".into(), v);
                }
                if let Some(v) = status {
                    params.insert("status".into(), v);
                }
                if let Some(v) = currency {
                    params.insert("currency".into(), v);
                }
                if let Some(v) = command {
                    params.insert("command".into(), v);
                }
                if let Some(v) = customer_id {
                    params.insert("customer_id".into(), v);
                }
                if let Some(v) = tm {
                    params.insert("test_mode".into(), v);
                }
                if let Some(v) = customer {
                    params.insert("customer".into(), v);
                }
                if let Some(v) = customer2 {
                    params.insert("customer".into(), v);
                }
                if let Some(v) = customer3 {
                    params.insert("customer".into(), v);
                }
                if let Some(v) = amount_str {
                    params.insert("amount".into(), v);
                }
                JsonValue::Object(params)
            },
        )
}

fn arb_case() -> impl Strategy<Value = (Vec<Policy>, EvalRequest<'static>)> {
    arb_policies().prop_flat_map(|policies| {
        (
            Just(policies.clone()),
            prop_oneof![
                Just("agent_a".to_string()),
                Just("agent_b".to_string()),
                Just("agent_c".to_string()),
            ],
            prop_oneof![
                Just("support".to_string()),
                Just("admin".to_string()),
                Just("auditor".to_string()),
            ],
            prop_oneof![
                Just("claude_code".to_string()),
                Just("cursor".to_string()),
                Just("sdk".to_string()),
            ],
            proptest::sample::select(REQUEST_TIMES.to_vec()).prop_map(String::from),
            0..3u32,
            prop_oneof![
                Just(json!({})),
                Just(json!({"agent_daily_total_amount": 350.0})),
                Just(json!({"agent_daily_total_amount": 0.0})),
            ],
            arb_params(),
        )
            .prop_map(
                move |(policies, agent, role, surface, rt, depth, derived, params)| {
                    let agent = Box::leak(agent.into_boxed_str());
                    let role = Box::leak(role.into_boxed_str());
                    let surface = Box::leak(surface.into_boxed_str());
                    let rt = Box::leak(rt.into_boxed_str());
                    let params = Box::leak(Box::new(params));
                    let derived = Box::leak(Box::new(derived));
                    let tool = Box::leak(Box::new("stripe.refunds.create".to_string()));
                    let req = EvalRequest {
                        agent_id: agent,
                        role,
                        tool,
                        params,
                        surface,
                        delegation_depth: depth,
                        request_time: rt,
                        derived,
                    };
                    (policies.clone(), req)
                },
            )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn cedar_matches_reference_1000((policies, req) in arb_case()) {
        let reference = evaluate_ir(&policies, &req);
        let cedar = match CedarEngine::compile(&policies) {
            Ok(e) => e,
            Err(e) => panic!("transpile failed on generated policy: {e}"),
        };
        let cedar_outcome = cedar.evaluate(&req);
        assert!(
            semantically_equal(&reference, &cedar_outcome),
            "differential mismatch!\nreference: {reference:?}\ncedar:     {cedar_outcome:?}\npolicies:  {policies:#?}\nparams:    {:#?}",
            req.params
        );
    }
}

pub(crate) mod determinism {
    #[cfg(test)]
    mod tests {
        use crate::engine::cedar_engine::CedarEngine;
        use crate::engine::reference::evaluate_ir;
        use crate::engine::{EngineOutcome, EvalRequest};
        use crate::models::ir::Policy;
        use serde_json::json;

        fn policies() -> Vec<Policy> {
            serde_json::from_value(json!([{
                "ir_version": "1",
                "policy_id": "pol_refunds",
                "version": 1,
                "description": "d",
                "rules": [
                    {
                        "rule_id": "r-allow-small",
                        "description": "d",
                        "effect": "allow",
                        "target": {"tools": ["stripe.refunds.create"], "agent_roles": ["support"]},
                        "condition": {
                            "op": "and",
                            "args": [
                                {"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}},
                                {"op": "time_between", "start": "09:00", "end": "17:00", "tz": "UTC", "days": ["mon"]},
                                {"op": "matches", "left": {"param": "customer_id"}, "pattern": "^cus_*$"}
                            ]
                        }
                    },
                    {
                        "rule_id": "r-block-flagged",
                        "description": "d",
                        "effect": "block",
                        "target": {"tools": ["stripe.refunds.create"]},
                        "condition": {"op": "exists", "param": "flag"}
                    }
                ]
            }]))
            .expect("fixture")
        }

        fn req() -> EvalRequest<'static> {
            EvalRequest {
                agent_id: "agent_support_09",
                role: "support",
                tool: "stripe.refunds.create",
                params: Box::leak(Box::new(json!({"amount": 150, "customer_id": "cus_123"}))),
                surface: "claude_code",
                delegation_depth: 0,
                request_time: "2026-08-24T14:00:00Z",
                derived: Box::leak(Box::new(json!({"agent_daily_total_amount": 350.0}))),
            }
        }

        #[test]
        fn same_input_same_output_1000x() {
            let req = req();
            let policies = policies();
            let cedar = CedarEngine::compile(&policies).expect("compile");

            let mut ref_first: Option<EngineOutcome> = None;
            let mut cedar_first: Option<EngineOutcome> = None;
            for _ in 0..1000 {
                let r = evaluate_ir(&policies, &req);
                let c = cedar.evaluate(&req);
                match &ref_first {
                    None => ref_first = Some(r.clone()),
                    Some(f) => assert_eq!(f, &r, "reference outcome drifted"),
                }
                match &cedar_first {
                    None => cedar_first = Some(c.clone()),
                    Some(f) => assert_eq!(f, &c, "cedar outcome drifted"),
                }
                assert_eq!(r, c, "engines disagree on the fixed case");
            }
        }
    }
}
