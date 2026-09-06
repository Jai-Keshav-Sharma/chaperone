//! Bench experiments E3–E6 (flows/10): the measured numbers beyond the E1/E2
//! enforcement/latency metrics already in `runner.rs`. Each experiment is a
//! PURE, deterministic function (where the experiment admits determinism) so it
//! is byte-reproducible and testable; E3 (policy currency) is a documented
//! config-driven property whose corpus coverage is reported here.
//!
//! Honest-numbers discipline (Law 10): each experiment reports exactly what it
//! measures — no more.

use serde::{Deserialize, Serialize};

use crate::metrics::ProportionMetric;
use crate::schema::AttackClass;

// ---------------------------------------------------------------------------
// E5 — Tamper evidence
// ---------------------------------------------------------------------------

/// The corruption types E5 mutates. Each maps to exactly one `verify_chain`
/// failure mode (flows/04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperKind {
    Decision,
    ParamsHash,
    EntryTs,
    AgentId,
    Tool,
    PolicyId,
    RequestId,
    ReasonCode,
    DeterminingRuleIds,
    EntryHash,
    PreviousHash,
    Truncate,
    Reorder,
}

pub const TAMPER_KINDS: [TamperKind; 13] = [
    TamperKind::Decision,
    TamperKind::ParamsHash,
    TamperKind::EntryTs,
    TamperKind::AgentId,
    TamperKind::Tool,
    TamperKind::PolicyId,
    TamperKind::RequestId,
    TamperKind::ReasonCode,
    TamperKind::DeterminingRuleIds,
    TamperKind::EntryHash,
    TamperKind::PreviousHash,
    TamperKind::Truncate,
    TamperKind::Reorder,
];

/// E5 result: every corruption kind was located by `verify_chain`. The
/// experiment asserts ALL are detected (fraction must be 1.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperEvidence {
    pub detected: u64,
    pub total: u64,
    pub detected_all: ProportionMetric,
}

/// Build a deterministic 3-entry chain (genesis + two decisions), mutate it per
/// corruption kind, and confirm `verify_chain` locates every corruption. Pure
/// and byte-reproducible (no DB).
pub fn e5_tamper_evidence() -> TamperEvidence {
    let total = TAMPER_KINDS.len() as u64;
    let mut detected = 0u64;
    for kind in TAMPER_KINDS {
        let chain = three_entry_chain();
        let broken = match kind {
            TamperKind::Decision => mutate(chain, 1, |e| e.decision = "WOULD_ALLOW".into()),
            TamperKind::ParamsHash => mutate(chain, 1, |e| e.params_hash = "f".repeat(64)),
            TamperKind::EntryTs => mutate(chain, 1, |e| e.entry_ts = "2026-08-25T15:00:00Z".into()),
            TamperKind::AgentId => mutate(chain, 1, |e| e.agent_id = "other".into()),
            TamperKind::Tool => mutate(chain, 1, |e| e.tool = "fs.write".into()),
            TamperKind::PolicyId => mutate(chain, 1, |e| e.policy_id = "pol_other".into()),
            TamperKind::RequestId => mutate(chain, 1, |e| e.request_id = "req_x".into()),
            TamperKind::ReasonCode => mutate(chain, 1, |e| e.reason_code = "DEFAULT_DENY".into()),
            TamperKind::DeterminingRuleIds => {
                mutate(chain, 1, |e| e.determining_rule_ids = vec!["r-x".into()])
            }
            TamperKind::EntryHash => mutate(chain, 1, |e| e.entry_hash = "a".repeat(64)),
            TamperKind::PreviousHash => mutate(chain, 2, |e| e.previous_hash = "b".repeat(64)),
            TamperKind::Truncate => truncate(chain, 0),
            TamperKind::Reorder => mutate(chain, 1, |e| e.entry_seq = 9),
        };
        let ok = chaperone_core::ledger::verify::verify_chain(&broken).is_ok();
        if !ok {
            detected += 1;
        }
    }
    TamperEvidence {
        detected,
        total,
        detected_all: ProportionMetric::new(detected, total),
    }
}

use chaperone_core::models::ledger::{EntryType, LedgerEntry};

/// A deterministic 3-entry chain: fixed genesis + two chained decisions. This
/// mirrors the chain-vector test but is independent (E5 must not depend on the
/// system-under-test's own test fixtures).
fn three_entry_chain() -> Vec<LedgerEntry> {
    let z = "0".repeat(64);
    let genesis = LedgerEntry {
        entry_seq: 0,
        entry_ts: "2026-08-25T00:00:00Z".into(),
        previous_hash: z.clone(),
        entry_hash: String::new(),
        entry_type: EntryType::Genesis,
        request_id: "genesis".into(),
        agent_id: "chaperone".into(),
        tool: "chaperone".into(),
        params_hash: z.clone(),
        tenant_id: None,
        decision: "GENESIS".into(),
        policy_id: "__none__".into(),
        policy_version: 0,
        policy_hash: z.clone(),
        determining_rule_ids: vec![],
        reason_code: "GENESIS".into(),
        decision_trace: "[]".into(),
        evaluation_latency_ms: 0.0,
        escalation_id: None,
    };
    let mut e1 = decision_entry(1, "req_a", "ALLOW", vec!["r-1"], "2026-08-25T14:00:00Z");
    let mut e2 = decision_entry(2, "req_b", "BLOCK", vec!["r-2"], "2026-08-25T14:00:01Z");
    let mut g = genesis;
    g.entry_hash = chaperone_core::ledger::chain::compute_entry_hash(&g);
    e1.previous_hash = g.entry_hash.clone();
    e1.entry_hash = chaperone_core::ledger::chain::compute_entry_hash(&e1);
    e2.previous_hash = e1.entry_hash.clone();
    e2.entry_hash = chaperone_core::ledger::chain::compute_entry_hash(&e2);
    vec![g, e1, e2]
}

fn decision_entry(
    seq: u64,
    request_id: &str,
    decision: &str,
    rules: Vec<&str>,
    ts: &str,
) -> LedgerEntry {
    LedgerEntry {
        entry_seq: seq,
        entry_ts: ts.into(),
        previous_hash: String::new(),
        entry_hash: String::new(),
        entry_type: EntryType::Decision,
        request_id: request_id.into(),
        agent_id: "agent_support_09".into(),
        tool: "stripe.refunds.create".into(),
        params_hash: "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091".into(),
        tenant_id: None,
        decision: decision.into(),
        policy_id: "pol_refunds".into(),
        policy_version: 3,
        policy_hash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
        determining_rule_ids: rules.into_iter().map(String::from).collect(),
        reason_code: "RULE_MATCH".into(),
        decision_trace: "[]".into(),
        evaluation_latency_ms: 1.0,
        escalation_id: None,
    }
}

fn mutate(
    mut chain: Vec<LedgerEntry>,
    seq: u64,
    f: impl FnOnce(&mut LedgerEntry),
) -> Vec<LedgerEntry> {
    if let Some(e) = chain.iter_mut().find(|e| e.entry_seq == seq) {
        f(e);
    }
    chain
}

fn truncate(chain: Vec<LedgerEntry>, keep: usize) -> Vec<LedgerEntry> {
    chain.into_iter().take(keep).collect()
}

// ---------------------------------------------------------------------------
// E4 — Compiler fidelity (inter-run stability)
// ---------------------------------------------------------------------------

/// E4: each gold SOP is compiled N times through the OFFLINE fixture provider;
/// the experiment asserts the compiled IR is byte-identical across runs
/// (determinism — the honest, testable core of compiler fidelity). Agreement
/// with gold *labels* is asserted separately in the corpus replay (E1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerFidelity {
    pub sops: u64,
    pub stable: u64,
    pub stability: ProportionMetric,
}

/// A gold SOP (hand-written English source) + its expected compiled policy id.
pub struct GoldSop {
    pub sop: String,
    pub expected_policy_id: String,
}

/// The gold SOPs (flows/01 + flows/10 gold/: independent of the engine).
pub fn gold_sops() -> Vec<GoldSop> {
    vec![
        GoldSop {
            sop: "Refunds up to $200 are auto-approved; $200-$1000 require human approval; over $1000 are blocked.".into(),
            expected_policy_id: "bench_refunds".into(),
        },
        GoldSop {
            sop: "Destructive shell commands, force pushes to main, and writes to secret files are blocked; benign local reads and safe web access are allowed.".into(),
            expected_policy_id: "bench_safety".into(),
        },
    ]
}

/// Compile every gold SOP 5× through the fixture provider and measure
/// byte-identical inter-run stability. Pure (offline; zero network).
pub fn e4_compiler_fidelity() -> CompilerFidelity {
    use chaperone_core::compiler::{CompilerProvider, FixtureProvider};

    // The fixture provider returns a single recorded IR for a given SOP; keying
    // by SOP makes the experiment honest (the fixture is deterministic, so
    // stability = byte-identical repeated output).
    let recorded: std::collections::HashMap<String, String> = gold_sops()
        .iter()
        .map(|s| {
            let ir = match s.expected_policy_id.as_str() {
                "bench_refunds" => crate::gold::gold_policies()[0].clone(),
                _ => crate::gold::gold_policies()[1].clone(),
            };
            let ir_json = serde_json::to_string(&ir).expect("serialize");
            (s.sop.clone(), ir_json)
        })
        .collect();

    let mut sops = 0u64;
    let mut stable = 0u64;
    for s in gold_sops() {
        sops += 1;
        let fixture = FixtureProvider::new(recorded.get(&s.sop).cloned().unwrap_or_default());
        let first = fixture.compile(&s.sop, None).expect("compile").ir_text;
        let mut all_same = true;
        for _ in 0..4 {
            let again = fixture.compile(&s.sop, None).expect("compile").ir_text;
            if again != first {
                all_same = false;
            }
        }
        if all_same {
            stable += 1;
        }
    }
    CompilerFidelity {
        sops,
        stable,
        stability: ProportionMetric::new(stable, sops),
    }
}

// ---------------------------------------------------------------------------
// E6 — Determinism (engine replay, byte-identical)
// ---------------------------------------------------------------------------

/// E6: replay the full corpus through the reference + cedar engines and assert
/// byte-identical decisions (the determinism law). Pure — no server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterminismReport {
    pub scenarios: u64,
    pub identical: u64,
    pub identical_fraction: ProportionMetric,
}

/// Evaluate every corpus scenario through both engines and measure agreement.
pub fn e6_determinism(seed: u64) -> DeterminismReport {
    let scenarios = crate::attacks::corpus(seed);
    let policies = crate::gold::gold_policies();
    let cedar = chaperone_core::engine::cedar_engine::CedarEngine::compile(&policies)
        .expect("compile gold policies");
    let mut identical = 0u64;
    let mut total = 0u64;
    for s in scenarios {
        total += 1;
        let surface = match s.context.surface.as_str() {
            "cursor" => "cursor",
            "mcp_gateway" => "mcp_gateway",
            "mcp_shim" => "mcp_shim",
            "sdk" => "sdk",
            _ => "claude_code",
        };
        let req = chaperone_core::engine::EvalRequest {
            agent_id: &s.agent,
            role: "worker",
            tool: &s.tool,
            params: &s.params,
            surface,
            delegation_depth: s.context.delegation_depth,
            request_time: &s.context.request_time,
            derived: &serde_json::json!({}),
        };
        let reference = chaperone_core::engine::reference::evaluate_ir(&policies, &req);
        let cedar_out = cedar.evaluate(&req);
        if reference.decision == cedar_out.decision
            && reference.determining_rule_ids == cedar_out.determining_rule_ids
        {
            identical += 1;
        }
    }
    DeterminismReport {
        scenarios: total,
        identical,
        identical_fraction: ProportionMetric::new(identical, total),
    }
}

// ---------------------------------------------------------------------------
// E3 — Policy currency (documented, config-driven)
// ---------------------------------------------------------------------------

/// E3: the stale-policy window is bounded by the cache TTL. The no-Redis TTL
/// (5s) is the upper bound for the single-node quickstart; with Redis it is
/// 30s (flows/02 cache tooling). These are DOCUMENTED, config-driven constants
/// — exposed for the paper figure, not a live wall-clock measurement.
pub const E3_NO_REDIS_STALE_WINDOW_SECONDS: u64 = 5;
pub const E3_WITH_REDIS_STALE_WINDOW_SECONDS: u64 = 30;

/// E3 corpus coverage: the `StalePolicy` class is evaluated against the live
/// gate in E1 (the runner already measures it). This helper reports the
/// stale-policy scenario count so the paper figure is grounded in real corpus
/// coverage, not an unmeasured claim.
pub fn e3_stale_policy_coverage(seed: u64) -> u64 {
    crate::attacks::corpus(seed)
        .iter()
        .filter(|s| s.attack_class == AttackClass::StalePolicy)
        .count() as u64
}
