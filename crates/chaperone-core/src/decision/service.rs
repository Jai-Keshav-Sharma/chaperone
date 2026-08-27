//! DecisionService — the Flow 2 hot path, orchestrated fail-closed (build-plan
//! Phase 7): agent lookup → policy lookup (via the Phase 6.5 policy cache) →
//! derived context → engine eval → SYNCHRONOUS ledger append → respond.
//! Append-then-respond (Law 3); idempotent replay via request_id; mode is
//! server-side config, never client-supplied (flows/02 invariant 8, flows/08
//! rule 1). ESCALATE creates a human-in-the-loop ticket (Flow 3); retries with
//! escalation_id consume it (single-use, params-bound).

use serde_json::{Value as JsonValue, json};
use std::sync::Arc;
use std::time::Instant;

use crate::cache::policy_cache::{CompiledPolicies, PolicyProvider};
use crate::engine::derive::{DerivedCounterValue, DerivedDeclaration, compute_derived};
use crate::engine::{EngineDecision, EvalRequest};
use crate::escalation::service::EscalationService;
use crate::ledger::chain::append;
use crate::ledger::{ChainError, ChainStore};
use crate::models::decision::{Decision, DecisionRequest, DecisionResponse, TraceEntry};
use crate::models::ledger::{EntryType, LedgerEntry};
use crate::models::reason_code::ReasonCode;
use crate::storage::store::{AgentIdentityRow, Store, StoreError};

/// The escalation seam the decision service uses (Flow 3). Implemented by
/// `EscalationService`; tests use a no-op seam so the pure decision tests
/// need no sqlx store.
#[allow(async_fn_in_trait)] // auto-trait bounds are not needed on this seam
pub trait EscalationSeam: Send + Sync {
    async fn create(
        &self,
        escalation_id: &str,
        req: &DecisionRequest,
        policy_id: &str,
        policy_version: u32,
        rule_ids: &[String],
    ) -> Result<(), StoreError>;
    /// Read-only validation of a retry against the ticket (no transition).
    async fn check_consume(
        &self,
        escalation_id: &str,
        req: &DecisionRequest,
    ) -> Result<ReasonCode, StoreError>;
    /// Transition an APPROVED ticket to consumed (after the retry's ledger
    /// entry is appended).
    async fn consume(&self, escalation_id: &str) -> Result<(), StoreError>;
    async fn attach(
        &self,
        escalation_id: String,
        decision_entry_seq: i64,
    ) -> Result<(), StoreError>;
    async fn expires_at_for(&self, escalation_id: &str) -> String;
}

impl EscalationSeam for EscalationService {
    async fn create(
        &self,
        escalation_id: &str,
        req: &DecisionRequest,
        policy_id: &str,
        policy_version: u32,
        rule_ids: &[String],
    ) -> Result<(), StoreError> {
        EscalationService::create(
            self,
            escalation_id,
            req,
            policy_id,
            policy_version,
            rule_ids,
        )
        .await
    }
    async fn check_consume(
        &self,
        escalation_id: &str,
        req: &DecisionRequest,
    ) -> Result<ReasonCode, StoreError> {
        EscalationService::check_consume(self, escalation_id, req).await
    }
    async fn consume(&self, escalation_id: &str) -> Result<(), StoreError> {
        EscalationService::consume(self, escalation_id).await
    }
    async fn attach(
        &self,
        escalation_id: String,
        decision_entry_seq: i64,
    ) -> Result<(), StoreError> {
        EscalationService::attach(self, escalation_id, decision_entry_seq).await
    }
    async fn expires_at_for(&self, escalation_id: &str) -> String {
        EscalationService::expires_at_for(self, escalation_id).await
    }
}

/// Fail-closed errors — never decisions. A 5xx triggers a BLOCK at the
/// interceptor; a verdict is never returned from an error path (Law 1).
#[derive(Debug, Clone, thiserror::Error)]
pub enum DecisionError {
    /// Ledger write failed → no verdict (503); the envelope carries a
    /// synthesized BLOCK (FAIL_CLOSED_LEDGER_UNAVAILABLE) as the non-forward.
    #[error("ledger: {0}")]
    LedgerUnavailable(String),
    /// Policy store unreachable → BLOCK (FAIL_CLOSED_POLICY_UNAVAILABLE).
    #[error("policy: {0}")]
    PolicyUnavailable(String),
    /// The active policy set failed to compile (transpile/parse/drift).
    #[error("policy compile: {0}")]
    PolicyCompile(String),
}

/// Server-side operator config (chaperone.yaml, docs/data-model.md). mode is
/// NEVER client-supplied (review-4 B1) — an agent cannot self-exempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    Enforce,
    Shadow,
}

impl ServiceMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceMode::Enforce => "enforce",
            ServiceMode::Shadow => "shadow",
        }
    }
}

/// Deployment policy choice for ungoverned tools (flows/02 step 4) — a POLICY
/// choice, never a failure fallback (review BUG-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UngovernedDefault {
    Block,
    Allow,
}

/// Fail-closed decision envelope (flows/02): a BLOCK + a valid ledger entry on
/// every in-band decision. `error` is set exactly when the gate itself failed
/// (ledger/policy unavailable) — the interceptor treats that as a non-forward
/// (fail-closed), and the server surfaces it as 503 (never a verdict).
#[derive(Debug)]
pub struct DecisionEnvelope {
    pub response: DecisionResponse,
    pub error: Option<DecisionError>,
}

/// Reads the materialized derived_counters for the active declarations.
pub trait DerivedCounterSource: Send + Sync {
    fn read(&self, req: &DecisionRequest) -> Result<Vec<DerivedCounterValue>, DecisionError>;
}

/// The decision service — the single orchestration point of the hot path.
/// Generic over the ledger store, the policy cache (provider), and the
/// derived-counter source so tests use in-memory seams and production uses
/// sqlx Store.
pub struct DecisionService<S, P, D, E> {
    store: S,
    policies: P,
    counters: D,
    escalations: Arc<E>,
    mode: ServiceMode,
    ungoverned_default: UngovernedDefault,
    declarations: Vec<DerivedDeclaration>,
}

impl<S, P, D, E> DecisionService<S, P, D, E>
where
    S: ChainStore + AgentSource,
    P: PolicyProvider,
    D: DerivedCounterSource,
    E: EscalationSeam,
{
    pub fn new(
        store: S,
        policies: P,
        counters: D,
        escalations: Arc<E>,
        mode: ServiceMode,
        ungoverned_default: UngovernedDefault,
        declarations: Vec<DerivedDeclaration>,
    ) -> Self {
        DecisionService {
            store,
            policies,
            counters,
            escalations,
            mode,
            ungoverned_default,
            declarations,
        }
    }

    /// The hot path (flows/02). Idempotent on request_id: replays return the
    /// original decision (ledger DuplicateEntry is answered from the original
    /// entry — no double evaluation, no double append).
    pub async fn decide(&self, req: &DecisionRequest) -> DecisionEnvelope {
        let start = Instant::now();

        // --- fail-closed guard: a policy load failure is NEVER a verdict ---
        let compiled = match self.policies.load().await {
            Ok(c) => c,
            Err(e) => {
                return self.synthesized_block(ReasonCode::FailClosedPolicyUnavailable, start, e);
            }
        };

        // --- step 1: agent lookup (unknown/inactive → BLOCK, still ledgered) ---
        let agent: Option<AgentIdentityRow> =
            match self.store.get_agent_identity(&req.agent_id).await {
                Ok(a) => a,
                Err(e) => {
                    // A DB failure here is a policy-store-class failure (fail-closed).
                    return self.synthesized_block(
                        ReasonCode::FailClosedPolicyUnavailable,
                        start,
                        DecisionError::PolicyUnavailable(format!(
                            "agent lookup failed for {}: {e}",
                            req.agent_id
                        )),
                    );
                }
            };
        let Some(agent) = agent else {
            // Unknown agent → BLOCK (AGENT_UNKNOWN), still ledgered (flows/02
            // step 1). Never evaluated by the engine: an unknown identity is a
            // deterministic block, not a policy question.
            return self
                .agent_block(ReasonCode::AgentUnknown, req, &compiled, start)
                .await;
        };
        if !agent.is_active {
            // Registered but inactive → BLOCK (AGENT_INACTIVE), still ledgered.
            return self
                .agent_block(ReasonCode::AgentInactive, req, &compiled, start)
                .await;
        }

        // --- step 3: derived context (boundary-computed, then ledgered) ---
        let derived_values = match self.counters.read(req) {
            Ok(v) => v,
            Err(e) => {
                // A counter failure is a policy-store-class failure (fail-closed).
                return self.synthesized_block(ReasonCode::FailClosedPolicyUnavailable, start, e);
            }
        };
        let derived_context = compute_derived(self.declarations(), &derived_values);

        // --- step 3.5: escalation consumption (Flow 3 step 4) ---
        // A retry carrying an escalation_id is resolved against the ticket —
        // approved + unconsumed + params-bound → ALLOW (consumed); anything
        // else → BLOCK with the ESCALATION_* reason. The DECISION entry for
        // the retry is appended before responding (append-then-respond).
        if let Some(esc_id) = &req.escalation_id {
            // Read-only check (no transition): approve + unconsumed + params
            // bound → ALLOW; anything else → BLOCK with the ESCALATION_*
            // reason. The transition happens AFTER the retry's ledger entry
            // appends (append-then-respond, Law 3).
            let rc = match self.escalations.check_consume(esc_id, req).await {
                Ok(rc) => rc,
                Err(e) => {
                    return self.synthesized_block(
                        ReasonCode::FailClosedPolicyUnavailable,
                        start,
                        DecisionError::PolicyUnavailable(format!("escalation lookup failed: {e}")),
                    );
                }
            };
            let (decision, reason) = if rc == ReasonCode::EscalationApproved {
                (Decision::Allow, rc)
            } else {
                (Decision::Block, rc)
            };
            let entry = self.build_entry(req, &decision, &reason, &[], &[], &compiled);
            let append_result = append(&self.store, entry).await;
            let (entry_seq, entry_hash) = match append_result {
                Ok(seq_hash) => seq_hash,
                Err(e) => {
                    return self.synthesized_block(
                        ReasonCode::FailClosedLedgerUnavailable,
                        start,
                        DecisionError::LedgerUnavailable(e.to_string()),
                    );
                }
            };
            // NOW transition the ticket to consumed (single-use). The row's
            // decision_entry_seq (the ORIGINAL ESCALATE entry) is untouched —
            // the retry's entry is in the ledger carrying the escalation_id.
            if rc == ReasonCode::EscalationApproved
                && let Err(e) = self.escalations.consume(esc_id).await
            {
                return self.synthesized_block(
                    ReasonCode::FailClosedPolicyUnavailable,
                    start,
                    DecisionError::PolicyUnavailable(format!("escalation consume failed: {e}")),
                );
            }
            let (policy_id, policy_version, policy_hash) = compiled
                .governing()
                .map(|(id, v, h)| (id.to_string(), v, h.to_string()))
                .unwrap_or_else(|| ("__none__".to_string(), 0, "0".repeat(64)));
            return DecisionEnvelope {
                response: DecisionResponse {
                    decision,
                    reason_code: reason,
                    determining_rule_ids: vec![],
                    policy_id,
                    policy_version,
                    policy_hash,
                    entry_seq,
                    entry_hash,
                    escalation_id: Some(esc_id.clone()),
                    escalation_expires_at: None,
                    trace: vec![],
                    derived_context,
                    evaluation_latency_ms: elapsed_ms(start),
                },
                error: None,
            };
        }

        // --- step 4: engine evaluation ---
        let outcome = compiled.engine().evaluate(&EvalRequest {
            agent_id: &req.agent_id,
            role: &agent.role,
            tool: &req.tool,
            params: &req.params,
            surface: req.context.surface.as_str(),
            delegation_depth: req.context.delegation_depth,
            request_time: &req.context.request_time,
            derived: &derived_context,
        });

        // --- map the engine verdict to the wire decision + reason ---
        let (decision, reason, rule_ids, trace) = match outcome.decision {
            EngineDecision::Block => {
                if outcome.eval_error.is_some() {
                    (
                        Decision::Block,
                        ReasonCode::EvalError,
                        vec![],
                        outcome.trace,
                    )
                } else if outcome.determining_rule_ids.is_empty() {
                    (
                        Decision::Block,
                        ReasonCode::DefaultDeny,
                        vec![],
                        outcome.trace,
                    )
                } else {
                    (
                        Decision::Block,
                        ReasonCode::RuleMatch,
                        outcome.determining_rule_ids.clone(),
                        outcome.trace,
                    )
                }
            }
            EngineDecision::Escalate => (
                Decision::Escalate,
                ReasonCode::RuleMatch,
                outcome.determining_rule_ids.clone(),
                outcome.trace,
            ),
            EngineDecision::Allow => (
                Decision::Allow,
                ReasonCode::RuleMatch,
                outcome.determining_rule_ids.clone(),
                outcome.trace,
            ),
            EngineDecision::NoPolicy => match self.ungoverned_default {
                UngovernedDefault::Block => {
                    (Decision::Block, ReasonCode::NoPolicy, vec![], outcome.trace)
                }
                UngovernedDefault::Allow => (
                    Decision::Allow,
                    ReasonCode::UngovernedAllow,
                    vec![],
                    outcome.trace,
                ),
            },
        };

        // --- step 5: SYNCHRONOUS ledger append (append-then-respond, Law 3) ---
        // Shadow mode ledgered as WOULD_* (flows/08 rule 2: same chain, same
        // guarantees); the response mirrors the ledgered decision.
        let wire_decision = if self.mode == ServiceMode::Shadow {
            to_would(decision)
        } else {
            decision
        };
        let entry = self.build_entry(req, &wire_decision, &reason, &rule_ids, &trace, &compiled);
        let append_result = append(&self.store, entry).await;
        let (entry_seq, entry_hash) = match append_result {
            Ok(seq_hash) => seq_hash,
            Err(ChainError::DuplicateEntry { request_id, .. }) => {
                // Replay: the original entry already exists — answer from it
                // (no double evaluation, no double append; invariant 3).
                match self.store.find_entry_by_request(&request_id).await {
                    Ok(Some(e)) => {
                        return DecisionEnvelope {
                            response: DecisionResponse {
                                decision: decision_from_str(&e.decision),
                                reason_code: reason_code_from_str(&e.reason_code),
                                determining_rule_ids: e.determining_rule_ids.clone(),
                                policy_id: e.policy_id.clone(),
                                policy_version: e.policy_version,
                                policy_hash: e.policy_hash.clone(),
                                entry_seq: e.entry_seq,
                                entry_hash: e.entry_hash.clone(),
                                escalation_id: e.escalation_id.clone(),
                                escalation_expires_at: None,
                                trace: serde_json::from_str(&e.decision_trace).unwrap_or_default(),
                                derived_context: json!({}),
                                evaluation_latency_ms: elapsed_ms(start),
                            },
                            error: None,
                        };
                    }
                    _ => {
                        // UNIQUE constraint fired but no row found — a broken
                        // store. Fail closed: no verdict (503), never a decision.
                        return self.synthesized_block(
                            ReasonCode::FailClosedLedgerUnavailable,
                            start,
                            DecisionError::LedgerUnavailable(
                                "duplicate request_id but original entry not found".to_string(),
                            ),
                        );
                    }
                }
            }
            Err(e) => {
                // Ledger write failed → NO verdict (503). Fail-closed (Law 1).
                return self.synthesized_block(
                    ReasonCode::FailClosedLedgerUnavailable,
                    start,
                    DecisionError::LedgerUnavailable(e.to_string()),
                );
            }
        };

        // --- step 5.5: ESCALATE → create the human-in-the-loop ticket ---
        // (Flow 3 step 1). Enforce mode only — shadow NEVER creates tickets
        // (flows/08 rule 3: ledger + metrics only). The DECISION entry already
        // appended; the ticket is attached to its seq.
        let mut escalation_id_out = None;
        let mut escalation_expires_at = None;
        if decision == Decision::Escalate && self.mode == ServiceMode::Enforce {
            let esc_id = format!("esc_{}", uuid::Uuid::new_v4().simple());
            let (pid, pver, _) = compiled
                .governing()
                .map(|(id, v, h)| (id.to_string(), v, h.to_string()))
                .unwrap_or_else(|| ("__none__".to_string(), 0, "0".repeat(64)));
            match self
                .escalations
                .create(&esc_id, req, &pid, pver, &rule_ids)
                .await
            {
                Ok(()) => {
                    // Attach the decision entry seq (FK to ledger_entries).
                    if self
                        .escalations
                        .attach(esc_id.clone(), entry_seq as i64)
                        .await
                        .is_err()
                    {
                        // The ticket exists but the link failed — surface a
                        // ledger-class failure (fail-closed: no verdict).
                        return self.synthesized_block(
                            ReasonCode::FailClosedLedgerUnavailable,
                            start,
                            DecisionError::LedgerUnavailable(format!(
                                "escalation {esc_id} attach failed"
                            )),
                        );
                    }
                    escalation_id_out = Some(esc_id.clone());
                    escalation_expires_at = Some(self.escalations.expires_at_for(&esc_id).await);
                }
                Err(e) => {
                    // Ticket creation failed → ledger-class failure (fail-closed).
                    return self.synthesized_block(
                        ReasonCode::FailClosedLedgerUnavailable,
                        start,
                        DecisionError::LedgerUnavailable(format!("escalation create failed: {e}")),
                    );
                }
            }
        }

        // --- step 6: respond (the entry exists BEFORE this response) ---
        let (policy_id, policy_version, policy_hash) = compiled
            .governing()
            .map(|(id, v, h)| (id.to_string(), v, h.to_string()))
            .unwrap_or_else(|| ("__none__".to_string(), 0, "0".repeat(64)));
        let response = DecisionResponse {
            decision: wire_decision,
            reason_code: reason,
            determining_rule_ids: rule_ids,
            policy_id,
            policy_version,
            policy_hash,
            entry_seq,
            entry_hash,
            escalation_id: escalation_id_out,
            escalation_expires_at,
            trace,
            derived_context,
            evaluation_latency_ms: elapsed_ms(start),
        };
        DecisionEnvelope {
            response,
            error: None,
        }
    }

    /// An agent-identity block (unknown/inactive) — an IN-BAND decision
    /// (HTTP 200, AGENT_UNKNOWN / AGENT_INACTIVE), still ledgered (flows/02
    /// step 1). Append-then-respond applies exactly as for rule verdicts.
    async fn agent_block(
        &self,
        reason: ReasonCode,
        req: &DecisionRequest,
        compiled: &CompiledPolicies,
        start: Instant,
    ) -> DecisionEnvelope {
        let decision = Decision::Block;
        let entry = self.build_entry(req, &decision, &reason, &[], &[], compiled);
        let (entry_seq, entry_hash) = match crate::ledger::chain::append(&self.store, entry).await {
            Ok(seq_hash) => seq_hash,
            Err(e) => {
                // Ledger write failed → NO verdict (503). Fail-closed (Law 1).
                return self.synthesized_block(
                    ReasonCode::FailClosedLedgerUnavailable,
                    start,
                    DecisionError::LedgerUnavailable(e.to_string()),
                );
            }
        };
        let (policy_id, policy_version, policy_hash) = compiled
            .governing()
            .map(|(id, v, h)| (id.to_string(), v, h.to_string()))
            .unwrap_or_else(|| ("__none__".to_string(), 0, "0".repeat(64)));
        DecisionEnvelope {
            response: DecisionResponse {
                decision,
                reason_code: reason,
                determining_rule_ids: vec![],
                policy_id,
                policy_version,
                policy_hash,
                entry_seq,
                entry_hash,
                escalation_id: None,
                escalation_expires_at: None,
                trace: vec![],
                derived_context: json!({}),
                evaluation_latency_ms: elapsed_ms(start),
            },
            error: None,
        }
    }

    /// A synthesized fail-closed block — the non-forward the interceptor sees
    /// when the gate itself failed (Law 1: no "degraded allow" exists).
    fn synthesized_block(
        &self,
        reason: ReasonCode,
        start: Instant,
        error: DecisionError,
    ) -> DecisionEnvelope {
        DecisionEnvelope {
            response: DecisionResponse {
                decision: Decision::Block,
                reason_code: reason,
                determining_rule_ids: vec![],
                policy_id: "__none__".to_string(),
                policy_version: 0,
                policy_hash: "0".repeat(64),
                entry_seq: 0,
                entry_hash: "0".repeat(64),
                escalation_id: None,
                escalation_expires_at: None,
                trace: vec![],
                derived_context: json!({}),
                evaluation_latency_ms: elapsed_ms(start),
            },
            error: Some(error),
        }
    }

    fn declarations(&self) -> &[crate::engine::derive::DerivedDeclaration] {
        // Declarations are server-side operator config (chaperone.yaml
        // `derived_attributes`, docs/data-model.md); they live on the service
        // and the counter source is constructed against them.
        &self.declarations
    }

    fn build_entry(
        &self,
        req: &DecisionRequest,
        decision: &Decision,
        reason: &ReasonCode,
        rule_ids: &[String],
        trace: &[TraceEntry],
        compiled: &CompiledPolicies,
    ) -> LedgerEntry {
        let params_hash = sha256_params(&req.params);
        let (policy_id, policy_version, policy_hash) = compiled
            .governing()
            .map(|(id, v, h)| (id.to_string(), v, h.to_string()))
            .unwrap_or_else(|| ("__none__".to_string(), 0, "0".repeat(64)));
        // Shadow mode ledgered as WOULD_* (flows/08 rule 2: "WOULD_* entries
        // live in the real ledger"). The interceptor proceeds, the chain does
        // not — the ledger is the honest record of the WOULD-be verdict.
        let ledger_decision = if self.mode == ServiceMode::Shadow {
            to_would(*decision)
        } else {
            *decision
        };
        LedgerEntry {
            entry_seq: 0, // chain assigns
            entry_ts: req.context.request_time.clone(),
            previous_hash: String::new(), // chain assigns
            entry_hash: String::new(),    // chain computes
            entry_type: EntryType::Decision,
            request_id: req.request_id.clone(),
            agent_id: req.agent_id.clone(),
            tool: req.tool.clone(),
            params_hash,
            tenant_id: None,
            decision: decision_ledger_str(&ledger_decision).to_string(),
            policy_id,
            policy_version,
            policy_hash,
            determining_rule_ids: rule_ids.to_vec(),
            reason_code: reason_code_str(reason).to_string(),
            decision_trace: serde_json::to_string(trace).unwrap_or_else(|_| "[]".to_string()),
            evaluation_latency_ms: 0.0,
            escalation_id: None,
        }
    }
}

// --- small helpers ---------------------------------------------------------

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

/// sha256 of the CANONICAL JSON of params — the decision service's params
/// preimage (the raw-bytes hash lives at the transport boundary; flows/06
/// defines per-surface preimages).
fn sha256_params(params: &JsonValue) -> String {
    crate::canonical::sha256_hex(&crate::canonical::canonical_dumps(params))
}

fn decision_ledger_str(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "ALLOW",
        Decision::Block => "BLOCK",
        Decision::Escalate => "ESCALATE",
        Decision::WouldAllow => "WOULD_ALLOW",
        Decision::WouldBlock => "WOULD_BLOCK",
        Decision::WouldEscalate => "WOULD_ESCALATE",
    }
}

fn reason_code_str(r: &ReasonCode) -> &'static str {
    match r {
        ReasonCode::RuleMatch => "RULE_MATCH",
        ReasonCode::DefaultDeny => "DEFAULT_DENY",
        ReasonCode::NoPolicy => "NO_POLICY",
        ReasonCode::UngovernedAllow => "UNGOVERNED_ALLOW",
        ReasonCode::EvalError => "EVAL_ERROR",
        ReasonCode::AgentUnknown => "AGENT_UNKNOWN",
        ReasonCode::AgentInactive => "AGENT_INACTIVE",
        ReasonCode::FailClosedPolicyUnavailable => "FAIL_CLOSED_POLICY_UNAVAILABLE",
        ReasonCode::FailClosedLedgerUnavailable => "FAIL_CLOSED_LEDGER_UNAVAILABLE",
        ReasonCode::FailClosedGateUnreachable => "FAIL_CLOSED_GATE_UNREACHABLE",
        ReasonCode::RateLimited => "RATE_LIMITED",
        ReasonCode::EscalationApproved => "ESCALATION_APPROVED",
        ReasonCode::EscalationDenied => "ESCALATION_DENIED",
        ReasonCode::EscalationExpired => "ESCALATION_EXPIRED",
        ReasonCode::EscalationParamsMismatch => "ESCALATION_PARAMS_MISMATCH",
        ReasonCode::EscalationAlreadyConsumed => "ESCALATION_ALREADY_CONSUMED",
    }
}

fn decision_from_str(s: &str) -> Decision {
    match s {
        "ALLOW" => Decision::Allow,
        "BLOCK" => Decision::Block,
        "ESCALATE" => Decision::Escalate,
        "WOULD_ALLOW" => Decision::WouldAllow,
        "WOULD_BLOCK" => Decision::WouldBlock,
        "WOULD_ESCALATE" => Decision::WouldEscalate,
        _ => Decision::Block,
    }
}

fn reason_code_from_str(s: &str) -> ReasonCode {
    match s {
        "RULE_MATCH" => ReasonCode::RuleMatch,
        "DEFAULT_DENY" => ReasonCode::DefaultDeny,
        "NO_POLICY" => ReasonCode::NoPolicy,
        "UNGOVERNED_ALLOW" => ReasonCode::UngovernedAllow,
        "EVAL_ERROR" => ReasonCode::EvalError,
        "AGENT_UNKNOWN" => ReasonCode::AgentUnknown,
        "AGENT_INACTIVE" => ReasonCode::AgentInactive,
        "FAIL_CLOSED_POLICY_UNAVAILABLE" => ReasonCode::FailClosedPolicyUnavailable,
        "FAIL_CLOSED_LEDGER_UNAVAILABLE" => ReasonCode::FailClosedLedgerUnavailable,
        "FAIL_CLOSED_GATE_UNREACHABLE" => ReasonCode::FailClosedGateUnreachable,
        "RATE_LIMITED" => ReasonCode::RateLimited,
        "ESCALATION_APPROVED" => ReasonCode::EscalationApproved,
        "ESCALATION_DENIED" => ReasonCode::EscalationDenied,
        "ESCALATION_EXPIRED" => ReasonCode::EscalationExpired,
        "ESCALATION_PARAMS_MISMATCH" => ReasonCode::EscalationParamsMismatch,
        "ESCALATION_ALREADY_CONSUMED" => ReasonCode::EscalationAlreadyConsumed,
        _ => ReasonCode::DefaultDeny,
    }
}

fn to_would(d: Decision) -> Decision {
    match d {
        Decision::Allow => Decision::WouldAllow,
        Decision::Block => Decision::WouldBlock,
        Decision::Escalate => Decision::WouldEscalate,
        other => other,
    }
}

/// The agent-identity seam the service reads (unknown/inactive → BLOCK, still
/// ledgered — flows/02 step 1).
#[allow(async_fn_in_trait)] // auto-trait bounds are not needed on this seam
pub trait AgentSource: Send + Sync {
    async fn get_agent_identity(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentIdentityRow>, StoreError>;
    async fn find_entry_by_request(
        &self,
        request_id: &str,
    ) -> Result<Option<LedgerEntry>, ChainError>;
}

impl AgentSource for Store {
    async fn get_agent_identity(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentIdentityRow>, StoreError> {
        Store::get_agent_identity(self, agent_id).await
    }
    async fn find_entry_by_request(
        &self,
        request_id: &str,
    ) -> Result<Option<LedgerEntry>, ChainError> {
        Store::find_entry_by_request(self, request_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::policy_cache::ActivePolicy;
    use crate::models::decision::{RequestContext, Surface};
    use crate::models::ir::Policy;
    use crate::models::reason_code::ReasonCode;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    // --- in-memory seams ---------------------------------------------------

    /// The ledger seam: an in-memory chain (genesis + appends) that enforces
    /// UNIQUE(request_id, entry_type) exactly like the sqlx store.
    #[derive(Clone, Default)]
    struct MemChain {
        entries: Arc<Mutex<Vec<LedgerEntry>>>,
        /// The agent identity lookup — configurable so the unknown/inactive
        /// paths are exercised (flows/02 step 1).
        agent: Arc<Mutex<Option<AgentIdentityRow>>>,
    }

    impl MemChain {
        fn with_agent(agent: AgentIdentityRow) -> Self {
            MemChain {
                agent: Arc::new(Mutex::new(Some(agent))),
                ..Self::default()
            }
        }
        fn with_no_agent() -> Self {
            MemChain {
                agent: Arc::new(Mutex::new(None)),
                ..Self::default()
            }
        }
        fn entries(&self) -> Vec<LedgerEntry> {
            self.entries.lock().unwrap().clone()
        }
    }

    impl ChainStore for MemChain {
        async fn last_entry(&self) -> Result<Option<LedgerEntry>, ChainError> {
            Ok(self.entries.lock().unwrap().last().cloned())
        }
        async fn insert_entry(&self, entry: &LedgerEntry) -> Result<(), ChainError> {
            let mut entries = self.entries.lock().unwrap();
            let dup = entries
                .iter()
                .any(|e| e.request_id == entry.request_id && e.entry_type == entry.entry_type);
            if dup {
                return Err(ChainError::DuplicateEntry {
                    request_id: entry.request_id.clone(),
                    entry_type: entry.entry_type,
                });
            }
            entries.push(entry.clone());
            Ok(())
        }
    }

    impl AgentSource for MemChain {
        async fn get_agent_identity(
            &self,
            _agent_id: &str,
        ) -> Result<Option<AgentIdentityRow>, StoreError> {
            Ok(self.agent.lock().unwrap().clone())
        }
        async fn find_entry_by_request(
            &self,
            request_id: &str,
        ) -> Result<Option<LedgerEntry>, ChainError> {
            Ok(self
                .entries()
                .into_iter()
                .find(|e| e.request_id == request_id && e.entry_type == EntryType::Decision))
        }
    }

    /// The policy seam: a fixed compiled set (or a failure to inject).
    #[derive(Clone)]
    struct MemPolicyProvider {
        compiled: Arc<Mutex<Result<CompiledPolicies, DecisionError>>>,
    }

    impl MemPolicyProvider {
        fn ok(policies: Vec<ActivePolicy>) -> Self {
            MemPolicyProvider {
                compiled: Arc::new(Mutex::new(
                    CompiledPolicies::compile(policies)
                        .map_err(|e| DecisionError::PolicyCompile(e.to_string())),
                )),
            }
        }
        fn failing() -> Self {
            MemPolicyProvider {
                compiled: Arc::new(Mutex::new(Err(DecisionError::PolicyUnavailable(
                    "db down".into(),
                )))),
            }
        }
    }

    impl PolicyProvider for MemPolicyProvider {
        async fn load(&self) -> Result<CompiledPolicies, DecisionError> {
            self.compiled.lock().unwrap().clone()
        }
    }

    /// The counter seam: fixed values keyed by declaration id.
    #[derive(Clone, Default)]
    struct MemCounterSource {
        values: Arc<Mutex<Vec<DerivedCounterValue>>>,
    }

    impl DerivedCounterSource for MemCounterSource {
        fn read(&self, _req: &DecisionRequest) -> Result<Vec<DerivedCounterValue>, DecisionError> {
            Ok(self.values.lock().unwrap().clone())
        }
    }

    fn active_policy(policy: Policy, policy_hash: &str) -> ActivePolicy {
        ActivePolicy {
            policy,
            policy_hash: policy_hash.to_string(),
        }
    }

    fn refund_policy() -> Policy {
        serde_json::from_value(json!({
            "ir_version": "1",
            "policy_id": "pol_refunds",
            "version": 3,
            "description": "refund policy",
            "rules": [
                {
                    "rule_id": "r-allow-small",
                    "description": "allow refunds up to 200",
                    "effect": "allow",
                    "target": {"tools": ["stripe.refunds.create"]},
                    "condition": {"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}}
                },
                {
                    "rule_id": "r-block-large",
                    "description": "block refunds over 1000",
                    "effect": "block",
                    "target": {"tools": ["stripe.refunds.create"]},
                    "condition": {"op": "gt", "left": {"param": "amount"}, "right": {"value": 1000}}
                }
            ]
        }))
        .expect("fixture")
    }

    fn req(amount: i64) -> DecisionRequest {
        DecisionRequest {
            request_id: "req_7f3a2b1c".into(),
            agent_id: "agent_support_09".into(),
            tool: "stripe.refunds.create".into(),
            params: json!({"amount": amount}),
            context: RequestContext {
                session_id: None,
                surface: Surface::ClaudeCode,
                delegation_depth: 0,
                request_time: "2026-08-25T14:00:00Z".into(),
            },
            escalation_id: None,
        }
    }

    fn known_agent(is_active: bool) -> AgentIdentityRow {
        AgentIdentityRow {
            agent_id: "agent_support_09".into(),
            name: "Support Agent".into(),
            role: "support".into(),
            spiffe_id: None,
            tenant_id: None,
            max_delegation_depth: 1,
            is_active,
            created_at: "2026-08-25T00:00:00Z".into(),
        }
    }

    /// A no-op escalation seam for the pure decision tests (they never hit an
    /// ESCALATE verdict, so no ticket machinery is needed).
    struct NoopEscalation;

    impl EscalationSeam for NoopEscalation {
        async fn create(
            &self,
            _id: &str,
            _req: &DecisionRequest,
            _pid: &str,
            _pver: u32,
            _rules: &[String],
        ) -> Result<(), StoreError> {
            Ok(())
        }
        async fn check_consume(
            &self,
            _id: &str,
            _req: &DecisionRequest,
        ) -> Result<ReasonCode, StoreError> {
            Ok(ReasonCode::EscalationDenied)
        }
        async fn consume(&self, _id: &str) -> Result<(), StoreError> {
            Ok(())
        }
        async fn attach(&self, _id: String, _seq: i64) -> Result<(), StoreError> {
            Ok(())
        }
        async fn expires_at_for(&self, _id: &str) -> String {
            String::new()
        }
    }

    fn service(
        chain: MemChain,
        provider: MemPolicyProvider,
        mode: ServiceMode,
    ) -> DecisionService<MemChain, MemPolicyProvider, MemCounterSource, NoopEscalation> {
        DecisionService::new(
            chain,
            provider,
            MemCounterSource::default(),
            std::sync::Arc::new(NoopEscalation),
            mode,
            UngovernedDefault::Block,
            vec![],
        )
    }

    fn policy_provider() -> MemPolicyProvider {
        MemPolicyProvider::ok(vec![active_policy(
            refund_policy(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        )])
    }

    /// A policy with an escalate rule — the escalation integration tests need
    /// an ESCALATE verdict (the refund fixture is allow/block only).
    fn escalate_policy() -> Policy {
        serde_json::from_value(json!({
            "ir_version": "1",
            "policy_id": "pol_refunds",
            "version": 3,
            "description": "refund policy with escalate",
            "rules": [
                {
                    "rule_id": "r-allow-small",
                    "description": "allow refunds up to 200",
                    "effect": "allow",
                    "target": {"tools": ["stripe.refunds.create"]},
                    "condition": {"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}}
                },
                {
                    "rule_id": "r-escalate-mid",
                    "description": "escalate refunds 100..1000",
                    "effect": "escalate",
                    "target": {"tools": ["stripe.refunds.create"]},
                    "condition": {"op": "gte", "left": {"param": "amount"}, "right": {"value": 100}}
                },
                {
                    "rule_id": "r-block-large",
                    "description": "block refunds over 1000",
                    "effect": "block",
                    "target": {"tools": ["stripe.refunds.create"]},
                    "condition": {"op": "gt", "left": {"param": "amount"}, "right": {"value": 1000}}
                }
            ]
        }))
        .expect("fixture")
    }

    fn escalate_provider() -> MemPolicyProvider {
        MemPolicyProvider::ok(vec![active_policy(
            escalate_policy(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        )])
    }

    /// A chain seeded with genesis + a known ACTIVE agent (the happy path).
    async fn seeded_chain() -> MemChain {
        let chain = MemChain::with_agent(known_agent(true));
        crate::ledger::chain::append_genesis(&chain).await.unwrap();
        chain
    }

    // --- the five Phase 7 tests -------------------------------------------

    #[tokio::test]
    async fn allow_appends_then_responds() {
        let chain = seeded_chain().await;
        let svc = service(chain.clone(), policy_provider(), ServiceMode::Enforce);

        let env = svc.decide(&req(150)).await;
        assert!(env.error.is_none(), "no error: {:?}", env.error);
        let resp = env.response;
        assert_eq!(resp.decision, Decision::Allow);
        assert_eq!(resp.reason_code, ReasonCode::RuleMatch);
        assert_eq!(resp.determining_rule_ids, vec!["r-allow-small".to_string()]);
        assert_eq!(resp.policy_id, "pol_refunds");
        assert_eq!(resp.policy_version, 3);
        assert_eq!(resp.entry_seq, 1, "genesis(0) + decision(1)");
        assert_eq!(resp.entry_hash.len(), 64);

        // The ledger entry exists BEFORE the response (append-then-respond).
        let entries = chain.entries();
        assert_eq!(entries.len(), 2);
        let last = &entries[1];
        assert_eq!(last.entry_seq, 1);
        assert_eq!(last.request_id, "req_7f3a2b1c");
        assert_eq!(last.decision, "ALLOW");
        assert_eq!(last.reason_code, "RULE_MATCH");
        assert_eq!(last.policy_id, "pol_refunds");
        assert_eq!(last.policy_version, 3);
        assert_eq!(last.entry_hash, resp.entry_hash);
        // params_hash is the canonical hash of the params — never raw JSON.
        assert_eq!(last.params_hash.len(), 64);
    }

    #[tokio::test]
    async fn policy_unavailable_blocks() {
        let chain = seeded_chain().await;
        let svc = service(
            chain.clone(),
            MemPolicyProvider::failing(),
            ServiceMode::Enforce,
        );

        let env = svc.decide(&req(150)).await;
        let resp = env.response;
        assert_eq!(resp.decision, Decision::Block);
        assert_eq!(resp.reason_code, ReasonCode::FailClosedPolicyUnavailable);
        assert!(resp.determining_rule_ids.is_empty());
        assert!(env.error.is_some(), "gate failure must be surfaced");
        // A policy failure is NOT a verdict: no ledger entry is appended.
        assert_eq!(chain.entries().len(), 1, "only genesis");
    }

    #[tokio::test]
    async fn ledger_failure_returns_503() {
        // A chain with NO genesis: append fails with GenesisMissing — the
        // ledger-unavailable path.
        let chain = MemChain::with_agent(known_agent(true));
        let svc = service(chain.clone(), policy_provider(), ServiceMode::Enforce);

        let env = svc.decide(&req(150)).await;
        let resp = env.response;
        assert_eq!(resp.decision, Decision::Block);
        assert_eq!(resp.reason_code, ReasonCode::FailClosedLedgerUnavailable);
        assert!(matches!(
            env.error,
            Some(DecisionError::LedgerUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn replay_is_idempotent() {
        let chain = seeded_chain().await;
        let svc = service(chain.clone(), policy_provider(), ServiceMode::Enforce);

        let first = svc.decide(&req(150)).await;
        assert!(first.error.is_none());
        let second = svc.decide(&req(150)).await;

        // Same request_id → same original decision, no double append.
        assert_eq!(second.response.decision, first.response.decision);
        assert_eq!(second.response.reason_code, first.response.reason_code);
        assert_eq!(
            second.response.determining_rule_ids,
            first.response.determining_rule_ids
        );
        assert_eq!(second.response.entry_seq, first.response.entry_seq);
        assert_eq!(second.response.entry_hash, first.response.entry_hash);
        assert!(second.error.is_none());
        assert_eq!(chain.entries().len(), 2, "genesis + ONE decision entry");
    }

    #[tokio::test]
    async fn mode_never_from_client() {
        // The wire request has no mode field (models test reject_unknown_field
        // proves it); the service maps a client that TRIES to smuggle one into
        // params — the verdict must still follow the server-side mode.
        let chain = seeded_chain().await;
        let svc = service(chain.clone(), policy_provider(), ServiceMode::Enforce);

        let mut r = req(150);
        r.params = json!({"amount": 150, "mode": "shadow"});
        let env = svc.decide(&r).await;
        assert_eq!(
            env.response.decision,
            Decision::Allow,
            "params.mode must NOT flip the verdict — enforce mode stays enforce"
        );
        assert_eq!(
            chain.entries()[1].decision,
            "ALLOW",
            "the ledger records the ENFORCE verdict"
        );
        assert_eq!(chain.entries()[1].reason_code, "RULE_MATCH");
    }

    #[tokio::test]
    async fn shadow_ledgers_would_and_responds_would() {
        // flows/08 rule 2: shadow decisions ledger as WOULD_* in the real chain.
        let chain = seeded_chain().await;
        let svc = service(chain.clone(), policy_provider(), ServiceMode::Shadow);

        let env = svc.decide(&req(150)).await;
        assert!(env.error.is_none());
        assert_eq!(env.response.decision, Decision::WouldAllow);
        let last = &chain.entries()[1];
        assert_eq!(last.decision, "WOULD_ALLOW", "shadow ledgered as WOULD_*");
        assert_eq!(last.reason_code, "RULE_MATCH");
        assert_eq!(last.entry_hash, env.response.entry_hash);
    }

    #[tokio::test]
    async fn unknown_agent_blocks_but_ledgers() {
        // flows/02 step 1: unknown agent → BLOCK (AGENT_UNKNOWN), still
        // ledgered — an IN-BAND decision (HTTP 200), never engine-evaluated.
        let chain = MemChain::with_no_agent();
        crate::ledger::chain::append_genesis(&chain).await.unwrap();
        let svc = service(chain.clone(), policy_provider(), ServiceMode::Enforce);

        let env = svc.decide(&req(50)).await;
        assert!(env.error.is_none(), "in-band decision, not a gate failure");
        let resp = env.response;
        assert_eq!(resp.decision, Decision::Block);
        assert_eq!(resp.reason_code, ReasonCode::AgentUnknown);
        assert!(resp.determining_rule_ids.is_empty());
        // Still ledgered: genesis + the AGENT_UNKNOWN decision entry.
        assert_eq!(chain.entries().len(), 2);
        let last = &chain.entries()[1];
        assert_eq!(last.decision, "BLOCK");
        assert_eq!(last.reason_code, "AGENT_UNKNOWN");
        assert_eq!(last.request_id, "req_7f3a2b1c");
        assert_eq!(last.entry_hash, resp.entry_hash);
    }

    #[tokio::test]
    async fn inactive_agent_blocks_but_ledgers() {
        // flows/02 step 1: registered but inactive → BLOCK (AGENT_INACTIVE),
        // still ledgered — never engine-evaluated.
        let chain = MemChain::with_agent(known_agent(false));
        crate::ledger::chain::append_genesis(&chain).await.unwrap();
        let svc = service(chain.clone(), policy_provider(), ServiceMode::Enforce);

        let env = svc.decide(&req(50)).await;
        assert!(env.error.is_none(), "in-band decision, not a gate failure");
        let resp = env.response;
        assert_eq!(resp.decision, Decision::Block);
        assert_eq!(resp.reason_code, ReasonCode::AgentInactive);
        assert!(resp.determining_rule_ids.is_empty());
        // Still ledgered: genesis + the AGENT_INACTIVE decision entry.
        assert_eq!(chain.entries().len(), 2);
        let last = &chain.entries()[1];
        assert_eq!(last.decision, "BLOCK");
        assert_eq!(last.reason_code, "AGENT_INACTIVE");
        assert_eq!(last.entry_hash, resp.entry_hash);
    }

    #[test]
    fn derived_counter_key_is_deterministic() {
        let a = crate::engine::derive::derived_counter_key(
            "agent_daily_total_amount",
            "agent_support_09",
            "stripe.refunds.create",
            1755000000,
            "amount",
        );
        let b = crate::engine::derive::derived_counter_key(
            "agent_daily_total_amount",
            "agent_support_09",
            "stripe.refunds.create",
            1755000000,
            "amount",
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    // --- escalation integration (Flow 3 through the decision service) ------

    /// Build a service over a REAL sqlx pool so the ledger + escalation FK
    /// chain share ONE store (the append lands in the pool the FK references).
    fn sqlx_service(
        pool: sqlx::SqlitePool,
        mode: ServiceMode,
    ) -> DecisionService<Store, MemPolicyProvider, MemCounterSource, EscalationService> {
        let store = crate::storage::store::Store::from_test_pool(pool.clone());
        let escalations = std::sync::Arc::new(crate::escalation::service::EscalationService::new(
            store.clone(),
            std::sync::Arc::new(crate::clock::SystemClock),
            900,
        ));
        DecisionService::new(
            store,
            escalate_provider(),
            MemCounterSource::default(),
            escalations,
            mode,
            UngovernedDefault::Block,
            vec![],
        )
    }

    async fn seed_sqlx_agent(pool: &sqlx::SqlitePool) {
        crate::storage::store::Store::from_test_pool(pool.clone())
            .upsert_agent_identity(&known_agent(true))
            .await
            .unwrap();
    }

    /// A refund of 450 hits the escalate rule → ESCALATE + a ticket is created
    /// (enforce mode), with escalation_id + expires_at in the response.
    #[sqlx::test]
    async fn escalate_creates_ticket(pool: sqlx::SqlitePool) {
        seed_sqlx_agent(&pool).await;
        let store = crate::storage::store::Store::from_test_pool(pool.clone());
        crate::ledger::chain::append_genesis(&store).await.unwrap();
        let svc = sqlx_service(pool.clone(), ServiceMode::Enforce);

        let env = svc.decide(&req(450)).await;
        assert!(env.error.is_none(), "err: {:?}", env.error);
        let resp = env.response;
        assert_eq!(resp.decision, Decision::Escalate);
        assert_eq!(resp.reason_code, ReasonCode::RuleMatch);
        let esc_id = resp.escalation_id.expect("ticket id");
        assert!(esc_id.starts_with("esc_"), "esc_ + uuid");
        assert!(
            resp.escalation_expires_at.is_some(),
            "expires_at present on ESCALATE"
        );

        // The ticket row exists (pending) with the decision entry attached.
        let row = crate::storage::store::Store::from_test_pool(pool.clone())
            .get_escalation(&esc_id)
            .await
            .unwrap()
            .expect("ticket row");
        assert_eq!(row.status, "pending");
        assert_eq!(row.decision_entry_seq, Some(resp.entry_seq as i64));
    }

    /// Approve the ticket, retry with the SAME escalation_id + params →
    /// ALLOW (ESCALATION_APPROVED), ticket consumed, DECISION entry appended.
    #[sqlx::test]
    async fn approved_retry_allows(pool: sqlx::SqlitePool) {
        seed_sqlx_agent(&pool).await;
        let store = crate::storage::store::Store::from_test_pool(pool.clone());
        crate::ledger::chain::append_genesis(&store).await.unwrap();
        let svc = sqlx_service(pool.clone(), ServiceMode::Enforce);

        let esc = svc.decide(&req(450)).await.response;
        let esc_id = esc.escalation_id.expect("ticket");

        // Human approves via the inbox/CLI path.
        crate::storage::store::Store::from_test_pool(pool.clone())
            .resolve_escalation(&esc_id, "approved", Some("manager"), Some("ok"), None)
            .await
            .expect("approve");

        // Retry the identical call with escalation_id — a NEW request_id (the
        // retry is a new decision event; escalation_id is the correlation key).
        let mut retry = req(450);
        retry.request_id = "req_retry_1".into();
        retry.escalation_id = Some(esc_id.clone());
        let env = svc.decide(&retry).await;
        assert!(env.error.is_none(), "err: {:?}", env.error);
        assert_eq!(env.response.decision, Decision::Allow);
        assert_eq!(env.response.reason_code, ReasonCode::EscalationApproved);
        assert_eq!(env.response.escalation_id.as_deref(), Some(esc_id.as_str()));

        // Ticket consumed (single-use) — and decision_entry_seq still points
        // at the ORIGINAL ESCALATE entry (the retry's consume must NOT
        // overwrite the FK evidence link).
        let original_seq = esc.entry_seq as i64;
        let row = crate::storage::store::Store::from_test_pool(pool.clone())
            .get_escalation(&esc_id)
            .await
            .unwrap()
            .expect("ticket row");
        assert_eq!(row.status, "consumed");
        assert_eq!(
            row.decision_entry_seq,
            Some(original_seq),
            "decision_entry_seq must keep the original ESCALATE entry seq"
        );

        // A second retry → already consumed (block) — also a fresh request_id.
        let mut retry2 = req(450);
        retry2.request_id = "req_retry_2".into();
        retry2.escalation_id = Some(esc_id);
        let env2 = svc.decide(&retry2).await;
        assert_eq!(env2.response.decision, Decision::Block);
        assert_eq!(
            env2.response.reason_code,
            ReasonCode::EscalationAlreadyConsumed
        );
    }

    /// Shadow mode: ESCALATE verdict → WOULD_ESCALATE, and NO ticket is
    /// created (flows/08 rule 3: ledger + metrics only).
    #[sqlx::test]
    async fn shadow_no_ticket(pool: sqlx::SqlitePool) {
        seed_sqlx_agent(&pool).await;
        let store = crate::storage::store::Store::from_test_pool(pool.clone());
        crate::ledger::chain::append_genesis(&store).await.unwrap();
        let svc = sqlx_service(pool.clone(), ServiceMode::Shadow);

        let env = svc.decide(&req(450)).await;
        assert!(env.error.is_none(), "err: {:?}", env.error);
        assert_eq!(env.response.decision, Decision::WouldEscalate);
        assert!(
            env.response.escalation_id.is_none(),
            "shadow never creates a ticket"
        );
        assert!(env.response.escalation_expires_at.is_none());

        // The ledger entry is WOULD_ESCALATE (flows/08 rule 2).
        let last = store.last_entry().await.unwrap().expect("last entry");
        assert_eq!(last.decision, "WOULD_ESCALATE");
    }
}
