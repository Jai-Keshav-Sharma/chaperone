//! EscalationService — the Flow 3 lifecycle: create on ESCALATE, resolve by a
//! human (approve/deny), consume on retry (single-use, params-bound).

use crate::clock::Clock;
use crate::models::decision::DecisionRequest;
use crate::models::reason_code::ReasonCode;
use crate::storage::store::{EscalationRow, Store, StoreError};
use std::sync::Arc;

/// The outcome of a retry-with-escalation_id (Flow 3 step 4 consumption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationOutcome {
    /// Approved + unconsumed + params match → the action may proceed.
    Approved,
    /// Escalation denied / expired / already consumed / not found / pending /
    /// agent or tool mismatch → block (silence = deny).
    Denied,
    /// Retry params differ from the approved params_binding_hash.
    ParamsMismatch,
}

/// The escalation lifecycle service. Writes go through the sqlx Store (the
/// row-lock `WHERE status='pending'` / `WHERE status='approved'` makes
/// concurrent approve/consume safe — flows/03 tooling).
pub struct EscalationService {
    store: Store,
    clock: Arc<dyn Clock>,
    /// TTL for new escalations (chaperone.yaml `escalation_ttl_seconds`,
    /// default 900).
    ttl_seconds: i64,
}

impl EscalationService {
    pub fn new(store: Store, clock: Arc<dyn Clock>, ttl_seconds: i64) -> Self {
        EscalationService {
            store,
            clock,
            ttl_seconds,
        }
    }

    /// Create a pending escalation (Flow 3 step 1): stores the full params for
    /// approver visibility + the canonical params_binding_hash for retry
    /// binding. The DECISION ledger entry is appended by the decision service
    /// BEFORE the ticket is attached (append-then-respond, Law 3).
    pub async fn create(
        &self,
        escalation_id: &str,
        req: &DecisionRequest,
        policy_id: &str,
        policy_version: u32,
        rule_ids: &[String],
    ) -> Result<(), StoreError> {
        let now = self.clock.now();
        let expires_at = now + chrono::Duration::seconds(self.ttl_seconds);
        let row = EscalationRow {
            escalation_id: escalation_id.to_string(),
            request_id: req.request_id.clone(),
            agent_id: req.agent_id.clone(),
            policy_id: policy_id.to_string(),
            policy_version: policy_version as i64,
            rule_ids: serde_json::to_string(rule_ids).unwrap_or_else(|_| "[]".to_string()),
            tool: req.tool.clone(),
            proposed_params: Some(crate::canonical::canonical_dumps(&req.params)),
            params_binding_hash: crate::canonical::sha256_hex(&crate::canonical::canonical_dumps(
                &req.params,
            )),
            status: "pending".to_string(),
            resolver: None,
            resolution_note: None,
            created_at: crate::clock::rfc3339_utc(now),
            expires_at: crate::clock::rfc3339_utc(expires_at),
            resolved_at: None,
            decision_entry_seq: None,
            resolution_entry_seq: None,
        };
        self.store.insert_escalation(&row).await
    }

    /// Attach the deciding ledger entry to the ticket (set decision_entry_seq).
    pub async fn attach(
        &self,
        escalation_id: String,
        decision_entry_seq: i64,
    ) -> Result<(), StoreError> {
        self.store
            .attach_escalation_entry(&escalation_id, decision_entry_seq)
            .await
    }

    /// The ticket's expiry (RFC3339) — the response's escalation_expires_at.
    pub async fn expires_at_for(&self, escalation_id: &str) -> String {
        match self.store.get_escalation(escalation_id).await {
            Ok(Some(row)) => row.expires_at,
            _ => String::new(),
        }
    }

    /// Consume an approved escalation on retry (Flow 3 step 4): validates
    /// exists · approved · unconsumed · params_binding_hash equality, then
    /// marks consumed (single-use).
    ///
    /// Returns the reason code for the retry decision:
    ///   ESCALATION_APPROVED → the action may proceed (consumed here).
    ///   ESCALATION_PARAMS_MISMATCH → params differ from the approved binding.
    ///   ESCALATION_DENIED / ESCALATION_EXPIRED / ESCALATION_ALREADY_CONSUMED
    ///   → block. Unknown / pending / agent / tool mismatch → ESCALATION_DENIED
    ///   (silence = deny).
    pub async fn consume(
        &self,
        escalation_id: &str,
        req: &DecisionRequest,
        decision_entry_seq: i64,
    ) -> Result<ReasonCode, StoreError> {
        let Some(row) = self.store.get_escalation(escalation_id).await? else {
            return Ok(ReasonCode::EscalationDenied);
        };
        // Agent and tool must match the approved call (bait-and-switch guard).
        if row.agent_id != req.agent_id || row.tool != req.tool {
            return Ok(ReasonCode::EscalationDenied);
        }
        // Params binding: canonical hash equality (semantic, key-order
        // independent — legitimate retries do not false-mismatch).
        let binding = crate::canonical::sha256_hex(&crate::canonical::canonical_dumps(&req.params));
        if binding != row.params_binding_hash {
            return Ok(ReasonCode::EscalationParamsMismatch);
        }
        match row.status.as_str() {
            "approved" => {
                self.store
                    .consume_escalation(escalation_id, decision_entry_seq)
                    .await?;
                Ok(ReasonCode::EscalationApproved)
            }
            "denied" => Ok(ReasonCode::EscalationDenied),
            "expired" => Ok(ReasonCode::EscalationExpired),
            "consumed" => Ok(ReasonCode::EscalationAlreadyConsumed),
            // "pending" → not yet decided; silence means deny.
            _ => Ok(ReasonCode::EscalationDenied),
        }
    }

    /// Sweep overdue pending escalations to expired, appending one
    /// ESCALATION_RESOLVED(EXPIRED) ledger entry each (flows/03: the sweeper
    /// appends entry_type=ESCALATION_RESOLVED, decision=EXPIRED; review-3
    /// P1-5). Append-then-mark: the ledger entry is the evidence, the row
    /// update is the state — order is sacred (append first).
    /// Returns the number expired.
    pub async fn sweep_due(&self) -> Result<u64, StoreError> {
        let now = self.clock.now();
        let rows = self.store.list_pending_escalations().await?;
        let mut expired: u64 = 0;
        for row in rows {
            let expires_at = chrono::DateTime::parse_from_rfc3339(&row.expires_at)
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::DateTime::<chrono::Utc>::MIN_UTC);
            if expires_at <= now {
                // 1. Append the ESCALATION_RESOLVED(EXPIRED) ledger entry
                //    (ChainStore is implemented by Store — same DB, same
                //    transaction boundary; the entry links the escalation).
                let entry = self.expired_resolution_entry(&row, now);
                let appended = crate::ledger::chain::append(&self.store, entry).await;
                let entry_seq = match appended {
                    Ok((seq, _)) => Some(seq as i64),
                    Err(crate::ledger::ChainError::DuplicateEntry { .. }) => {
                        // Already ledgered (idempotent sweep) — proceed to the
                        // row transition.
                        None
                    }
                    Err(e) => {
                        return Err(StoreError::NotFound(format!(
                            "ledger append failed for {}: {e}",
                            row.escalation_id
                        )));
                    }
                };
                // 2. Mark the row expired (attach the resolution seq).
                match self
                    .store
                    .resolve_escalation(&row.escalation_id, "expired", None, None, entry_seq)
                    .await
                {
                    Ok(()) => expired += 1,
                    Err(StoreError::NotFound(_)) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(expired)
    }

    /// Build the ESCALATION_RESOLVED(EXPIRED) ledger entry for a swept ticket.
    /// The preimage pins the escalation context (request_id, agent, tool,
    /// params_hash, policy) so the evidence chain ties the expiry to the
    /// original decision.
    fn expired_resolution_entry(
        &self,
        row: &EscalationRow,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::models::ledger::LedgerEntry {
        let z = "0".repeat(64);
        crate::models::ledger::LedgerEntry {
            entry_seq: 0, // chain assigns
            entry_ts: crate::clock::rfc3339_utc(now),
            previous_hash: String::new(), // chain assigns
            entry_hash: String::new(),    // chain computes
            entry_type: crate::models::ledger::EntryType::EscalationResolved,
            request_id: row.request_id.clone(),
            agent_id: row.agent_id.clone(),
            tool: row.tool.clone(),
            // params_hash is the ledger's raw-bytes hash of the params; the
            // escalation stores only the canonical binding, so the entry
            // carries the zeros placeholder + the binding in reason context.
            // (The evidence substance is the ESCALATION_RESOLVED link itself.)
            params_hash: z.clone(),
            tenant_id: None,
            decision: "EXPIRED".to_string(),
            policy_id: row.policy_id.clone(),
            policy_version: row.policy_version as u32,
            policy_hash: z.clone(),
            determining_rule_ids: Vec::new(),
            reason_code: "ESCALATION_EXPIRED".to_string(),
            decision_trace: "[]".to_string(),
            evaluation_latency_ms: 0.0,
            escalation_id: Some(row.escalation_id.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ChainStore;
    use crate::models::decision::{RequestContext, Surface};
    use crate::storage::store::Store;
    use chrono::TimeZone;
    use serde_json::json;
    use std::sync::Arc;

    fn clock() -> Arc<dyn Clock> {
        Arc::new(crate::clock::FixedClock::new(
            chrono::Utc.with_ymd_and_hms(2026, 8, 25, 14, 0, 0).unwrap(),
        ))
    }

    fn req(amount: i64) -> DecisionRequest {
        DecisionRequest {
            request_id: "req_esc".into(),
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

    fn service(pool: sqlx::SqlitePool) -> EscalationService {
        EscalationService::new(Store::from_test_pool(pool), clock(), 900)
    }

    async fn seed_agent(pool: &sqlx::SqlitePool) {
        Store::from_test_pool(pool.clone())
            .upsert_agent_identity(&crate::storage::store::AgentIdentityRow {
                agent_id: "agent_support_09".into(),
                name: "Support".into(),
                role: "support".into(),
                spiffe_id: None,
                tenant_id: None,
                max_delegation_depth: 1,
                is_active: true,
                created_at: "2026-08-25T00:00:00Z".into(),
            })
            .await
            .unwrap();
    }

    /// Seed the chain so escalation FKs (decision_entry_seq →
    /// ledger_entries.entry_seq) reference REAL entries. Returns the seq of
    /// the appended DECISION entry.
    async fn seed_chain(pool: &sqlx::SqlitePool) -> i64 {
        let store = Store::from_test_pool(pool.clone());
        crate::ledger::chain::append_genesis(&store)
            .await
            .expect("genesis");
        let (seq, _) = crate::ledger::chain::append(
            &store,
            crate::ledger::chain::tests::decision_entry(
                0,
                "req_esc",
                "ESCALATE",
                vec!["r-escalate-mid"],
                "2026-08-25T14:00:00Z",
            ),
        )
        .await
        .expect("append");
        seq as i64
    }

    #[sqlx::test]
    async fn approve_then_consume(pool: sqlx::SqlitePool) {
        seed_agent(&pool).await;
        let decision_seq = seed_chain(&pool).await;
        let svc = service(pool.clone());
        svc.create(
            "esc_1",
            &req(450),
            "pol_refunds",
            3,
            &["r-escalate-mid".into()],
        )
        .await
        .expect("create");

        // Approve the pending escalation.
        Store::from_test_pool(pool.clone())
            .resolve_escalation("esc_1", "approved", Some("manager"), Some("ok"), None)
            .await
            .expect("approve");

        // Retry with the SAME params → approved + consumed (single-use).
        let rc = svc
            .consume("esc_1", &req(450), decision_seq)
            .await
            .expect("consume");
        assert_eq!(rc, ReasonCode::EscalationApproved);

        // Second retry → already consumed.
        let rc = svc
            .consume("esc_1", &req(450), decision_seq)
            .await
            .expect("consume again");
        assert_eq!(rc, ReasonCode::EscalationAlreadyConsumed);
    }

    #[sqlx::test]
    async fn params_mismatch_blocks(pool: sqlx::SqlitePool) {
        seed_agent(&pool).await;
        let decision_seq = seed_chain(&pool).await;
        let svc = service(pool.clone());
        svc.create(
            "esc_2",
            &req(450),
            "pol_refunds",
            3,
            &["r-escalate-mid".into()],
        )
        .await
        .expect("create");

        Store::from_test_pool(pool.clone())
            .resolve_escalation("esc_2", "approved", Some("manager"), None, None)
            .await
            .expect("approve");

        // Retry with DIFFERENT params → params mismatch (bait-and-switch).
        let rc = svc
            .consume("esc_2", &req(999), decision_seq)
            .await
            .expect("consume");
        assert_eq!(rc, ReasonCode::EscalationParamsMismatch);
    }

    #[sqlx::test]
    async fn single_use_enforced(pool: sqlx::SqlitePool) {
        seed_agent(&pool).await;
        let decision_seq = seed_chain(&pool).await;
        let svc = service(pool.clone());
        svc.create(
            "esc_3",
            &req(450),
            "pol_refunds",
            3,
            &["r-escalate-mid".into()],
        )
        .await
        .expect("create");

        Store::from_test_pool(pool.clone())
            .resolve_escalation("esc_3", "approved", Some("manager"), None, None)
            .await
            .expect("approve");

        // First retry consumes; the ticket is single-use.
        assert_eq!(
            svc.consume("esc_3", &req(450), decision_seq).await.unwrap(),
            ReasonCode::EscalationApproved
        );
        assert_eq!(
            svc.consume("esc_3", &req(450), decision_seq).await.unwrap(),
            ReasonCode::EscalationAlreadyConsumed
        );
    }

    #[sqlx::test]
    async fn sweeper_expires_overdue(pool: sqlx::SqlitePool) {
        seed_agent(&pool).await;
        let store = Store::from_test_pool(pool.clone());
        crate::ledger::chain::append_genesis(&store)
            .await
            .expect("genesis");
        let svc = service(pool.clone());
        svc.create(
            "esc_4",
            &req(450),
            "pol_refunds",
            3,
            &["r-escalate-mid".into()],
        )
        .await
        .expect("create");

        // Advance the clock past the 900s TTL and sweep.
        let mut fixed = crate::clock::FixedClock::new(
            chrono::Utc.with_ymd_and_hms(2026, 8, 25, 14, 0, 0).unwrap(),
        );
        fixed.advance(chrono::Duration::seconds(901));
        let svc2 =
            EscalationService::new(Store::from_test_pool(pool.clone()), Arc::new(fixed), 900);
        let expired = svc2.sweep_due().await.expect("sweep");
        assert_eq!(expired, 1);

        // The ledger carries the ESCALATION_RESOLVED(EXPIRED) evidence entry
        // (flows/03: the sweeper appends entry_type=ESCALATION_RESOLVED,
        // decision=EXPIRED; review-3 P1-5).
        let last = store.last_entry().await.unwrap().expect("last entry");
        assert_eq!(
            last.entry_type,
            crate::models::ledger::EntryType::EscalationResolved
        );
        assert_eq!(last.decision, "EXPIRED");
        assert_eq!(last.reason_code, "ESCALATION_EXPIRED");
        assert_eq!(last.escalation_id.as_deref(), Some("esc_4"));
        assert_eq!(last.entry_seq, 1, "genesis(0) + resolution(1)");

        // The escalation is now expired; a retry blocks with ESCALATION_EXPIRED.
        let rc = svc
            .consume("esc_4", &req(450), 42)
            .await
            .expect("consume after expiry");
        assert_eq!(rc, ReasonCode::EscalationExpired);
    }
}
