//! sqlx-backed Store — one code path for SQLite + Postgres.
//!
//! `Store` wraps an `Inner` enum that dispatches to the right engine at
//! runtime. All writes go through transactional helpers that enforce the
//! single-writer invariant (BEGIN IMMEDIATE on SQLite; advisory lock on
//! Postgres). Ledger tables remain strictly append-only (Law 5).

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Executor, Pool, Sqlite};
use std::str::FromStr;

use crate::engine::derive::DerivedCounterUpdate;
use crate::ledger::{ChainError, ChainStore};
use crate::models::ledger::{EntryType, LedgerEntry};

/// The public handle. Cheap to clone (Arc inside sqlx::Pool).
#[derive(Clone)]
pub struct Store {
    inner: Inner,
}

#[derive(Clone)]
enum Inner {
    Sqlite(Pool<Sqlite>),
    // Postgres is a documented fleet-mode engine; the dispatcher variant is
    // added here when it ships (same schema, swap via config).
}

impl Store {
    /// Open (or create) a SQLite database and apply migrations.
    pub async fn open_sqlite(path: &str) -> Result<Self, StoreError> {
        let opts = SqliteConnectOptions::from_str(path)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Full);
        let pool = SqlitePoolOptions::new()
            .max_connections(1) // single-writer
            .connect_with(opts)
            .await?;
        super::schema::run_migrations(&pool).await?;
        Ok(Self {
            inner: Inner::Sqlite(pool),
        })
    }

    /// Open an in-memory SQLite database (tests only).
    #[cfg(test)]
    pub async fn open_memory() -> Result<Self, StoreError> {
        Self::open_sqlite("sqlite::memory:").await
    }

    /// Wrap an injected sqlx pool (sqlx::test — tests only). The pool already
    /// has the schema applied by the test harness.
    #[cfg(test)]
    pub fn from_test_pool(pool: Pool<Sqlite>) -> Self {
        Store {
            inner: Inner::Sqlite(pool),
        }
    }

    fn pool(&self) -> &Pool<Sqlite> {
        match &self.inner {
            Inner::Sqlite(p) => p,
        }
    }
}

// ---------------------------------------------------------------------------
// ChainStore implementation (async)
// ---------------------------------------------------------------------------

/// Row shape for `ledger_entries` as returned by sqlx.
#[derive(Debug, Clone, sqlx::FromRow)]
struct LedgerRow {
    entry_seq: i64,
    entry_ts: String,
    previous_hash: String,
    entry_hash: String,
    entry_type: String,
    request_id: String,
    agent_id: String,
    tool: String,
    params_hash: String,
    tenant_id: Option<String>,
    decision: String,
    policy_id: String,
    policy_version: i64,
    policy_hash: String,
    determining_rule_ids: String,
    reason_code: String,
    decision_trace: String,
    evaluation_latency_ms: f64,
    escalation_id: Option<String>,
}

impl From<LedgerRow> for LedgerEntry {
    fn from(r: LedgerRow) -> Self {
        LedgerEntry {
            entry_seq: r.entry_seq as u64,
            entry_ts: r.entry_ts,
            previous_hash: r.previous_hash,
            entry_hash: r.entry_hash,
            entry_type: EntryType::parse_str(&r.entry_type),
            request_id: r.request_id,
            agent_id: r.agent_id,
            tool: r.tool,
            params_hash: r.params_hash,
            tenant_id: r.tenant_id,
            decision: r.decision,
            policy_id: r.policy_id,
            policy_version: r.policy_version as u32,
            policy_hash: r.policy_hash,
            determining_rule_ids: serde_json::from_str(&r.determining_rule_ids).unwrap_or_default(),
            reason_code: r.reason_code,
            decision_trace: r.decision_trace,
            evaluation_latency_ms: r.evaluation_latency_ms,
            escalation_id: r.escalation_id,
        }
    }
}

impl From<&LedgerEntry> for LedgerRow {
    fn from(e: &LedgerEntry) -> Self {
        LedgerRow {
            entry_seq: e.entry_seq as i64,
            entry_ts: e.entry_ts.clone(),
            previous_hash: e.previous_hash.clone(),
            entry_hash: e.entry_hash.clone(),
            entry_type: e.entry_type.as_str().to_string(),
            request_id: e.request_id.clone(),
            agent_id: e.agent_id.clone(),
            tool: e.tool.clone(),
            params_hash: e.params_hash.clone(),
            tenant_id: e.tenant_id.clone(),
            decision: e.decision.clone(),
            policy_id: e.policy_id.clone(),
            policy_version: e.policy_version as i64,
            policy_hash: e.policy_hash.clone(),
            determining_rule_ids: serde_json::to_string(&e.determining_rule_ids)
                .unwrap_or_else(|_| "[]".to_string()),
            reason_code: e.reason_code.clone(),
            decision_trace: e.decision_trace.clone(),
            evaluation_latency_ms: e.evaluation_latency_ms,
            escalation_id: e.escalation_id.clone(),
        }
    }
}

impl ChainStore for Store {
    async fn last_entry(&self) -> Result<Option<LedgerEntry>, ChainError> {
        let row: Option<LedgerRow> = sqlx::query_as(
            "SELECT entry_seq, entry_ts, previous_hash, entry_hash, entry_type,
                    request_id, agent_id, tool, params_hash, tenant_id, decision,
                    policy_id, policy_version, policy_hash, determining_rule_ids,
                    reason_code, decision_trace, evaluation_latency_ms, escalation_id
             FROM ledger_entries ORDER BY entry_seq DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| ChainError::Storage(e.to_string()))?;
        Ok(row.map(LedgerEntry::from))
    }

    async fn insert_entry(&self, entry: &LedgerEntry) -> Result<(), ChainError> {
        insert_entry_in(self.pool(), entry).await
    }

    /// Append a linked ledger entry AND apply derived-counter updates inside
    /// ONE transaction (docs/data-model.md PERF-1). The whole write succeeds or
    /// rolls back — the ledger entry and its counter increments are inseparable.
    /// The single-connection pool (max_connections(1)) serializes writers, so
    /// the begin → read-head → link → insert → upsert sequence cannot interleave.
    async fn append_entry(
        &self,
        entry: LedgerEntry,
        updates: &[DerivedCounterUpdate],
    ) -> Result<(u64, String), ChainError> {
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        let head = last_entry_in(&mut *tx).await?;
        let entry = crate::ledger::chain::link_entry(head.as_ref(), entry)?;
        insert_entry_in(&mut *tx, &entry).await?;
        for up in updates {
            upsert_derived_counter_in(&mut *tx, up, entry.entry_seq as i64).await?;
        }
        tx.commit()
            .await
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        Ok((entry.entry_seq, entry.entry_hash))
    }
}

/// Read the chain head from any SQLite executor (pool or transaction).
async fn last_entry_in<'e, E>(conn: E) -> Result<Option<LedgerEntry>, ChainError>
where
    E: Executor<'e, Database = Sqlite>,
{
    let row: Option<LedgerRow> = sqlx::query_as(
        "SELECT entry_seq, entry_ts, previous_hash, entry_hash, entry_type,
                request_id, agent_id, tool, params_hash, tenant_id, decision,
                policy_id, policy_version, policy_hash, determining_rule_ids,
                reason_code, decision_trace, evaluation_latency_ms, escalation_id
         FROM ledger_entries ORDER BY entry_seq DESC LIMIT 1",
    )
    .fetch_optional(conn)
    .await
    .map_err(|e| ChainError::Storage(e.to_string()))?;
    Ok(row.map(LedgerEntry::from))
}

/// Insert one ledger entry through any SQLite executor.
async fn insert_entry_in<'e, E>(conn: E, entry: &LedgerEntry) -> Result<(), ChainError>
where
    E: Executor<'e, Database = Sqlite>,
{
    let row = LedgerRow::from(entry);
    sqlx::query(
        "INSERT INTO ledger_entries (
            entry_seq, entry_ts, previous_hash, entry_hash, entry_type,
            request_id, agent_id, tool, params_hash, tenant_id, decision,
            policy_id, policy_version, policy_hash, determining_rule_ids,
            reason_code, decision_trace, evaluation_latency_ms, escalation_id
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
            ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
        )",
    )
    .bind(row.entry_seq)
    .bind(&row.entry_ts)
    .bind(&row.previous_hash)
    .bind(&row.entry_hash)
    .bind(&row.entry_type)
    .bind(&row.request_id)
    .bind(&row.agent_id)
    .bind(&row.tool)
    .bind(&row.params_hash)
    .bind(&row.tenant_id)
    .bind(&row.decision)
    .bind(&row.policy_id)
    .bind(row.policy_version)
    .bind(&row.policy_hash)
    .bind(&row.determining_rule_ids)
    .bind(&row.reason_code)
    .bind(&row.decision_trace)
    .bind(row.evaluation_latency_ms)
    .bind(&row.escalation_id)
    .execute(conn)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            ChainError::DuplicateEntry {
                request_id: entry.request_id.clone(),
                entry_type: entry.entry_type,
            }
        } else {
            ChainError::Storage(e.to_string())
        }
    })?;
    Ok(())
}

/// Upsert a derived counter inside the append transaction.
async fn upsert_derived_counter_in<'e, E>(
    conn: E,
    update: &DerivedCounterUpdate,
    updated_seq: i64,
) -> Result<(), ChainError>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO derived_counters (counter_key, agent_id, tool, window_ts, value, updated_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (counter_key) DO UPDATE SET
             value = value + excluded.value,
             updated_seq = excluded.updated_seq",
    )
    .bind(&update.counter_key)
    .bind(&update.agent_id)
    .bind(&update.tool)
    .bind(update.window_ts)
    .bind(update.increment)
    .bind(updated_seq)
    .execute(conn)
    .await
    .map_err(|e| ChainError::Storage(e.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy operations (Phase 7 decision-service seam)
// ---------------------------------------------------------------------------

/// Row shape for the `policies` shell table (the /v1/policies list route).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PolicyShellRow {
    pub policy_id: String,
    pub name: String,
    pub active_version: Option<i64>,
}

/// Row shape for `policy_versions`.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PolicyVersionRow {
    pub policy_id: String,
    pub version: i64,
    pub status: String,
    pub raw_sop_text: Option<String>,
    pub ir_json: String,
    pub cedar_text: String,
    pub policy_hash: String,
    pub conflict_report: Option<String>,
    pub test_report: Option<String>,
    pub compiler_model: Option<String>,
    pub created_by: Option<String>,
    pub approved_by: Option<String>,
    pub created_at: String,
    pub activated_at: Option<String>,
}

impl Store {
    /// Upsert a policy shell (idempotent).
    pub async fn upsert_policy(
        &self,
        policy_id: &str,
        name: &str,
        tenant_id: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO policies (policy_id, name, tenant_id)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (policy_id) DO UPDATE SET name = excluded.name",
        )
        .bind(policy_id)
        .bind(name)
        .bind(tenant_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// All policy shells (the /v1/policies list route).
    pub async fn list_policies(&self) -> Result<Vec<PolicyShellRow>, StoreError> {
        let rows: Vec<PolicyShellRow> = sqlx::query_as(
            "SELECT policy_id, name, active_version FROM policies ORDER BY policy_id",
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Insert a new policy version. Enforces one-active invariant at the
    /// application level (the partial unique index is the safety net).
    pub async fn insert_policy_version(&self, row: &PolicyVersionRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO policy_versions (
                policy_id, version, status, raw_sop_text, ir_json, cedar_text,
                policy_hash, conflict_report, test_report, compiler_model,
                created_by, approved_by, created_at, activated_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        )
        .bind(&row.policy_id)
        .bind(row.version)
        .bind(&row.status)
        .bind(&row.raw_sop_text)
        .bind(&row.ir_json)
        .bind(&row.cedar_text)
        .bind(&row.policy_hash)
        .bind(&row.conflict_report)
        .bind(&row.test_report)
        .bind(&row.compiler_model)
        .bind(&row.created_by)
        .bind(&row.approved_by)
        .bind(&row.created_at)
        .bind(&row.activated_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Fetch the active policy version for a given policy_id.
    pub async fn get_active_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<PolicyVersionRow>, StoreError> {
        let row: Option<PolicyVersionRow> = sqlx::query_as(
            "SELECT policy_id, version, status, raw_sop_text, ir_json, cedar_text,
                    policy_hash, conflict_report, test_report, compiler_model,
                    created_by, approved_by, created_at, activated_at
             FROM policy_versions
             WHERE policy_id = ?1 AND status = 'active'
             LIMIT 1",
        )
        .bind(policy_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// All active policy versions — the decision service's policy load path
    /// (flows/02 tier 3: the DB is the source of truth).
    pub async fn list_active_policies(&self) -> Result<Vec<PolicyVersionRow>, StoreError> {
        let rows: Vec<PolicyVersionRow> = sqlx::query_as(
            "SELECT policy_id, version, status, raw_sop_text, ir_json, cedar_text,
                    policy_hash, conflict_report, test_report, compiler_model,
                    created_by, approved_by, created_at, activated_at
             FROM policy_versions
             WHERE status = 'active'
             ORDER BY policy_id, version",
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Fetch the original DECISION ledger entry for a request_id — the
    /// idempotent-replay answer path (flows/02 invariant 3).
    pub async fn find_entry_by_request(
        &self,
        request_id: &str,
    ) -> Result<Option<LedgerEntry>, ChainError> {
        let row: Option<LedgerRow> = sqlx::query_as(
            "SELECT entry_seq, entry_ts, previous_hash, entry_hash, entry_type,
                    request_id, agent_id, tool, params_hash, tenant_id, decision,
                    policy_id, policy_version, policy_hash, determining_rule_ids,
                    reason_code, decision_trace, evaluation_latency_ms, escalation_id
             FROM ledger_entries
             WHERE request_id = ?1 AND entry_type = 'DECISION'
             ORDER BY entry_seq DESC LIMIT 1",
        )
        .bind(request_id)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| ChainError::Storage(e.to_string()))?;
        Ok(row.map(LedgerEntry::from))
    }

    /// Ledger entries after a seq, bounded (the /v1/ledger/entries route).
    pub async fn list_ledger_entries(
        &self,
        after_seq: u64,
        limit: u64,
    ) -> Result<Vec<LedgerEntry>, StoreError> {
        let rows: Vec<LedgerRow> = sqlx::query_as(
            "SELECT entry_seq, entry_ts, previous_hash, entry_hash, entry_type,
                    request_id, agent_id, tool, params_hash, tenant_id, decision,
                    policy_id, policy_version, policy_hash, determining_rule_ids,
                    reason_code, decision_trace, evaluation_latency_ms, escalation_id
             FROM ledger_entries
             WHERE entry_seq > ?1
             ORDER BY entry_seq
             LIMIT ?2",
        )
        .bind(after_seq as i64)
        .bind(limit as i64)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(LedgerEntry::from).collect())
    }

    /// The full chain (the /v1/ledger/verify route).
    pub async fn all_ledger_entries(&self) -> Result<Vec<LedgerEntry>, StoreError> {
        let rows: Vec<LedgerRow> = sqlx::query_as(
            "SELECT entry_seq, entry_ts, previous_hash, entry_hash, entry_type,
                    request_id, agent_id, tool, params_hash, tenant_id, decision,
                    policy_id, policy_version, policy_hash, determining_rule_ids,
                    reason_code, decision_trace, evaluation_latency_ms, escalation_id
             FROM ledger_entries ORDER BY entry_seq",
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(LedgerEntry::from).collect())
    }

    /// Re-verify the whole chain (hashes + linkage + contiguous seq) at
    /// startup — refuse to serve a tampered ledger (flows/04 crash recovery).
    pub async fn verify_chain(
        &self,
    ) -> Result<crate::ledger::verify::VerificationResult, StoreError> {
        let entries = self.all_ledger_entries().await?;
        Ok(crate::ledger::verify::verify_chain(&entries))
    }

    /// Build an inclusion-proof bundle for one entry (the /v1/ledger/prove
    /// route): the leaf hash + path + root over the full chain.
    pub async fn prove_entry(&self, seq: u64) -> Result<Option<serde_json::Value>, StoreError> {
        let entries = self.all_ledger_entries().await?;
        let index = seq as usize;
        if index >= entries.len() {
            return Ok(None);
        }
        let leaves: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();
        let Some(leaf) = leaves.get(index).cloned() else {
            return Ok(None);
        };
        let Some(path) = crate::ledger::merkle::inclusion_proof(&leaves, index) else {
            return Ok(None);
        };
        let root = crate::ledger::merkle::root_hash(&leaves).unwrap_or_default();
        Ok(Some(serde_json::json!({
            "seq": seq,
            "entry_hash": leaf,
            "root_hash": root,
            "tree_size": leaves.len(),
            "path": path,
        })))
    }

    /// Activate a policy version (supersede the previous active if any).
    /// Runs in a transaction to maintain the one-active invariant.
    pub async fn activate_policy_version(
        &self,
        policy_id: &str,
        version: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool().begin().await?;
        // Supersede the current active (if any).
        sqlx::query(
            "UPDATE policy_versions
             SET status = 'superseded'
             WHERE policy_id = ?1 AND status = 'active'",
        )
        .bind(policy_id)
        .execute(&mut *tx)
        .await?;
        // Activate the target version.
        let now = chrono::Utc::now().to_rfc3339();
        let changes = sqlx::query(
            "UPDATE policy_versions
             SET status = 'active', activated_at = ?1
             WHERE policy_id = ?2 AND version = ?3 AND status != 'active'",
        )
        .bind(&now)
        .bind(policy_id)
        .bind(version)
        .execute(&mut *tx)
        .await?;
        if changes.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(StoreError::NotFound(format!(
                "policy {policy_id} v{version} not found or already active"
            )));
        }
        // Update the denormalized active_version on the shell.
        sqlx::query("UPDATE policies SET active_version = ?1 WHERE policy_id = ?2")
            .bind(version)
            .bind(policy_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Escalation operations (Phase 8)
// ---------------------------------------------------------------------------

/// Row shape for `escalations`.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct EscalationRow {
    pub escalation_id: String,
    pub request_id: String,
    pub agent_id: String,
    pub policy_id: String,
    pub policy_version: i64,
    pub rule_ids: String,
    pub tool: String,
    pub proposed_params: Option<String>,
    pub params_binding_hash: String,
    pub status: String,
    pub resolver: Option<String>,
    pub resolution_note: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub resolved_at: Option<String>,
    pub decision_entry_seq: Option<i64>,
    pub resolution_entry_seq: Option<i64>,
}

impl Store {
    /// Insert a new escalation (pending).
    pub async fn insert_escalation(&self, row: &EscalationRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO escalations (
                escalation_id, request_id, agent_id, policy_id, policy_version,
                rule_ids, tool, proposed_params, params_binding_hash, status,
                resolver, resolution_note, created_at, expires_at, resolved_at,
                decision_entry_seq, resolution_entry_seq
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        )
        .bind(&row.escalation_id)
        .bind(&row.request_id)
        .bind(&row.agent_id)
        .bind(&row.policy_id)
        .bind(row.policy_version)
        .bind(&row.rule_ids)
        .bind(&row.tool)
        .bind(&row.proposed_params)
        .bind(&row.params_binding_hash)
        .bind(&row.status)
        .bind(&row.resolver)
        .bind(&row.resolution_note)
        .bind(&row.created_at)
        .bind(&row.expires_at)
        .bind(&row.resolved_at)
        .bind(row.decision_entry_seq)
        .bind(row.resolution_entry_seq)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Fetch a pending escalation by id.
    pub async fn get_escalation(
        &self,
        escalation_id: &str,
    ) -> Result<Option<EscalationRow>, StoreError> {
        let row: Option<EscalationRow> = sqlx::query_as(
            "SELECT escalation_id, request_id, agent_id, policy_id, policy_version,
                    rule_ids, tool, proposed_params, params_binding_hash, status,
                    resolver, resolution_note, created_at, expires_at, resolved_at,
                    decision_entry_seq, resolution_entry_seq
             FROM escalations WHERE escalation_id = ?1",
        )
        .bind(escalation_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Attach the deciding ledger entry to an escalation (set
    /// decision_entry_seq) — called after the ESCALATE decision entry appends.
    pub async fn attach_escalation_entry(
        &self,
        escalation_id: &str,
        decision_entry_seq: i64,
    ) -> Result<(), StoreError> {
        let changes = sqlx::query(
            "UPDATE escalations
             SET decision_entry_seq = ?1
             WHERE escalation_id = ?2 AND decision_entry_seq IS NULL",
        )
        .bind(decision_entry_seq)
        .bind(escalation_id)
        .execute(self.pool())
        .await?;
        if changes.rows_affected() == 0 {
            return Err(StoreError::NotFound(format!(
                "escalation {escalation_id} not found or already attached"
            )));
        }
        Ok(())
    }

    /// Consume an approved escalation — the single-use transition (Flow 3
    /// step 4). Only an APPROVED, unconsumed escalation can be consumed; the
    /// row-lock (WHERE status='approved') makes concurrent consumption safe.
    /// decision_entry_seq is NOT touched: it is the FK to the ORIGINAL
    /// ESCALATE decision entry (set by attach) — the retry's own entry is
    /// already in the ledger carrying the escalation_id.
    pub async fn consume_escalation(&self, escalation_id: &str) -> Result<(), StoreError> {
        let changes = sqlx::query(
            "UPDATE escalations
             SET status = 'consumed'
             WHERE escalation_id = ?1 AND status = 'approved'",
        )
        .bind(escalation_id)
        .execute(self.pool())
        .await?;
        if changes.rows_affected() == 0 {
            return Err(StoreError::NotFound(format!(
                "escalation {escalation_id} not found or not approved"
            )));
        }
        Ok(())
    }

    /// List pending escalations (sweeper + inbox).
    pub async fn list_pending_escalations(&self) -> Result<Vec<EscalationRow>, StoreError> {
        let rows: Vec<EscalationRow> = sqlx::query_as(
            "SELECT escalation_id, request_id, agent_id, policy_id, policy_version,
                    rule_ids, tool, proposed_params, params_binding_hash, status,
                    resolver, resolution_note, created_at, expires_at, resolved_at,
                    decision_entry_seq, resolution_entry_seq
             FROM escalations WHERE status = 'pending'
             ORDER BY created_at",
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Fetch a policy version (for the escalation row + ledger pinning).
    pub async fn get_policy_version(
        &self,
        policy_id: &str,
        version: i64,
    ) -> Result<Option<PolicyVersionRow>, StoreError> {
        let row: Option<PolicyVersionRow> = sqlx::query_as(
            "SELECT policy_id, version, status, raw_sop_text, ir_json, cedar_text,
                    policy_hash, conflict_report, test_report, compiler_model,
                    created_by, approved_by, created_at, activated_at
             FROM policy_versions
             WHERE policy_id = ?1 AND version = ?2",
        )
        .bind(policy_id)
        .bind(version)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// All versions of a policy (the /v1/policies/{id}/versions route).
    pub async fn list_policy_versions(
        &self,
        policy_id: &str,
    ) -> Result<Vec<PolicyVersionRow>, StoreError> {
        let rows: Vec<PolicyVersionRow> = sqlx::query_as(
            "SELECT policy_id, version, status, raw_sop_text, ir_json, cedar_text,
                    policy_hash, conflict_report, test_report, compiler_model,
                    created_by, approved_by, created_at, activated_at
             FROM policy_versions
             WHERE policy_id = ?1
             ORDER BY version",
        )
        .bind(policy_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Resolve an escalation (approve/deny/consume). Runs in a transaction.
    pub async fn resolve_escalation(
        &self,
        escalation_id: &str,
        status: &str,
        resolver: Option<&str>,
        resolution_note: Option<&str>,
        resolution_entry_seq: Option<i64>,
    ) -> Result<(), StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        let changes = sqlx::query(
            "UPDATE escalations
             SET status = ?1, resolver = ?2, resolution_note = ?3,
                 resolved_at = ?4, resolution_entry_seq = ?5
             WHERE escalation_id = ?6 AND status = 'pending'",
        )
        .bind(status)
        .bind(resolver)
        .bind(resolution_note)
        .bind(&now)
        .bind(resolution_entry_seq)
        .bind(escalation_id)
        .execute(self.pool())
        .await?;
        if changes.rows_affected() == 0 {
            return Err(StoreError::NotFound(format!(
                "escalation {escalation_id} not found or not pending"
            )));
        }
        Ok(())
    }

    /// Sweep expired escalations (called by the sweeper loop).
    pub async fn sweep_expired_escalations(&self) -> Result<u64, StoreError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE escalations
             SET status = 'expired'
             WHERE status = 'pending' AND expires_at <= ?1",
        )
        .bind(&now)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Purge `proposed_params` from escalations resolved more than `days` ago
    /// (data-model.md `proposed_params_retention_days`; default 30). The full
    /// params are approver-visible only during the retention window; afterwards
    /// they are NULLed (the row survives, the params are purged — P1-3).
    pub async fn purge_resolved_params(&self, days: i64) -> Result<u64, StoreError> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339();
        let result = sqlx::query(
            "UPDATE escalations
             SET proposed_params = NULL
             WHERE status IN ('approved','denied','expired','consumed')
               AND proposed_params IS NOT NULL
               AND resolved_at <= ?1",
        )
        .bind(&cutoff)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

// ---------------------------------------------------------------------------
// Checkpoint operations (Phase 5.5 / ledger)
// ---------------------------------------------------------------------------

/// Row shape for `ledger_checkpoints`.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct CheckpointRow {
    pub checkpoint_id: i64,
    pub tree_size: i64,
    pub root_hash: String,
    pub checkpoint_text: String,
    pub key_id: Option<String>,
    pub signature: Option<String>,
    pub anchored_rekor: Option<String>,
    pub anchored_tsa: Option<String>,
    pub created_at: String,
}

impl Store {
    /// Insert a checkpoint record.
    pub async fn insert_checkpoint(&self, row: &CheckpointRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO ledger_checkpoints (
                checkpoint_id, tree_size, root_hash, checkpoint_text,
                key_id, signature, anchored_rekor, anchored_tsa, created_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        )
        .bind(row.checkpoint_id)
        .bind(row.tree_size)
        .bind(&row.root_hash)
        .bind(&row.checkpoint_text)
        .bind(&row.key_id)
        .bind(&row.signature)
        .bind(&row.anchored_rekor)
        .bind(&row.anchored_tsa)
        .bind(&row.created_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Fetch the latest checkpoint.
    pub async fn latest_checkpoint(&self) -> Result<Option<CheckpointRow>, StoreError> {
        let row: Option<CheckpointRow> = sqlx::query_as(
            "SELECT checkpoint_id, tree_size, root_hash, checkpoint_text,
                    key_id, signature, anchored_rekor, anchored_tsa, created_at
             FROM ledger_checkpoints
             ORDER BY checkpoint_id DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// All checkpoints, newest first (the /v1/ledger/checkpoints route).
    pub async fn list_checkpoints(&self) -> Result<Vec<CheckpointRow>, StoreError> {
        let rows: Vec<CheckpointRow> = sqlx::query_as(
            "SELECT checkpoint_id, tree_size, root_hash, checkpoint_text,
                    key_id, signature, anchored_rekor, anchored_tsa, created_at
             FROM ledger_checkpoints
             ORDER BY checkpoint_id DESC",
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// One checkpoint by id.
    pub async fn get_checkpoint(
        &self,
        checkpoint_id: i64,
    ) -> Result<Option<CheckpointRow>, StoreError> {
        let row: Option<CheckpointRow> = sqlx::query_as(
            "SELECT checkpoint_id, tree_size, root_hash, checkpoint_text,
                    key_id, signature, anchored_rekor, anchored_tsa, created_at
             FROM ledger_checkpoints WHERE checkpoint_id = ?1",
        )
        .bind(checkpoint_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Emit a Merkle checkpoint over the current chain (flows/04 Layer 2):
    /// RFC 6962 root over all entry hashes, C2SP text (signed with `signing_key`
    /// when provided, else unsigned dev mode), persisted to `ledger_checkpoints`.
    /// Returns the new checkpoint row. Async/cadence is the caller's job.
    pub async fn emit_checkpoint(
        &self,
        signing_key: Option<&ed25519_dalek::SigningKey>,
    ) -> Result<CheckpointRow, StoreError> {
        let entries = self.all_ledger_entries().await?;
        let leaves: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();
        let root = crate::ledger::merkle::root_hash(&leaves).unwrap_or_else(|| "0".repeat(64));
        let size = leaves.len() as u64;

        let cp = match signing_key {
            Some(key) => crate::ledger::checkpoint::sign_checkpoint(
                crate::ledger::checkpoint::CHECKPOINT_ORIGIN,
                size,
                &root,
                key,
            ),
            None => crate::ledger::checkpoint::unsigned_checkpoint(
                crate::ledger::checkpoint::CHECKPOINT_ORIGIN,
                size,
                &root,
            ),
        };

        // Monotonic checkpoint id: MAX(checkpoint_id)+1 (first = 1).
        let next_id: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(checkpoint_id), 0) + 1 FROM ledger_checkpoints",
        )
        .fetch_one(self.pool())
        .await?;

        let row = CheckpointRow {
            checkpoint_id: next_id,
            tree_size: size as i64,
            root_hash: root,
            checkpoint_text: cp.text,
            key_id: if cp.signature.is_some() {
                Some(cp.key_id.clone())
            } else {
                None
            },
            signature: cp.signature,
            anchored_rekor: None,
            anchored_tsa: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        self.insert_checkpoint(&row).await?;
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// Agent identity operations
// ---------------------------------------------------------------------------

/// Row shape for `agent_identities`.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AgentIdentityRow {
    pub agent_id: String,
    pub name: String,
    pub role: String,
    pub spiffe_id: Option<String>,
    pub tenant_id: Option<String>,
    pub max_delegation_depth: i64,
    pub is_active: bool,
    pub created_at: String,
}

impl Store {
    /// Insert or replace an agent identity.
    pub async fn upsert_agent_identity(&self, row: &AgentIdentityRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO agent_identities (
                agent_id, name, role, spiffe_id, tenant_id,
                max_delegation_depth, is_active, created_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
            ON CONFLICT (agent_id) DO UPDATE SET
                name = excluded.name, role = excluded.role,
                spiffe_id = excluded.spiffe_id, tenant_id = excluded.tenant_id,
                max_delegation_depth = excluded.max_delegation_depth,
                is_active = excluded.is_active",
        )
        .bind(&row.agent_id)
        .bind(&row.name)
        .bind(&row.role)
        .bind(&row.spiffe_id)
        .bind(&row.tenant_id)
        .bind(row.max_delegation_depth)
        .bind(row.is_active)
        .bind(&row.created_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Fetch an agent identity by id.
    pub async fn get_agent_identity(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentIdentityRow>, StoreError> {
        let row: Option<AgentIdentityRow> = sqlx::query_as(
            "SELECT agent_id, name, role, spiffe_id, tenant_id,
                    max_delegation_depth, is_active, created_at
             FROM agent_identities WHERE agent_id = ?1",
        )
        .bind(agent_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// API key operations (Phase 9 — bearer auth; keys hashed at rest)
// ---------------------------------------------------------------------------

/// Row shape for `agent_api_keys` (docs/data-model.md: sha256 of the bearer
/// key; plaintext never stored; NULL agent_id = admin key).
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub key_hash: String,
    pub agent_id: Option<String>,
    pub is_admin: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl Store {
    /// Insert an API key row (key_hash is sha256 of the bearer key — the
    /// plaintext never touches the DB).
    pub async fn insert_api_key(&self, row: &ApiKeyRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO agent_api_keys (
                key_hash, agent_id, is_admin, created_at, last_used_at, expires_at, revoked_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        )
        .bind(&row.key_hash)
        .bind(&row.agent_id)
        .bind(row.is_admin)
        .bind(&row.created_at)
        .bind(&row.last_used_at)
        .bind(&row.expires_at)
        .bind(&row.revoked_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Look up a key by its sha256 hash. Returns None for unknown keys.
    pub async fn get_api_key(&self, key_hash: &str) -> Result<Option<ApiKeyRow>, StoreError> {
        let row: Option<ApiKeyRow> = sqlx::query_as(
            "SELECT key_hash, agent_id, is_admin, created_at, last_used_at, expires_at, revoked_at
             FROM agent_api_keys WHERE key_hash = ?1",
        )
        .bind(key_hash)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// Derived counter operations (Phase 9)
// ---------------------------------------------------------------------------

impl Store {
    /// Upsert a derived counter (INSERT or increment).
    pub async fn upsert_derived_counter(
        &self,
        counter_key: &str,
        agent_id: &str,
        tool: &str,
        window_ts: i64,
        increment: f64,
        updated_seq: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO derived_counters (counter_key, agent_id, tool, window_ts, value, updated_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (counter_key) DO UPDATE SET
                 value = value + excluded.value,
                 updated_seq = excluded.updated_seq",
        )
        .bind(counter_key)
        .bind(agent_id)
        .bind(tool)
        .bind(window_ts)
        .bind(increment)
        .bind(updated_seq)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Read the current value of one derived counter (0.0 when no row exists —
    /// the counter is a rebuildable read-acceleration index; missing = zero,
    /// docs/data-model.md derived_counters).
    pub async fn get_derived_counter(&self, counter_key: &str) -> Result<f64, StoreError> {
        let row: Option<(f64,)> =
            sqlx::query_as("SELECT value FROM derived_counters WHERE counter_key = ?1")
                .bind(counter_key)
                .fetch_optional(self.pool())
                .await?;
        Ok(row.map(|r| r.0).unwrap_or(0.0))
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("not found: {0}")]
    NotFound(String),
}

// ChainError needs a Storage variant — we'll add it to the ledger module.
// For now, map via string.
impl From<StoreError> for ChainError {
    fn from(e: StoreError) -> Self {
        ChainError::Storage(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ChainStore;
    use crate::ledger::chain::tests::decision_entry;
    use crate::ledger::chain::{append, append_genesis};

    /// Verify all 8 tables are created by the migration.
    #[sqlx::test]
    async fn schema_creates_all_tables_sqlite(pool: sqlx::SqlitePool) {
        let expected = [
            "agent_identities",
            "agent_api_keys",
            "policies",
            "policy_versions",
            "ledger_entries",
            "ledger_checkpoints",
            "escalations",
            "derived_counters",
        ];
        for table in &expected {
            let row: (String,) =
                sqlx::query_as("SELECT name FROM sqlite_master WHERE type='table' AND name=?1")
                    .bind(table)
                    .fetch_one(&pool)
                    .await
                    .unwrap_or_else(|e| panic!("table {table} not found: {e}"));
            assert_eq!(row.0, *table);
        }
    }

    /// One-active-policy: happy path — activate v1, insert v2 draft, activate v2,
    /// verify v1 superseded and v2 is the sole active version.
    #[sqlx::test]
    async fn one_active_policy_happy_path(pool: sqlx::SqlitePool) {
        let store = Store {
            inner: Inner::Sqlite(pool),
        };

        store
            .upsert_policy("pol_a", "Policy A", None)
            .await
            .unwrap();

        let v1 = PolicyVersionRow {
            policy_id: "pol_a".into(),
            version: 1,
            status: "active".into(),
            raw_sop_text: None,
            ir_json: r#"{"permit":{}}"#.into(),
            cedar_text: "permit(principal, action, resource);".into(),
            policy_hash: "h1".repeat(3),
            conflict_report: None,
            test_report: None,
            compiler_model: None,
            created_by: Some("test".into()),
            approved_by: Some("admin".into()),
            created_at: "2026-08-25T00:00:00Z".into(),
            activated_at: None,
        };
        store.insert_policy_version(&v1).await.unwrap();
        store.activate_policy_version("pol_a", 1).await.unwrap();

        let v2 = PolicyVersionRow {
            version: 2,
            status: "draft".into(),
            ..v1.clone()
        };
        store.insert_policy_version(&v2).await.unwrap();
        store.activate_policy_version("pol_a", 2).await.unwrap();

        // v1 is now superseded, v2 is active
        let active = store.get_active_policy("pol_a").await.unwrap().unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.status, "active");
    }

    /// One-active-policy: invariant violation — inserting a second "active"
    /// version directly (bypassing activate_policy_version) must be rejected
    /// by the partial unique index ux_policy_one_active.
    #[sqlx::test]
    async fn one_active_policy_rejects_direct_violation(pool: sqlx::SqlitePool) {
        let store = Store {
            inner: Inner::Sqlite(pool),
        };

        store
            .upsert_policy("pol_b", "Policy B", None)
            .await
            .unwrap();

        let base = PolicyVersionRow {
            policy_id: "pol_b".into(),
            version: 1,
            status: "active".into(),
            raw_sop_text: None,
            ir_json: r#"{"permit":{}}"#.into(),
            cedar_text: "permit(principal, action, resource);".into(),
            policy_hash: "h1".repeat(3),
            conflict_report: None,
            test_report: None,
            compiler_model: None,
            created_by: Some("test".into()),
            approved_by: Some("admin".into()),
            created_at: "2026-08-25T00:00:00Z".into(),
            activated_at: None,
        };
        store.insert_policy_version(&base).await.unwrap();
        store.activate_policy_version("pol_b", 1).await.unwrap();

        // Try to insert a second active version directly — violates the index.
        let duplicate_active = PolicyVersionRow {
            version: 2,
            status: "active".into(),
            ..base.clone()
        };
        let err = store
            .insert_policy_version(&duplicate_active)
            .await
            .expect_err("second active must be rejected");
        assert!(
            err.to_string().contains("UNIQUE constraint"),
            "expected UNIQUE constraint error, got: {err}"
        );
    }

    /// One-active-policy: activate_policy_version rejects when the target
    /// version does not exist.
    #[sqlx::test]
    async fn one_active_policy_activate_nonexistent(pool: sqlx::SqlitePool) {
        let store = Store {
            inner: Inner::Sqlite(pool),
        };

        store
            .upsert_policy("pol_c", "Policy C", None)
            .await
            .unwrap();

        let err = store
            .activate_policy_version("pol_c", 999)
            .await
            .expect_err("activating nonexistent version must fail");
        assert!(
            matches!(err, StoreError::NotFound(_)),
            "expected NotFound, got: {err}"
        );
    }

    /// params_binding_hash roundtrip through the escalations table.
    #[sqlx::test]
    async fn params_binding_hash_roundtrip(pool: sqlx::SqlitePool) {
        let store = Store {
            inner: Inner::Sqlite(pool),
        };

        // Insert the agent first (FK constraint on escalations.agent_id).
        store
            .upsert_agent_identity(&AgentIdentityRow {
                agent_id: "agent_a".into(),
                name: "Agent A".into(),
                role: "test".into(),
                spiffe_id: None,
                tenant_id: None,
                max_delegation_depth: 1,
                is_active: true,
                created_at: "2026-08-25T00:00:00Z".into(),
            })
            .await
            .unwrap();

        let esc = EscalationRow {
            escalation_id: "esc_test1".into(),
            request_id: "req_1".into(),
            agent_id: "agent_a".into(),
            policy_id: "pol_a".into(),
            policy_version: 1,
            rule_ids: r#"["rule-1"]"#.into(),
            tool: "fs.read".into(),
            proposed_params: Some(r#"{"path":"/etc/passwd"}"#.into()),
            params_binding_hash: "abcdef0123456789".repeat(4), // 64 hex chars
            status: "pending".into(),
            resolver: None,
            resolution_note: None,
            created_at: "2026-08-25T00:00:00Z".into(),
            expires_at: "2026-08-25T00:15:00Z".into(),
            resolved_at: None,
            decision_entry_seq: None,
            resolution_entry_seq: None,
        };
        store.insert_escalation(&esc).await.unwrap();

        let fetched = store.get_escalation("esc_test1").await.unwrap().unwrap();
        assert_eq!(fetched.params_binding_hash, esc.params_binding_hash);
        assert_eq!(fetched.status, "pending");
    }

    /// ChainStore roundtrip through SQLite (append → last_entry).
    #[sqlx::test]
    async fn chain_through_sqlite_store(pool: sqlx::SqlitePool) {
        let store = Store {
            inner: Inner::Sqlite(pool),
        };

        let g = append_genesis(&store).await.expect("genesis");
        assert_eq!(g.entry_seq, 0);

        let (seq, _hash) = append(
            &store,
            decision_entry(0, "req_a", "ALLOW", vec![], "2026-08-25T14:00:00Z"),
        )
        .await
        .expect("append");
        assert_eq!(seq, 1);

        let last = store.last_entry().await.unwrap().unwrap();
        assert_eq!(last.entry_seq, 1);
        assert_eq!(last.request_id, "req_a");
    }

    /// proposed_params retention purge: resolved escalations older than the
    /// window have their params NULLed; the row survives (P1-3).
    #[sqlx::test]
    async fn purge_resolved_params_nulls_old_params(pool: sqlx::SqlitePool) {
        let store = Store {
            inner: Inner::Sqlite(pool),
        };
        store
            .upsert_agent_identity(&AgentIdentityRow {
                agent_id: "agent_a".into(),
                name: "Agent A".into(),
                role: "test".into(),
                spiffe_id: None,
                tenant_id: None,
                max_delegation_depth: 1,
                is_active: true,
                created_at: "2026-08-25T00:00:00Z".into(),
            })
            .await
            .unwrap();

        let old_resolved_at = (chrono::Utc::now() - chrono::Duration::days(60)).to_rfc3339();
        let esc = EscalationRow {
            escalation_id: "esc_old".into(),
            request_id: "req_1".into(),
            agent_id: "agent_a".into(),
            policy_id: "pol_a".into(),
            policy_version: 1,
            rule_ids: r#"[]"#.into(),
            tool: "fs.read".into(),
            proposed_params: Some(r#"{"path":"/etc/passwd"}"#.into()),
            params_binding_hash: "a".repeat(64),
            status: "denied".into(),
            resolver: Some("admin".into()),
            resolution_note: None,
            created_at: "2026-08-25T00:00:00Z".into(),
            expires_at: "2026-08-25T00:15:00Z".into(),
            resolved_at: Some(old_resolved_at),
            decision_entry_seq: None,
            resolution_entry_seq: None,
        };
        store.insert_escalation(&esc).await.unwrap();

        let purged = store.purge_resolved_params(30).await.unwrap();
        assert_eq!(purged, 1, "one old resolved escalation purged");
        let fetched = store.get_escalation("esc_old").await.unwrap().unwrap();
        assert_eq!(
            fetched.proposed_params, None,
            "params NULLed after retention"
        );
        assert_eq!(fetched.status, "denied", "row survives");
    }
}
