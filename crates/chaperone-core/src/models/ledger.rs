use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Ledger entry types (docs/data-model.md ledger_entries.entry_type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryType {
    Genesis,
    Decision,
    EscalationResolved,
    Checkpoint,
}

impl EntryType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryType::Genesis => "GENESIS",
            EntryType::Decision => "DECISION",
            EntryType::EscalationResolved => "ESCALATION_RESOLVED",
            EntryType::Checkpoint => "CHECKPOINT",
        }
    }
}

/// One ledger row (docs/data-model.md ledger_entries) — the hash-chain node.
///
/// PREIMAGE FIELDS (docs/flows/04 — hashed via canonical_dumps, Law 4):
/// seq, ts, prev, entry_type, request_id, agent_id, tool, params_hash,
/// decision, policy_id, policy_version, policy_hash, determining_rule_ids,
/// reason_code. Everything else (trace, latency, tenant_id, escalation_id)
/// is stored but NOT hashed — the auditable substance is inside the preimage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Writer-assigned, NOT autoincrement (chain computes it from the head).
    pub entry_seq: u64,
    /// RFC3339 UTC; part of the preimage, stored exactly as hashed.
    pub entry_ts: String,
    pub previous_hash: String,
    pub entry_hash: String,
    pub entry_type: EntryType,
    pub request_id: String,
    pub agent_id: String,
    /// Universal tool namespace.
    pub tool: String,
    /// sha256 of RAW params bytes as received (never null) — DISTINCT from
    /// escalations.params_binding_hash (canonical, retry binding).
    pub params_hash: String,
    /// Unused in logic; multi-tenant fleet insurance. NOT in the preimage.
    pub tenant_id: Option<String>,
    /// ALLOW|BLOCK|ESCALATE|WOULD_*|APPROVED|DENIED|EXPIRED (VARCHAR(32) —
    /// a string so future values never silently truncate).
    pub decision: String,
    /// "__none__" when no policy applies.
    pub policy_id: String,
    pub policy_version: u32,
    /// sha256(canonical(ir_json)); all-zeros when no policy.
    pub policy_hash: String,
    /// JSON array, sorted. In the preimage.
    pub determining_rule_ids: Vec<String>,
    pub reason_code: String,
    /// JSON; REDACTED (rule ids, match booleans, operand paths — never raw
    /// values, Law 9). NOT in the preimage.
    pub decision_trace: String,
    /// NOT in the preimage.
    pub evaluation_latency_ms: f64,
    pub escalation_id: Option<String>,
}
