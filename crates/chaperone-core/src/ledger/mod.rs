pub mod anchor;
pub mod chain;
pub mod checkpoint;
pub mod export;
pub mod merkle;
pub mod proof;
pub mod verify;

use crate::models::ledger::{EntryType, LedgerEntry};

/// Errors from the append-only chain (Law 5: no UPDATE/DELETE, ever).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// append() called before genesis was written.
    GenesisMissing,
    /// append_genesis() called on a chain that already has entries.
    GenesisExists,
    /// The UNIQUE(request_id, entry_type) constraint rejected the entry — the
    /// exact idempotent-replay signal the decision service uses.
    DuplicateEntry {
        request_id: String,
        entry_type: EntryType,
    },
    /// The underlying store failed (single-writer violation, I/O, ...).
    Store(String),
    /// Storage layer error (sqlx, migrations, ...).
    Storage(String),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::GenesisMissing => write!(f, "genesis missing"),
            ChainError::GenesisExists => write!(f, "genesis already exists"),
            ChainError::DuplicateEntry {
                request_id,
                entry_type,
            } => write!(
                f,
                "duplicate entry (request_id={request_id}, entry_type={})",
                entry_type.as_str()
            ),
            ChainError::Store(msg) => write!(f, "store: {msg}"),
            ChainError::Storage(msg) => write!(f, "storage: {msg}"),
        }
    }
}

/// The storage seam for the chain (async — the sqlx implementation in
/// Phase 6/storage). Implementations MUST guarantee:
/// - single-writer semantics (SQLite WAL + BEGIN IMMEDIATE inside
///   insert_entry; Postgres advisory lock) so read-head → compute → insert
///   cannot interleave;
/// - append-only (insert only, never update/delete);
/// - UNIQUE(request_id, entry_type) enforced at insert (idempotent replay).
#[allow(async_fn_in_trait)] // auto-trait bounds are not needed on this seam
pub trait ChainStore {
    async fn last_entry(&self) -> Result<Option<LedgerEntry>, ChainError>;
    async fn insert_entry(&self, entry: &LedgerEntry) -> Result<(), ChainError>;
}
