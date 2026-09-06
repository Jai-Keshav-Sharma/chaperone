//! Storage seam — sqlx-backed persistence for all 8 tables (docs/data-model.md).
//!
//! The `Store` struct is the single entry point. It wraps an inner enum that
//! dispatches to SQLite or Postgres at runtime. Embedded migrations are applied
//! on first connection (idempotent). Ledger tables remain append-only (Law 5):
//! no UPDATE/DELETE exists anywhere for them.

pub mod checkpoint_daemon;
pub mod schema;
pub mod store;

pub use store::Store;
