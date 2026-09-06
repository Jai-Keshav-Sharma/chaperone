//! Escalation & human-in-the-loop (Flow 3) — lifecycle service + sweeper.
//!
//! Lifecycle: pending → approved|denied|expired → consumed (single-use).
//! The sweep of overdue escalations appends ESCALATION_RESOLVED(EXPIRED)
//! ledger entries (flows/03: "SILENCE ALWAYS MEANS DENY"). Retries bind to
//! the canonical params hash (params_binding_hash) — bait-and-switch is
//! impossible (Flow 3 invariant 2, Law 4).

pub mod service;
pub mod sweeper;
pub mod webhook;
