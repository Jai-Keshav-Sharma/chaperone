//! Chaperone benchmark harness (Flow 10 / Phase 13).
//!
//! Produces every published number: E1 enforcement efficacy, E2 latency,
//! E3 policy currency, E4 compiler fidelity, E5 tamper evidence, E6
//! determinism. The scenario corpus is the dataset - seeded, checked in,
//! externally auditable.

pub mod attacks;
pub mod gold;
pub mod metrics;
pub mod runner;
pub mod schema;
pub mod tools;
