//! Policy cache (Phase 6.5, flows/02 "Cache" tooling decision) — a 3-tier
//! policy cache where correctness NEVER depends on a cache.
//!
//! Tier 1: in-process parsed/compiled policy set (ALWAYS populated).
//! Tier 2: Redis shared copy + `chaperone:policy:invalidate` pub/sub.
//! Tier 3: the DB (source of truth, via storage).
//!
//! Failure semantics (flows/02): Redis down → skip to tier 3 (correct,
//! slower). DB down → FAIL_CLOSED_POLICY_UNAVAILABLE. A cache outage can never
//! change a verdict — the cache is latency optimization only.

pub mod policy_cache;
pub mod redis_tier;

pub use policy_cache::{ActivePolicy, CompiledPolicies, PolicyProvider, StorePolicyProvider};
