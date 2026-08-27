//! The policy cache (Phase 6.5, flows/02 "Cache" tooling decision).
//!
//! Three tiers:
//!   Tier 1 — in-process compiled policy set, TTL via the injected Clock
//!            (30s with Redis, 5s without). ALWAYS populated.
//!   Tier 2 — Redis shared copy + `chaperone:policy:invalidate` pub/sub
//!            subscriber thread (dropped from the local tier on invalidation).
//!   Tier 3 — the DB (source of truth, via `Store`).
//!
//! Failure semantics: Redis down → skip to tier 3 (correct, slower); reconnect
//! loop + full reload on reconnect. DB down → `PolicyUnavailable` — the
//! decision service maps that to FAIL_CLOSED_POLICY_UNAVAILABLE. A cache
//! outage can never change a verdict: the cache is latency optimization only.

use crate::clock::Clock;
use crate::decision::service::DecisionError;
use crate::engine::cedar_compile::TranspileError;
use crate::engine::cedar_engine::CedarEngine;
use crate::models::ir::Policy;
use crate::storage::store::{PolicyVersionRow, Store};

/// The policy source: the active policy set + the policies' byte-identity.
/// A policy's identity is its canonical IR hash — the response carries it as
/// policy_hash (docs/api-contracts.md) so every decision pins exact bytes.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ActivePolicy {
    /// The active policy document (already validated; policy_hash pinned).
    pub policy: Policy,
    /// sha256(canonical_json(ir_json)) — pinned at activation (Flow 1).
    pub policy_hash: String,
}

/// The Redis key holding the shared policy snapshot.
pub const POLICY_CACHE_KEY: &str = "chaperone:policy:set";
/// The pub/sub channel for invalidation broadcasts.
pub const POLICY_INVALIDATE_CHANNEL: &str = "chaperone:policy:invalidate";

/// The compiled policy set + its version identity (cache tier 1: always
/// populated; correctness never depends on a cache).
#[derive(Debug, Clone)]
pub struct CompiledPolicies {
    pub policies: Vec<ActivePolicy>,
    pub compiled: std::sync::Arc<CedarEngine>,
}

impl CompiledPolicies {
    /// Compile the active set. Deterministic and infallible by construction:
    /// policies are validated + linted before activation (Flow 1 walls), so a
    /// compile failure is a bug in the load path, not a request-time choice.
    pub fn compile(active: Vec<ActivePolicy>) -> Result<Self, TranspileError> {
        let raw: Vec<Policy> = active.iter().map(|a| a.policy.clone()).collect();
        let compiled = CedarEngine::compile(&raw)?;
        Ok(CompiledPolicies {
            policies: active,
            compiled: std::sync::Arc::new(compiled),
        })
    }

    pub fn engine(&self) -> &CedarEngine {
        &self.compiled
    }

    /// The identity of the governing policy — the single active policy in v1
    /// (the first in load order). None when no policy governs (the service then
    /// pins "__none__"/0/zeros per docs/data-model.md).
    pub fn governing(&self) -> Option<(&str, u32, &str)> {
        self.policies.first().map(|a| {
            (
                a.policy.policy_id.as_str(),
                a.policy.version,
                a.policy_hash.as_str(),
            )
        })
    }
}

/// The policy loader — the DB is the source of truth (cache tier 3; flows/02
/// tier 3: "Down → BLOCK (FAIL_CLOSED_POLICY_UNAVAILABLE)"). A cache outage
/// can never change a verdict. Dyn-safe (boxed future) so the server can hold
/// `Arc<dyn PolicyProvider>`.
pub trait PolicyProvider: Send + Sync {
    fn load(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CompiledPolicies, DecisionError>> + Send + '_>,
    >;
}

/// SQLite-backed loader: reads the active policy set from the Store.
pub struct StorePolicyProvider {
    store: Store,
}

impl StorePolicyProvider {
    pub fn new(store: Store) -> Self {
        StorePolicyProvider { store }
    }

    /// The async load (the trait's `load` delegates here).
    pub async fn load_async(&self) -> Result<CompiledPolicies, DecisionError> {
        let rows: Vec<PolicyVersionRow> = self
            .store
            .list_active_policies()
            .await
            .map_err(|e| DecisionError::PolicyUnavailable(e.to_string()))?;
        let mut active: Vec<ActivePolicy> = Vec::new();
        for row in rows {
            let policy: Policy = serde_json::from_str(&row.ir_json).map_err(|e| {
                DecisionError::PolicyUnavailable(format!("invalid IR for {}: {e}", row.policy_id))
            })?;
            if crate::ir::validate::validate(&policy).is_err() {
                return Err(DecisionError::PolicyUnavailable(format!(
                    "active policy {} failed validation",
                    row.policy_id
                )));
            }
            // Cedar drift check (Flow 1 wall 2/3): the pinned cedar_text is
            // regenerated + compared at load, so the compiled set always
            // matches the pinned hash.
            let regenerated = crate::engine::cedar_compile::to_cedar(&policy)
                .map_err(|e| DecisionError::PolicyCompile(e.to_string()))?
                .into_iter()
                .map(|c| c.text)
                .collect::<Vec<_>>()
                .join("\n");
            if regenerated != row.cedar_text.trim() {
                return Err(DecisionError::PolicyCompile(format!(
                    "policy {} v{} cedar_text drift",
                    row.policy_id, row.version
                )));
            }
            active.push(ActivePolicy {
                policy,
                policy_hash: row.policy_hash,
            });
        }
        CompiledPolicies::compile(active).map_err(|e| DecisionError::PolicyCompile(e.to_string()))
    }
}

impl PolicyProvider for StorePolicyProvider {
    fn load(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CompiledPolicies, DecisionError>> + Send + '_>,
    > {
        Box::pin(async move { self.load_async().await })
    }
}

/// The policy-cache facade — the decision service's single policy source.
///
/// `get()` walks the tiers in order:
///   Tier 1 (in-proc) — fresh (TTL via injected Clock) → return it.
///   Tier 2 (Redis, optional) — hit → promote to tier 1. Miss/down → tier 3.
///   Tier 3 (DB) — load, populate tier 1 (and tier 2 if available), return.
///
/// A Redis failure is never an error — it only makes the path slower
/// (correct, slower; flows/02). A DB failure surfaces as `PolicyUnavailable`,
/// which the decision service maps to FAIL_CLOSED_POLICY_UNAVAILABLE.
pub struct PolicyCache<P: PolicyProvider> {
    provider: P,
    clock: std::sync::Arc<dyn Clock>,
    ttl: std::time::Duration,
    redis: Option<std::sync::Arc<crate::cache::redis_tier::RedisTier>>,
    state: std::sync::Mutex<CacheState>,
    /// Dropped by the Redis subscriber on invalidation (pub/sub propagates).
    invalidated: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Tier-1 hit counter (observability/test hook).
    tier1_hits: std::sync::atomic::AtomicU64,
}

struct CacheState {
    compiled: Option<CompiledPolicies>,
    /// Clock timestamp of the last tier-1 population — TTL expiry is judged
    /// against the INJECTED Clock (Law 6: no wall clock in the decision path;
    /// build-plan: "TTL via injected Clock").
    loaded_at: chrono::DateTime<chrono::Utc>,
}

impl<P: PolicyProvider> PolicyCache<P> {
    /// `redis_url: null` → pass `None` (tier 2 skipped; TTL = 5s).
    /// `redis_url: Some(..)` → pass the connected tier (TTL = 30s).
    pub fn new(
        provider: P,
        clock: std::sync::Arc<dyn Clock>,
        redis: Option<std::sync::Arc<crate::cache::redis_tier::RedisTier>>,
    ) -> Self {
        // TTL: 30s with Redis, 5s without (flows/02 cache tooling decision).
        let ttl = if redis.is_some() {
            std::time::Duration::from_secs(30)
        } else {
            std::time::Duration::from_secs(5)
        };
        PolicyCache {
            provider,
            clock: clock.clone(),
            ttl,
            redis,
            state: std::sync::Mutex::new(CacheState {
                compiled: None,
                loaded_at: clock.now(),
            }),
            invalidated: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            tier1_hits: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Walk the tiers and return the compiled active set.
    pub async fn get(&self) -> Result<CompiledPolicies, DecisionError> {
        // Tier 1: fresh in-proc copy → return it.
        {
            let state = self.state.lock().unwrap();
            if let Some(c) = &state.compiled {
                let fresh = self.clock.now() - state.loaded_at
                    < chrono::Duration::from_std(self.ttl).unwrap_or_default();
                if !self.invalidated.load(std::sync::atomic::Ordering::Relaxed) && fresh {
                    self.tier1_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(c.clone());
                }
            }
        }

        // Tier 2: Redis shared copy (optional; miss/down → tier 3).
        if let Some(redis) = &self.redis
            && let Ok(Some(json)) = redis.get_snapshot().await
            && let Ok(compiled) = snapshot_from_json(&json)
        {
            self.populate_tier1(compiled.clone());
            return Ok(compiled);
        }

        // Tier 3: DB (source of truth). Failures surface as PolicyUnavailable.
        let compiled = self.provider.load().await?;
        if let Some(redis) = &self.redis
            && let Ok(json) = snapshot_json(&compiled)
        {
            redis.put_snapshot(&json).await;
        }
        self.populate_tier1(compiled.clone());
        Ok(compiled)
    }

    /// Store a fresh copy in tier 1 and clear the invalidation flag.
    fn populate_tier1(&self, compiled: CompiledPolicies) {
        let mut state = self.state.lock().unwrap();
        state.compiled = Some(compiled);
        state.loaded_at = self.clock.now();
        self.invalidated
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Drop the tier-1 copy (called by the subscriber on invalidation). The
    /// next `get()` falls through to tier 2/3 and reloads.
    pub fn invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        state.compiled = None;
        self.invalidated
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// The Redis tier handle (None when disabled) — lets the server spawn the
    /// subscriber task and publish invalidations on activation.
    pub fn redis(&self) -> Option<std::sync::Arc<crate::cache::redis_tier::RedisTier>> {
        self.redis.clone()
    }

    /// The invalidation signal the subscriber flips.
    pub fn invalidation_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.invalidated.clone()
    }

    /// The configured tier-1 TTL (used by tests via FixedClock).
    pub fn ttl(&self) -> std::time::Duration {
        self.ttl
    }

    /// Whether the cache is in the 3-tier (Redis) mode.
    pub fn has_redis(&self) -> bool {
        self.redis.is_some()
    }

    /// The number of tier-1 hits since construction (test/observability hook).
    pub fn tier1_hits(&self) -> u64 {
        self.tier1_hits.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The cache IS the policy provider for the decision service — it wraps any
/// tier-3 `PolicyProvider` and adds TTL + optional Redis. The decision service
/// uses `PolicyCache<StorePolicyProvider>` as its `P: PolicyProvider`.
impl<P: PolicyProvider + Send + Sync> PolicyProvider for PolicyCache<P> {
    fn load(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CompiledPolicies, DecisionError>> + Send + '_>,
    > {
        Box::pin(async move { self.get().await })
    }
}

/// Serialize a compiled set for the Redis tier (canonical JSON of the IR).
pub fn snapshot_json(compiled: &CompiledPolicies) -> Result<String, DecisionError> {
    let snap = PolicySetSnapshot {
        policies: compiled.policies.clone(),
    };
    serde_json::to_string(&snap).map_err(|e| DecisionError::PolicyUnavailable(e.to_string()))
}

/// Deserialize a snapshot from the Redis tier back into a compiled set.
pub fn snapshot_from_json(s: &str) -> Result<CompiledPolicies, DecisionError> {
    let snap: PolicySetSnapshot =
        serde_json::from_str(s).map_err(|e| DecisionError::PolicyUnavailable(e.to_string()))?;
    CompiledPolicies::compile(snap.policies)
        .map_err(|e| DecisionError::PolicyCompile(e.to_string()))
}

/// A serializable snapshot of the compiled set for the Redis tier.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicySetSnapshot {
    pub policies: Vec<ActivePolicy>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::models::ir::Policy;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use std::sync::Arc;

    /// A Clock the test can advance through shared state (FixedClock is
    /// &mut-advance; the cache holds it behind Arc<dyn Clock>).
    #[derive(Clone)]
    struct SharedClock(Arc<std::sync::Mutex<FixedClock>>);

    impl SharedClock {
        fn new(at: DateTime<Utc>) -> Self {
            SharedClock(Arc::new(std::sync::Mutex::new(FixedClock::new(at))))
        }
        fn advance(&self, by: Duration) {
            self.0.lock().unwrap().advance(by);
        }
    }

    impl Clock for SharedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0.lock().unwrap().now()
        }
    }

    fn fixed_clock() -> Arc<dyn Clock> {
        Arc::new(SharedClock::new(
            Utc.with_ymd_and_hms(2026, 8, 25, 14, 0, 0).unwrap(),
        ))
    }

    fn fixture_policy(id: &str, version: u32) -> Policy {
        serde_json::from_value(serde_json::json!({
            "ir_version": "1",
            "policy_id": id,
            "version": version,
            "description": "fixture",
            "rules": []
        }))
        .expect("fixture")
    }

    fn compiled(id: &str, version: u32) -> CompiledPolicies {
        CompiledPolicies::compile(vec![ActivePolicy {
            policy: fixture_policy(id, version),
            policy_hash: format!("hash-{id}-{version}"),
        }])
        .expect("compile")
    }

    /// A provider seam: returns a fixed compiled set, or fails.
    #[derive(Clone)]
    struct MemProvider {
        result: std::sync::Arc<std::sync::Mutex<Result<CompiledPolicies, DecisionError>>>,
        loads: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl MemProvider {
        fn ok(c: CompiledPolicies) -> Self {
            MemProvider {
                result: std::sync::Arc::new(std::sync::Mutex::new(Ok(c))),
                loads: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            }
        }
        fn failing() -> Self {
            MemProvider {
                result: std::sync::Arc::new(std::sync::Mutex::new(Err(
                    DecisionError::PolicyUnavailable("db down".into()),
                ))),
                loads: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            }
        }
        fn load_count(&self) -> u64 {
            self.loads.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl PolicyProvider for MemProvider {
        fn load(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<CompiledPolicies, DecisionError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                self.loads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.result.lock().unwrap().clone()
            })
        }
    }

    fn no_redis_cache(provider: MemProvider, clock: Arc<dyn Clock>) -> PolicyCache<MemProvider> {
        PolicyCache::new(provider, clock, None)
    }

    // --- the four Phase 6.5 tests ------------------------------------------

    /// Tier 3 is the source of truth; a DB failure is FAIL_CLOSED
    /// (PolicyUnavailable) — the decision service maps it to
    /// FAIL_CLOSED_POLICY_UNAVAILABLE.
    #[tokio::test]
    async fn db_down_returns_policy_unavailable() {
        let cache = no_redis_cache(MemProvider::failing(), fixed_clock());
        let err = cache.get().await.expect_err("db down must fail closed");
        assert!(matches!(err, DecisionError::PolicyUnavailable(_)));
    }

    /// Tier 1 is ALWAYS populated after the first load: a second get() hits
    /// the in-proc copy without touching the provider (tier 3).
    #[tokio::test]
    async fn in_proc_always_populated() {
        let provider = MemProvider::ok(compiled("pol_a", 1));
        let cache = no_redis_cache(provider.clone(), fixed_clock());

        let first = cache.get().await.expect("load");
        assert_eq!(provider.load_count(), 1);
        assert_eq!(
            first.governing().map(|(id, v, _)| (id, v)),
            Some(("pol_a", 1))
        );

        // Second get: served from tier 1 — the provider is not consulted.
        let second = cache.get().await.expect("cached");
        assert_eq!(provider.load_count(), 1, "tier 1 hit");
        assert_eq!(cache.tier1_hits(), 1);
        assert_eq!(
            second.governing().map(|(id, v, _)| (id, v)),
            Some(("pol_a", 1))
        );
    }

    /// TTL expiry uses the injected FixedClock (build-plan:
    /// ttl_expiry_uses_fixed_clock). Without Redis the TTL is 5s; after the
    /// clock advances past it, the next get() falls through to the provider.
    #[tokio::test]
    async fn ttl_expiry_uses_fixed_clock() {
        let provider = MemProvider::ok(compiled("pol_a", 1));
        let clock = Arc::new(SharedClock::new(
            Utc.with_ymd_and_hms(2026, 8, 25, 14, 0, 0).unwrap(),
        ));
        let cache = no_redis_cache(provider.clone(), clock.clone());

        let _ = cache.get().await.expect("load");
        assert_eq!(provider.load_count(), 1);

        // Advance the injected clock past the 5s no-redis TTL.
        clock.advance(chrono::Duration::seconds(6));

        let _ = cache.get().await.expect("reload");
        assert_eq!(provider.load_count(), 2, "TTL expired → provider reload");
    }

    /// Invalidation drops the tier-1 copy; the next get() reloads from tier 3
    /// (the pub/sub subscriber calls invalidate() on a message).
    #[tokio::test]
    async fn invalidation_drops_local_and_reloads() {
        let provider = MemProvider::ok(compiled("pol_a", 1));
        let cache = no_redis_cache(provider.clone(), fixed_clock());

        let _ = cache.get().await.expect("load");
        assert_eq!(provider.load_count(), 1);

        cache.invalidate(); // what the Redis subscriber does on a message
        let _ = cache.get().await.expect("reload");
        assert_eq!(provider.load_count(), 2, "invalidated → provider reload");
    }

    /// Tier-2 snapshot roundtrip: what is stored in Redis (canonical JSON of
    /// the IR) deserializes back into the same compiled set.
    #[test]
    fn snapshot_roundtrip() {
        let c = compiled("pol_a", 3);
        let json = snapshot_json(&c).expect("serialize");
        let back = snapshot_from_json(&json).expect("deserialize");
        assert_eq!(back.policies, c.policies);
        assert_eq!(
            back.governing().map(|(id, v, _)| (id, v)),
            Some(("pol_a", 3))
        );
    }

    /// The cache implements PolicyProvider — the decision service can use
    /// `PolicyCache<StorePolicyProvider>` as its `P: PolicyProvider`.
    #[tokio::test]
    async fn cache_as_policy_provider() {
        let provider = MemProvider::ok(compiled("pol_a", 1));
        let cache = no_redis_cache(provider.clone(), fixed_clock());

        // Use through the PolicyProvider trait (exactly how the decision service does).
        let result = PolicyProvider::load(&cache)
            .await
            .expect("load through trait");
        assert_eq!(provider.load_count(), 1);
        assert_eq!(
            result.governing().map(|(id, v, _)| (id, v)),
            Some(("pol_a", 1))
        );

        // Second call: tier-1 hit, provider not consulted.
        let result2 = PolicyProvider::load(&cache)
            .await
            .expect("cached through trait");
        assert_eq!(provider.load_count(), 1, "tier 1 hit via trait");
        assert_eq!(
            result2.governing().map(|(id, v, _)| (id, v)),
            Some(("pol_a", 1))
        );
    }
}
