//! Shared application state for the axum app factory.

use chaperone_core::cache::policy_cache::{PolicyCache, StorePolicyProvider};
use chaperone_core::clock::Clock;
use chaperone_core::decision::service::{
    DecisionService, DerivedCounterSource, ServiceMode, UngovernedDefault,
};
use chaperone_core::engine::derive::{DerivedCounterValue, DerivedDeclaration};
use chaperone_core::escalation::service::EscalationService;
use chaperone_core::models::decision::DecisionRequest;
use chaperone_core::storage::store::Store;
use std::sync::Arc;

/// The policy cache concrete type (Phase 6.5): tier 1 in-proc + optional
/// Redis + tier 3 DB. `redis_url: null` → `None` tier (5s TTL); with Redis →
/// 30s TTL + pub/sub invalidation.
pub type PolicyCacheType = PolicyCache<StorePolicyProvider>;

/// The decision service concrete type.
pub type DecisionServiceType =
    DecisionService<Store, PolicyCacheType, NoopCounters, EscalationService>;

/// The fully-wired service graph the routes share. Cheap to clone (all fields
/// are Arc/Store handles).
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub decisions: Arc<DecisionServiceType>,
    pub escalations: Arc<EscalationService>,
    pub mode: ServiceMode,
    pub ungoverned_default: UngovernedDefault,
}

/// No derived-attribute counters in v1 (empty declarations; compute_derived
/// defaults missing attributes to 0.0).
#[derive(Clone, Default)]
pub struct NoopCounters;

impl DerivedCounterSource for NoopCounters {
    fn read(
        &self,
        _req: &DecisionRequest,
    ) -> Result<Vec<DerivedCounterValue>, chaperone_core::decision::service::DecisionError> {
        Ok(Vec::new())
    }
}

/// Assemble the app state. `mode` is server-side operator config only (an
/// agent can never self-exempt — review-4 B1).
pub fn build_state(
    store: Store,
    cache: PolicyCacheType,
    clock: Arc<dyn Clock>,
    mode: ServiceMode,
    ungoverned_default: UngovernedDefault,
    escalation_ttl_seconds: i64,
    declarations: Vec<DerivedDeclaration>,
) -> AppState {
    let escalations = Arc::new(EscalationService::new(
        store.clone(),
        clock,
        escalation_ttl_seconds,
    ));
    let decisions = Arc::new(DecisionService::new(
        store.clone(),
        cache,
        NoopCounters,
        escalations.clone(),
        mode,
        ungoverned_default,
        declarations,
    ));
    AppState {
        store,
        decisions,
        escalations,
        mode,
        ungoverned_default,
    }
}

/// The tier-3 provider the cache wraps (used by the CLI/serve wiring).
pub fn store_provider(store: Store) -> StorePolicyProvider {
    StorePolicyProvider::new(store)
}
