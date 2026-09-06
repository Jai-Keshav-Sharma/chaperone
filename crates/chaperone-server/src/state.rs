//! Shared application state for the axum app factory.

use chaperone_core::cache::policy_cache::{PolicyCache, StorePolicyProvider};
use chaperone_core::clock::Clock;
use chaperone_core::decision::service::{
    DecisionService, DerivedCounterSource, ServiceMode, UngovernedDefault,
};
use chaperone_core::engine::derive::{DerivedCounterValue, DerivedDeclaration, counter_key_for};
use chaperone_core::escalation::service::EscalationService;
use chaperone_core::models::decision::{Decision, DecisionRequest, DecisionResponse};
use chaperone_core::storage::store::Store;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// The policy cache concrete type (Phase 6.5): tier 1 in-proc + optional
/// Redis + tier 3 DB. `redis_url: null` → `None` tier (5s TTL); with Redis →
/// 30s TTL + pub/sub invalidation.
pub type PolicyCacheType = PolicyCache<StorePolicyProvider>;

/// The decision service concrete type.
pub type DecisionServiceType =
    DecisionService<Store, PolicyCacheType, StoreCounters, EscalationService>;

/// Live-decision broadcast (the /ws/decisions stream). A bounded channel so a
/// slow consumer is dropped (drop-on-slow-consumer, api-contracts) rather than
/// backpressuring the decision path.
pub type DecisionBroadcast = tokio::sync::broadcast::Sender<DecisionResponse>;

/// The fully-wired service graph the routes share. Cheap to clone (all fields
/// are Arc/Store handles).
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub decisions: Arc<DecisionServiceType>,
    pub escalations: Arc<EscalationService>,
    pub mode: ServiceMode,
    pub ungoverned_default: UngovernedDefault,
    pub metrics: Arc<Metrics>,
    pub broadcast: DecisionBroadcast,
}

/// Prometheus-style decision counters (flows/02 "Observability"). Atomic
/// counters are the decision-path instrumentation; the /metrics route renders
/// them in the Prometheus text format.
#[derive(Default)]
pub struct Metrics {
    /// Total decisions evaluated (all verdicts, enforce + shadow).
    pub decisions_total: AtomicU64,
    /// Allowed decisions.
    pub decisions_allow: AtomicU64,
    /// Blocked decisions.
    pub decisions_block: AtomicU64,
    /// Escalated decisions.
    pub decisions_escalate: AtomicU64,
}

impl Metrics {
    fn observe(&self, decision: Decision) {
        self.decisions_total.fetch_add(1, Ordering::Relaxed);
        match decision {
            Decision::Allow | Decision::WouldAllow => {
                self.decisions_allow.fetch_add(1, Ordering::Relaxed);
            }
            Decision::Block | Decision::WouldBlock => {
                self.decisions_block.fetch_add(1, Ordering::Relaxed);
            }
            Decision::Escalate | Decision::WouldEscalate => {
                self.decisions_escalate.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The sqlx-backed derived-counter source: reads the materialized
/// `derived_counters` index for the active declarations, keyed by the SAME
/// deterministic key the append path writes (docs/data-model.md PERF-1).
#[derive(Clone)]
pub struct StoreCounters {
    store: Store,
    declarations: Arc<Vec<DerivedDeclaration>>,
}

impl DerivedCounterSource for StoreCounters {
    async fn read(
        &self,
        req: &DecisionRequest,
    ) -> Result<Vec<DerivedCounterValue>, chaperone_core::decision::service::DecisionError> {
        let mut values = Vec::with_capacity(self.declarations.len());
        for decl in self.declarations.iter() {
            let key = counter_key_for(decl, &req.agent_id, &req.tool, &req.context.request_time);
            let value = self.store.get_derived_counter(&key).await.map_err(|e| {
                chaperone_core::decision::service::DecisionError::PolicyUnavailable(format!(
                    "derived counter read failed: {e}"
                ))
            })?;
            values.push(DerivedCounterValue {
                declaration_id: decl.id.clone(),
                value,
            });
        }
        Ok(values)
    }
}

/// Fully-specified inputs for assembling the service graph. `mode` is
/// server-side operator config only (an agent can never self-exempt — review-4
/// B1). Grouping them in one struct keeps the builder's arity stable as the
/// graph grows.
pub struct StateConfig {
    pub store: Store,
    pub cache: PolicyCacheType,
    pub clock: Arc<dyn Clock>,
    pub mode: ServiceMode,
    pub ungoverned_default: UngovernedDefault,
    pub escalation_ttl_seconds: i64,
    pub declarations: Vec<DerivedDeclaration>,
    pub notifier: Option<Arc<dyn chaperone_core::escalation::webhook::WebhookNotifier>>,
}

/// Assemble the app state without a webhook notifier (flows/02/03).
pub fn build_state(config: StateConfig) -> AppState {
    build_state_with_notifier(StateConfig {
        notifier: None,
        ..config
    })
}

/// The full builder with an optional webhook notifier (flows/03).
pub fn build_state_with_notifier(config: StateConfig) -> AppState {
    let StateConfig {
        store,
        cache,
        clock,
        mode,
        ungoverned_default,
        escalation_ttl_seconds,
        declarations,
        notifier,
    } = config;
    let escalations = match notifier {
        Some(n) => Arc::new(
            EscalationService::new(store.clone(), clock, escalation_ttl_seconds).with_notifier(n),
        ),
        None => Arc::new(EscalationService::new(
            store.clone(),
            clock,
            escalation_ttl_seconds,
        )),
    };
    let counters = StoreCounters {
        store: store.clone(),
        declarations: Arc::new(declarations.clone()),
    };
    let decisions = Arc::new(DecisionService::new(
        store.clone(),
        cache,
        counters,
        escalations.clone(),
        mode,
        ungoverned_default,
        declarations,
    ));
    // Live-decision broadcast (bounded, drop-on-slow-consumer).
    let (broadcast, _) = tokio::sync::broadcast::channel(1024);
    AppState {
        store,
        decisions,
        escalations,
        mode,
        ungoverned_default,
        metrics: Arc::new(Metrics::default()),
        broadcast,
    }
}

/// Record a decision in the observability counters + broadcast it to live
/// subscribers. Called from the decisions route AFTER a successful verdict.
pub fn observe_decision(state: &AppState, response: &DecisionResponse) {
    state.metrics.observe(response.decision);
    // A slow/absent subscriber is dropped by the broadcast channel (bounded);
    // the decision path never blocks on this send.
    let _ = state.broadcast.send(response.clone());
}

/// The tier-3 provider the cache wraps (used by the CLI/serve wiring).
pub fn store_provider(store: Store) -> StorePolicyProvider {
    StorePolicyProvider::new(store)
}
