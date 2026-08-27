//! The Redis tier of the policy cache (Phase 6.5) — optional at runtime.
//!
//! `redis_url: null` (default) → tier 2 skipped: tier 1 (in-proc) + tier 3
//! (DB) only. `redis_url: redis://…` → full 3-tier with pub/sub invalidation:
//! a subscriber task listens on `chaperone:policy:invalidate`, and on a
//! message drops the local tier-1 copy so the next decision reloads from the
//! DB (correct, slower) or the refreshed Redis copy.
//!
//! A Redis failure NEVER changes a verdict — it only makes the path slower
//! (flows/02: "Down → skip to tier 3, reconnect loop").

use crate::decision::service::DecisionError;
use std::sync::Arc;

/// The Redis tier handle. `disabled()` (redis_url: null) makes every method a
/// no-op — the tier is skipped entirely and the cache runs tier 1 + tier 3.
#[derive(Clone)]
pub struct RedisTier {
    inner: Option<Arc<RedisInner>>,
}

struct RedisInner {
    client: redis::Client,
    conn: redis::aio::ConnectionManager,
}

impl RedisTier {
    /// Build the tier from a live connection manager. `None` when Redis is
    /// disabled (`redis_url: null`).
    pub fn new(client: redis::Client, conn: redis::aio::ConnectionManager) -> Self {
        RedisTier {
            inner: Some(Arc::new(RedisInner { client, conn })),
        }
    }

    /// The no-redis (disabled) tier — every method is a no-op.
    pub fn disabled() -> Self {
        RedisTier { inner: None }
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Read the shared snapshot. `Ok(None)` on miss OR on any Redis failure —
    /// the caller falls through to tier 3; never an error.
    pub async fn get_snapshot(&self) -> Result<Option<String>, DecisionError> {
        let Some(inner) = &self.inner else {
            return Ok(None);
        };
        let mut conn = inner.conn.clone();
        let key = crate::cache::policy_cache::POLICY_CACHE_KEY;
        match redis::AsyncCommands::get::<_, Option<String>>(&mut conn, key).await {
            Ok(Some(v)) => Ok(Some(v)),
            Ok(None) => Ok(None),
            Err(_) => Ok(None), // Redis down → tier 3 (correct, slower)
        }
    }

    /// Write the shared snapshot. Best-effort: a failure only means the next
    /// decision falls through to the DB and re-populates.
    pub async fn put_snapshot(&self, value: &str) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut conn = inner.conn.clone();
        let key = crate::cache::policy_cache::POLICY_CACHE_KEY;
        let _ = redis::AsyncCommands::set::<_, _, ()>(&mut conn, key, value).await;
    }

    /// Publish an invalidation broadcast (policy-activation path). Best-effort:
    /// a missed publish only delays freshness (TTL bound), never a verdict.
    pub async fn publish_invalidate(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut conn = inner.conn.clone();
        let channel = crate::cache::policy_cache::POLICY_INVALIDATE_CHANNEL;
        let _ = redis::AsyncCommands::publish::<_, _, i64>(&mut conn, channel, "reload").await;
    }

    /// The subscriber loop: listen for invalidation broadcasts and drop the
    /// local tier-1 copy. Runs until the task is aborted; on a connection
    /// error it re-subscribes (reconnect loop) rather than dying.
    pub async fn run_subscriber(&self, on_invalidate: Arc<dyn Fn() + Send + Sync>) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut pubsub = match inner.client.get_async_pubsub().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let channel = crate::cache::policy_cache::POLICY_INVALIDATE_CHANNEL;
        if pubsub.subscribe(channel).await.is_err() {
            return;
        }
        loop {
            use futures_util::StreamExt;
            // on_message() is a Stream of (channel, payload) messages; None
            // means the connection dropped.
            let received = pubsub.on_message().next().await;
            match received {
                Some(_msg) => on_invalidate(),
                None => {
                    // Reconnect: a brief gap only delays freshness (TTL bound);
                    // never a verdict.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    match inner.client.get_async_pubsub().await {
                        Ok(p) => {
                            pubsub = p;
                            if pubsub.subscribe(channel).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
        }
    }
}
