//! Per-key rate limiting (flows/02 invariant 10): a tower layer over the
//! decision endpoint applying a token bucket per authenticated API key
//! (burst + sustained). Above the ceiling → structured 429 RATE_LIMITED with
//! `retry_after_seconds`; a limited call is a non-forward (fail-closed
//! synthesis unchanged). Ceiling default aligns with scalability-targets
//! (300–1,000/sec/node).

use axum::http::Request;
use axum::response::Response;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower::{Layer, Service};

use crate::auth;
use crate::error;

/// The rate-limiter configuration (chaperone.yaml: `rate_limit_burst`,
/// `rate_limit_per_second`; defaults 1000 burst / 300 per-second sustained).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub burst: u64,
    pub per_second: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            burst: 1000,
            per_second: 300,
        }
    }
}

/// One bucket: capacity refills at `per_second` tokens/sec up to `burst`.
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(now: Instant, burst: u64) -> Self {
        // A fresh bucket starts FULL (burst available immediately) — the
        // ceiling applies to sustained rate, not to a cold start.
        Bucket {
            tokens: burst as f64,
            last_refill: now,
        }
    }

    /// Try to take one token; returns the seconds until the next token is
    /// available when denied.
    fn try_take(&mut self, burst: u64, per_second: u64, now: Instant) -> Result<(), u64> {
        // Refill: elapsed * rate, capped at burst.
        let elapsed = now.saturating_duration_since(self.last_refill);
        let refill = elapsed.as_secs_f64() * per_second as f64;
        self.tokens = (self.tokens + refill).min(burst as f64);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Seconds until the next token: (1 - tokens) / rate.
            let wait = ((1.0 - self.tokens) / per_second as f64).ceil() as u64;
            Err(wait.max(1))
        }
    }
}

/// The shared bucket map (keyed by the sha256 key hash).
#[derive(Clone, Default)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Bucket>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check one request's key. `None` key → not limited (auth handles it).
    /// Returns the retry-after seconds when over the ceiling.
    pub fn check(&self, key_hash: &str, config: RateLimitConfig) -> Result<(), u64> {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        let bucket = map
            .entry(key_hash.to_string())
            .or_insert_with(|| Bucket::new(now, config.burst));
        bucket.try_take(config.burst, config.per_second, now)
    }
}

/// The tower layer: read the Authorization header, hash the key, check the
/// bucket; 429 (RATE_LIMITED) when over the ceiling.
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: RateLimiter,
    config: RateLimitConfig,
}

impl RateLimitLayer {
    pub fn new(limiter: RateLimiter, config: RateLimitConfig) -> Self {
        RateLimitLayer { limiter, config }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
            config: self.config,
        }
    }
}

#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    limiter: RateLimiter,
    config: RateLimitConfig,
}

impl<S, B> Service<Request<B>> for RateLimitService<S>
where
    S: Service<Request<B>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = futures_util::future::BoxFuture<'static, Result<Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let key_hash = auth::bearer_header(req.headers())
            .map(|h| {
                h.strip_prefix("Bearer ")
                    .or_else(|| h.strip_prefix("bearer "))
                    .unwrap_or(h)
            })
            .map(auth::hash_key);
        let limited = key_hash.and_then(|k| self.limiter.check(&k, self.config).err());
        if let Some(wait) = limited {
            let resp = error::rate_limited(wait);
            return Box::pin(async move { Ok(resp) });
        }
        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}
