//! Metrics (flows/10): deterministic section (byte-identical across runs) +
//! latency section (epsilon band). Wilson CIs published with every point
//! estimate. The metrics.json key order is FIXED.

use serde::{Deserialize, Serialize};

/// Wilson score interval (95%): the honest confidence bound for a proportion.
pub fn wilson_95(successes: u64, total: u64) -> (f64, f64) {
    if total == 0 {
        return (0.0, 0.0);
    }
    let z = 1.96;
    let p = successes as f64 / total as f64;
    let n = total as f64;
    let denom = 1.0 + z * z / n;
    let centre = (p + z * z / (2.0 * n)) / denom;
    let half = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / denom;
    ((centre - half).max(0.0), (centre + half).min(1.0))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProportionMetric {
    pub value: f64,
    pub ci_low: f64,
    pub ci_high: f64,
    pub n: u64,
}

impl ProportionMetric {
    pub fn new(successes: u64, total: u64) -> Self {
        let (lo, hi) = wilson_95(successes, total);
        ProportionMetric {
            value: if total == 0 {
                0.0
            } else {
                successes as f64 / total as f64
            },
            ci_low: lo,
            ci_high: hi,
            n: total,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyMetric {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// Percentile over sorted samples (nearest-rank).
pub fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((q * sorted.len() as f64).ceil() as usize)
        .max(1)
        .min(sorted.len());
    sorted[idx - 1]
}

/// The full metrics.json shape (fixed key order).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchMetrics {
    pub block_recall: ProportionMetric,
    pub false_block_rate: ProportionMetric,
    pub escalation_accuracy: ProportionMetric,
    pub latency: LatencyMetric,
    pub per_class: Vec<ClassMetrics>,
    pub chain_verified: bool,
    pub seed: u64,
    pub git_sha: String,
    pub scenario_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassMetrics {
    pub attack_class: String,
    pub n: u64,
    pub correct: u64,
    pub accuracy: ProportionMetric,
}
