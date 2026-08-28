//! `chaperone bench` — the Flow 10 benchmark runner (Phase 13). Boots a
//! throwaway gate on a fresh DB, replays the seeded corpus over HTTP, writes
//! bench/metrics.json with Wilson CIs + latency split.

use clap::Args;

#[derive(Args, Debug)]
pub struct BenchArgs {
    /// Scenario seed (default 1337; pinned for reproducibility).
    #[arg(long, default_value_t = 1337)]
    pub seed: u64,
    /// Output path for metrics.json.
    #[arg(long, default_value = "bench/metrics.json")]
    pub metrics: String,
}

pub async fn run_bench(args: BenchArgs) -> i32 {
    chaperone_bench::runner::run_bench(args.seed, &args.metrics).await
}
