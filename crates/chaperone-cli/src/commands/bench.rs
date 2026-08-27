//! `chaperone bench` — the Flow 10 benchmark runner (Phase 13). Stub until
//! the bench harness lands; the verb exists for CLI completeness.

use clap::Args;

#[derive(Args, Debug)]
pub struct BenchArgs {
    /// Scenario file (scenarios.jsonl). Default: bench/gold/scenarios.jsonl.
    #[arg(long)]
    pub scenarios: Option<String>,
}

pub async fn run_bench(_args: BenchArgs) -> i32 {
    eprintln!("chaperone: bench lands with Phase 13 (Flow 10 harness)");
    1
}
