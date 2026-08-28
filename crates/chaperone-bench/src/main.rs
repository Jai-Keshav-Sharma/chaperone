//! `chaperone bench` (Flow 10): the benchmark runner CLI.

use chaperone_bench::runner;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "chaperone-bench",
    about = "Run the Chaperone benchmark (E1-E6)"
)]
struct Args {
    /// RNG seed (default 1337; pinned for reproducibility).
    #[arg(long, default_value_t = 1337)]
    seed: u64,
    /// Output path for metrics.json.
    #[arg(long, default_value = "bench/metrics.json")]
    metrics: String,
}

fn main() {
    let args = Args::parse();
    let rt = tokio::runtime::Runtime::new().expect("bench rt");
    std::process::exit(rt.block_on(runner::run_bench(args.seed, &args.metrics)));
}
