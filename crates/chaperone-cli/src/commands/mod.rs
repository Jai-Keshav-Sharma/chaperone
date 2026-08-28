//! Command dispatch + shared helpers.

pub mod approve;
pub mod bench;
pub mod doctor;
pub mod gateway;
pub mod hook;
pub mod init;
pub mod ledger;
pub mod policy;
pub mod serve;
pub mod shim;

use crate::Command;

/// Dispatch a parsed subcommand to its handler. Returns the process exit code.
pub async fn dispatch(command: Command) -> i32 {
    match command {
        Command::Init(args) => init::run_init(args).await,
        Command::Unhook(args) => init::run_unhook(args).await,
        Command::Hook(args) => hook::run_hook(args),
        Command::Serve(args) => serve::run_serve(args).await,
        Command::Gateway(args) => gateway::run_gateway(args).await,
        Command::Shim(args) => shim::run_shim(args).await,
        Command::Doctor(args) => doctor::run_doctor(args).await,
        Command::Approve(args) => approve::run_approve(args).await,
        Command::Deny(args) => approve::run_deny(args).await,
        Command::Escalations(args) => approve::run_escalations(args).await,
        Command::Policy(args) => policy::run_policy(args).await,
        Command::Ledger(args) => ledger::run_ledger(args).await,
        Command::Bench(args) => bench::run_bench(args).await,
    }
}

/// Open the configured SQLite store (default: ./chaperone.db). Async: every
/// caller runs inside the CLI's tokio runtime (a nested Runtime panics).
pub async fn open_store() -> Result<chaperone_core::storage::store::Store, String> {
    let path = std::env::var("CHAPERONE_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./chaperone.db".to_string());
    chaperone_core::storage::store::Store::open_sqlite(&path)
        .await
        .map_err(|e| e.to_string())
}
