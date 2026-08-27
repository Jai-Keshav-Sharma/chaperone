//! The `chaperone` binary.
//!
//! Canonical verb list (docs/tech-stack.md):
//! init | hook | serve | gateway | shim | doctor | unhook | approve | deny |
//! escalations list | policy compile|edit|lint|test|activate |
//! ledger verify|prove|checkpoint|export | bench

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "chaperone",
    version,
    about = "Deterministic authorization gate for AI agents — seatbelts for --dangerously-skip-permissions",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// One-command local install: DB + starter policy + hook wiring + autostart.
    Init(commands::init::InitArgs),
    /// Claude Code / Cursor PreToolUse hook (stdin event → stdout verdict).
    Hook(commands::hook::HookArgs),
    /// Run the decision server (API + ledger + inbox + dashboard).
    Serve(commands::serve::ServeArgs),
    /// MCP streamable-HTTP gateway (org-wide chokepoint).
    Gateway(commands::gateway::GatewayArgs),
    /// MCP stdio shim (desktop clients).
    Shim(commands::shim::ShimArgs),
    /// Validate wiring, gate, ledger, policy — with a live enforcement canary.
    Doctor(commands::doctor::DoctorArgs),
    /// Remove the hook wiring (explicit: no audit trail, no protection).
    Unhook(commands::init::UnhookArgs),
    /// Approve an escalation.
    Approve(commands::approve::ApproveArgs),
    /// Deny an escalation.
    Deny(commands::approve::DenyArgs),
    /// Escalation inbox commands.
    Escalations(commands::approve::EscalationsArgs),
    /// Policy lifecycle commands.
    Policy(commands::policy::PolicyArgs),
    /// Ledger commands.
    Ledger(commands::ledger::LedgerArgs),
    /// Run the benchmark (Flow 10).
    Bench(commands::bench::BenchArgs),
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = rt.block_on(commands::dispatch(cli.command));
    std::process::exit(code);
}
