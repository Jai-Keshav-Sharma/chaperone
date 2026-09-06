//! The `chaperone` binary.
//!
//! Canonical verb list (docs/tech-stack.md):
//! init | hook | serve | gateway | shim | doctor | unhook | approve | deny |
//! escalations list | policy compile|edit|lint|test|activate |
//! ledger verify|prove|checkpoint|export | bench

mod commands;
mod config;
mod console;

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
    /// Run the canned mock Stripe MCP server (demo dependency).
    MockStripe(commands::mock_mcp::MockStripeArgs),
}

fn main() {
    // Load root `.env` (if present) into the process env BEFORE config/CLI
    // reads. Chaperone's own config is chaperone.yaml; `.env` is a convenience
    // for provider keys (OPENAI/GROQ/GEMINI/ANTHROPIC/OLLAMA) and nothing else.
    load_dotenv();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = rt.block_on(commands::dispatch(cli.command));
    std::process::exit(code);
}

/// Minimal `.env` loader (KEY=VALUE, `#` comments, blank lines). Values that
/// are already set in the process env are NOT overwritten (env wins over .env).
fn load_dotenv() {
    let path = std::path::Path::new(".env");
    if !path.exists() {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if key.is_empty() || std::env::var_os(key).is_some() {
            continue;
        }
        // SAFETY: only ASCII key/value from a local .env, single-threaded at
        // startup (before any other threads/processes read the env).
        unsafe { std::env::set_var(key, value) };
    }
}
