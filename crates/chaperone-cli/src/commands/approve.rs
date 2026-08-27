//! `chaperone approve <id>`, `deny <id>`, `escalations list` — the terminal
//! inbox (flows/03). Resolutions append ESCALATION_RESOLVED ledger entries
//! via the escalation service.

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct ApproveArgs {
    /// The escalation id (esc_...).
    pub id: String,
    /// Optional resolver identity.
    #[arg(long)]
    pub resolver: Option<String>,
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Args, Debug)]
pub struct DenyArgs {
    pub id: String,
    #[arg(long)]
    pub resolver: Option<String>,
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Args, Debug)]
pub struct EscalationsArgs {
    #[command(subcommand)]
    pub command: EscalationsCommand,
}

#[derive(Subcommand, Debug)]
pub enum EscalationsCommand {
    /// List pending escalations (the inbox).
    List,
}

pub async fn run_approve(args: ApproveArgs) -> i32 {
    resolve(
        &args.id,
        "approved",
        args.resolver.as_deref(),
        args.note.as_deref(),
    )
    .await
}

pub async fn run_deny(args: DenyArgs) -> i32 {
    resolve(
        &args.id,
        "denied",
        args.resolver.as_deref(),
        args.note.as_deref(),
    )
    .await
}

pub async fn run_escalations(args: EscalationsArgs) -> i32 {
    match args.command {
        EscalationsCommand::List => {
            let store = match super::open_store() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("chaperone: cannot open store: {e}");
                    return 1;
                }
            };
            match store.list_pending_escalations().await {
                Ok(rows) => {
                    if rows.is_empty() {
                        println!("No pending escalations.");
                        return 0;
                    }
                    for r in rows {
                        println!(
                            "{}  {}  {}  {}  expires {}",
                            r.escalation_id,
                            r.tool,
                            r.agent_id,
                            r.params_binding_hash.chars().take(12).collect::<String>(),
                            r.expires_at
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("chaperone: list failed: {e}");
                    1
                }
            }
        }
    }
}

async fn resolve(id: &str, status: &str, resolver: Option<&str>, note: Option<&str>) -> i32 {
    let store = match super::open_store() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chaperone: cannot open store: {e}");
            return 1;
        }
    };
    match store
        .resolve_escalation(id, status, resolver, note, None)
        .await
    {
        Ok(()) => {
            println!("chaperone: {id} {status}");
            0
        }
        Err(chaperone_core::storage::store::StoreError::NotFound(_)) => {
            eprintln!("chaperone: {id} not found or not pending");
            1
        }
        Err(e) => {
            eprintln!("chaperone: resolve failed: {e}");
            1
        }
    }
}
