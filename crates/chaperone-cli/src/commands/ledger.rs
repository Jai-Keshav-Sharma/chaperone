//! `chaperone ledger verify|prove|checkpoint|export` — the audit commands.

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct LedgerArgs {
    #[command(subcommand)]
    pub command: LedgerCommand,
}

#[derive(Subcommand, Debug)]
pub enum LedgerCommand {
    /// Verify the chain (recompute hashes + linkage). CHAIN OK / BROKEN.
    Verify {
        #[arg(long)]
        from: Option<u64>,
        #[arg(long)]
        to: Option<u64>,
    },
    /// Build an inclusion proof bundle for one entry.
    Prove {
        /// Entry sequence number.
        seq: u64,
    },
    /// Emit a Merkle checkpoint (C2SP) over the current chain.
    Checkpoint,
    /// Export an evidence pack (eu-ai-act | soc2).
    Export {
        #[arg(long, default_value = "soc2")]
        format: String,
    },
}

pub async fn run_ledger(args: LedgerArgs) -> i32 {
    let store = match super::open_store().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chaperone: cannot open store: {e}");
            return 1;
        }
    };
    match args.command {
        LedgerCommand::Verify { .. } => verify(&store).await,
        LedgerCommand::Prove { seq } => prove(&store, seq).await,
        LedgerCommand::Checkpoint => checkpoint(&store).await,
        LedgerCommand::Export { format } => export(&store, &format).await,
    }
}

async fn verify(store: &chaperone_core::storage::store::Store) -> i32 {
    let entries = match store.all_ledger_entries().await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("chaperone: ledger read failed: {e}");
            return 1;
        }
    };
    match chaperone_core::ledger::verify::verify_chain(&entries) {
        chaperone_core::ledger::verify::VerificationResult::ChainOk { .. } => {
            println!("CHAIN OK ({} entries)", entries.len());
            0
        }
        chaperone_core::ledger::verify::VerificationResult::ChainBroken { seq, reason } => {
            println!(
                "CHAIN BROKEN at seq {}: {}",
                seq.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                reason
            );
            1
        }
    }
}

async fn prove(store: &chaperone_core::storage::store::Store, seq: u64) -> i32 {
    match store.prove_entry(seq).await {
        Ok(Some(bundle)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&bundle).unwrap_or_default()
            );
            0
        }
        _ => {
            eprintln!("chaperone: no entry at seq {seq}");
            1
        }
    }
}

async fn checkpoint(store: &chaperone_core::storage::store::Store) -> i32 {
    let entries = match store.all_ledger_entries().await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("chaperone: ledger read failed: {e}");
            return 1;
        }
    };
    let leaves: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();
    let root = chaperone_core::ledger::merkle::root_hash(&leaves).unwrap_or_default();
    let size = leaves.len() as u64;
    // Unsigned dev checkpoint (the signing key path lands with config wiring).
    let body = chaperone_core::ledger::checkpoint::note_body(
        chaperone_core::ledger::checkpoint::CHECKPOINT_ORIGIN,
        size,
        &root,
    );
    println!("{body}");
    println!("chaperone: checkpoint covers {size} entries (unsigned dev mode)");
    0
}

async fn export(store: &chaperone_core::storage::store::Store, format: &str) -> i32 {
    let entries = match store.all_ledger_entries().await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("chaperone: ledger read failed: {e}");
            return 1;
        }
    };
    let fmt = match format {
        "eu-ai-act" => chaperone_core::ledger::export::ExportFormat::EuAiAct,
        "soc2" => chaperone_core::ledger::export::ExportFormat::Soc2,
        other => {
            eprintln!("chaperone: unknown export format {other:?} (eu-ai-act|soc2)");
            return 1;
        }
    };
    // The entries JSONL is the substantive evidence; checkpoint + policy-version
    // manifests are included from the model types.
    let bundle =
        chaperone_core::ledger::export::build_export(&entries, &[], &serde_json::json!([]), fmt);
    println!(
        "{}",
        serde_json::to_string_pretty(&bundle).unwrap_or_default()
    );
    0
}
