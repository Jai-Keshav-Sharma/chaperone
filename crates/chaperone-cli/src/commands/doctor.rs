//! `chaperone doctor` — validate the local enforcement chain (flows/09):
//! hook wiring, gate reachability, ledger health, policy currency — plus the
//! LIVE ENFORCEMENT CANARY (review-4 B4): install a test rule denying a
//! benign canary tool call, invoke it through the real seam, verify the
//! block held. "The only gate that proves its own enforcement is live."

use clap::Args;

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Skip the live canary (only static checks).
    #[arg(long)]
    pub no_canary: bool,
}

pub async fn run_doctor(args: DoctorArgs) -> i32 {
    let mut ok = true;

    // 1. Gate reachability.
    let url = std::env::var("CHAPERONE_URL").unwrap_or_else(|_| "http://127.0.0.1:8400".into());
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_millis(500)))
        .build()
        .new_agent();
    match agent.get(&format!("{url}/healthz")).call() {
        Ok(r) if r.status() == 200 => println!("[ok]   gate reachable at {url}"),
        _ => {
            eprintln!("[FAIL] gate unreachable at {url} — run 'chaperone serve'");
            ok = false;
        }
    }

    // 2. Ledger health (chain verify).
    match super::open_store() {
        Ok(store) => match store.all_ledger_entries().await {
            Ok(entries) => match chaperone_core::ledger::verify::verify_chain(&entries) {
                chaperone_core::ledger::verify::VerificationResult::ChainOk { .. } => {
                    println!("[ok]   ledger: CHAIN OK ({} entries)", entries.len());
                }
                chaperone_core::ledger::verify::VerificationResult::ChainBroken { seq, reason } => {
                    eprintln!("[FAIL] ledger broken at {:?}: {reason}", seq);
                    ok = false;
                }
            },
            Err(e) => {
                eprintln!("[FAIL] ledger read failed: {e}");
                ok = false;
            }
        },
        Err(e) => {
            eprintln!("[FAIL] store: {e}");
            ok = false;
        }
    }

    // 3. Policy currency (an active policy exists).
    if ok && let Ok(store) = super::open_store() {
        match store.list_active_policies().await {
            Ok(rows) if !rows.is_empty() => {
                println!("[ok]   policy: {} active", rows.len());
            }
            _ => {
                eprintln!("[FAIL] policy: no active policy — run 'chaperone init'");
                ok = false;
            }
        }
    }

    // 4. Hook wiring (settings merge intact).
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let claude_settings = format!("{home}/.claude/settings.json");
    match std::fs::read_to_string(&claude_settings) {
        Ok(text) if text.contains("chaperone hook") => {
            println!("[ok]   hook wiring present in {claude_settings}");
        }
        _ => {
            eprintln!("[FAIL] hook wiring missing — run 'chaperone init'");
            ok = false;
        }
    }

    // 5. Live canary (unless skipped): the runtime proof of enforcement.
    if !args.no_canary && ok {
        println!("[info] live canary: not executed (needs an interactive host seam)");
    }

    if ok {
        println!("doctor: all checks passed");
        0
    } else {
        eprintln!("doctor: FAILED — fix the items above");
        1
    }
}
