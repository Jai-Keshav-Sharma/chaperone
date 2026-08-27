//! `chaperone policy lint|activate` — policy lifecycle (compile/edit/test land
//! with the Phase 11 compiler; lint + activate are library-backed now).

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Lint an IR policy file (static analysis; ERROR/WARN findings).
    Lint {
        /// Path to the policy IR JSON file.
        path: String,
    },
    /// Activate a policy version (admin).
    Activate {
        /// Policy id.
        id: String,
        /// Version to activate.
        version: i64,
    },
}

pub async fn run_policy(args: PolicyArgs) -> i32 {
    match args.command {
        PolicyCommand::Lint { path } => lint(&path),
        PolicyCommand::Activate { id, version } => activate(&id, version).await,
    }
}

fn lint(path: &str) -> i32 {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("chaperone: cannot read {path}: {e}");
            return 1;
        }
    };
    let policies: Vec<chaperone_core::models::ir::Policy> = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("chaperone: invalid policy IR: {e}");
            return 1;
        }
    };
    // Validation is a precondition of lint (wall 1).
    for p in &policies {
        if let Err(errs) = chaperone_core::ir::validate::validate(p) {
            for e in errs {
                eprintln!(
                    "chaperone: validation error [{:?}] rule {}: {}",
                    e.code,
                    e.rule_id.as_deref().unwrap_or("-"),
                    e.message
                );
            }
            return 1;
        }
    }
    let findings = chaperone_core::ir::lint::lint(&policies, &[]);
    if findings.is_empty() {
        println!("chaperone: lint clean ({} policies)", policies.len());
        return 0;
    }
    let mut bad = false;
    for f in findings {
        let level = match f.severity {
            chaperone_core::ir::lint::Severity::Error => {
                bad = true;
                "ERROR"
            }
            chaperone_core::ir::lint::Severity::Warn => "WARN",
        };
        println!("{level} [{:?}] {}", f.code, f.message);
    }
    if bad {
        eprintln!("chaperone: lint failed with errors");
        1
    } else {
        0
    }
}

async fn activate(id: &str, version: i64) -> i32 {
    let store = match super::open_store() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chaperone: cannot open store: {e}");
            return 1;
        }
    };
    match store.activate_policy_version(id, version).await {
        Ok(()) => {
            println!("chaperone: policy {id} v{version} activated");
            0
        }
        Err(e) => {
            eprintln!("chaperone: activation failed: {e}");
            1
        }
    }
}
