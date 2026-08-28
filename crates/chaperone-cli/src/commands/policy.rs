//! `chaperone policy compile|lint|activate` — policy lifecycle (flows/01).
//! compile runs the offline NL→IR pipeline with the HUMAN APPROVAL GATE:
//! nothing is written until a human approves (Law 2).

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Compile an SOP into validated IR via the offline provider (fixture in
    /// CI; anthropic/openai-compat/ollama when wired). Never auto-activates.
    Compile {
        /// Path to the SOP text file.
        sop: String,
        /// Provider: fixture (default) | anthropic | openai-compat | ollama.
        #[arg(long, default_value = "fixture")]
        provider: String,
        /// Non-interactive: write the compiled IR to this path instead of
        /// prompting (still never activates).
        #[arg(long)]
        out: Option<String>,
    },
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
        PolicyCommand::Compile { sop, provider, out } => {
            compile(&sop, &provider, out.as_deref()).await
        }
        PolicyCommand::Lint { path } => lint(&path),
        PolicyCommand::Activate { id, version } => activate(&id, version).await,
    }
}

/// The trust loop: compile → show the IR + conflict report → HUMAN APPROVE
/// → only then write the policy version as a DRAFT (never active).
async fn compile(sop_path: &str, provider: &str, out: Option<&str>) -> i32 {
    let sop = match std::fs::read_to_string(sop_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("chaperone: cannot read {sop_path}: {e}");
            return 1;
        }
    };
    let kind = match chaperone_core::compiler::providers::ProviderKind::parse(provider) {
        Some(k) => k,
        None => {
            eprintln!(
                "chaperone: unknown provider {provider:?} (fixture|anthropic|openai-compat|ollama)"
            );
            return 1;
        }
    };
    let provider_obj: Box<dyn chaperone_core::compiler::CompilerProvider> = match kind {
        chaperone_core::compiler::providers::ProviderKind::Fixture => {
            // In the CLI, the fixture needs a recorded IR — for a real SOP the
            // HTTP providers produce it. With fixture selected, we look for a
            // sibling `<sop>.ir.json` recorded response (offline CI path).
            match std::fs::read_to_string(format!("{sop_path}.ir.json")) {
                Ok(ir) => Box::new(chaperone_core::compiler::providers::FixtureProvider::new(
                    ir,
                )),
                Err(_) => {
                    eprintln!(
                        "chaperone: fixture provider needs a recorded response at {sop_path}.ir.json"
                    );
                    return 1;
                }
            }
        }
        k => Box::new(chaperone_core::compiler::providers::HttpProviderStub::new(
            k,
        )),
    };

    let result = match chaperone_core::compiler::compile_sop(provider_obj.as_ref(), &sop) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("chaperone: compile failed: {e}");
            return 1;
        }
    };

    // Show the compiled IR + conflict report for human review.
    println!("--- compiled IR (model: {}) ---", result.model);
    println!(
        "{}",
        serde_json::to_string_pretty(&result.policy).unwrap_or_default()
    );
    println!("--- conflict report ---");
    println!("{}", result.conflict_report);

    // Non-interactive: write the IR to a file (still inert — never active).
    if let Some(path) = out {
        if let Err(e) = std::fs::write(
            path,
            serde_json::to_string_pretty(&result.policy).unwrap_or_default(),
        ) {
            eprintln!("chaperone: cannot write {path}: {e}");
            return 1;
        }
        println!("chaperone: compiled IR written to {path} (draft — activate separately)");
        return 0;
    }

    // Human gate: explicit approval required (Law 2 trust loop).
    println!("Review the IR above. Type 'approve' to save as a DRAFT, anything else to abort.");
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() || line.trim() != "approve" {
        eprintln!("chaperone: compile aborted — nothing was written");
        return 1;
    }
    match write_draft(&result).await {
        Ok(()) => {
            println!(
                "chaperone: draft saved (policy {} — NOT active; run 'policy activate')",
                result.policy.policy_id
            );
            0
        }
        Err(e) => {
            eprintln!("chaperone: draft write failed: {e}");
            1
        }
    }
}

/// Write the compiled policy as a DRAFT version (never active — activation is
/// a separate explicit step).
async fn write_draft(result: &chaperone_core::compiler::CompileResult) -> Result<(), String> {
    let store = super::open_store().await?;
    let ir_json = serde_json::to_string(&result.policy).map_err(|e| e.to_string())?;
    let policy_hash =
        chaperone_core::canonical::sha256_hex(&chaperone_core::canonical::canonical_dumps(
            &serde_json::from_str::<serde_json::Value>(&ir_json).map_err(|e| e.to_string())?,
        ));
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    // Next version number = current max + 1 (draft).
    let version = store
        .list_policy_versions(&result.policy.policy_id)
        .await
        .map(|rows| rows.iter().map(|r| r.version).max().unwrap_or(0) + 1)
        .unwrap_or(1);
    store
        .insert_policy_version(&chaperone_core::storage::store::PolicyVersionRow {
            policy_id: result.policy.policy_id.clone(),
            version,
            status: "draft".into(),
            raw_sop_text: None,
            ir_json,
            cedar_text: result.cedar_text.clone(),
            policy_hash,
            conflict_report: Some(result.conflict_report.clone()),
            test_report: None,
            compiler_model: Some(result.model.clone()),
            created_by: Some("chaperone compile".into()),
            approved_by: None, // activation requires approval
            created_at: now,
            activated_at: None,
        })
        .await
        .map_err(|e| e.to_string())
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
    let store = match super::open_store().await {
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
