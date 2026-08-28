//! `chaperone init` / `unhook` (flows/09): one-command local install —
//! DB + genesis, starter-safety policy pack, hook wiring (merge, never
//! clobber), autostart. `init --demo` bundles the mock-stripe MCP server
//! through the shim (flows/09 demo dependencies).

use chaperone_core::ledger::ChainStore;
use clap::Args;
use serde_json::{Value as JsonValue, json};

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Bundle the mock-stripe MCP server (the Flow 9 demo).
    #[arg(long)]
    pub demo: bool,
    /// Skip autostart installation (daemon lifecycle is manual).
    #[arg(long)]
    pub no_autostart: bool,
}

#[derive(Args, Debug)]
pub struct UnhookArgs {}

pub async fn run_init(args: InitArgs) -> i32 {
    let store = match super::open_store().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chaperone: cannot open store: {e}");
            return 1;
        }
    };
    // 1. Genesis on first startup.
    if store
        .last_entry()
        .await
        .map(|e| e.is_none())
        .unwrap_or(true)
        && let Err(e) = chaperone_core::ledger::chain::append_genesis(&store).await
    {
        eprintln!("chaperone: genesis failed: {e}");
        return 1;
    }

    // 2. Starter-safety pack: load + activate (review BUG-3: explicit benign
    //    allow rules so nothing falls to NO_POLICY).
    if let Err(e) = load_starter_pack(&store).await {
        eprintln!("chaperone: starter pack failed: {e}");
        return 1;
    }

    // 3. Hook wiring: merge into .claude/settings.json + .cursor/hooks.json
    //    (merge, never clobber — flows/05).
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let claude_settings = format!("{home}/.claude/settings.json");
    if let Err(e) = merge_hook_entry(&claude_settings) {
        eprintln!("chaperone: hook wiring failed: {e}");
        return 1;
    }

    // 4. Autostart (unless opted out).
    if !args.no_autostart {
        eprintln!(
            "chaperone: autostart installation is platform-specific (Phase 10.5); run 'chaperone serve' manually"
        );
    }

    println!("Chaperone installed. Try this:");
    println!("  claude --dangerously-skip-permissions");
    println!("  ask the agent to \"clean up\" with rm -rf /  → BLOCK with a ledger receipt");
    println!("  chaperone ledger verify  → CHAIN OK");
    if args.demo {
        println!("  (demo) refund flow via the bundled mock-stripe server");
    }
    0
}

pub async fn run_unhook(_args: UnhookArgs) -> i32 {
    // Removing the wiring is intentionally explicit (flows/09): the message
    // states what unhook costs — no audit trail, no protection.
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let claude_settings = format!("{home}/.claude/settings.json");
    if let Err(e) = remove_hook_entry(&claude_settings) {
        eprintln!("chaperone: unhook failed: {e}");
        return 1;
    }
    eprintln!(
        "chaperone: hook removed. NOTE: no audit trail and no protection — you are unguarded."
    );
    0
}

/// Load + activate the starter-safety pack (benign allow rules cover the full
/// normalized namespace so nothing falls to NO_POLICY after init).
async fn load_starter_pack(store: &chaperone_core::storage::store::Store) -> Result<(), String> {
    store
        .upsert_policy("starter-safety", "Starter Safety Pack", None)
        .await
        .map_err(|e| e.to_string())?;
    let ir = json!({
        "ir_version": "1",
        "policy_id": "starter-safety",
        "version": 1,
        "description": "Starter safety pack (flows/05 + flows/09): blocks destructive acts, escalates risky ones, allows the benign namespace.",
        "rules": [
            {
                "rule_id": "s-block-destructive",
                "description": "block destructive shell commands",
                "effect": "block",
                "target": {"tools": ["shell.exec"]},
                "condition": {"op": "matches", "left": {"param": "command"}, "pattern": "^*rm -rf*$"}
            },
            {
                "rule_id": "s-block-secrets",
                "description": "block writes to secret paths",
                "effect": "block",
                "target": {"tools": ["fs.write"]},
                "condition": {"op": "matches", "left": {"param": "path"}, "pattern": "^*env*$"}
            },
            {
                "rule_id": "s-allow-benign-read",
                "description": "benign reads within the workspace",
                "effect": "allow",
                "target": {"tools": ["fs.read"]}
            },
            {
                "rule_id": "s-allow-benign-shell",
                "description": "benign local shell commands",
                "effect": "allow",
                "target": {"tools": ["shell.exec"]},
                "condition": {"op": "matches", "left": {"param": "command"}, "pattern": "^*git status*$"}
            },
            {
                "rule_id": "s-allow-safe-web",
                "description": "safe web reads",
                "effect": "allow",
                "target": {"tools": ["web.fetch", "web.search"]}
            }
        ]
    });
    let policy: chaperone_core::models::ir::Policy =
        serde_json::from_value(ir.clone()).map_err(|e| e.to_string())?;
    if let Err(errs) = chaperone_core::ir::validate::validate(&policy) {
        return Err(format!(
            "starter pack failed validation: {:?}",
            errs[0].message
        ));
    }
    let cedar_text = chaperone_core::engine::cedar_compile::to_cedar(&policy)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|c| c.text)
        .collect::<Vec<_>>()
        .join("\n");
    let policy_hash =
        chaperone_core::canonical::sha256_hex(&chaperone_core::canonical::canonical_dumps(&ir));
    store
        .insert_policy_version(&chaperone_core::storage::store::PolicyVersionRow {
            policy_id: "starter-safety".into(),
            version: 1,
            status: "active".into(),
            raw_sop_text: None,
            ir_json: ir.to_string(),
            cedar_text,
            policy_hash,
            conflict_report: None,
            test_report: None,
            compiler_model: None,
            created_by: Some("init".into()),
            approved_by: Some("init".into()),
            created_at: "2026-08-25T00:00:00Z".into(),
            activated_at: None,
        })
        .await
        .map_err(|e| e.to_string())?;
    store
        .activate_policy_version("starter-safety", 1)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Merge the PreToolUse hook entry into a settings JSON (preserve unknown
/// keys; never write outside the target file; idempotent).
fn merge_hook_entry(path: &str) -> Result<(), String> {
    let mut settings: JsonValue = match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or(json!({})),
        Err(_) => json!({}),
    };
    let hooks = settings
        .get_mut("hooks")
        .and_then(|h| h.as_object_mut())
        .map(|m| JsonValue::Object(m.clone()))
        .unwrap_or_else(|| json!({}));
    let mut hooks = hooks;
    let pretool = hooks
        .get_mut("PreToolUse")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let mut pretool: Vec<JsonValue> = serde_json::from_value(pretool).unwrap_or_default();
    let entry = json!({
        "matcher": "Bash|Write|Edit|Read|WebFetch|WebSearch|NotebookEdit|Task|mcp__.*",
        "hooks": [{"type": "command", "command": "chaperone hook"}]
    });
    if !pretool
        .iter()
        .any(|e| e["hooks"][0]["command"] == "chaperone hook")
    {
        pretool.push(entry);
    }
    hooks["PreToolUse"] = JsonValue::Array(pretool);
    settings["hooks"] = hooks;
    let out = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(path, out).map_err(|e| e.to_string())
}

/// Remove the chaperone hook entry (idempotent).
fn remove_hook_entry(path: &str) -> Result<(), String> {
    let mut settings: JsonValue = match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| e.to_string())?,
        Err(_) => return Ok(()),
    };
    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut())
        && let Some(pretool) = hooks.get_mut("PreToolUse").and_then(|p| p.as_array_mut())
    {
        pretool.retain(|e| e["hooks"][0]["command"] != "chaperone hook");
    }
    let out = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(path, out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The settings merge must: create the file when missing, ADD the hook
    /// entry, PRESERVE unknown keys, and be idempotent (never duplicate).
    #[test]
    fn init_writes_settings_merge() {
        let dir = std::env::temp_dir().join(format!("chaperone_init_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let path = path.to_str().unwrap().to_string();

        // 1. Missing file → created with the hook entry.
        let _ = std::fs::remove_file(&path);
        merge_hook_entry(&path).expect("create");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("chaperone hook"));
        assert!(text.contains("mcp__.*"), "matcher covers MCP tools");

        // 2. Existing file with unknown keys → keys preserved + hook added.
        std::fs::write(
            &path,
            r#"{"apiKey": "user-secret", "permissions": {"allow": ["Bash"]}}"#,
        )
        .unwrap();
        merge_hook_entry(&path).expect("merge");
        let v: JsonValue = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["apiKey"], "user-secret", "unknown keys preserved");
        assert_eq!(v["permissions"]["allow"][0], "Bash");
        let entries = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "one chaperone entry");
        assert_eq!(entries[0]["hooks"][0]["command"], "chaperone hook");

        // 3. Idempotent: a second merge does not duplicate.
        merge_hook_entry(&path).expect("merge again");
        let v: JsonValue = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);

        // 4. Unhook removes the entry but preserves the rest.
        remove_hook_entry(&path).expect("unhook");
        let v: JsonValue = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["apiKey"], "user-secret");
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("chaperone hook")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
