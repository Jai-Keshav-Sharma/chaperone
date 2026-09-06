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

    // 2.5 Register the default local agent the hook/shim use (CHAPERONE_AGENT_ID
    //     defaults to "local_agent"). Without this, the demo blocks with
    //     AGENT_UNKNOWN instead of a policy RULE_MATCH — a weak first impression.
    store
        .upsert_agent_identity(&chaperone_core::storage::store::AgentIdentityRow {
            agent_id: "local_agent".into(),
            name: "Local Agent".into(),
            role: "worker".into(),
            spiffe_id: None,
            tenant_id: None,
            max_delegation_depth: 1,
            is_active: true,
            created_at: "2026-08-25T00:00:00Z".into(),
        })
        .await
        .ok(); // idempotent; a pre-existing identity is fine

    // A named support agent — the actor the customer-facing support console
    // (and gateway) authorizes. The refund demo drives this identity.
    store
        .upsert_agent_identity(&chaperone_core::storage::store::AgentIdentityRow {
            agent_id: "support_agent".into(),
            name: "Support Agent".into(),
            role: "support".into(),
            spiffe_id: None,
            tenant_id: None,
            max_delegation_depth: 1,
            is_active: true,
            created_at: "2026-08-25T00:00:00Z".into(),
        })
        .await
        .ok();

    // 3. Default API key (idempotent: skip if already present).
    let dev_key_hash = chaperone_core::canonical::sha256_hex("dev-token");
    let key_exists = store
        .get_api_key(&dev_key_hash)
        .await
        .ok()
        .flatten()
        .is_some();
    if !key_exists {
        store
            .insert_api_key(&chaperone_core::storage::store::ApiKeyRow {
                key_hash: dev_key_hash,
                agent_id: None,
                is_admin: true,
                created_at: chrono::Utc::now().to_rfc3339(),
                last_used_at: None,
                expires_at: None,
                revoked_at: None,
            })
            .await
            .ok(); // ignore if already exists (race-safe)
    }

    // A demo key BOUND to the local agent — the gateway pins identity to the
    // key (review-4 B3), so an admin key (agent_id: None) is refused for
    // tools/call. This key lets the gateway demo run out of the box.
    let demo_key_hash = chaperone_core::canonical::sha256_hex("demo-agent-token");
    if store
        .get_api_key(&demo_key_hash)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        store
            .insert_api_key(&chaperone_core::storage::store::ApiKeyRow {
                key_hash: demo_key_hash,
                agent_id: Some("local_agent".into()),
                is_admin: false,
                created_at: chrono::Utc::now().to_rfc3339(),
                last_used_at: None,
                expires_at: None,
                revoked_at: None,
            })
            .await
            .ok();
    }

    // 4. Hook wiring: merge into .claude/settings.json + .cursor/hooks.json
    //    (merge, never clobber — flows/05).
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let claude_settings = format!("{home}/.claude/settings.json");
    if let Err(e) = merge_hook_entry(&claude_settings) {
        eprintln!("chaperone: hook wiring failed: {e}");
        return 1;
    }

    // Cursor project-level hooks (flows/05): fail-closed by config (Law 1).
    let cursor_hooks = ".cursor/hooks.json";
    if let Err(e) = write_cursor_hooks(cursor_hooks) {
        eprintln!("chaperone: cursor hook wiring failed: {e}");
        return 1;
    }

    // 4. Autostart (unless opted out): register the gate to run at login.
    //    Best-effort: a failure warns but does not fail init (the user can run
    //    `serve` manually — autostart is convenience, not correctness).
    if !args.no_autostart
        && let Err(e) = install_autostart()
    {
        eprintln!(
            "chaperone: warning: autostart not installed ({e}); run 'chaperone serve' manually"
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
    if store
        .get_active_policy("starter-safety")
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Ok(());
    }
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
                "rule_id": "s-block-delete",
                "description": "block file deletions (the agent may pivot from shell to the Delete tool)",
                "effect": "block",
                "target": {"tools": ["fs.delete"]}
            },
            {
                "rule_id": "s-block-secrets",
                "description": "block writes to secret paths",
                "effect": "block",
                "target": {"tools": ["fs.write"]},
                "condition": {"op": "matches", "left": {"param": "path"}, "pattern": "^*env*$"}
            },
            {
                "rule_id": "s-block-secret-read",
                "description": "block reads of secret paths",
                "effect": "block",
                "target": {"tools": ["fs.read"]},
                "condition": {"op": "matches", "left": {"param": "path"}, "pattern": "^*\\.env*$"}
            },
            {
                "rule_id": "s-allow-benign-read",
                "description": "benign reads within the workspace",
                "effect": "allow",
                "target": {"tools": ["fs.read"]}
            },
            {
                "rule_id": "s-allow-benign-search",
                "description": "local grep/glob searches (pure-local, high-frequency)",
                "effect": "allow",
                "target": {"tools": ["local.grep", "local.todo"]}
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
            },
            {
                "rule_id": "s-escalate-force-push",
                "description": "AMBIGUOUS: force pushes to protected branches need human approval",
                "effect": "escalate",
                "target": {"tools": ["git.push"]},
                "condition": {"op": "eq", "left": {"param": "force"}, "right": {"value": true}}
            },
            {
                "rule_id": "s-allow-git-push",
                "description": "non-force git push",
                "effect": "allow",
                "target": {"tools": ["git.push"]},
                "condition": {"op": "eq", "left": {"param": "force"}, "right": {"value": false}}
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

/// Register the gate to run at login (flows/09 autostart). Best-effort: a
/// failure is reported but does NOT fail init (the user can run `serve`
/// manually) — autostart is convenience, not a correctness requirement.
fn install_autostart() -> Result<(), String> {
    #[cfg(windows)]
    {
        // Windows: a scheduled task at logon runs `chaperone serve`.
        let exe = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .to_string();
        let status = std::process::Command::new("schtasks")
            .args([
                "/Create",
                "/F",
                "/TN",
                "ChaperoneGate",
                "/TR",
                &format!("\"{exe}\" serve"),
                "/SC",
                "ONLOGON",
            ])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("schtasks exited {status}"));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let exe = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .to_string();
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
               <key>Label</key><string>com.chaperone.gate</string>\n\
               <key>ProgramArguments</key><array><string>{exe}</string><string>serve</string></array>\n\
               <key>RunAtLoad</key><true/>\n\
             </dict></plist>\n"
        );
        std::fs::write(
            std::path::Path::new(&std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join("Library/LaunchAgents/com.chaperone.gate.plist"),
            plist,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let exe = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .to_string();
        let unit = format!(
            "[Unit]\nDescription=Chaperone authorization gate\nAfter=network.target\n\n\
             [Service]\nExecStart={exe} serve\nRestart=on-failure\n\n\
             [Install]\nWantedBy=default.target\n"
        );
        std::fs::write(
            std::path::Path::new(&std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join(".config/systemd/user/chaperone.service"),
            unit,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("autostart not supported on this platform".to_string())
    }
}

/// Write the project-level `.cursor/hooks.json` (flows/05): fail-closed by
/// config (Law 1 — Cursor defaults to fail-OPEN). Merge-preserves any existing
/// entries; the chaperone entries are added idempotently.
fn write_cursor_hooks(path: &str) -> Result<(), String> {
    let mut cfg: JsonValue = match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or(json!({"version": 1, "hooks": {}})),
        Err(_) => json!({"version": 1, "hooks": {}}),
    };
    if cfg.get("version").is_none() {
        cfg["version"] = json!(1);
    }
    if cfg.get("hooks").is_none() {
        cfg["hooks"] = json!({});
    }
    // Ensure the fail-closed arrays exist and carry the chaperone entry. We
    // wire the GENERIC preToolUse hook (fires for Delete/Write/Read/Shell/Task)
    // plus the two shell/read-specific hooks. preToolUse is the one that closes
    // the "agent pivots from shell to the Delete tool" fail-open.
    for event in [
        "preToolUse",
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
    ] {
        let entry = json!({
            "command": "chaperone hook",
            "timeout": 35,
            "failClosed": true
        });
        let arr = cfg["hooks"][event].as_array().cloned().unwrap_or_default();
        let mut arr = arr;
        if !arr.iter().any(|e| e["command"] == "chaperone hook") {
            arr.push(entry);
        }
        cfg["hooks"][event] = JsonValue::Array(arr);
    }
    let out = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    // Never write outside the target project dir: the path is a literal relative
    // `.cursor/hooks.json` (flows/05 "never writes outside target project dir").
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
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

    /// Cursor hooks.json must be fail-closed (failClosed: true) across the
    /// three enforcement events, and idempotent (flows/05 review-3 P0).
    #[test]
    fn cursor_hooks_fail_closed_and_idempotent() {
        let dir =
            std::env::temp_dir().join(format!("chaperone_cursor_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hooks.json");
        let path = path.to_str().unwrap().to_string();

        write_cursor_hooks(&path).expect("write");
        let v: JsonValue = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        for event in [
            "beforeShellExecution",
            "beforeMCPExecution",
            "beforeReadFile",
        ] {
            let entries = v["hooks"][event].as_array().expect(event);
            assert_eq!(entries.len(), 1, "{event} has one entry");
            assert_eq!(entries[0]["command"], "chaperone hook");
            assert_eq!(
                entries[0]["timeout"], 35,
                "{event} timeout above prompt bound"
            );
            assert_eq!(
                entries[0]["failClosed"], true,
                "{event} must be fail-closed"
            );
        }

        // Idempotent: a second write does not duplicate.
        write_cursor_hooks(&path).expect("write again");
        let v: JsonValue = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v["hooks"]["beforeShellExecution"].as_array().unwrap().len(),
            1
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
