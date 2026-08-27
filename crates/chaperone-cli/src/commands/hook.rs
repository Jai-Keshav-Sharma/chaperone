//! `chaperone hook` — the Claude Code / Cursor PreToolUse hook (flows/05).
//!
//! stdin: the event JSON. stdout: the hookSpecificOutput envelope.
//! Fail-closed (Law 1): ANY error (parse, network, timeout, malformed
//! response) → deny. Cursor entries are wired with failClosed:true so a
//! crash also denies. The hook is a one-shot process: blocking ureq, no
//! tokio runtime (cold-start target ~1ms, measured in E2).

use clap::Args;
use serde_json::{Value as JsonValue, json};

#[derive(Args, Debug)]
pub struct HookArgs {
    /// The decision service URL (default http://127.0.0.1:8400).
    #[arg(long, env = "CHAPERONE_URL")]
    pub url: Option<String>,
    /// The agent identity (CHAPERONE_AGENT_ID; hook/shim local seam only —
    /// the gateway pins identity server-side, review-4 B3).
    #[arg(long, env = "CHAPERONE_AGENT_ID")]
    pub agent_id: Option<String>,
}

/// The universal namespace mapping (flows/05 normalization map; the single
/// source of truth for tool names).
pub fn normalize_tool(tool: &str) -> String {
    match tool {
        "Bash" => "shell.exec".to_string(),
        "Write" | "Edit" => "fs.write".to_string(),
        "Read" => "fs.read".to_string(),
        "WebFetch" => "web.fetch".to_string(),
        "WebSearch" => "web.search".to_string(),
        "NotebookEdit" => "notebook.edit".to_string(),
        "Task" => "task.spawn".to_string(),
        other => {
            if let Some(mcp) = other.strip_prefix("mcp__") {
                // mcp__stripe__refund → mcp.stripe.refunds.create
                format!("mcp.{}", mcp.replace("__", "."))
            } else {
                other.to_string()
            }
        }
    }
}

pub fn run_hook(args: HookArgs) -> i32 {
    // Read the event JSON from stdin.
    let mut input = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_err() {
        return deny("failed to read event");
    }
    let event: JsonValue = match serde_json::from_str(&input) {
        Ok(e) => e,
        Err(_) => return deny("malformed event"),
    };
    evaluate_event(&event, &args)
}

/// The core hook logic (testable): evaluate one event and return the exit
/// code (0 = allow, 2 = deny). Fail-closed on any error.
fn evaluate_event(event: &JsonValue, args: &HookArgs) -> i32 {
    let tool = event["tool_name"].as_str().unwrap_or("");
    let tool_input = event.get("tool_input").cloned().unwrap_or(json!({}));
    let session_id = event["session_id"].as_str().map(|s| s.to_string());

    // Build the decision request (request_id at the boundary).
    let agent_id = args.agent_id.clone().unwrap_or_else(|| {
        std::env::var("CHAPERONE_AGENT_ID").unwrap_or_else(|_| "local_agent".into())
    });
    let request = json!({
        "request_id": format!("hook_{}", uuid::Uuid::new_v4().simple()),
        "agent_id": agent_id,
        "tool": normalize_tool(tool),
        "params": tool_input,
        "context": {
            "session_id": session_id,
            "surface": "claude_code",
            "delegation_depth": 0,
            "request_time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        },
        "escalation_id": null
    });

    // Call the decision service (blocking agent, 1000ms global timeout).
    let url = args
        .url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8400".to_string());
    let endpoint = format!("{url}/v1/decisions");
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_millis(1000)))
        .build()
        .new_agent();
    let resp = agent.post(&endpoint).send_json(request);
    match resp {
        Ok(mut r) => {
            let status = r.status();
            let body: JsonValue = match r.body_mut().read_json() {
                Ok(b) => b,
                Err(_) => return deny("gate returned a non-JSON response"),
            };
            // 200 → verdict (in-band); anything else is a gate failure.
            if status != 200 {
                return deny(&format!("gate failure (HTTP {status})"));
            }
            match body["decision"].as_str() {
                Some("ALLOW") => allow(),
                Some("BLOCK") => {
                    let reason = body["reason_code"].as_str().unwrap_or("BLOCKED");
                    let entry = body["entry_seq"].as_u64().unwrap_or(0);
                    deny(&format!("{reason} (ledger #{entry})"))
                }
                Some("ESCALATE") => {
                    // Flows/03 hook-local approval: the hook resolves the
                    // escalation itself via the console (bounded ~30s). The
                    // full console path lands with the interactive approval
                    // seam; fail-closed deny with the ticket message.
                    let esc = body["escalation_id"].as_str().unwrap_or("?");
                    let expires = body["escalation_expires_at"].as_str().unwrap_or("?");
                    deny(&format!(
                        "CHAPERONE_ESCALATED: approval required ({esc}, expires {expires})"
                    ))
                }
                _ => deny("gate returned an unknown verdict"),
            }
        }
        Err(_) => deny("FAIL_CLOSED_GATE_UNREACHABLE"),
    }
}

fn allow() -> i32 {
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "Chaperone ALLOW"
        }
    });
    println!("{out}");
    0
}

fn deny(reason: &str) -> i32 {
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": format!("Chaperone BLOCK: {reason}")
        }
    });
    println!("{out}");
    // Exit 2 ≡ deny (Cursor's deny convention; Claude Code reads the output).
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-closed: with the gate unreachable, an rm -rf / event DENIES (a
    /// non-forward) — the fail-closed envelope. The e2e happy path (gate up →
    /// allow/deny by policy) runs against a live serve in the integration
    /// suite.
    #[test]
    fn hook_blocks_rm_rf_when_gate_unreachable() {
        let args = HookArgs {
            url: Some("http://127.0.0.1:1".to_string()), // nothing listens here
            agent_id: Some("test_agent".to_string()),
        };
        let event = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "session_id": "s-test"
        });
        let code = evaluate_event(&event, &args);
        assert_eq!(code, 2, "unreachable gate must deny");
    }

    #[test]
    fn hook_malformed_event_denies() {
        let args = HookArgs {
            url: Some("http://127.0.0.1:1".to_string()),
            agent_id: None,
        };
        // A malformed event (no tool_name) still builds a request; the
        // unreachable gate denies. The parse-failure path is covered by
        // run_hook's stdin handling.
        let event = json!({"unexpected": true});
        assert_eq!(evaluate_event(&event, &args), 2);
    }

    #[test]
    fn normalize_tool_names() {
        assert_eq!(normalize_tool("Bash"), "shell.exec");
        assert_eq!(normalize_tool("Write"), "fs.write");
        assert_eq!(normalize_tool("Edit"), "fs.write");
        assert_eq!(normalize_tool("Read"), "fs.read");
        assert_eq!(normalize_tool("WebFetch"), "web.fetch");
        assert_eq!(normalize_tool("WebSearch"), "web.search");
        assert_eq!(normalize_tool("NotebookEdit"), "notebook.edit");
        assert_eq!(normalize_tool("Task"), "task.spawn");
        assert_eq!(normalize_tool("mcp__stripe__refund"), "mcp.stripe.refund");
    }
}
