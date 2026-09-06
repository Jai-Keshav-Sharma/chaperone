//! `chaperone hook` — the Claude Code / Cursor hook (flows/05).
//!
//! stdin: the host's event JSON. stdout: the host's expected decision envelope.
//! Fail-closed (Law 1): ANY error (parse, network, timeout, malformed
//! response) → deny. Cursor entries are wired with failClosed:true so a
//! crash also denies. The hook is a one-shot process: blocking ureq, no
//! tokio runtime (cold-start target ~1ms, measured in E2).
//!
//! Two hosts, one decision path:
//!   - Claude Code `PreToolUse`: {tool_name, tool_input} → hookSpecificOutput
//!   - Cursor `beforeShellExecution`: {command, cwd} → {permission, ...}
//!   - Cursor `preToolUse`: {tool_name, tool_input} → {permission, ...}
//!   - Cursor `beforeReadFile`: {file_path, content} → {permission, ...}
//!   - Cursor `beforeMCPExecution`: {tool_name, mcp_server_name, tool_input}
//!
//! Windows note (review-2 ADOPT-7): Cursor prefixes its stdin JSON with a UTF-8
//! BOM, which breaks serde_json::from_str — so we strip it before parsing.

use clap::Args;
use serde_json::{Value as JsonValue, json};
use std::time::{Duration, Instant};

#[derive(Args, Debug)]
pub struct HookArgs {
    /// The decision service URL (default http://127.0.0.1:8400).
    #[arg(long, env = "CHAPERONE_URL")]
    pub url: Option<String>,
    /// The agent identity (CHAPERONE_AGENT_ID; hook/shim local seam only —
    /// the gateway pins identity server-side, review-4 B3).
    #[arg(long, env = "CHAPERONE_AGENT_ID")]
    pub agent_id: Option<String>,
    /// The admin API key for the gate + hook-local escalation resolution
    /// (CHAPERONE_API_TOKEN; default dev-token).
    #[arg(long, env = "CHAPERONE_API_TOKEN", default_value = "dev-token")]
    pub api_token: String,
    /// The hook-local approval prompt bound in seconds (default 30; flows/03).
    #[arg(
        long,
        env = "CHAPERONE_HOOK_PROMPT_BOUND_SECONDS",
        default_value_t = 30
    )]
    pub prompt_bound_seconds: u64,
}

/// Which host is invoking the hook (determines the output envelope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Host {
    ClaudeCode,
    Cursor,
}

/// The universal namespace mapping (flows/05 normalization map; the single
/// source of truth for tool names).
pub fn normalize_tool(tool: &str) -> String {
    match tool {
        "Bash" | "Shell" => "shell.exec".to_string(),
        "Write" | "Edit" => "fs.write".to_string(),
        "Read" => "fs.read".to_string(),
        "WebFetch" => "web.fetch".to_string(),
        "WebSearch" => "web.search".to_string(),
        "NotebookEdit" => "notebook.edit".to_string(),
        "Task" => "task.spawn".to_string(),
        "Delete" => "fs.delete".to_string(),
        // Benign read-only tools (flows/05: pure-local, high-frequency reads).
        // Mapped to their own namespace so no param-path rule can spuriously
        // EVAL_ERROR them (Grep params are {pattern}, not {path}).
        "Grep" | "Glob" => "local.grep".to_string(),
        "TodoWrite" => "local.todo".to_string(),
        other => {
            if let Some(mcp) = other.strip_prefix("mcp__") {
                format!("mcp.{}", mcp.replace("__", "."))
            } else {
                other.to_string()
            }
        }
    }
}

pub fn run_hook(args: HookArgs) -> i32 {
    let mut input = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_err() {
        return deny(Host::ClaudeCode, "failed to read event");
    }
    // Strip a leading UTF-8 BOM (Cursor on Windows; review-2 ADOPT-7).
    if let Some(stripped) = input.strip_prefix('\u{feff}') {
        input = stripped.to_string();
    }
    let event: JsonValue = match serde_json::from_str(&input) {
        Ok(e) => e,
        Err(_) => return deny(Host::ClaudeCode, "malformed event"),
    };
    let host = detect_host(&event);
    evaluate_event(&event, &args, host)
}

fn detect_host(event: &JsonValue) -> Host {
    if event.get("hook_event_name").is_some()
        || event.get("cursor_version").is_some()
        || event.get("workspace_roots").is_some()
    {
        Host::Cursor
    } else {
        Host::ClaudeCode
    }
}

/// Extract the normalized (tool, params) pair from a host event.
fn extract_call(event: &JsonValue) -> (String, JsonValue) {
    // Cursor beforeShellExecution: {command, cwd, sandbox}
    if event["tool_name"].is_null() && event["command"].is_string() {
        let cmd = event["command"].as_str().unwrap_or("").to_string();
        return ("shell.exec".to_string(), json!({"command": cmd}));
    }
    // Cursor beforeReadFile: {file_path, content}
    if event["tool_name"].is_null() && event["file_path"].is_string() {
        let path = event["file_path"].as_str().unwrap_or("").to_string();
        return ("fs.read".to_string(), json!({"path": path}));
    }
    // Cursor beforeMCPExecution: {tool_name, tool_input (string), mcp_server_name}
    if let (Some(server), Some(tool)) = (
        event["mcp_server_name"].as_str(),
        event["tool_name"].as_str(),
    ) {
        let params = match &event["tool_input"] {
            JsonValue::String(s) => serde_json::from_str(s).unwrap_or_else(|_| json!({})),
            other => other.clone(),
        };
        return (format!("mcp.{server}.{tool}"), params);
    }
    // preToolUse (both hosts): {tool_name, tool_input}
    if let Some(tool) = event["tool_name"].as_str() {
        let params = event
            .get("tool_input")
            .cloned()
            .unwrap_or_else(|| json!({}));
        return (normalize_tool(tool), params);
    }
    // Unknown → empty shell call (fails closed, never an allow).
    ("shell.exec".to_string(), json!({}))
}

fn evaluate_event(event: &JsonValue, args: &HookArgs, host: Host) -> i32 {
    let (tool, tool_input) = extract_call(event);
    let session_id = event["session_id"].as_str().map(|s| s.to_string());

    let agent_id = args.agent_id.clone().unwrap_or_else(|| {
        std::env::var("CHAPERONE_AGENT_ID").unwrap_or_else(|_| "local_agent".into())
    });
    let request = json!({
        "request_id": format!("hook_{}", uuid::Uuid::new_v4().simple()),
        "agent_id": agent_id,
        "tool": tool,
        "params": tool_input,
        "context": {
            "session_id": session_id,
            "surface": if host == Host::Cursor { "cursor" } else { "claude_code" },
            "delegation_depth": 0,
            "request_time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        },
        "escalation_id": null
    });

    let url = args
        .url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8400".to_string());
    let body = match decide_once(&url, &args.api_token, &request) {
        Ok(b) => b,
        Err(e) => return deny(host, &e),
    };

    match body["decision"].as_str() {
        Some("ALLOW") => allow(host),
        Some("BLOCK") => {
            let reason = body["reason_code"].as_str().unwrap_or("BLOCKED");
            let entry = body["entry_seq"].as_u64().unwrap_or(0);
            deny(host, &format!("{reason} (ledger #{entry})"))
        }
        Some("ESCALATE") => hook_local_approval(host, &body, &request, args),
        _ => deny(host, "gate returned an unknown verdict"),
    }
}

fn decide_once(url: &str, api_token: &str, request: &JsonValue) -> Result<JsonValue, String> {
    let endpoint = format!("{url}/v1/decisions");
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(1000)))
        .build()
        .new_agent();
    match agent
        .post(&endpoint)
        .header("authorization", &format!("Bearer {api_token}"))
        .send_json(request.clone())
    {
        Ok(mut r) => {
            let status = r.status();
            let body: JsonValue = r
                .body_mut()
                .read_json()
                .map_err(|_| "gate returned a non-JSON response".to_string())?;
            if status != 200 {
                return Err(format!("gate failure (HTTP {status})"));
            }
            Ok(body)
        }
        Err(_) => Err("FAIL_CLOSED_GATE_UNREACHABLE".to_string()),
    }
}

fn hook_local_approval(
    host: Host,
    body: &JsonValue,
    original_request: &JsonValue,
    args: &HookArgs,
) -> i32 {
    let esc = body["escalation_id"].as_str().unwrap_or("?");
    let expires = body["escalation_expires_at"].as_str().unwrap_or("?");

    if !crate::console::console_available() {
        return deny(
            host,
            &format!(
                "DENY_NO_CONSOLE: CHAPERONE_ESCALATED {esc} (expires {expires}; \
                 approve via 'chaperone approve {esc}' then retry)"
            ),
        );
    }

    let prompt = format!(
        "Chaperone: approval required.\n  what: {} (agent {})\n  expires: {}\n  [A]pprove / [D]eny: ",
        body["tool"].as_str().unwrap_or("?"),
        original_request["agent_id"].as_str().unwrap_or("?"),
        expires
    );
    if crate::console::write_prompt(&prompt).is_err() {
        return deny(host, "DENY_NO_CONSOLE: cannot write to console");
    }

    let read_handle = std::thread::spawn(crate::console::read_line_blocking);
    let bound = Duration::from_secs(args.prompt_bound_seconds.max(1));
    let deadline = Instant::now() + bound;
    let answer = loop {
        if read_handle.is_finished() {
            break read_handle.join().ok().and_then(|r| r.ok());
        }
        if Instant::now() >= deadline {
            return deny(
                host,
                &format!(
                    "CHAPERONE_ESCALATED: prompt timed out ({esc}, expires {expires}); \
                     approve via CLI/dashboard then retry"
                ),
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let Some(answer) = answer else {
        return deny(host, "DENY_NO_CONSOLE: cannot read from console");
    };

    apply_answer(host, &answer, esc, expires, original_request, args)
}

fn apply_answer(
    host: Host,
    answer: &str,
    esc: &str,
    expires: &str,
    original_request: &JsonValue,
    args: &HookArgs,
) -> i32 {
    match answer.trim().to_ascii_lowercase().as_str() {
        "a" | "approve" | "y" | "yes" => resolve_and_retry(host, esc, original_request, args),
        "d" | "deny" | "n" | "no" => {
            let url = args
                .url
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:8400".to_string());
            let _ = resolve(&url, &args.api_token, esc, "denied");
            deny(host, &format!("CHAPERONE_DENIED: {esc}"))
        }
        _ => deny(
            host,
            &format!("CHAPERONE_ESCALATED: unrecognized answer ({esc}, expires {expires})"),
        ),
    }
}

fn resolve_and_retry(host: Host, esc: &str, original_request: &JsonValue, args: &HookArgs) -> i32 {
    let url = args
        .url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8400".to_string());
    if !resolve(&url, &args.api_token, esc, "approved") {
        return deny(
            host,
            &format!("CHAPERONE_ESCALATED: resolution failed for {esc}"),
        );
    }
    let mut retry = original_request.clone();
    retry["request_id"] = json!(format!("hook_{}", uuid::Uuid::new_v4().simple()));
    retry["escalation_id"] = json!(esc);
    match decide_once(&url, &args.api_token, &retry) {
        Ok(body) if body["decision"].as_str() == Some("ALLOW") => allow(host),
        Ok(body) => {
            let rc = body["reason_code"].as_str().unwrap_or("BLOCKED");
            deny(host, rc)
        }
        Err(e) => deny(host, &e),
    }
}

fn resolve(url: &str, api_token: &str, id: &str, status: &str) -> bool {
    let endpoint = format!("{url}/v1/escalations/{id}/resolve");
    let body = json!({"resolution": status, "resolver": "hook", "note": null});
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(1000)))
        .build()
        .new_agent();
    match agent
        .post(&endpoint)
        .header("authorization", &format!("Bearer {api_token}"))
        .send_json(body)
    {
        Ok(r) => r.status() == 200,
        Err(_) => false,
    }
}

/// Emit the ALLOW decision in the host's expected envelope.
fn allow(host: Host) -> i32 {
    match host {
        Host::ClaudeCode => {
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": "Chaperone ALLOW"
                    }
                })
            );
            0
        }
        Host::Cursor => {
            println!("{}", json!({ "permission": "allow" }));
            0
        }
    }
}

/// Emit the DENY decision in the host's expected envelope. Exit 2 ≡ deny.
fn deny(host: Host, reason: &str) -> i32 {
    match host {
        Host::ClaudeCode => {
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": format!("Chaperone BLOCK: {reason}")
                    }
                })
            );
            2
        }
        Host::Cursor => {
            println!(
                "{}",
                json!({
                    "permission": "deny",
                    "user_message": format!("Chaperone BLOCK: {reason}"),
                    "agent_message": format!("Blocked by Chaperone policy: {reason}")
                })
            );
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> HookArgs {
        HookArgs {
            url: Some("http://127.0.0.1:1".to_string()),
            agent_id: Some("test_agent".to_string()),
            api_token: "dev-token".to_string(),
            prompt_bound_seconds: 30,
        }
    }

    #[test]
    fn hook_blocks_rm_rf_when_gate_unreachable() {
        let event = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "session_id": "s-test"
        });
        assert_eq!(evaluate_event(&event, &args(), Host::ClaudeCode), 2);
    }

    #[test]
    fn hook_malformed_event_denies() {
        let event = json!({"unexpected": true});
        assert_eq!(evaluate_event(&event, &args(), Host::ClaudeCode), 2);
    }

    #[test]
    fn normalize_tool_names() {
        assert_eq!(normalize_tool("Bash"), "shell.exec");
        assert_eq!(normalize_tool("Shell"), "shell.exec");
        assert_eq!(normalize_tool("Write"), "fs.write");
        assert_eq!(normalize_tool("Edit"), "fs.write");
        assert_eq!(normalize_tool("Read"), "fs.read");
        assert_eq!(normalize_tool("WebFetch"), "web.fetch");
        assert_eq!(normalize_tool("WebSearch"), "web.search");
        assert_eq!(normalize_tool("NotebookEdit"), "notebook.edit");
        assert_eq!(normalize_tool("Task"), "task.spawn");
        assert_eq!(normalize_tool("Delete"), "fs.delete");
        assert_eq!(normalize_tool("mcp__stripe__refund"), "mcp.stripe.refund");
    }

    #[test]
    fn detect_host_cursor_vs_claude() {
        assert_eq!(
            detect_host(&json!({"tool_name": "Bash", "tool_input": {}})),
            Host::ClaudeCode
        );
        assert_eq!(
            detect_host(&json!({"command": "ls", "cursor_version": "1.0"})),
            Host::Cursor
        );
        assert_eq!(
            detect_host(&json!({"hook_event_name": "beforeShellExecution", "command": "ls"})),
            Host::Cursor
        );
    }

    #[test]
    fn extract_call_cursor_before_shell() {
        let (tool, params) = extract_call(&json!({"command": "rm -rf /", "cwd": "/x"}));
        assert_eq!(tool, "shell.exec");
        assert_eq!(params["command"], "rm -rf /");
    }

    #[test]
    fn extract_call_cursor_before_read() {
        let (tool, params) = extract_call(&json!({"file_path": "/etc/passwd", "content": "x"}));
        assert_eq!(tool, "fs.read");
        assert_eq!(params["path"], "/etc/passwd");
    }

    #[test]
    fn extract_call_cursor_mcp() {
        let (tool, params) = extract_call(&json!({
            "tool_name": "refund",
            "mcp_server_name": "stripe",
            "tool_input": "{\"amount\": 500}"
        }));
        assert_eq!(tool, "mcp.stripe.refund");
        assert_eq!(params["amount"], 500);
    }

    #[test]
    fn answer_deny_maps_to_deny_code() {
        let req = json!({"agent_id": "agent_support_09"});
        assert_eq!(
            apply_answer(Host::ClaudeCode, "d", "esc_1", "exp", &req, &args()),
            2
        );
    }
}
