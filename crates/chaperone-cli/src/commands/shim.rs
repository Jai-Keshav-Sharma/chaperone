//! `chaperone shim -- <child command>` — the MCP stdio shim (flows/07).
//!
//! Desktop MCP clients configure servers as command lines over stdio, not HTTP
//! URLs. The shim wraps the child server process so such clients get Chaperone
//! by changing one command line:
//!
//!   BEFORE:  "command": "npx @stripe/mcp-server"
//!   AFTER:   "command": "chaperone shim -- npx @stripe/mcp-server"
//!
//! Flow (flows/07): initialize / tools/list pass through untouched; tools/call
//! is intercepted and decided by the SAME decision service the hook/gateway
//! use. A stdio pipe is a single serialized channel, so ESCALATE is
//! poll-and-retry (NEVER blocking): fail the call with a structured tool error
//! carrying the escalation ticket, let the agent continue, retry after approval.
//!
//! Identity (flows/07): CHAPERONE_AGENT_ID env; fallback "local_agent" (a
//! policy-blockable unknown agent — never a trusted override, unlike the
//! gateway which pins identity to the API key server-side, review-4 B3).
//!
//! Windows (review-2 ADOPT-7): `npx` resolves to `npx.cmd` via `cmd.exe /C` on
//! Windows (no SIGTERM — clean teardown is a job-object concern documented in
//! threat-model; the child is killed on drop here).

use clap::Args;
use serde_json::{Value as JsonValue, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[derive(Args, Debug)]
pub struct ShimArgs {
    /// The child command to wrap (e.g. `npx @stripe/mcp-server`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub child: Vec<String>,
}

pub async fn run_shim(args: ShimArgs) -> i32 {
    let (child, rest) = args.child.split_first().expect("child command");
    let decision_url =
        std::env::var("CHAPERONE_URL").unwrap_or_else(|_| "http://127.0.0.1:8400".to_string());
    let agent_id =
        std::env::var("CHAPERONE_AGENT_ID").unwrap_or_else(|_| "local_agent".to_string());

    let mut cmd = spawn_child(child, rest);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    let mut proc = match cmd.spawn() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("chaperone: cannot spawn child {child}: {e}");
            return 1;
        }
    };

    let mut child_stdin = proc.stdin.take().expect("child stdin");
    let child_stdout = proc.stdout.take().expect("child stdout");

    // Bridge child stdout → our stdout (responses + notifications stream back
    // untouched). A dedicated task keeps the pipe flowing while we read stdin.
    let stdout_task = tokio::spawn(async move {
        let mut reader = BufReader::new(child_stdout);
        let mut line = String::new();
        let mut stdout = tokio::io::stdout();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if stdout.write_all(line.as_bytes()).await.is_err() {
                        break;
                    }
                    stdout.flush().await.ok();
                }
            }
        }
    });

    // Read our stdin line-by-line (MCP stdio = newline-delimited JSON-RPC 2.0).
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    let mut exit = 0;
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: JsonValue = match serde_json::from_str(trimmed) {
            Ok(m) => m,
            Err(_) => {
                // Not a parseable line — forward as-is (never corrupt the pipe).
                if child_stdin.write_all(line.as_bytes()).await.is_err() {
                    exit = 1;
                    break;
                }
                child_stdin.flush().await.ok();
                continue;
            }
        };

        // Only tools/call is intercepted.
        let is_tools_call = msg["method"].as_str() == Some("tools/call");
        if !is_tools_call {
            if child_stdin.write_all(line.as_bytes()).await.is_err() {
                exit = 1;
                break;
            }
            child_stdin.flush().await.ok();
            continue;
        }

        // Decide the tool call (same mapping as hook/gateway).
        let tool = msg["params"]["name"].as_str().unwrap_or("").to_string();
        let params = msg
            .get("params")
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let id = msg.get("id").cloned().unwrap_or(JsonValue::Null);
        match decide(&decision_url, &agent_id, &tool, &params).await {
            Decision::Allow => {
                if child_stdin.write_all(line.as_bytes()).await.is_err() {
                    exit = 1;
                    break;
                }
                child_stdin.flush().await.ok();
            }
            Decision::Block { reason, entry_seq } => {
                let error_line = tool_error(
                    &id,
                    &format!("blocked by policy: {reason} (ledger #{entry_seq})"),
                );
                if write_stdout(&error_line).await.is_err() {
                    exit = 1;
                    break;
                }
            }
            Decision::Escalate {
                escalation_id,
                expires_at,
            } => {
                let error_line = tool_error(
                    &id,
                    &format!(
                        "CHAPERONE_ESCALATED: approval required ({escalation_id}, expires {expires_at})"
                    ),
                );
                if write_stdout(&error_line).await.is_err() {
                    exit = 1;
                    break;
                }
            }
        }
    }

    // Close the child's stdin (EOF) and reap it.
    drop(child_stdin);
    let _ = proc.kill().await;
    let _ = proc.wait().await;
    let _ = stdout_task.await;
    exit
}

/// A local decision outcome (flows/07: same mapping as hook/gateway).
enum Decision {
    Allow,
    Block {
        reason: String,
        entry_seq: u64,
    },
    Escalate {
        escalation_id: String,
        expires_at: String,
    },
}

/// POST the tools/call to the decision service and map the verdict. Fail-closed:
/// any error (network, timeout, non-JSON, non-200) → BLOCK.
async fn decide(url: &str, agent_id: &str, tool: &str, params: &JsonValue) -> Decision {
    let request = json!({
        "request_id": format!("shim_{}", uuid::Uuid::new_v4().simple()),
        "agent_id": agent_id,
        "tool": crate::commands::hook::normalize_tool(tool),
        "params": params,
        "context": {
            "session_id": null,
            "surface": "mcp_shim",
            "delegation_depth": 0,
            "request_time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        },
        "escalation_id": null
    });
    let endpoint = format!("{url}/v1/decisions");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(1000))
        .build()
        .expect("client");
    match client.post(&endpoint).json(&request).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body: JsonValue = resp.json().await.unwrap_or(JsonValue::Null);
            if status != 200 {
                return Decision::Block {
                    reason: format!("gate failure (HTTP {status})"),
                    entry_seq: 0,
                };
            }
            match body["decision"].as_str() {
                Some("ALLOW") => Decision::Allow,
                Some("BLOCK") => Decision::Block {
                    reason: body["reason_code"]
                        .as_str()
                        .unwrap_or("BLOCKED")
                        .to_string(),
                    entry_seq: body["entry_seq"].as_u64().unwrap_or(0),
                },
                Some("ESCALATE") => Decision::Escalate {
                    escalation_id: body["escalation_id"].as_str().unwrap_or("?").to_string(),
                    expires_at: body["escalation_expires_at"]
                        .as_str()
                        .unwrap_or("?")
                        .to_string(),
                },
                _ => Decision::Block {
                    reason: "unknown verdict".to_string(),
                    entry_seq: 0,
                },
            }
        }
        Err(_) => Decision::Block {
            reason: "FAIL_CLOSED_GATE_UNREACHABLE".to_string(),
            entry_seq: 0,
        },
    }
}

/// Build a JSON-RPC tool error response line (flows/07: BLOCK/ESCALATE → tool
/// error, never forwarded).
fn tool_error(id: &JsonValue, message: &str) -> String {
    let err = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32000, "message": message }
    });
    format!("{err}\n")
}

async fn write_stdout(line: &str) -> std::io::Result<()> {
    let mut stdout = tokio::io::stdout();
    stdout.write_all(line.as_bytes()).await?;
    stdout.flush().await
}

/// Build the child process command with Windows cmd-shim resolution: `npx` on
/// Windows must resolve to `npx.cmd` (review-2 ADOPT-7). We launch through
/// `cmd.exe /C` on Windows so the system's PATHEXT resolution applies.
#[cfg(windows)]
fn spawn_child(child: &str, rest: &[String]) -> Command {
    let mut cmd = Command::new("cmd.exe");
    cmd.arg("/C").arg(child);
    for a in rest {
        cmd.arg(a);
    }
    cmd
}

#[cfg(not(windows))]
fn spawn_child(child: &str, rest: &[String]) -> Command {
    let mut cmd = Command::new(child);
    cmd.args(rest);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_shape_is_jsonrpc() {
        let line = tool_error(&json!(1), "blocked by policy");
        let v: JsonValue = serde_json::from_str(line.trim()).expect("jsonrpc line");
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["error"]["code"], -32000);
        assert!(v["error"]["message"].as_str().unwrap().contains("blocked"));
    }

    #[test]
    fn normalize_tool_is_reused_for_shim() {
        // The shim uses the SAME normalization map as the hook (flows/07:
        // "shared mapping module as hook/gateway — one code path").
        assert_eq!(crate::commands::hook::normalize_tool("Bash"), "shell.exec");
        assert_eq!(
            crate::commands::hook::normalize_tool("mcp__stripe__refund"),
            "mcp.stripe.refund"
        );
    }
}
