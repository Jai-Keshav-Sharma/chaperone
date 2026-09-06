//! Mock MCP server (flows/06 "fake_mcp_server fixture", flows/09 `init --demo`).
//!
//! A self-contained streamable-HTTP MCP server with ONE tool,
//! `stripe.refunds.create`. It is the UPSTREAM the gateway sits in front of for
//! the demo: the gateway authorizes the call, and only on ALLOW does the mock
//! "process" it and return a canned refund receipt. Zero network, deterministic.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use clap::Args;
use serde_json::{Value, json};

/// `chaperone mock-stripe` — run the canned mock Stripe MCP server (flows/09
/// demo dependency). The gateway sits in front of this.
#[derive(Args, Debug)]
pub struct MockStripeArgs {
    /// Listen port (default 8700).
    #[arg(long, default_value_t = 8700)]
    pub port: u16,
}

pub async fn run_mock_mcp(args: MockStripeArgs) -> i32 {
    let addr = format!("127.0.0.1:{}", args.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chaperone: cannot bind {addr}: {e}");
            return 1;
        }
    };
    println!("chaperone: mock Stripe MCP server on http://{addr}");
    if let Err(e) = axum::serve(listener, mock_mcp_router()).await {
        eprintln!("chaperone: mock server error: {e}");
        return 1;
    }
    0
}

#[derive(Clone)]
pub struct MockMcpState;

/// The one tool the mock exposes.
const TOOLS_LIST: &str = r#"{
  "tools": [
    {
      "name": "stripe.refunds.create",
      "description": "Create a refund against a Stripe payment",
      "inputSchema": {
        "type": "object",
        "properties": {
          "amount": {"type": "number", "description": "refund amount in dollars"},
          "customer_id": {"type": "string"}
        },
        "required": ["amount", "customer_id"]
      }
    }
  ]
}"#;

/// Handle a JSON-RPC request (initialize / tools/list / tools/call).
async fn handle(State(_): State<MockMcpState>, body: String) -> Response {
    let req: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::OK,
                Json(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}})),
            )
                .into_response();
        }
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2026-07-28",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-stripe", "version": "1.0.0"}
        }),
        "tools/list" => serde_json::from_str::<Value>(TOOLS_LIST).unwrap_or(Value::Null),
        "tools/call" => {
            let tool = req["params"]["name"].as_str().unwrap_or("");
            let args = req["params"]["arguments"].clone();
            if tool != "stripe.refunds.create" {
                return (
                    StatusCode::OK,
                    Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"unknown tool"}})),
                )
                    .into_response();
            }
            let amount = args["amount"].as_f64().unwrap_or(0.0);
            let customer = args["customer_id"].as_str().unwrap_or("?");
            // Canned deterministic receipt (no real refund is created).
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("REFUND OK: ${amount:.2} refunded to {customer} (receipt re_mock_{:x})", 42u64)
                }],
                "isError": false
            })
        }
        _ => {
            return (
                StatusCode::OK,
                Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}})),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(json!({"jsonrpc":"2.0","id":id,"result":result})),
    )
        .into_response()
}

/// The axum router for the mock MCP server (streamable HTTP: POST is the only
/// transport; the response carries the JSON-RPC result).
pub fn mock_mcp_router() -> axum::Router {
    axum::Router::new()
        .route("/", axum::routing::post(handle))
        .with_state(MockMcpState)
}
