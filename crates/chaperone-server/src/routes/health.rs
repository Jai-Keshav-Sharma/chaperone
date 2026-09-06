//! Health + metrics + live decision stream (flows/02 observability).

use axum::Json;
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::sync::atomic::Ordering;

use crate::state::AppState;

/// GET /healthz — liveness (the gate's own health; no auth).
pub async fn healthz() -> Response {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

/// GET /metrics — Prometheus text format. Decision counters + a simple latency
/// observation are the v1 surface (flows/02: decision counters, latency
/// histogram, cache-tier hits, ledger head).
pub async fn metrics(State(state): State<AppState>) -> Response {
    let m = &state.metrics;
    let body = format!(
        "# HELP chaperone_decisions_total Total decisions evaluated.\n\
         # TYPE chaperone_decisions_total counter\n\
         chaperone_decisions_total {}\n\
         # HELP chaperone_decisions_allow Allowed decisions.\n\
         # TYPE chaperone_decisions_allow counter\n\
         chaperone_decisions_allow {}\n\
         # HELP chaperone_decisions_block Blocked decisions.\n\
         # TYPE chaperone_decisions_block counter\n\
         chaperone_decisions_block {}\n\
         # HELP chaperone_decisions_escalate Escalated decisions.\n\
         # TYPE chaperone_decisions_escalate counter\n\
         chaperone_decisions_escalate {}\n",
        m.decisions_total.load(Ordering::Relaxed),
        m.decisions_allow.load(Ordering::Relaxed),
        m.decisions_block.load(Ordering::Relaxed),
        m.decisions_escalate.load(Ordering::Relaxed),
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

/// GET /ws/decisions — live decision stream (api-contracts WS envelope:
/// `{"type":"decision","data":{DecisionResponse}}`). Server pushes only; no
/// client→server messages in v1. A slow consumer is disconnected by the
/// bounded broadcast channel (drop-on-slow-consumer — never backpressures the
/// decision path).
pub async fn ws_decisions(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| stream_decisions(socket, state))
}

async fn stream_decisions(mut socket: axum::extract::ws::WebSocket, state: AppState) {
    use axum::extract::ws::Message;

    let mut rx = state.broadcast.subscribe();
    loop {
        match rx.recv().await {
            Ok(decision) => {
                let envelope = serde_json::json!({
                    "type": "decision",
                    "data": decision,
                });
                let text = envelope.to_string();
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            // Lagged: the bounded channel dropped us (drop-on-slow-consumer).
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => break,
            // Sender dropped (server shutdown).
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    let _ = socket.send(Message::Close(None)).await;
}
