//! `chaperone gateway --upstream <url>` — the MCP streamable-HTTP gateway
//! (flows/06). Reverse proxy with the decision path: fast-path
//! needs_params, params_hash on the raw body, MRTR retry-native ESCALATE with
//! a signed requestState (HMAC over canonical_json — Law 4, review-4 B2).
//!
//! This command wires the core pieces; the full axum proxy + MCP framing
//! lands with the MCP SDK integration (the decision contract + HMAC
//! machinery are here and tested).

use base64::Engine;
use clap::Args;
use hmac::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Args, Debug)]
pub struct GatewayArgs {
    /// The upstream MCP server URL.
    #[arg(long)]
    pub upstream: String,
    /// Listen port (default 8500).
    #[arg(long, default_value_t = 8500)]
    pub port: u16,
    /// The requestState HMAC root secret (CHAPERONE_GATEWAY_SECRET).
    #[arg(long, env = "CHAPERONE_GATEWAY_SECRET", default_value = "dev-secret")]
    pub secret: String,
}

/// Sign a requestState: HMAC-SHA256 over the CANONICAL JSON of the tuple
/// {escalation_id, expires_at, params_binding_hash, agent_id} (flows/06,
/// review-4 B2: never ‖-concatenation). Tested below; consumed by the MCP
/// SDK gateway integration.
#[allow(dead_code)]
pub fn sign_request_state(
    secret: &str,
    escalation_id: &str,
    expires_at: &str,
    params_binding_hash: &str,
    agent_id: &str,
) -> String {
    let payload = serde_json::json!({
        "escalation_id": escalation_id,
        "expires_at": expires_at,
        "params_binding_hash": params_binding_hash,
        "agent_id": agent_id,
    });
    let canonical = chaperone_core::canonical::canonical_dumps(&payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(canonical.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Verify a signed requestState. Returns true on a valid signature.
#[allow(dead_code)]
pub fn verify_request_state(
    secret: &str,
    signature: &str,
    escalation_id: &str,
    expires_at: &str,
    params_binding_hash: &str,
    agent_id: &str,
) -> bool {
    let expected = sign_request_state(
        secret,
        escalation_id,
        expires_at,
        params_binding_hash,
        agent_id,
    );
    // Constant-time compare via hmac::Mac::verify_slice.
    let sig = match base64::engine::general_purpose::STANDARD.decode(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(
        chaperone_core::canonical::canonical_dumps(&serde_json::json!({
            "escalation_id": escalation_id,
            "expires_at": expires_at,
            "params_binding_hash": params_binding_hash,
            "agent_id": agent_id,
        }))
        .as_bytes(),
    );
    mac.verify_slice(&sig).is_ok() && signature == expected
}

pub async fn run_gateway(args: GatewayArgs) -> i32 {
    // The full proxy (axum reverse proxy + MCP framing + upstream streaming)
    // lands with the MCP SDK integration. The HMAC machinery above is the
    // security core — exercised by tests. Fail closed until then.
    eprintln!(
        "chaperone: gateway proxy lands with the MCP SDK integration; upstream={} port={}",
        args.upstream, args.port
    );
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_state_sign_and_verify() {
        let secret = "root-secret";
        let sig = sign_request_state(secret, "esc_1", "2026-08-25T14:15:00Z", "abc123", "agent_1");
        assert!(!sig.is_empty());
        assert!(verify_request_state(
            secret,
            &sig,
            "esc_1",
            "2026-08-25T14:15:00Z",
            "abc123",
            "agent_1"
        ));
    }

    #[test]
    fn request_state_tamper_rejected() {
        let secret = "root-secret";
        let sig = sign_request_state(secret, "esc_1", "2026-08-25T14:15:00Z", "abc123", "agent_1");
        // Different params_binding_hash → rejected.
        assert!(!verify_request_state(
            secret,
            &sig,
            "esc_1",
            "2026-08-25T14:15:00Z",
            "CHANGED",
            "agent_1"
        ));
        // Wrong secret → rejected.
        assert!(!verify_request_state(
            "other-secret",
            &sig,
            "esc_1",
            "2026-08-25T14:15:00Z",
            "abc123",
            "agent_1"
        ));
        // Garbage signature → rejected.
        assert!(!verify_request_state(
            secret,
            "!!!",
            "esc_1",
            "2026-08-25T14:15:00Z",
            "abc123",
            "agent_1"
        ));
    }

    #[test]
    fn canonical_payload_not_concatenated() {
        // The same fields in a different order must produce a DIFFERENT
        // signature (canonical JSON sorts keys — order-independent by
        // construction), and the signing is over canonical JSON, not
        // concatenation: two fields with ambiguous boundaries ("a"+"bc" vs
        // "ab"+"c") cannot collide.
        let s1 = sign_request_state("k", "ab", "c", "d", "e");
        let s2 = sign_request_state("k", "a", "bc", "d", "e");
        assert_ne!(s1, s2, "no ‖-concatenation ambiguity");
    }
}
