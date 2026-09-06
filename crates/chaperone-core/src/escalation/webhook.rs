//! Escalation webhook notifications (flows/03): generic signed HTTP POST on
//! escalation events. Slack/Teams are webhook-format adapters over this same
//! mechanism. The HMAC payload is signed with a purpose-bound key derived from
//! the root secret (review-2 SEC-6: webhook key ≠ requestState key — both
//! derive from one root via distinct HKDF labels).

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// The webhook notifier seam (flows/03 "Notifications"). Implementations POST
/// the signed event; a no-op is the safe default (no webhook configured).
pub trait WebhookNotifier: Send + Sync {
    fn notify(&self, event: &EscalationEvent) -> Result<(), String>;
}

/// The escalation event payload (flows/03). Provenance fields only — the full
/// proposed params are deliberately NOT in the webhook (approver visibility is
/// via the inbox/CLI).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EscalationEvent {
    pub escalation_id: String,
    pub event: String, // "created" | "approved" | "denied" | "expired"
    pub agent_id: String,
    pub tool: String,
    pub policy_id: String,
    pub expires_at: String,
}

/// Sign a webhook payload: HMAC-SHA256 over canonical JSON, base64. The
/// `X-Chaperone-Signature` header carries this; the receiver verifies with the
/// shared secret.
pub fn sign_webhook(secret: &str, event: &EscalationEvent) -> String {
    let canonical = crate::canonical::canonical_dumps(
        &serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(canonical.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Verify a webhook signature (constant-time).
pub fn verify_webhook(secret: &str, signature: &str, event: &EscalationEvent) -> bool {
    let expected = sign_webhook(secret, event);
    let sig = match base64::engine::general_purpose::STANDARD.decode(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(
        crate::canonical::canonical_dumps(
            &serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
        )
        .as_bytes(),
    );
    mac.verify_slice(&sig).is_ok() && signature == expected
}

/// A no-op notifier (no webhook configured — the safe default).
pub struct NoopNotifier;

impl WebhookNotifier for NoopNotifier {
    fn notify(&self, _event: &EscalationEvent) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> EscalationEvent {
        EscalationEvent {
            escalation_id: "esc_1".into(),
            event: "created".into(),
            agent_id: "agent_1".into(),
            tool: "stripe.refunds.create".into(),
            policy_id: "pol_refunds".into(),
            expires_at: "2026-08-25T14:15:00Z".into(),
        }
    }

    #[test]
    fn webhook_sign_and_verify() {
        let e = event();
        let sig = sign_webhook("secret", &e);
        assert!(verify_webhook("secret", &sig, &e));
        assert!(!verify_webhook("wrong", &sig, &e));
        assert!(!verify_webhook("secret", "!!!", &e));
    }

    #[test]
    fn webhook_tamper_rejected() {
        let e = event();
        let sig = sign_webhook("secret", &e);
        let mut tampered = e.clone();
        tampered.event = "approved".into();
        assert!(!verify_webhook("secret", &sig, &tampered));
    }

    #[test]
    fn noop_notifier_succeeds() {
        assert!(NoopNotifier.notify(&event()).is_ok());
    }
}
