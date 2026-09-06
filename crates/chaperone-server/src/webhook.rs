//! HTTP webhook notifier (flows/03): posts a signed escalation event to the
//! configured webhook URL. Best-effort — a notification failure never affects
//! the escalation lifecycle (the ledger is the source of truth).

use chaperone_core::escalation::webhook::{EscalationEvent, WebhookNotifier, sign_webhook};

/// An async HTTP notifier. Sends are fire-and-forget (`tokio::spawn`); the
/// HMAC-signed payload carries `X-Chaperone-Signature`.
pub struct HttpWebhookNotifier {
    url: String,
    secret: String,
    client: reqwest::Client,
}

impl HttpWebhookNotifier {
    pub fn new(url: impl Into<String>, secret: impl Into<String>) -> Self {
        HttpWebhookNotifier {
            url: url.into(),
            secret: secret.into(),
            client: reqwest::Client::new(),
        }
    }
}

impl WebhookNotifier for HttpWebhookNotifier {
    fn notify(&self, event: &EscalationEvent) -> Result<(), String> {
        let signature = sign_webhook(&self.secret, event);
        let url = self.url.clone();
        let body = serde_json::to_string(event).map_err(|e| e.to_string())?;
        let client = self.client.clone();
        let secret = self.secret.clone();
        let event = event.clone();
        // Fire-and-forget: the send happens off the caller's path.
        tokio::spawn(async move {
            let _ = client
                .post(&url)
                .header("content-type", "application/json")
                .header("x-chaperone-signature", signature)
                .body(body)
                .send()
                .await;
            let _ = (secret, event);
        });
        Ok(())
    }
}
