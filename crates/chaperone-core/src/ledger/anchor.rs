//! External anchoring (docs/flows/04 Layer 3, optional/best-effort): publish
//! each signed checkpoint to Rekor v2 and/or an RFC 3161 TSA so old
//! checkpoints exist OUTSIDE the system. The pure core defines the seam; the
//! concrete HTTP clients land in chaperone-server (reqwest) — the network is
//! the server's job, never the pure layer's.

use crate::ledger::checkpoint::Checkpoint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorReceipt {
    /// Rekor v2 entry JSON.
    Rekor(String),
    /// RFC 3161 time-stamp token.
    Tsa(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorError {
    pub message: String,
}

impl AnchorError {
    pub fn new(message: impl Into<String>) -> Self {
        AnchorError {
            message: message.into(),
        }
    }
}

/// The anchoring seam. Implementations (Phase 9, server crate) are
/// best-effort by contract: anchoring failure must never affect decisions or
/// checkpoint emission — it only weakens Layer 3 coverage.
pub trait AnchorProvider: Send + Sync {
    fn anchor_checkpoint(&self, checkpoint: &Checkpoint) -> Result<AnchorReceipt, AnchorError>;
}

/// No-op provider for dev/test deployments (anchoring is config-driven;
/// unsigned dev mode already signals "no external witnesses").
pub struct NoopAnchorProvider;

impl AnchorProvider for NoopAnchorProvider {
    fn anchor_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<AnchorReceipt, AnchorError> {
        Err(AnchorError::new("no anchor provider configured"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_provider_errors_cleanly() {
        let provider = NoopAnchorProvider;
        let err = provider
            .anchor_checkpoint(&Checkpoint {
                origin: "chaperone".into(),
                tree_size: 1,
                root_hash: "0".repeat(64),
                key_id: "k".into(),
                signature: None,
                body: "body".into(),
                text: "text".into(),
            })
            .expect_err("noop must fail");
        assert!(err.message.contains("no anchor provider"));
    }
}
