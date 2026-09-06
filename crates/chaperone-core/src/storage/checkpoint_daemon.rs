//! The checkpoint daemon (Flow 4 Layer 2): a tokio background task that emits
//! a signed Merkle checkpoint every N entries or T seconds (whichever comes
//! first), asynchronously — checkpoints never block the decision hot path.
//! Lives in `storage` (it orchestrates the `Store`), which is the same band as
//! the escalation sweeper (Layering Law 7).

use crate::ledger::ChainStore;
use crate::storage::store::Store;
use std::sync::Arc;
use std::time::Duration;

/// Spawn the checkpoint daemon. `signing_key` is `None` in unsigned dev mode.
/// The loop runs until the runtime shuts down.
pub fn spawn_checkpoint_daemon(
    store: Store,
    signing_key: Option<ed25519_dalek::SigningKey>,
    interval_entries: u64,
    interval_seconds: u64,
) -> tokio::task::JoinHandle<()> {
    let store = Arc::new(store);
    let signing_key = Arc::new(signing_key);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(interval_seconds.max(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let should = match should_emit(&store, interval_entries).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("chaperone: checkpoint daemon: {e}");
                    continue;
                }
            };
            if should && let Err(e) = store.emit_checkpoint(signing_key.as_ref().as_ref()).await {
                eprintln!("chaperone: checkpoint emit failed: {e}");
            }
        }
    })
}

/// Decide whether a new checkpoint is due: the chain head has advanced past
/// `last_checkpoint.tree_size + interval_entries`, OR no checkpoint exists yet
/// and the head has advanced at least `interval_entries` past genesis.
async fn should_emit(
    store: &Store,
    interval_entries: u64,
) -> Result<bool, crate::storage::store::StoreError> {
    let last_cp = store.latest_checkpoint().await?;
    let head = store
        .last_entry()
        .await
        .map(|e| e.map(|x| x.entry_seq).unwrap_or(0))
        .unwrap_or(0);
    let last_covered = last_cp.as_ref().map(|cp| cp.tree_size as u64).unwrap_or(0);
    Ok(head >= last_covered + interval_entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn should_emit_tracks_entry_cadence(pool: sqlx::SqlitePool) {
        let store = Store::from_test_pool(pool);
        crate::ledger::chain::append_genesis(&store).await.unwrap();
        // No checkpoint yet, head = 0 (genesis). interval 0 → due.
        assert!(should_emit(&store, 0).await.unwrap());
        // interval 10 → genesis alone not enough.
        assert!(!should_emit(&store, 10).await.unwrap());
    }
}
