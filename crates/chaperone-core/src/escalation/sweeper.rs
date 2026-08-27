//! The escalation sweeper (Flow 3): a tokio background task that runs the
//! expiry sweep on a fixed interval. SILENCE ALWAYS MEANS DENY — an overdue
//! pending escalation is auto-expired (ESCALATION_RESOLVED(EXPIRED) ledgered).

use crate::escalation::service::EscalationService;
use std::sync::Arc;
use std::time::Duration;

/// Spawn the sweeper loop. `interval` is the sweep cadence (chaperone.yaml;
/// default 30s per flows/03). The loop runs until the runtime shuts down.
pub fn spawn_sweeper(
    service: Arc<EscalationService>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            // Errors are logged-and-continued: a transient DB failure must
            // not kill the sweeper (it retries next tick).
            if let Err(e) = service.sweep_due().await {
                eprintln!("chaperone: escalation sweeper error: {e}");
            }
        }
    })
}
