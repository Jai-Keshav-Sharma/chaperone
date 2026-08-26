use crate::ledger::chain::{compute_entry_hash, genesis_entry};
use crate::models::ledger::LedgerEntry;

/// The result of re-verifying a chain (docs/flows/04 verify CLI):
/// `chaperone ledger verify` → CHAIN OK (N entries) / CHAIN BROKEN at seq K.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    ChainOk { entries: u64 },
    ChainBroken { seq: Option<u64>, reason: String },
}

impl VerificationResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, VerificationResult::ChainOk { .. })
    }
}

/// Recompute hashes + linkage over the full entry list (pure — the caller
/// reads entries from the store). Checks, in order:
/// 1. non-empty and entry 0 is the fixed genesis (prev = 0*64);
/// 2. every entry's stored entry_hash equals sha256(canonical(preimage));
/// 3. every entry's previous_hash equals the predecessor's entry_hash;
/// 4. seq is contiguous (0, 1, 2, ...).
pub fn verify_chain(entries: &[LedgerEntry]) -> VerificationResult {
    if entries.is_empty() {
        return VerificationResult::ChainBroken {
            seq: None,
            reason: "chain is empty — genesis entry missing".to_string(),
        };
    }
    let genesis = genesis_entry();
    let first = &entries[0];
    if first.entry_seq != 0
        || first.entry_type != genesis.entry_type
        || first.previous_hash != genesis.previous_hash
        || first.entry_ts != genesis.entry_ts
        || first.agent_id != genesis.agent_id
        || first.tool != genesis.tool
        || first.request_id != genesis.request_id
    {
        return VerificationResult::ChainBroken {
            seq: Some(0),
            reason: "entry 0 is not the fixed genesis entry".to_string(),
        };
    }
    for (i, entry) in entries.iter().enumerate() {
        if entry.entry_seq != i as u64 {
            return VerificationResult::ChainBroken {
                seq: Some(entry.entry_seq),
                reason: format!("sequence gap: expected {i}, found {}", entry.entry_seq),
            };
        }
        let recomputed = compute_entry_hash(entry);
        if recomputed != entry.entry_hash {
            return VerificationResult::ChainBroken {
                seq: Some(entry.entry_seq),
                reason: format!(
                    "hash mismatch: entry_hash is {}, recomputed {}",
                    entry.entry_hash, recomputed
                ),
            };
        }
        if i > 0 && entry.previous_hash != entries[i - 1].entry_hash {
            return VerificationResult::ChainBroken {
                seq: Some(entry.entry_seq),
                reason: "previous_hash does not link to the predecessor's entry_hash".to_string(),
            };
        }
    }
    VerificationResult::ChainOk {
        entries: entries.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::chain::tests::{InMemoryChainStore, decision_entry};
    use crate::ledger::chain::{append, append_genesis};

    fn three_entry_chain() -> InMemoryChainStore {
        let store = InMemoryChainStore::new();
        append_genesis(&store).expect("genesis");
        append(
            &store,
            decision_entry(0, "req_a", "ALLOW", vec![], "2026-08-25T14:00:00Z"),
        )
        .expect("a");
        append(
            &store,
            decision_entry(0, "req_b", "BLOCK", vec![], "2026-08-25T14:00:01Z"),
        )
        .expect("b");
        store
    }

    type Mutation = fn(&mut InMemoryChainStore);

    #[test]
    fn verify_detects_tamper() {
        // every preimage field, mutated → CHAIN BROKEN at the right seq
        let mutations: Vec<(&str, Mutation)> = vec![
            ("decision", |s| {
                s.mutate(1, |e| e.decision = "WOULD_ALLOW".to_string())
            }),
            ("params_hash", |s| {
                s.mutate(1, |e| e.params_hash = "f".repeat(64))
            }),
            ("entry_ts", |s| {
                s.mutate(1, |e| e.entry_ts = "2026-08-25T15:00:00Z".to_string())
            }),
            ("agent_id", |s| {
                s.mutate(1, |e| e.agent_id = "other".to_string())
            }),
            ("tool", |s| s.mutate(1, |e| e.tool = "fs.write".to_string())),
            ("policy_id", |s| {
                s.mutate(1, |e| e.policy_id = "pol_other".to_string())
            }),
            ("request_id", |s| {
                s.mutate(1, |e| e.request_id = "req_x".to_string())
            }),
            ("reason_code", |s| {
                s.mutate(1, |e| e.reason_code = "DEFAULT_DENY".to_string())
            }),
            ("determining_rule_ids", |s| {
                s.mutate(1, |e| e.determining_rule_ids = vec!["r-x".into()])
            }),
            ("entry_hash", |s| {
                s.mutate(1, |e| e.entry_hash = "a".repeat(64))
            }),
            ("previous_hash", |s| {
                s.mutate(2, |e| e.previous_hash = "b".repeat(64))
            }),
        ];
        for (field, mutate) in mutations {
            let mut store = three_entry_chain();
            mutate(&mut store);
            let result = verify_chain(&store.entries());
            assert!(!result.is_ok(), "tampered field {field} not detected");
            assert!(
                matches!(
                    result,
                    VerificationResult::ChainBroken {
                        seq: Some(1 | 2),
                        ..
                    }
                ),
                "tampered field {field}: wrong location {result:?}"
            );
        }
    }

    #[test]
    fn verify_ok_chain() {
        let store = three_entry_chain();
        assert_eq!(
            verify_chain(&store.entries()),
            VerificationResult::ChainOk { entries: 3 }
        );
    }

    #[test]
    fn verify_detects_truncation_and_reorder() {
        let store = three_entry_chain();
        store.truncate(2);
        assert_eq!(
            verify_chain(&store.entries()),
            VerificationResult::ChainOk { entries: 2 }
        );
        // truncation below genesis
        let store = three_entry_chain();
        store.truncate(0);
        let r = verify_chain(&store.entries());
        assert!(matches!(
            r,
            VerificationResult::ChainBroken { seq: None, .. }
        ));

        // reorder: swap entries 1 and 2 → linkage breaks
        let store = three_entry_chain();
        store.mutate(1, |e| e.entry_seq = 9);
        store.mutate(2, |e| e.entry_seq = 9);
        let r = verify_chain(&store.entries());
        assert!(!r.is_ok());
    }
}
