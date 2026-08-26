use serde_json::{Value as JsonValue, json};

use crate::canonical::{canonical_dumps, sha256_hex};
use crate::ledger::{ChainError, ChainStore};
use crate::models::ledger::{EntryType, LedgerEntry};

/// The preimage of a ledger entry — EXACTLY the field set of docs/flows/04:
/// seq, ts, prev, entry_type, request_id, agent_id, tool, params_hash,
/// decision, policy_id, policy_version, policy_hash, determining_rule_ids,
/// reason_code. Trace, latency, tenant_id, escalation_id are NOT hashed.
/// Canonical JSON (sorted keys, no whitespace) via the single hashing path
/// (Law 4). Golden-vector-pinned (tests below).
pub fn entry_preimage(entry: &LedgerEntry) -> JsonValue {
    json!({
        "seq": entry.entry_seq,
        "ts": entry.entry_ts,
        "prev": entry.previous_hash,
        "entry_type": entry.entry_type.as_str(),
        "request_id": entry.request_id,
        "agent_id": entry.agent_id,
        "tool": entry.tool,
        "params_hash": entry.params_hash,
        "decision": entry.decision,
        "policy_id": entry.policy_id,
        "policy_version": entry.policy_version,
        "policy_hash": entry.policy_hash,
        "determining_rule_ids": entry.determining_rule_ids,
        "reason_code": entry.reason_code,
    })
}

/// entry_hash = sha256(canonical_dumps(preimage)) — the only hashing path.
pub fn compute_entry_hash(entry: &LedgerEntry) -> String {
    sha256_hex(&canonical_dumps(&entry_preimage(entry)))
}

/// The fixed genesis entry (docs/flows/04: "entry 0 fixed, written on first
/// startup"). Its digest is golden-vector-pinned below — any drift in the
/// preimage shape or hashing breaks the chain from entry zero.
pub fn genesis_entry() -> LedgerEntry {
    let z = "0".repeat(64);
    LedgerEntry {
        entry_seq: 0,
        entry_ts: "2026-08-25T00:00:00Z".to_string(),
        previous_hash: z.clone(),
        entry_hash: String::new(), // computed by append_genesis
        entry_type: EntryType::Genesis,
        request_id: "genesis".to_string(),
        agent_id: "chaperone".to_string(),
        tool: "chaperone".to_string(),
        params_hash: z.clone(),
        tenant_id: None,
        decision: "GENESIS".to_string(),
        policy_id: "__none__".to_string(),
        policy_version: 0,
        policy_hash: z.clone(),
        determining_rule_ids: Vec::new(),
        reason_code: "GENESIS".to_string(),
        decision_trace: "[]".to_string(),
        evaluation_latency_ms: 0.0,
        escalation_id: None,
    }
}

/// Write the fixed genesis entry. Fails if the chain already has entries.
pub fn append_genesis(store: &dyn ChainStore) -> Result<LedgerEntry, ChainError> {
    if store.last_entry()?.is_some() {
        return Err(ChainError::GenesisExists);
    }
    let mut entry = genesis_entry();
    entry.entry_hash = compute_entry_hash(&entry);
    store.insert_entry(&entry)?;
    Ok(entry)
}

/// Synchronous append (docs/flows/04 Layer 1): read head → compute seq, prev,
/// hash → insert. The store provides the atomic single-writer guarantee.
/// Idempotency: a duplicate (request_id, entry_type) surfaces as
/// ChainError::DuplicateEntry from the store's UNIQUE constraint — the
/// decision service answers the replay from the original entry instead.
pub fn append(store: &dyn ChainStore, mut entry: LedgerEntry) -> Result<(u64, String), ChainError> {
    let last = store.last_entry()?;
    match &last {
        Some(head) => {
            entry.entry_seq = head.entry_seq + 1;
            entry.previous_hash = head.entry_hash.clone();
        }
        None => return Err(ChainError::GenesisMissing),
    }
    entry.entry_hash = compute_entry_hash(&entry);
    store.insert_entry(&entry)?;
    Ok((entry.entry_seq, entry.entry_hash.clone()))
}

#[cfg(test)]
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    /// In-memory ChainStore for pure tests: enforces the UNIQUE
    /// (request_id, entry_type) constraint and append-only semantics, exactly
    /// like the Phase-6 sqlx implementation must.
    pub(crate) struct InMemoryChainStore {
        entries: RefCell<Vec<LedgerEntry>>,
    }

    impl InMemoryChainStore {
        pub fn new() -> Self {
            InMemoryChainStore {
                entries: RefCell::new(Vec::new()),
            }
        }
        pub fn entries(&self) -> Vec<LedgerEntry> {
            self.entries.borrow().clone()
        }
        /// Tamper helper for verify tests: mutate one entry in place.
        pub fn mutate(&self, seq: u64, f: impl FnOnce(&mut LedgerEntry)) {
            let mut entries = self.entries.borrow_mut();
            let entry = entries
                .iter_mut()
                .find(|e| e.entry_seq == seq)
                .expect("seq exists");
            f(entry);
        }
        pub fn truncate(&self, keep: usize) {
            self.entries.borrow_mut().truncate(keep);
        }
    }

    impl ChainStore for InMemoryChainStore {
        fn last_entry(&self) -> Result<Option<LedgerEntry>, ChainError> {
            Ok(self.entries.borrow().last().cloned())
        }
        fn insert_entry(&self, entry: &LedgerEntry) -> Result<(), ChainError> {
            let mut entries = self.entries.borrow_mut();
            let dup = entries
                .iter()
                .any(|e| e.request_id == entry.request_id && e.entry_type == entry.entry_type);
            if dup {
                return Err(ChainError::DuplicateEntry {
                    request_id: entry.request_id.clone(),
                    entry_type: entry.entry_type,
                });
            }
            entries.push(entry.clone());
            Ok(())
        }
    }

    pub(crate) fn decision_entry(
        seq_hint: u64,
        request_id: &str,
        decision: &str,
        rules: Vec<&str>,
        ts: &str,
    ) -> LedgerEntry {
        LedgerEntry {
            entry_seq: seq_hint,
            entry_ts: ts.to_string(),
            previous_hash: String::new(),
            entry_hash: String::new(),
            entry_type: EntryType::Decision,
            request_id: request_id.to_string(),
            agent_id: "agent_support_09".to_string(),
            tool: "stripe.refunds.create".to_string(),
            params_hash: "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091"
                .to_string(),
            tenant_id: None,
            decision: decision.to_string(),
            policy_id: "pol_refunds".to_string(),
            policy_version: 3,
            policy_hash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                .to_string(),
            determining_rule_ids: rules.into_iter().map(String::from).collect(),
            reason_code: "RULE_MATCH".to_string(),
            decision_trace: "[]".to_string(),
            evaluation_latency_ms: 1.0,
            escalation_id: None,
        }
    }

    #[test]
    fn golden_vector_chain() {
        // Independently computed (Python hashlib, pinned as literals): the
        // genesis + two linked decision entries. A drift in the preimage
        // shape, canonical form, or hashing breaks these pins.
        let genesis = genesis_entry();
        assert_eq!(
            compute_entry_hash(&genesis),
            "61eaf75514a57b377ee3b3ead172419206321b6d2fa2e300d907ec250a5a90e5"
        );
        assert_eq!(
            canonical_dumps(&entry_preimage(&genesis)),
            r#"{"agent_id":"chaperone","decision":"GENESIS","determining_rule_ids":[],"entry_type":"GENESIS","params_hash":"0000000000000000000000000000000000000000000000000000000000000000","policy_hash":"0000000000000000000000000000000000000000000000000000000000000000","policy_id":"__none__","policy_version":0,"prev":"0000000000000000000000000000000000000000000000000000000000000000","reason_code":"GENESIS","request_id":"genesis","seq":0,"tool":"chaperone","ts":"2026-08-25T00:00:00Z"}"#
        );

        let mut e1 = decision_entry(
            0,
            "req_7f3a2b1c",
            "ALLOW",
            vec!["r-allow-small"],
            "2026-08-25T14:00:00Z",
        );
        e1.previous_hash = compute_entry_hash(&genesis);
        e1.entry_seq = 1;
        assert_eq!(
            compute_entry_hash(&e1),
            "7e5babc927e18e223203fbad5af6a49dd6a5ac3b9746c2bd4e4c5a52e6cadc04"
        );

        let mut e2 = decision_entry(
            0,
            "req_9c4e2f70",
            "BLOCK",
            vec!["r-block-large"],
            "2026-08-25T14:00:01Z",
        );
        e2.previous_hash = compute_entry_hash(&e1);
        e2.entry_seq = 2;
        e2.params_hash =
            "d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e".to_string();
        assert_eq!(
            compute_entry_hash(&e2),
            "d2ee2798f322de5f437efb296f58304f132d4a470877a6a9735e94c868b65388"
        );
    }

    #[test]
    fn genesis_written_on_first_startup() {
        let store = InMemoryChainStore::new();
        let g = super::genesis_entry();
        assert_eq!(g.entry_seq, 0);
        assert_eq!(g.entry_type, EntryType::Genesis);
        assert_eq!(g.previous_hash, "0".repeat(64));
        // the fixed genesis digest is golden-vector-pinned
        assert_eq!(
            compute_entry_hash(&g),
            "61eaf75514a57b377ee3b3ead172419206321b6d2fa2e300d907ec250a5a90e5"
        );
        // append_genesis writes it (with its hash) and refuses a second
        let written = append_genesis(&store).expect("genesis");
        let mut expected = g;
        expected.entry_hash = compute_entry_hash(&expected);
        assert_eq!(written, expected);
        assert_eq!(append_genesis(&store), Err(ChainError::GenesisExists));
    }

    #[test]
    fn append_links_and_numbers() {
        let store = InMemoryChainStore::new();
        append_genesis(&store).expect("genesis");
        let (seq1, h1) = append(
            &store,
            decision_entry(0, "req_a", "ALLOW", vec![], "2026-08-25T14:00:00Z"),
        )
        .expect("append");
        assert_eq!(seq1, 1);
        let (seq2, h2) = append(
            &store,
            decision_entry(0, "req_b", "BLOCK", vec![], "2026-08-25T14:00:01Z"),
        )
        .expect("append");
        assert_eq!(seq2, 2);
        let entries = store.entries();
        assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
        assert_eq!(entries[2].previous_hash, entries[1].entry_hash);
        assert_eq!(entries[1].entry_hash, h1);
        assert_eq!(entries[2].entry_hash, h2);
    }

    #[test]
    fn append_before_genesis_fails() {
        let store = InMemoryChainStore::new();
        assert_eq!(
            append(
                &store,
                decision_entry(0, "req_a", "ALLOW", vec![], "2026-08-25T14:00:00Z")
            ),
            Err(ChainError::GenesisMissing)
        );
    }

    #[test]
    fn idempotent_replay() {
        let store = InMemoryChainStore::new();
        append_genesis(&store).expect("genesis");
        let entry = decision_entry(0, "req_dup", "ALLOW", vec![], "2026-08-25T14:00:00Z");
        append(&store, entry.clone()).expect("first append");
        // Replaying the same (request_id, entry_type) is rejected by the
        // UNIQUE constraint — the decision service answers from the original.
        let err = append(&store, entry.clone()).expect_err("duplicate must fail");
        assert!(matches!(err, ChainError::DuplicateEntry { .. }));
        assert_eq!(store.entries().len(), 2); // genesis + original, no double append
    }

    #[test]
    fn no_update_or_delete_statements() {
        // Law 5 made mechanical: the ledger package's source contains no SQL
        // mutation statements anywhere. The keywords are assembled from chars
        // so the test's own source cannot trip the check it performs.
        let update_kw: String = ['U', 'P', 'D', 'A', 'T', 'E', ' '].into_iter().collect();
        let delete_kw: String = ['D', 'E', 'L', 'E', 'T', 'E', ' '].into_iter().collect();
        let files = [
            include_str!("mod.rs"),
            include_str!("chain.rs"),
            include_str!("verify.rs"),
            include_str!("merkle.rs"),
            include_str!("checkpoint.rs"),
            include_str!("anchor.rs"),
            include_str!("proof.rs"),
            include_str!("export.rs"),
        ];
        for src in files {
            for (i, line) in src.lines().enumerate() {
                let up = line.to_uppercase();
                assert!(
                    !up.contains(&update_kw) && !up.contains(&delete_kw),
                    "ledger source contains a mutation statement: line {}",
                    i + 1
                );
            }
        }
    }
}
