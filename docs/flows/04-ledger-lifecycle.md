# Flow 4 — Ledger Lifecycle (hash chain → checkpoints → anchoring)

Status: DECIDED. Date: 2026-08-23.

## Three layers, three threats

```
Layer 1  Hash chain           (hot path, synchronous)  detects modification of past entries
Layer 2  Merkle checkpoints   (async, Ed25519-signed)  detects full rewrites w/o the signing key
Layer 3  External anchoring   (optional, Rekor/TSA)    detects rewrites even by the key holder
```

## Layer 1 — hash chain (synchronous hot path)

- Every decision appends one entry before the verdict is returned (Flow 2 invariant).
- Hash preimage = CANONICAL JSON of the entry fields (sorted keys, fixed separators, exact
  number formatting). NEVER string concatenation (ambiguous preimages).
- Preimage fields: seq, ts (exact RFC3339 string, hashed as stored), prev, entry_type,
  request_id, agent_id, tool, params_hash, decision, policy_id, policy_version, policy_hash,
  determining_rule_ids, reason_code.
- Trace + latency stored but NOT hashed (trace format can evolve; auditable substance is inside).
- Discipline:
  - Single writer; append = one transaction (read last hash → write next entry).
  - Idempotency: UNIQUE(request_id, entry_type); replays return the original entry.
  - NO UPDATE/DELETE statements in the ledger package. Append-only by construction.
  - Genesis: entry 0 fixed, written on first startup.
  - Crash recovery: re-verify head + linkage on startup; corrupt → refuse to start (fail-closed).
- Shadow mode decisions ledger as WOULD_* — same chain, same guarantees.

## Layer 2 — Merkle checkpoints (async, never blocks decisions)

- Every N entries (default 1000) or T seconds (default 300): build RFC 6962 Merkle tree over
  entry hashes, emit C2SP checkpoint (tree size + root hash), Ed25519-signed.
- Buys: O(log n) inclusion proofs for any entry; consistency proofs between checkpoints;
  verifiable offline with the public key.

## Layer 3 — external anchoring (optional, config-driven, best-effort)

- Publish each checkpoint to Sigstore Rekor v2 and/or RFC 3161 TSA.
- Closes the residual threat: chain-owner rewrites everything + re-signs; old checkpoints
  exist outside the system.

## Honest threat model (published verbatim in docs/threat-model.md)

The chain alone detects modification of past entries by anyone without DB write access to
every subsequent row; chain + signed checkpoints detects rewrites unless the attacker also
holds the signing key; + external anchoring detects rewrites even by the key holder after
the anchoring interval. Warden does not defend against an attacker who controls the
decision service AT DECISION TIME — that boundary belongs to the interceptor/deployment.
Saying what we don't protect is what makes the protection credible.

## Tooling

| Capability | Tool |
|---|---|
| Hashing | `sha2` (SHA-256) |
| Canonical JSON | serde_json, sorted keys + fixed separators, single `canonical` module (only hashing path in the codebase) |
| Signing | `ed25519-dalek` |
| Merkle tree | RFC 6962 implemented in-house (~100 lines, golden-vectored) — no magic dependency in the crypto core |
| Checkpoint format | C2SP text (small, implemented + golden-vectored) |
| Rekor anchoring | `reqwest` against Rekor v2 HTTP API |
| TSA anchoring | `ts-rfc3161` crate |
| Storage | `ledger_entries` + `ledger_checkpoints` tables (same relational store); checkpoints store signed text + anchor receipts |
| Verify CLI | `warden ledger verify [--from N --to M]` → CHAIN OK (N entries) / CHAIN BROKEN at seq K: <reason> |
| Proofs CLI | `warden ledger prove --seq N` → JSON bundle (leaf + path + root + checkpoint + signature + pubkey), verifiable offline |
| Export CLI | `warden ledger export --format eu-ai-act|soc2` → zip: entries + checkpoints + proofs + policy versions + manifest mapping to regulation clauses |
| Golden vectors | Fully-specified entry + exact digest pinned as test literals; hash spec can never drift silently |
| Config | WARDEN_CHECKPOINT_INTERVAL_ENTRIES=1000, WARDEN_CHECKPOINT_INTERVAL_SECONDS=300, signing key path, Rekor/TSA URLs |

## Summary

Synchronous chain for durability; signed Merkle checkpoints for proof; external anchoring
for ultimate trust — all verifiable offline by a third party. A security product's claims
must never depend on its own database.
