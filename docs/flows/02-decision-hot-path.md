# Flow 2 — Decision Hot Path

Status: DECIDED. Date: 2026-08-23.

## The flow

```
Agent proposes action (tool call)
  → Interceptor (hook / gateway / shim) builds DecisionRequest
      {request_id, agent_id, tool, params, context{request_time, surface, delegation_depth}}
  → POST to decision service (1000ms timeout)
  → 1. Agent lookup   (unknown/inactive → BLOCK AGENT_UNKNOWN / AGENT_INACTIVE, still ledgered)
  → 2. Policy lookup  (in-proc → Redis → DB; unavailable → BLOCK FAIL_CLOSED_POLICY_UNAVAILABLE)
  → 3. Derived context (budgets/velocity computed from ledger at the boundary, then ledgered)
  → 4. Engine evaluation (Cedar): determining rules →
       BLOCK-rule → BLOCK | else ESCALATE-rule → ESCALATE | else ALLOW-rule → ALLOW
       | else BLOCK (DEFAULT_DENY). Eval error → BLOCK (EVAL_ERROR). No policy → BLOCK (NO_POLICY)
  → 5. SYNCHRONOUS ledger append (before any response) → seq + entry_hash
  → 6. Respond {decision, reason_code, determining_rule_ids, policy_id/version/hash, entry refs, trace}
  → 7. Interceptor acts: ALLOW → forward/permit | BLOCK → structured denial | ESCALATE → pending approval
  → Fail-closed envelope: timeout/5xx/malformed → synthesize BLOCK (FAIL_CLOSED_GATE_UNREACHABLE)
```

## Invariants

1. Append-then-respond: no ledger entry → no verdict → interceptor blocks. Order is sacred.
2. Fail-closed always: an interceptor forwards iff it holds a fresh, well-formed ALLOW for
   the exact request_id. Every other state is a non-forward. No "degraded allow" exists.
3. Idempotency via request_id: replays return the original decision, no double evaluation/append.
4. Determinism: request_time and derived context computed at the boundary, passed in, ledgered.
   Engine never reads wall clock / randomness. Same request + policy → same verdict, forever.
5. Shadow mode (explicit opt-in): same evaluation + ledger as WOULD_*; interceptor always proceeds.
6. Latency budget: engine <10ms P95, endpoint <50ms P95, hook binary startup ~1ms.

## Tooling decisions

### Storage — one ACID relational store, two engines

| Component | Choice | Rationale |
|---|---|---|
| Primary store | Relational (SQLite → Postgres) via `sqlx` | Intensely relational data; ACID transactions for ledger append (read-last-hash + write-next-entry) and policy activation (deactivate-old + activate-new) |
| Document DB | Rejected | Schema flexibility is a vulnerability in a security product; Postgres JSONB covers blobs (traces, params, reports) inside the transactional store |
| Kafka / ES / Flink | Rejected | Detection-pipeline infrastructure (Zenity's world); our prevention-first path needs ordering + durability, not eventual-consistency streams |

- SQLite (WAL mode) = default single-node engine; Postgres = fleet-mode engine, same schema, swap via config.
- One database = one transaction boundary = provable integrity.
- Competitor precedent: OpenFGA uses Postgres/MySQL; OPA is DB-less but has no ledger to keep.

### Cache — optional Redis, correctness never depends on it

| Tier | Contents | Failure behavior |
|---|---|---|
| 1. In-process | Active policy set (parsed, compiled) | Always present |
| 2. Redis | Shared copy + pub/sub invalidation | Down → skip to tier 3, reconnect loop |
| 3. Database | Source of truth | Down → BLOCK (FAIL_CLOSED_POLICY_UNAVAILABLE) |

- Cache is purely a latency optimization; a cache outage cannot change a verdict.
- Single-node runs with no Redis (zero mandatory infra for the quickstart).

### Supporting decisions

| Concern | Choice |
|---|---|
| API format | JSON over HTTP via `axum` + serde; frozen wire contracts (unknown fields rejected) |
| Service auth | Static bearer API keys, SHA-256 hashed at rest; agent keys ≠ admin keys |
| Time | Injected `Clock` trait; request_time computed at interceptor boundary |
| IDs | UUIDv4 request_id at interceptor; esc_ + uuid for escalations; never generated inside evaluation |
| Observability | `tracing` (structured JSON) + Prometheus `/metrics` (decision counters, latency histogram, cache-tier hits, ledger head) |
| Migrations | Embedded via `sqlx migrate` (schema versioned in the binary) |
| Ledger hygiene | entry_ts stored as the exact hashed RFC3339 string; params stored as hash only (full JSON only in escalations) — the ledger keeps no secrets |
