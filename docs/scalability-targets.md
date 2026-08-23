# Scalability Targets & Scale-Out Path

Status: DECIDED. Date: 2026-08-23.

## Target

**300–1,000 authenticated, synchronously-ledgered decisions/sec per node** — with full
fsync durability on every append. Published as an honest benchmark number.

## Why that target is generous

Agent tool calls are throttled by LLM token generation (seconds per turn), so traffic in
this domain is tiny compared to web-scale:

- A busy agent: ~1 tool call per few seconds
- A huge enterprise fleet (10,000 concurrent agents): ~1,000–3,000 calls/sec absolute peak
- One modest server covers a Fortune-500-scale fleet

## Layer capacity map

| Layer | Capacity per node | Bottleneck? |
|---|---|---|
| Policy engine (Cedar, in-process) | 10k–100k evals/sec (µs) | No |
| Policy cache (in-proc / Redis) | µs – <1ms | No |
| HTTP (axum/tokio) | tens of thousands req/s | No |
| Ledger append (synchronous fsync) | 300–1,000/sec | Yes — by design |

The sync fsync append (~1–3ms) is a deliberate durability tax, not an accident: no
unlogged ALLOW may ever exist. A security/audit product trades throughput for provable
durability — the correct trade. (Contrast: detection platforms like Zenity buffer events
in Kafka because losing a few is survivable; losing a ledger entry is not.)

## Per-decision guarantees (independent of load)

- Engine <10ms P95; endpoint <50ms P95 incl. sync ledger append
- Interceptor timeout 1000ms → fail-closed BLOCK
- Fail-closed doctrine unchanged under any load

## Designed scale-out path (in order, only when measured traffic demands)

1. Read/write split: verify, proofs, exports, dashboard reads are replica-safe already.
2. Multi-writer ledger: sequence assignment moves into a DB transaction
   (SELECT ... FOR UPDATE + insert). Preimage spec unchanged. → several thousand/sec on Postgres.
3. Per-shard chains with cross-anchored checkpoints: shard ledger by tenant/agent-group;
   each shard its own chain; all shard checkpoints anchor into the same Rekor/TSA witnesses.
   → platform scale. (Merkle structure fully earns its name here.)
4. Stateless decision replicas: engine is a pure function over immutable policy bytes;
   evaluation replicas scale freely behind a load balancer once writes are decoupled.

Principle: hard guarantees are independent of load; aggregate throughput is added only
when traffic demands. Never pre-build scale we can't measure.

## Competitor context

- OAP (research): 53ms median over 1,000 decisions. Warden targets <50ms P95 at thousands/sec.
- Arcade: 25x tool-call growth, but OAuth checks — no sync audit chain, no fsync tax.
- Zenity: Kafka event streams — more ingest, fewer guarantees (detection-first, not prevention-first).
