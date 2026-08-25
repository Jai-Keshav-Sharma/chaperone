# Chaperone — Technology Stack (LOCKED)

Decision date: 2026-08-23. Owner: Jai Keshav Sharma.

## Stack

| Layer | Technology |
|---|---|
| Core language | Rust (single monolith, one static binary named `chaperone`) |
| Policy engine | Chaperone Policy IR (JSON) transpiled to Cedar (`cedar-policy` crate, the formally verified engine AWS uses) + Cedar Analysis for policy verification |
| Runtime / service | `axum` + `tokio` (async HTTP service: decisions API, policy admin, escalations, ledger, WebSocket stream) |
| Ledger | SHA-256 hash chain (`sha2`) + RFC 6962 Merkle checkpoints + `ed25519-dalek` signing + optional Rekor v2 / RFC 3161 TSA anchoring (`reqwest`); storage: SQLite / Postgres via `sqlx` ONLY (one storage code path — no rusqlite) |
| Interceptors | Same binary: `chaperone hook` (Claude Code / Cursor PreToolUse), `chaperone gateway` (MCP streamable-HTTP proxy), `chaperone shim` (MCP stdio proxy); cold-start TARGET ~1ms (measured in E2 — Windows process spawn is several ms), fail-closed. Hook HTTP client = `ureq` (blocking, no async runtime — faster cold start); gateway uses `reqwest` |
| NL policy compiler | Rust: `anthropic` / `async-openai` crates, `serde` + `schemars` (schema-constrained structured outputs), offline only, human-approval trust loop |
| Escalation / HITL | In-core: approval inbox API + auto-deny sweeper + params-hash binding |
| Cache / policy currency | In-process -> Redis (`redis` crate) -> DB, with pub/sub invalidation |
| Dashboard | TypeScript + React (Vite), dark terminal aesthetic |
| CLI | `clap` — CANONICAL verb list (all other docs point here; review-3 P2-8): `chaperone init [--demo] [--no-autostart] \| hook \| serve \| gateway \| shim \| doctor \| unhook \| approve <id> \| deny <id> \| escalations list \| policy compile\|edit\|lint\|test\|activate \| ledger verify\|prove\|checkpoint\|export \| bench` |
| Plugins (future) | WASM components via `wasmtime` (language-agnostic, sandboxed) |
| Browser demo | chaperone-core's engine is pure/I/O-free → compiles to `wasm32` — landing-page interactive demo ("type a rule, watch the decision + ledger receipt render") |
| ML (future) | Train in Python -> export ONNX -> run in Rust via `ort` (ONNX Runtime); zero ML in the decision path, by design |
| Testing | Table-driven unit + property (`proptest`) + differential (reference evaluator == Cedar) + integration + latency bench (criterion) |
| Packaging | Single static binary per platform (prebuilt releases + `cargo install` + brew + winget/scoop); optional `npx` shim later for hook distribution. NOTE: crate name `chaperone` is FREE on crates.io (verified); binary stays `chaperone`, crate = `chaperone`; reserve before launch (ADOPT-1) |
| License | Apache-2.0 |
## Principles

1. **No ML in the decision path.** The gate is 100% deterministic, replayable, and
   auditor-verifiable — a property NO ML-based system (Zenity, Straiker, Cerbos
   argument-aware ABAC) can claim. This is the first sentence of every technical
   conversation, not a footnote (review-5 §7d).
2. Rust everywhere in the decision path. One language, one binary, one trust boundary.
3. Fail-closed always. Shadow mode is explicit opt-in, never a fallback.
4. Extensibility via protocols (MCP), data (Policy IR), and WASM plugins — not via
   host-language runtime.
5. LLM lives only in the offline compiler, and its output never activates without
   human approval.
6. Launch comms lead with MEASURED numbers from E2, whatever they are — if cold start
   is 8ms on Windows and 3ms on Linux, say that (review-5 §7a).