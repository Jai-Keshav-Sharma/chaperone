# AGENTS.md — Warden build instructions (read this first)

This repo is the implementation of **Warden — the deterministic authorization gate for
AI agents.** Deterministic ALLOW / BLOCK / ESCALATE before every tool call, compiled
from plain-English policy, with a tamper-evident ledger you can hand to an auditor.

Positioning: "Seatbelts for `--dangerously-skip-permissions`." Apache-2.0, single Rust
binary, self-hostable. First mover in India's agent-governance layer.

## How to use this repo

All design decisions are LOCKED. Read these before writing code, in this order:

1. `docs/goals.md` — what we're building and why (north star, horizons, OSS/paid split, paper/dataset)
2. `docs/tech-stack.md` — the stack (Rust core + Cedar, sqlx-only storage, React dashboard)
3. `docs/flows/01..10` — the ten flows; the system IS these flows
4. `docs/data-model.md` — 8 tables, append-only ledger
5. `docs/policy-ir.md` — the rule language (compiler output + engine input)
6. `docs/repo-layout.md` — crate structure
7. `docs/threat-model.md` — honest boundaries
8. `docs/compliance-mapping.md` + `docs/aarm-mapping.md` — the standards story
9. `docs/competitive-positioning.md`, `docs/adoption-integration.md`, `docs/scalability-targets.md`
10. `docs/review-findings-resolution.md` — every external-review finding and its fix

## The laws (non-negotiable; any code violating these is wrong)

1. **Fail-closed always.** Interceptor forwards iff it holds a fresh well-formed ALLOW
   for the exact request_id. Every other state is a non-forward. No fail-open flag exists.
   Shadow mode is an explicit operator choice, never a fallback.
2. **No LLM in the decision path.** The gate is 100% deterministic. The LLM lives only
   in the offline compiler, and its output never activates without human approval.
3. **Append-then-respond.** No ledger entry → no verdict → interceptor blocks.
4. **One canonical hashing path.** Everything hashed or byte-compared goes through
   `canonical.rs`. Never string-concatenate preimages; never hash non-canonical JSON.
5. **Append-only ledger.** No UPDATE/DELETE in the ledger package. Ever.
6. **Determinism.** No wall-clock, randomness, or env reads inside evaluation. Time via
   the injected Clock; IDs generated at API boundaries only.
7. **Layering law.** models → ir|engine|ledger|storage|cache|escalation|compiler|docs
   → decision → server|cli. Nothing imports upward. models/ir/engine do zero I/O
   (that's what makes wasm demo + replay possible).
8. **Frozen wire contracts.** DecisionRequest/Response fields are fixed; unknown fields
   rejected. Reason codes: ESCALATION_* family unified.
9. **Trace redaction.** decision_trace carries rule ids, match booleans, operand paths —
   NEVER raw param values. Ledger stores params_hash (raw bytes) only; escalations
   store params_binding_hash (canonical) — the two are distinct, do not conflate.
10. **Honest numbers.** Cite only what the benchmark (E1–E6) measures. Claim AARM
    Aligned, not Conformant (production + evidence + TWG review required).
11. **Windows is first-class** (it's the dev platform): CI matrix includes
    windows-latest; hooks on Windows need CONIN$/CONOUT$ console access; shim needs
    npx.cmd + job-object handling.

## Build order (bottom-up; each step's tests must pass before the next)

1. `warden-core/models` — serde types: DecisionRequest/Response, Policy IR, reason codes (docs/policy-ir.md, flows/02)
2. `canonical.rs` + `clock.rs` + golden vectors (data-model, flows/04)
3. `ir` — validation + lint (docs/policy-ir.md)
4. `engine` — IR→Cedar transpile, cedar eval, reference evaluator, differential tests, needs_params, derived attributes
5. `ledger` — chain append/verify/genesis/recovery, RFC 6962 Merkle, C2SP checkpoints + Ed25519 + key_id, anchoring, proofs, export (flows/04)
6. `storage` — schema.rs (8 tables, data-model.md), sqlx for SQLite + Postgres
7. `decision` — DecisionService (flows/02 invariants)
8. `escalation` — lifecycle + sweeper (flows/03)
9. `warden-server` — axum routes (decisions, policies, escalations, ledger, health, metrics, ws)
10. `warden-cli` — init, hook (flows/05 incl. hook-local approval + ~30s bound), gateway (flows/06 incl. retry-native MRTR + signed requestState), shim (flows/07), doctor, policy/ledger/approve commands
11. `compiler` — provider trait (anthropic|openai-compat|ollama|fixture), pipeline, trust loop (flows/01)
12. `dashboard` — React/TS inbox + stream + ledger explorer
13. `bench` — env, gold, scenarios, runner, E1–E6 (flows/10)

## Conventions

- TDD: write the failing test, confirm RED, minimal code, GREEN, then `cargo test` clean.
- Table-driven tests for the engine; property tests (proptest) for differential; golden
  vectors pinned as literals; FixedClock is the only clock in unit tests.
- Commits: `<type>(<area>): <summary>` — one logical change per commit.
- Never weaken a test to make a task pass. A differential mismatch is always an engine
  bug — fix the engine, never the test.
- `docs/` is the spec: changing a decision = update the doc in the same commit.
- `review-findings.md`, `review-2-findings.md`, `docs/review-findings-resolution.md`
  are records — never silently edit them.

## External facts (verified Aug 2026 — do not "fix" these)

- MCP 2026-07-28 is the final spec: stateless core, MRTR retry-native with signed
  requestState, EMA. Claude Code hooks: nested hookSpecificOutput envelope, four
  outcomes (allow/deny/ask/defer — we emit allow/deny only), deny holds in bypass mode
  (verify per pinned host version).
- AARM v1.0: Core R1–R6 MUST; R4 = five decisions (we ship three — see aarm-mapping).
- EU AI Act: Art. 50 in force Aug 2 2026; Annex III deferred to Dec 2 2027.
- crates.io: `warden` and `warden-cli` both taken; crate name TBD (candidate:
  `warden-guard`), binary stays `warden`. GitHub org `wardengate` available.
