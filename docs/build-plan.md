# Build Plan — task-level execution for the Chaperone implementation

Status: DECIDED. Date: 2026-08-25. Companion to AGENTS.md (build order + laws) and
docs/flows + docs/api-contracts.md + docs/data-model.md + docs/policy-ir.md.

Purpose: guide an implementing model (e.g. DeepSeek V4 Flash) through the build with
explicit per-task contracts, test-first names, Definition-of-Done, and guardrails, so
execution does not drift from the laws or the flows. The FLOWS + LAWS remain the source
of truth; this plan only sequences and structures the work.

## How to use this plan

- Work strictly bottom-up (Phase 0 → Phase 13). A phase's tests must pass before the next.
- For every task: write the failing test FIRST (TDD), confirm RED, implement minimal,
  confirm GREEN, then run the whole suite. This is mandatory (Law: TDD protocol).
- Before writing ANY code, load and apply the `karpathy-guidelines` skill (AGENTS.md).
- Every law in AGENTS.md is binding. If a task seems to require violating a law, STOP and
  surface the conflict — do not improvise around it.
- One logical change per commit; conventional-commit messages (changelog is generated
  from commits).

---

## Phase 0 — Scaffold the workspace

**Objective:** Cargo workspace, CI, makefile, config. No product logic.

Files: `Cargo.toml` (workspace), `crates/chaperone-core/`, `crates/chaperone-server/`,
`crates/chaperone-cli/`, `Makefile`, `.github/workflows/ci.yml`, `.gitignore`.

- Workspace members: `chaperone-core` (lib), `chaperone-server` (lib — axum app factory),
  `chaperone-cli` (bin named `chaperone`). Exactly ONE binary ships (Law).
- `ci.yml`: OS matrix `windows-latest` + `ubuntu-latest`; jobs = lint (clippy) + type
  + test (sqlite). cargo-fuzz job runs `ubuntu-latest` ONLY.
- `Makefile` targets: `install | check | test | test-all | bench | serve | changelog`.

**DoD:** `cargo build` succeeds across workspace; `make check` green in CI on both OSes.
**Guardrails:** No product code yet. Do not add dependencies beyond the scaffold.

---

## Phase 1 — chaperone-core/models

**Objective:** serde types for DecisionRequest/Response, Policy IR, reason codes.

Files: `crates/chaperone-core/src/models/{decision.rs, ir.rs, reason_code.rs, errors.rs}`.

Contract (from docs/api-contracts.md + docs/policy-ir.md):
- `DecisionRequest`, `DecisionResponse` exactly as frozen (unknown fields rejected).
- `Policy`, `Rule`, `Target`, condition nodes (closed op set), operands (param/context/value).
- `ReasonCode` closed enum (the ESCALATION_* family).

Tests (first): `models::decision::tests::roundtrip_decision_request`,
`models::decision::tests::reject_unknown_field`,
`models::ir::tests::parse_all_ops`, `models::reason_code::tests::enum_complete`.

**DoD:** models serialize/deserialize round-trip; unknown-field rejection works.
**Guardrails:** models have ZERO I/O (Law). No network, no DB, no filesystem here.

---

## Phase 2 — canonical.rs + clock.rs + golden vectors

**Objective:** the single hashing path + injected clock.

Files: `crates/chaperone-core/src/canonical.rs`, `crates/chaperone-core/src/clock.rs`.

Contract:
- `canonical_dumps(value) -> String` — RFC 8785-style canonical JSON (sorted keys,
  fixed separators, ensure_ascii=false). Used for entry hashes, params_hash, policy_hash.
- `sha256_hex(s) -> String`.
- `Clock` trait, `SystemClock`, `FixedClock` (the ONLY clock in unit tests — Law 6).

Tests (first): `canonical::tests::key_order_stable`,
`canonical::tests::golden_vector_entry_hash` (pinned literal digest),
`clock::tests::fixed_clock_advances`.

**DoD:** canonical output deterministic across runs; golden vector digest matches pinned literal.
**Guardrails:** ONE hashing path (Law 4). Never `‖`-concatenate preimages. Golden vectors
are literals, not computed at runtime.

---

## Phase 3 — ir (validation + lint)

**Objective:** IR validation and static lint per docs/policy-ir.md.

Files: `crates/chaperone-core/src/ir/{validate.rs, lint.rs}`.

Contract:
- Validation: schema-strict (extra=forbid), closed op set, operand types.
- Lint codes: ERROR_DUPLICATE_RULE_ID, ERROR_NO_RULES, ERROR_ALLOW_ESCALATE_OVERLAP,
  ERROR_CROSS_POLICY_CONFLICT; WARN_UNREACHABLE_ALLOW, WARN_TOOL_UNGOVERNED,
  WARN_BROAD_TARGET. Overlap detection = DNF over atomic predicates (bounded ~64 atoms);
  `matches` treated as always-satisfiable (conservative).

Tests (first): `ir::lint::tests::each_error_code_fires`,
`ir::lint::tests::cross_policy_conflict_detected`.

**DoD:** every lint code has a passing test; validation rejects malformed IR.
**Guardrails:** lint must not evaluate anything at runtime (Law).

---

## Phase 4 — engine

**Objective:** IR→Cedar transpile, Cedar eval, reference evaluator, differential tests,
needs_params, derived attributes.

Files: `crates/chaperone-core/src/engine/{cedar_compile.rs, cedar_engine.rs, reference.rs, derive.rs}`.

Contract:
- `to_cedar(policy) -> String` (deterministic; snapshot-tested). Effects map: allow→permit,
  block→forbid, escalate→forbid+`@warden_effect("escalate")`. Entity model per flows/06.
- `CedarEngine::evaluate(policies, request) -> EngineResult`.
- `reference::evaluate_ir(policies, request) -> EngineResult` (pure Python-free Rust eval).
- Decision semantics per flows/02: block > escalate > allow > default-deny; eval error →
  BLOCK(EVAL_ERROR), never skip the rule.
- `needs_params(policy_set, tool) -> bool`: true if any targeting rule references params
  OR has effect escalate (flows/06).
- `derive::compute_derived(...)` — budgets/velocity from derived_counters.

Tests (first): `engine::tests::refund_allow_escalate_block`,
`engine::tests::missing_param_blocks`, `engine::tests::eval_error_never_skips`,
`engine::differential::tests::cedar_matches_reference_1000` (property-based, proptest),
`engine::determinism::tests::same_input_same_output_1000x`.

**DoD:** differential suite passes on ≥1000 random cases; determinism test green.
**Guardrails:** A differential mismatch is ALWAYS an engine bug — fix the engine, never the
test. No LLM in the engine (Law 2). No wall-clock/randomness in evaluation (Law 6).

---

## Phase 5 — ledger

**Objective:** hash chain append/verify/genesis/recovery, RFC 6962 Merkle, C2SP
checkpoints + Ed25519 + key_id, anchoring, proofs, export.

Files: `crates/chaperone-core/src/ledger/{chain.rs, verify.rs, merkle.rs, checkpoint.rs, anchor.rs, proof.rs, export.rs}`.

Contract (from docs/flows/04 + docs/data-model.md):
- `chain::append(entry) -> (seq, entry_hash)` — SYNCHRONOUS, single writer, one transaction.
- entry_hash = sha256(canonical_dumps(preimage)) — canonical JSON, NEVER `‖` concat (Law 4).
  Trace + latency EXCLUDED from preimage.
- `verify::verify_chain(from, to) -> VerificationResult` — recompute + linkage.
- `merkle` (RFC 6962), `checkpoint` (C2SP + Ed25519, carries key_id), `anchor`
  (Rekor v2 / RFC 3161, optional, async, best-effort), `proof` (inclusion proofs),
  `export` (eu-ai-act | soc2 evidence packs).
- Idempotency via UNIQUE(request_id, entry_type). Append-only — NO UPDATE/DELETE (Law 5).

Tests (first): `ledger::tests::golden_vector_chain`, `ledger::tests::verify_detects_tamper`,
`ledger::tests::genesis_entry`, `ledger::tests::idempotent_replay`,
`ledger::tests::no_update_or_delete_statements` (static check / test invariant).

**DoD:** verify detects single-field mutation; golden vector matches; append is atomic.
**Guardrails:** append-then-respond order. No wall-clock inside hashing (inject Clock).
NO UPDATE/DELETE statements anywhere in this crate (Law 5).

---

## Phase 6 — storage

**Objective:** schema.rs (8 tables), sqlx for SQLite + Postgres.

Files: `crates/chaperone-core/src/storage/{schema.rs, store.rs}`.

Contract (from docs/data-model.md): 8 tables — agent_identities, agent_api_keys, policies,
policy_versions, audit_ledger (ledger_entries), ledger_checkpoints, escalations,
derived_counters. One `sqlx` code path for BOTH SQLite and Postgres.

Tests (first): `storage::tests::schema_creates_all_tables_sqlite`,
`storage::tests::one_active_policy_invariant`, `storage::tests::params_binding_hash_roundtrip`.

**DoD:** schema applies on SQLite; Postgres path compiles; unique constraints enforced.
**Guardrails:** sqlx Core (not ORM); embedded migrations; single storage code path.

---

## Phase 7 — decision

**Objective:** DecisionService orchestrating the hot path.

Files: `crates/chaperone-core/src/decision/service.rs`.

Contract: `DecisionService::decide(request) -> DecisionResponse` — agent lookup →
policy lookup (cache tiers) → derived context → engine eval → SYNCHRONOUS ledger append
→ respond. Fail-closed envelope. Idempotent replay via request_id. Mode from server-side
config (never client-supplied).

Tests (first): `decision::tests::allow_appends_then_responds`,
`decision::tests::policy_unavailable_blocks`, `decision::tests::ledger_failure_returns_503`,
`decision::tests::replay_is_idempotent`, `decision::tests::mode_never_from_client`.

**DoD:** append-then-respond enforced; fail-closed paths tested; no client-supplied mode.
**Guardrails:** append BEFORE respond (Law 3). Fail-closed always (Law 1). No LLM (Law 2).

---

## Phase 8 — escalation

**Objective:** escalation lifecycle + sweeper.

Files: `crates/chaperone-core/src/escalation/{service.rs, sweeper.rs}`.

Contract: create escalation on ESCALATE; approve/deny/expire; single-use; params_binding_hash
binding; sweeper (30s) → ESCALATION_RESOLVED(EXPIRED); hook-local approval flow.

Tests (first): `escalation::tests::approve_then_consume`,
`escalation::tests::params_mismatch_blocks`, `escalation::tests::single_use_enforced`,
`escalation::tests::sweeper_expires_overdue`.

**DoD:** lifecycle state machine complete; params binding enforced; sweeper works.
**Guardrails:** silence = deny. params binding via canonical hash (never raw-bytes for
escalation binding).

---

## Phase 9 — chaperone-server

**Objective:** axum app factory + routes.

Files: `crates/chaperone-server/src/{lib.rs, routes/}`.

Contract: routes — `/v1/decisions`, `/v1/policies/*`, `/v1/escalations/*`,
`/v1/ledger/*`, `/healthz`, `/metrics`, `/ws/decisions`. Bearer auth (hashed keys).
Request/response exactly per docs/api-contracts.md. Rate limiting per key. TLS option.

Tests (first): `server::tests::decisions_endpoint_allow`, `server::tests::rate_limited_429`,
`server::tests::unknown_key_401`, `server::tests::ledger_verify_endpoint`.

**DoD:** all endpoints respond per contract; auth enforced; rate limiting works.
**Guardrails:** wire contracts frozen (Law 8). chaperone-server is a LIBRARY (app factory),
NOT a separate binary (Law).

---

## Phase 10 — chaperone-cli

**Objective:** the `chaperone` binary — init, hook, gateway, shim, doctor, policy/ledger/approve.

Files: `crates/chaperone-cli/src/{main.rs, commands/}`.

Contract (from docs/tech-stack.md canonical verb list + docs/flows/05-09):
- `init [--demo] [--no-autostart]`, `hook`, `serve`, `gateway`, `shim`, `doctor`,
  `unhook`, `approve <id>`, `deny <id>`, `escalations list`,
  `policy compile|edit|lint|test|activate`, `ledger verify|prove|checkpoint|export`, `bench`.
- Hook: Claude Code + Cursor wiring (failClosed:true, timeout:35 for Cursor); hook-local
  approval with ~30s bound; DENY_NO_CONSOLE when no console.
- Gateway: MRTR retry-native with signed requestState (canonical_json HMAC); body buffered,
  fail-closed on oversize.
- Shim: stdio proxy, poll-based escalation.
- Doctor: live enforcement canary + wiring/gate/ledger/policy checks.

Tests (first): `cli::tests::init_writes_settings_merge`,
`cli::tests::hook_blocks_rm_rf`, `cli::tests::doctor_canary_detects_enforcement`,
`cli::tests::gateway_retry_native_mrtr`.

**DoD:** `chaperone init` → demo flow works; hook blocks dangerous; doctor canary passes.
**Guardrails:** exactly ONE binary named `chaperone`. Cursor entries carry failClosed:true.
Hook approval bound (~30s) below host timeout.

---

## Phase 11 — compiler

**Objective:** NL→Policy IR offline compiler + trust loop.

Files: `crates/chaperone-core/src/compiler/{providers.rs, pipeline.rs, prompts.rs}`.

Contract: provider trait (anthropic | openai-compat | ollama | fixture);
`compile_sop(text) -> CompileResult(ir, cedar_text, conflict_report)`; validation + lint +
transpile; NEVER activates without human approval. Fixture provider for offline CI.

Tests (first): `compiler::tests::fixture_provider_offline`,
`compiler::tests::compile_produces_valid_ir`, `compiler::tests::never_auto_activates`.

**DoD:** offline fixture pipeline works; output is valid IR; no auto-activation.
**Guardrails:** LLM ONLY here, never in the decision path (Law 2). Offline CI via fixture.

---

## Phase 12 — dashboard

**Objective:** React/TS inbox + live stream + ledger explorer.

Files: `dashboard/` (React + Vite + TS + Tailwind; dark theme tokens).

Contract: approval inbox (approve/deny + note + expiry countdown), live decision stream
(WebSocket), ledger explorer (verify button, checkpoint/anchor badges), metrics tiles.

Tests (first): `dashboard::tests::inbox_shows_pending`,
`dashboard::tests::stream_renders_decisions`.

**DoD:** `npm run build` + `npm run lint` clean; inbox/stream/ledger views render.
**Guardrails:** dashboard auth = session token at startup (never unauthenticated).

---

## Phase 13 — bench

**Objective:** benchmark env, gold, scenarios, runner, E1–E6.

Files: `bench/{env/, gold/, scenarios.jsonl, attacks/, runner, metrics, plots}`.

Contract (from docs/flows/10): ≥1000 scenarios (benign ≥400); attack classes incl.
tool_name_confusion, tool_alias_downgrade, confused_deputy_delegation; deterministic
metrics (byte-identical) + latency metrics (epsilon band); Wilson CIs; seeded (--seed 1337).

Tests (first): `bench::tests::metrics_deterministic_section_identical`,
`bench::tests::scenario_count_gte_1000`, `bench::tests::latency_within_epsilon`.

**DoD:** `make bench` runs; deterministic metrics byte-identical across runs.
**Guardrails:** gold labels are hand-authored (never derived by running the engine).
Publish Wilson CIs. External-label plan per flows/10.

---

## Global verification (after every phase)

1. `cargo test --workspace` — all green.
2. `cargo clippy --workspace -- -D warnings` — clean.
3. The 11 laws still hold — re-check AGENTS.md before moving on.
4. No new dependency without updating `Cargo.toml` + noting it in the commit.
