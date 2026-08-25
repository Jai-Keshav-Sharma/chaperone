# Review Findings — Resolution Log

Status: RESOLVED (passes 1–4 + drift fixes). Date: 2026-08-23 through 2026-08-24.

## Review pass 2 — resolutions

| ID | Verdict (my independent verification) | Resolution |
|---|---|---|
| SPEC-1 AARM overclaim | ✅ VALID — verified against aarm.dev/spec v1.0: R4 = five decisions (ALLOW/DENY/MODIFY/STEP_UP/DEFER); Core R1–R6 MUST; Conformant requires production deployment + evidence package + ~14d TWG review + security certification | goals.md restated: claim **AARM Aligned** at launch, Core conformance post-production; new docs/aarm-mapping.md (R1–R6 → feature mapping, gaps stated honestly) |
| SPEC-2 MRTR retry-native | ✅ VALID — verified against MCP 2026-07-28 MRTR spec: client retries with echoed requestState; servers MUST treat as attacker-controlled + integrity-protect (HMAC/AEAD) when it affects authorization | flows/06 primary path = retry-native with signed requestState. (SUPERSEDED by pass-4 B2: HMAC over canonical_json of the tuple, never ‖ concatenation — Law 4) |
| SPEC-3 matcher + coverage | ✅ VALID (canonical glob form confirmed; coverage-gap argument sound) | flows/05: `mcp__.*` + CI grammar assertion; WebFetch/WebSearch/NotebookEdit/Task added; Grep/Glob/TodoWrite exclusion documented with latency math; SPEC-3b updatedInput → aarm-mapping MODIFY roadmap |
| SPEC-4 daemon lifecycle | ✅ VALID (genuine week-one footgun) | flows/09: autostart (scheduled task/launchd/systemd user) + failure UX naming remedy + `chaperone doctor` verb |
| SPEC-5 context-trust | ✅ VALID | flows/02 invariant 8: context computed at trusted boundary; API never accepts verdict-influencing context from agent-controlled payloads |
| COMP-1 Cerbos stale | ✅ VALID — verified Cerbos blog (Jun 10 2026): agentgateway + Synapse, argument-aware ABAC, initialize-gating, kill switch, Hub logs | competitive-positioning.md table + one-liner refreshed against verified reality |
| COMP-2 incident anchor | ✅ Plausible + useful (Cerbos analysis cited) | Added as launch narrative anchor |
| COMP-3 AISVS + EMA nuance | ✅ VALID (EMA verified: IdP-authoritative server access, no traffic inspection) | goals.md one-liners |
| SEC-1 key rotation | ✅ VALID | `key_id` in ledger_checkpoints + rotation procedure + multi-key verify/prove |
| SEC-2 TLS | ✅ VALID | flows/02 invariant 9: rustls or documented proxy termination |
| SEC-3 dashboard auth | ✅ VALID | flows/03: session token at startup; SSO paid-tier later |
| SEC-4 supply chain | ✅ VALID (on-brand) | repo-layout CI: cargo-deny/cargo-audit + cosign-signed releases + SBOM |
| SEC-5 fuzzing | ✅ VALID | repo-layout: cargo-fuzz targets for boundary parsers |
| SEC-6 retention/rotation knobs | ✅ VALID | flows/03 + threat-model: proposed_params purge (default 30d), HMAC dual-secret rotation |
| DATA-1 api-key columns | ✅ VALID (free insurance) | data-model: last_used_at + expires_at |
| DATA-2 policies.tenant_id | ✅ VALID (consistency) | data-model: added |
| PERF-6 group commit | ✅ VALID (conditional lever) | scalability-targets step 0.5 |
| PERF-7 latency math | ✅ VALID | flows/05 matcher coverage note carries the math |
| ADOPT-6 console matrix | ✅ VALID | flows/03/05: test matrix + DENY_NO_CONSOLE reason code |
| ADOPT-7 npx.cmd/job object | ✅ VALID (Windows reality) | flows/07 process-wrapper row |
| ADOPT-8 installer scripts | ✅ VALID | goals.md launch assets |
| ADOPT-9 seed packs | ✅ VALID | goals.md launch assets (3–4 packs at launch) |
| ADOPT-10 diff-aware CI | ✅ VALID | goals.md (chaperone-policy-test = diff-aware) |
| ADOPT-11 31 hook events | ✅ VALID (roadmap note) | flows/05 roadmap row |

### Third pass — cross-doc drift (resolved same day)
- flows/03 MRTR references (lines 15, 60, 74) updated to retry-native per flows/06:
  client retries with signed requestState; poll-and-hold ≤120s = fallback only.
  The tooling row (the one an implementer codes from) no longer says "auto re-submit".
- adoption-integration.md deployment-modes table gained Daemon lifecycle (autostart +
  chaperone doctor, SPEC-4) and Transport security (TLS, SEC-2) rows.
- aarm-mapping.md now cites the verified organizational conditions exactly
  (≥5 active production customers running ≥3 months + benchmarking commitment).

### Review pass 3 (reviewer, P0/P1/P2) — resolutions

| ID | Verdict (my verification) | Resolution |
|---|---|---|
| P0 Cursor fail-open | ✅ CONFIRMED against cursor.com/docs/hooks: failClosed defaults false; crash/timeout/invalid-JSON → action proceeds; cloud agents run repo hooks but ignore user-level hooks | flows/05 Cursor wiring section: project-level .cursor/hooks.json with failClosed:true + timeout:35; allow/deny only; exit-2 ≡ deny. threat-model boundary note |
| P1-1 normalization map | ✅ VALID | flows/05: web.fetch, web.search, notebook.edit, task.spawn added |
| P1-2 shadow escalation tickets | ✅ VALID | flows/08 rule 3: shadow never creates escalations/notifications — ledger + metrics only |
| P1-3 proposed_params purge vs NOT NULL | ✅ VALID | data-model: column nullable-after-retention (NOT NULL at insert, NULLed on purge, row survives) |
| P1-4 ungoverned_default in config | ✅ VALID | data-model chaperone.yaml section includes it |
| P1-5 EXPIRED entry shape | ✅ VALID | flows/03: sweeper appends entry_type=ESCALATION_RESOLVED, decision=EXPIRED |
| P1-6 HMAC key separation | ✅ VALID | flows/06: HKDF purpose-bound keys (requestState vs webhook) from one root secret |
| P1-7 params_hash per surface | ✅ VALID | flows/06: preimage table per transport (gateway body / hook tool_input / shim params bytes) |
| P2-8 CLI verb lists | ✅ VALID | tech-stack = canonical list (incl. unhook, approve/deny, escalations list, policy edit, init --demo/--no-autostart); repo-layout points at it |
| P2-9 chaperone-server wording | ✅ VALID | repo-layout: chaperone-server = library crate; exactly ONE binary named chaperone |
| P2-10 cargo-fuzz on MSVC | ✅ VALID (libFuzzer unavailable on windows-msvc) | repo-layout: fuzz jobs ubuntu-latest only |
| P2-11 demo refund tool | ✅ VALID | flows/09: chaperone init --demo bundles canned mock MCP server via shim |
| P2-12 spooling option | ✅ VALID (honest-caveat) | flows/02: optional local JSONL spool + reconcile; not chain-grade until reconciled |

### Review pass 3b (additional findings N1–N6) — resolutions

| ID | Verdict | Resolution |
|---|---|---|
| N1 compliance-mapping.md missing | ❌ WRONG — docs/compliance-mapping.md EXISTS (verified via repo listing; created before the review). The EU AI Act Art.-mapping and SOC 2 evidence-pack content it demands is present. No change | — |
| N2 flows/06 structural drift | ✅ VALID | params_hash-per-surface section moved below the MRTR numbered steps |
| N3 flows/02 spool placement | ✅ VALID | Spool note moved out of invariant 7 into its own invariant 10 |
| N4 Cursor beforeReadFile unverified | ✅ VALID (sources genuinely conflict) | flows/05 build-time verification line + fallback boundary note |
| N5 ~1ms stated as fact | ✅ VALID (own Law 10) | flows/05 (x2), flows/02, tech-stack rephrased: "cold-start TARGET ~1ms, measured in E2; Windows process spawn is several ms" |
| N6 org decision split | ✅ VALID | Pinned: claim GitHub org `chaperone` (verified FREE), fallback `chaperonegate` — recorded in AGENTS.md + resolution log |
| Cosmetic step 0.5 | ✅ | Scalability scale-out path renumbered 1–5 |

### Review pass 4 (review-2026-08-24.md, A–E) — resolutions

| ID | Verdict | Resolution |
|---|---|---|
| A1 pipe mode skips hooks (#37559, #40506) | ✅ Adopted (conservative; cited issues) | threat-model + adoption-integration: headless/CI boundary; steer to gateway/shim; Bash ungovernable on that surface |
| A2 Desktop/Cowork deny ignored on Windows (#77708) | ✅ Adopted (build-time verify) | flows/05 surface×mode matrix; doctor canary as runtime proof |
| A3 Auto mode default (Aug 14 2026) | ✅ Adopted | flows/05 matrix + launch-narrative line ("misses 1 in 9; we show the receipt") |
| A4 gateway cohort (Cordon, Lasso, agentgateway, MS/Docker/IBM/Bifrost) | ✅ Adopted | competitive-positioning cohort table; first-mover claim scoped to ledger+compiler+benchmark |
| B1 client-controlled shadow mode = fail-open bypass | ✅ VALID — HIGH severity spec bug | mode removed from client request; server-side operator config (flows/08 rule 1, flows/06 config); interceptors report seam only |
| B2 requestState ‖ concatenation violates Law 4 | ✅ VALID | HMAC over canonical_json of the tuple (flows/06) |
| B3 identity override spoofing | ✅ VALID | agent_id pinned to authenticated key server-side; CHAPERONE_AGENT_ID only for hook/shim local seams (flows/06) |
| B4 doctor enforcement canary | ✅ Adopted | flows/09: test-rule deny → invoke through real seam → verify block held |
| C1 byte-identical metrics.json impossible | ✅ VALID | Split schema: deterministic section byte-identical; latency section epsilon band + absolute bound (flows/10, goals) |
| C2 sample size at noise floor | ✅ VALID | ≥1,000 scenarios (benign ≥400); Wilson CIs published (flows/10, goals) |
| C3 demo hardcoded seqs | ✅ VALID | Demo queries ledger seqs at runtime (flows/09) |
| D body buffering / counter_key collision / TTL visibility | ✅ VALID | Max-body-size fail-closed reject + no streaming claim (flows/06); declaration_id in counter_key (data-model); TTL printed in deny message (flows/03) |
| E cut line to flows 2/4/5/9 | ❌ REJECTED | Conflicts with the owner's explicit directive: ALL ten flows, four seams, full system — no phased cuts. Recorded, not adopted |

### Pass-4 drift pass (resolved same day)

| Item | Fix |
|---|---|
| flows/08 tooling row still had client `mode` field | Rewritten: server-side operator config only; matches rule 1 |
| flows/06 Escalation tooling row still had ‖ HMAC | Rewritten: HMAC over canonical_json (Law 4); matches the code block |
| B1 mode had no storage location | chaperone.yaml gains `mode: enforce|shadow` (deployment default); per-agent/per-key override = future column, none in v1 tables |
| flows/09 demo transcript had literal seqs | Now #N placeholders; CI asserts output SHAPE, never numbers |
| Resolution-log SPEC-2 row had stale formula | Marked "(SUPERSEDED by pass-4 B2)"; header updated to passes 1–4 |

### PR-review pass (GitHub PR #2, Copilot reviewer) — resolved

| Item | Fix |
|---|---|
| flows/06 fast-path claimed "payload streams through byte-perfect" while the body-handling row required buffering | Aligned: governed REQUEST bodies are always buffered (bounded, fail-closed on oversize) because params_hash hashes raw bytes; only deserialization is skipped on the fast path; upstream RESPONSES stream byte-perfect. Same fix applied to the canonical repo and the PR branch |

### PR-review pass 2 (GitHub PR #3, Copilot reviewer) — resolved

| Item | Fix |
|---|---|
| flows/06 "raw params bytes" (fast-path + bait-and-switch) ambiguous vs the defined gateway preimage "raw HTTP body bytes" | Aligned: gateway params_hash = sha256(raw HTTP BODY bytes as received, preimage table) in all three flows/06 spots; threat-model generalized with a per-surface pointer to flows/06 |

---

## Verdict summary

The review is high quality. Of its findings: all 5 BUGs valid and fixed; AARM
correction valid and adopted as a launch requirement; 2 of its external claims were
WRONG (corrected below with verification); all PERF/ADOPT items adopted.

## External claims — verification results (my own checks, same day)

| Claim | Verification |
|---|---|
| MCP 2026-07-28 / EMA / MRTR | ✅ Confirmed real (did not re-verify every detail; already sourced in vault) |
| Rekor v2 GA | ✅ Consistent with earlier research |
| Cedar 4.x + Cedar Analysis | ✅ Consistent with earlier research |
| AARM = Vanta-authored, CSA-donated, arXiv 2602.09433 | ✅ CONFIRMED (CSA WG page, Vanta donation post Apr 30 2026, arXiv abstract) |
| `chaperone-cli` taken on crates.io | ✅ CONFIRMED (v0.1.1, another coding-agent tool) |
| "bare `chaperone` appears unclaimed" | ❌ WRONG — `chaperone` EXISTS on crates.io (v0.0.1, squatted). npm `chaperone` exists too. GitHub org `chaperone` is FREE. Action: crate name must be `chaperone-guard` or similar; claim the GitHub org; binary stays `chaperone`. |
| "EU AI Act high-risk deadline landed Aug 2026" | ❌ WRONG — Annex III high-risk was DEFERRED to Dec 2, 2027 by the Digital Omnibus. Art. 50 transparency is what's in force (Aug 2, 2026). competitive-positioning.md uses the corrected timeline. |

## BUG resolutions

| ID | Finding | Resolution | Where |
|---|---|---|---|
| BUG-1 | Hook "ask" breaks evidence chain | Hook-local approval: the hook resolves the escalation itself (console prompt → resolve entry → re-submit → allow). Host never approves anything Chaperone can't see | flows/03, flows/05, threat-model |
| BUG-2 | Fast-path null params_hash → bait-and-switch hole | params_hash ALWAYS = sha256(raw params bytes), never null; ESCALATE always deserializes (inbox visibility) and binds retries via canonical semantic hash — exact binding without false mismatches on legit retries | flows/06, flows/02, data-model |
| BUG-3 | NO_POLICY→BLOCK wrecks the demo | Starter pack gains explicit benign-namespace allow rules; new deployment config `ungoverned_default: block\|allow` (serve defaults block; init sets allow) with UNGOVERNED_ALLOW loudly ledgered. Fail-closed on FAILURE untouched — this is policy choice, not fallback | flows/09, flows/02, policy-ir |
| BUG-4 | Hook envelope wrong; 4-value outcome set | Contract corrected to hookSpecificOutput nesting; Chaperone emits allow/deny only; defer documented as unused; bypass-mode e2e verification added as build-time requirement (upstream interplay in flux: #39344, #36059) | flows/05, threat-model |
| BUG-5 | threat-model.md missing | Created, including the hook = seatbelt-not-jail honesty and the gateway = real chokepoint line | docs/threat-model.md |

## AARM — adopted

- Expansion corrected: Autonomous Action Runtime Management, Vanta-authored
  (arXiv:2602.09433, Feb 2026), donated to CSA (Apr 2026).
- Promoted from optional to LAUNCH REQUIREMENT with the positioning line
  "AARM-conformant, and the only implementation whose conformance and decisions are
  cryptographically verifiable."

## Competitive reality check — adopted

- OPA/Cerbos/Oso table added (the PDP cohort question).
- Timing catalysts corrected (Art. 50 in force Aug 2026; Annex III Dec 2027; FINRA 2026).

## PERF — all adopted

| ID | Fix | Where |
|---|---|---|
| PERF-1 | derived_counters table (materialized budgets, updated in the append transaction, rebuildable from chain) | data-model |
| PERF-2 | tenant_id nullable slot on ledger + identity tables now | data-model |
| PERF-3 | Capacity metrics/alarms; archive-and-anchor retention designed pre-production; trace redaction guarantee | data-model, flows/02 |
| PERF-4 | ureq for the hook path (blocking, no tokio init) | tech-stack, flows/05 |
| PERF-5 | sqlx only (SQLite + Postgres), no rusqlite — one storage code path | tech-stack, data-model |

## ADOPT — all adopted

| ID | Fix | Where |
|---|---|---|
| ADOPT-1 | Name reality (updated for the rename to Chaperone): `chaperone` is FREE on crates.io (verified). Binary + crate = `chaperone`; GitHub org `chaperone` is TAKEN (verified) — org candidates re-check at launch; domain TBD — claim pre-launch | tech-stack, AGENTS.md |
| ADOPT-2 | Browser demo via wasm32-compiled pure engine | tech-stack, goals |
| ADOPT-3 | Windows first-class: CI OS matrix + winget/scoop | repo-layout, goals |
| ADOPT-4 | chaperone-policy-test GitHub Action as launch asset | goals |
| ADOPT-5 | Label provenance {labeler, source, date}, versioned submission format, Cohen's κ cited in paper | flows/10, goals |

## Small stuff — adopted

- Cross-policy conflict lint (ERROR_CROSS_POLICY_CONFLICT) → policy-ir.
- MRTR real-client-library testing → flows/06 (build-time verification; design unchanged).
- leptess maintenance check + fallback (rusty-tesseract / Tesseract CLI) → flows/01.
- Paper venue with artifact evaluation (AE badges) → goals.

## Second review pass — residual items (resolved 2026-08-23)

| Item | Fix |
|---|---|
| Hook-local approval prompt needs a time bound below the host's hook timeout (~60s) | Prompt bound ~30s hard; on expiry → deny + CHAPERONE_ESCALATED message, escalation stays pending; late approval via CLI/dashboard; params-bound retry completes. Prompt bound and 900s TTL are independent clocks, never assumed to coincide → flows/03 step 2/5 rewritten |
| Table count drift (repo-layout said "7 tables") | Corrected to 8 (derived_counters added) → repo-layout |
| tenant_id overclaim (resolution log said ledger + identity tables; only ledger_entries had it) | tenant_id added to agent_identities (matters more in multi-tenant fleet mode) → data-model. Resolution log claim now accurate |
| Two hashes, one name (ledger_entries.params_hash = raw bytes vs escalations.params_hash = canonical) | Renamed: `escalations.params_binding_hash` (canonical, retry binding only); both DDL comments state the distinction explicitly → data-model, flows/06 |
