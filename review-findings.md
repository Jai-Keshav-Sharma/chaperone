# Pre-Build Review — Findings & Action Items

Status: OPEN. Date: 2026-08-23. Source: external review of the locked specs
(all 17 docs) + web verification of external assumptions (Aug 2026).
Companion to docs/goals.md, docs/tech-stack.md, docs/policy-ir.md,
docs/data-model.md, docs/adoption-integration.md, docs/scalability-targets.md,
docs/flows/01–10.

## Verdict

Spec discipline is unusually strong — fail-closed doctrine, append-only ledger,
one canonical hashing path, honest-numbers rule, non-goals, layering law are
consistent across all ten flows. External bets verified current (MCP 2026-07-28
/ EMA / MRTR, Rekor v2 GA, Cedar 4.12 + Cedar Analysis). Three real spec bugs
and one strategic gap (AARM) must be addressed before building. Everything else
rides along.

## External assumptions — verified Aug 2026

| Assumption | Status |
|---|---|
| MCP 2026-07-28 spec: stateless core, EMA, MRTR (SEP-2322, `resultType: input_required`) | ✅ Real, as specified |
| Rekor v2 anchoring (Flow 4 Layer 3) | ✅ GA, production instance with 99.5% SLO |
| Cedar as engine (`cedar-policy` 4.x + Cedar Analysis toolkit) | ✅ Cedar 4.12 (Jul 2026); Cedar Analysis is an official AWS OSS toolkit |
| AARM | ⚠️ Real but different than goals.md implies — see §AARM |
| `warden-cli` crate name free for `cargo install` | ❌ TAKEN on crates.io (another coding-agent tool); bare `warden` appears unclaimed |

## Spec bugs — fix before writing code

- [ ] **BUG-1. Hook interactive ESCALATE → "ask" breaks the evidence chain.**
  Flows 3/5 map ESCALATE to Claude Code's `ask`. A human approving in the host
  UI lets the host run the tool WITHOUT telling Warden → ledger shows ESCALATE
  then a sweeper-written EXPIRED entry for a call that actually executed.
  Contradicts Flow 3 invariant 4 ("every state transition is ledgered") and the
  EU AI Act Art. 14 evidence story.
  **Fix:** on interactive ESCALATE the hook itself resolves the escalation —
  spawn `warden approve esc_…` prompt (`inquire` already in stack), write the
  ESCALATION_RESOLVED entry, only then return allow. One approval surface,
  chain intact.

- [ ] **BUG-2. Gateway fast path punches a hole in the bait-and-switch defense.**
  Flow 6: `needs_params(tool) == false` → `params_hash: null`. But starter-pack
  velocity rules ("deletions above N/hour") are escalate rules with NO param
  conditions → fast path → escalation created with `params_hash: null` →
  approval binds to nothing → ANY params pass on retry. This is exactly the
  attack class Flow 10's escalation_bait_and_switch claims to validate.
  **Fix (cheap, keeps fast path):** ALWAYS hash the raw request body bytes
  (sha256 of raw bytes — no JSON deserialization, fast path stays fast);
  deserialize only when the engine needs operands or an approver needs to see
  params. `params_hash` then binds the exact payload on every path.

- [ ] **BUG-3. NO_POLICY → BLOCK wrecks the five-minute demo.**
  Starter-safety pack has blocks/escalades but no allow rules for benign
  surfaces → after `warden init`, fs.read / web search / ordinary commands fall
  to BLOCK(NO_POLICY). Agent unusable out of the box; "zero friction ALLOW at
  40–75ms" dies in minute one.
  **Fix (both):**
  1. Starter pack must cover the whole normalized namespace with explicit
     low-risk allow rules (fs.read, ls, grep, …) so nothing falls to NO_POLICY.
  2. Consider an explicit per-deployment `ungoverned: block|allow` default —
     loudly ledgered, WARN_TOOL_UNGOVERNED + shadow stats push toward coverage.
     Note: this does NOT touch the sacred doctrine. Fail-closed on FAILURE is
     about Warden breaking; ungoverned-tool behavior is a POLICY choice.
     Default-allow-with-alarm is defensible for the dev wedge; enterprise
     keeps default-deny.

- [ ] **BUG-4. Hook output envelope is wrong; outcome set has grown.**
  Flow 5 shows `{"permissionDecision": ...}` at top level — the contract
  requires nesting under `hookSpecificOutput.permissionDecision` (classic
  mistake). The outcome set now has FOUR values: allow, deny, ask, **defer** —
  evaluate defer for escalation UX. Known upstream bug
  (anthropics/claude-code#18312): `permissionDecision` ignored for allow-listed
  tools — VERIFY the "seatbelts for --dangerously-skip-permissions" pitch
  against that interplay before building the demo on it.

- [ ] **BUG-5. docs/threat-model.md does not exist (referenced by Flow 4).**
  When written, add the honest line the docs currently dance around: anything
  on the machine — including the agent itself — can edit
  `.claude/settings.json` and uninstall the hook. Hook = seatbelt against a
  MISTAKEN agent, not a jail against an ADVERSARIAL one; the gateway is the
  real chokepoint. Same "honest boundary" move made for SaaS-hosted agents,
  applied to the flagship surface. Saying it strengthens credibility.

## AARM — strategic correction

- [ ] goals.md says "Optional: AARM conformance" — outdated. Reality (Aug 2026):
  AARM = **Autonomous Action Runtime Management** (not "Agent Authorization
  Runtime Manager"), created by Vanta, donated to the Cloud Security Alliance,
  with a working group, an arXiv paper (2602.09433, Feb 2026), and vendors
  ALREADY claiming conformance (SpartanX: "first AARM implementation";
  containment.ai: "AARM v1.0-aligned"). The category is being standardized NOW
  by a compliance-automation company with enterprise reach.
  **Decision: promote AARM conformance from optional to LAUNCH REQUIREMENT.**
  Warden's architecture (intercept → policy eval → ledgered decision → HITL)
  maps almost 1:1 onto AARM's R1–R6 — conformance is nearly free and flips into
  a weapon: "AARM-conformant, and the only implementation whose conformance and
  decisions are cryptographically verifiable." Sitting it out cedes the
  compliance-buyer channel to checklist-badge systems.
  Also: correct the AARM expansion in goals.md; CSA relationship = India /
  enterprise credibility channel.

## Competitive reality check

- [ ] Docs name Zenity/PlainID/Arcade/AWS/Microsoft — the funded platforms. But
  the first Show HN comment will be **"how is this different from OPA /
  Cerbos?"** — and Cerbos actively markets agent-specific features TODAY (agent
  kill switch, MCP tool-access control). The answer exists in the design
  (deterministic replayable decisions, tamper-evident ledger, NL compiler +
  trust loop, agent-native seams, open benchmark) — put it in the README as a
  table aimed at the PDP cohort (OPA, Cerbos, Oso), not just platforms.
- [ ] Launch narrative should explicitly ride the timing catalysts: EU AI Act
  high-risk deadline landed Aug 2026; FINRA 2026 report calls for human
  checkpoints before agent execution.

## Performance improvements

- [ ] **PERF-1. Materialize derived attributes.** Budget/velocity rules do a
  windowed SUM over `ledger_entries` per decision — O(window size) per call,
  degrading as the ledger grows. Keep a small running-counter table per
  (agent, tool, window) updated inside the append transaction; derived data,
  rebuildable from the chain, determinism untouched.
- [ ] **PERF-2. Add a `tenant_id` slot to ledger + identity tables NOW.**
  Scale-out plan shards by tenant; migrating an append-only table with hundreds
  of millions of rows later is the most expensive migration. Nullable unused
  column today ≈ free insurance.
- [ ] **PERF-3. Disk-full is the fleet-wide off switch.** Fail-closed is
  correct, so a full disk (ledger + traces grow forever) = every agent blocks.
  Right behavior, but needs an operational answer early: capacity metrics +
  alarms on /metrics; design archive-and-anchor retention BEFORE someone's
  production ledger hits 500GB. Related: guarantee `decision_trace` can never
  echo secrets — params are hashed in the ledger, but the trace JSON needs a
  redaction guarantee too.
- [ ] **PERF-4. Hook cold start.** reqwest + tokio runtime init per PreToolUse
  makes "~1ms startup" optimistic (Windows process spawn alone is several ms).
  Consider a lean blocking client (ureq) for the hook path — it doesn't need
  async.
- [ ] **PERF-5. One storage code path.** Spec has rusqlite (SQLite) + sqlx
  (Postgres) — two implementations of the most correctness-critical writes.
  sqlx speaks SQLite fine; one code path (compile-time checked for both)
  halves the differential-testing burden.

## Adoption improvements

- [ ] **ADOPT-1. Reserve names BEFORE launch.** `warden-cli` crate is TAKEN on
  crates.io by another coding-agent tool; bare `warden` appears unclaimed.
  Reserve `warden` on crates.io; check npm, GitHub org, landing domains.
  Renaming after Show HN is brutal. (Repo dir is literally named warden-cli —
  easy to trip over.)
- [ ] **ADOPT-2. Ship a browser demo.** Layering law makes warden-core's engine
  pure / I/O-free → compiles to wasm32. Landing-page demo: "type a rule, watch
  a decision + ledger receipt render, live, no signup." The Show HN equivalent
  of the five-minute CLI wow; almost nobody in the category can do it because
  their engines aren't pure.
- [ ] **ADOPT-3. Windows is the dev platform — treat it as first-class.**
  repo-layout CI has no OS matrix. Claude Code hooks on Windows is the daily
  setup; winget/scoop packages + a Windows CI leg prevent the flagship demo
  rotting on the platform we use.
- [ ] **ADOPT-4. MCP registry listing + `warden-policy-test` GitHub Action.**
  "CI for policies" already exists as a concept — releasing it as a free Action
  is a cheap, sticky adoption loop; the test corpus format already exists.
- [ ] **ADOPT-5. Benchmark moat needs other people.** Self-built corpus with
  self-written gold policies = conformance test, not an efficacy benchmark — a
  paper reviewer will say so, and benchmark-as-standard only compounds if
  outsiders contribute. Plan from day one: versioned submission format for
  attack scenarios, external red-teamers post-launch, inter-annotator
  agreement (Cohen's κ) on gold labels to cite in the paper. Honest-numbers
  rule applied to honest LABELS.

## Small stuff

- [ ] Lint's ERROR_ALLOW_ESCALATE_OVERLAP is per-policy; add a cross-policy
  conflict check when two active policies target the same tool.
- [ ] Gateway MRTR: "gateway re-submits on approval, agent never re-submits"
  is sound, but test real client libraries — SEP-2322's native pattern is
  client-retry-with-`inputResponses`; some clients may mishandle a long-held
  request.
- [ ] OCR choice `leptess` looks stale — check maintenance before committing
  (rusty-tesseract or shelling to Tesseract CLI as fallback).
- [ ] Paper: target a venue with artifact evaluation — checked-in scenarios +
  byte-identical `make paper-figures` is practically designed for an
  Available/Reusable badge; free credibility.

## Priority order (before writing code)

1. BUG-1, BUG-2, BUG-3 — cheap now, expensive later.
2. BUG-5 — write docs/threat-model.md incl. the hook-uninstall honesty.
3. AARM decision (recommend: launch requirement) + fix goals.md expansion.
4. ADOPT-1 — reserve `warden` crate name; trademark/domain landscape check.
5. Competitive FAQ — add the OPA/Cerbos row (README table).

Everything else rides along with the build.

## Sources (verified 2026-08-23)

- MCP: https://modelcontextprotocol.io/specification/2026-07-28 ·
  https://blog.modelcontextprotocol.io/posts/2026-07-28/ ·
  https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/ ·
  MRTR: https://modelcontextprotocol.io/seps/2322-MRTR ·
  https://stacktr.ee/blog/mcp-2026-spec-changes
- Rekor v2: https://blog.sigstore.dev/rekor-v2-ga/ ·
  https://github.com/sigstore/rekor-tiles
- Cedar: https://cedarpolicy.com/ ·
  https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/
- AARM: https://aarm.dev/ ·
  https://cloudsecurityalliance.org/research/working-groups/autonomous-action-runtime-management-aarm ·
  https://arxiv.org/abs/2602.09433 ·
  https://www.vanta.com/resources/vanta-donates-aarm-to-csa ·
  https://www.spartanx.ai/blog/aarm-is-no-longer-a-specification
- Competitors: https://www.cerbos.dev/features-benefits-and-use-cases/ai-security
- Claude Code hooks: https://code.claude.com/docs/en/hooks ·
  https://hidekazu-konishi.com/entry/claude_code_hooks_complete_guide.html ·
  https://github.com/anthropics/claude-code/issues/18312
- Name collision: https://crates.io/crates/warden-cli
