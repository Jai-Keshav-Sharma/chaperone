# Project Goals

Status: ALIGNED. Date: 2026-08-23. Owner: Jai Keshav Sharma.

## North star

Build and release Warden — the open-source, deterministic authorization gate for AI
agents — as the product that proves, with evidence, that autonomous agents can be
deployed safely; and be the first mover in India's agent-governance layer while the
global race is young.

## Goals by horizon

### 1. Product

- A real, enterprise-grade system: all ten flows, all four seams, single Rust binary,
  Apache-2.0, self-hostable. No demo-grade compromises anywhere decisions are locked.
- The three-pillar identity: NL policy compiler with the human trust loop ·
  tamper-evident ledger (hash chain + Merkle checkpoints + external anchoring) ·
  open pre-action benchmark.

### 2. Launch

- Public release: repo + docs + demo + landing narrative, Show-HN-ready,
  positioned as "Seatbelts for `--dangerously-skip-permissions`".
- Five-minute wow: warden init → rm -rf blocked with ledger receipt → refund escalated
  → approve → retry. The demo IS the pitch.
- Launch assets: interactive browser demo (wasm-compiled engine — type a rule, watch
  a decision + receipt render, no signup); `warden-policy-test` GitHub Action (the
  "CI for policies" as a free Action — diff-aware: lint/test/replay the changed policy
  against the PR diff, "your SOP change gets tested in CI like code"); Windows
  first-class (winget/scoop, CI OS matrix) — the dev platform is Windows; installer
  scripts (`curl … | sh` POSIX + PowerShell one-liner pulling prebuilt binaries);
  policy-pack registry seeded with 3–4 real packs at launch (fintech refunds, DB-guard,
  HR/PII, secrets hygiene) — empty registries don't compound.
- Honest-numbers discipline: publish only what the benchmark measures
  (recall ≥98.5%, false-block ≤1.5%, P95 <50ms, chain verification).

### 3. Market

- Win the unowned wedge: trust loop + anchored ledger + open benchmark — not the
  funded competitors' breadth game (Zenity/PlainID/Arcade/AWS/Microsoft).
- Determinism as the differentiator: everyone claims authorization; Warden's decisions
  are replayable and auditor-verifiable — proven, not asserted.
- Distribution: bottom-up (free OSS, hook adapter) → team (committed config) →
  enterprise (gateway + central service + compliance evidence).
- India first-mover narrative on the local demand curve (EY / RBI / SEBI / MeitY).
- Native framework integration: Warden as a first-class, officially documented option
  inside LangGraph (then OpenAI Agents SDK, CrewAI, ADK).
- **AARM: claim "Aligned" at launch; target Core conformance post-production.** AARM —
  Autonomous Action Runtime Management — is the Vanta-authored spec (arXiv:2602.09433,
  Feb 2026) donated to the Cloud Security Alliance (Apr 2026). Verified against the
  published spec (aarm.dev/spec v1.0): Core = R1–R6 (MUST); R4 requires FIVE decisions
  (ALLOW, DENY, MODIFY, STEP_UP, DEFER — we emit three); R2/R3 require intent modeling
  (we model derived aggregates, not stated intent); full Conformant status requires
  production deployment + evidence package + ~14-day TWG review + a security
  certification. Therefore: honest launch claim = **AARM Aligned** (self-declared),
  with the R1–R6 gap mapping published (docs/aarm-mapping.md) — partial-conformance
  honesty is itself the differentiator vs checklist-badge vendors. Positioning:
  "built to AARM Core, and the only implementation whose decisions are
  cryptographically verifiable." Core conformance = post-production milestone.
  Also track **OWASP AISVS** (Agentic AI Security Verification Standard) — same
  control-mapping exercise once the AARM mapping exists.
- **EMA positioning nuance** (verified): EMA makes the IdP authoritative for *server
  access* via ID-JAG exchange; it never inspects traffic. State it explicitly:
  "AuthN/coarse-grant lives in the IdP (EMA); per-call AuthZ + proof lives in Warden."

### 4. Research (paper + dataset)

- Paper (draft exists: warden_paper.pdf, 5pp, CSVTU Bhilai): update §IV against the
  locked spec (remove the LLM slow path, fix the hash formula, fix latency hierarchy
  and citations) and complete §V with E1–E6 measured results.
- Dataset = the benchmark corpus (Flow 10): scenarios.jsonl + gold policies + gold SOPs,
  public, seeded, reproducible. Code Apache-2.0, data CC-BY-4.0. Closes the paper's
  open problem (iii) — the first public pre-action-authorization benchmark.
- Label provenance is part of honesty: every gold_decision carries {labeler, source,
  date}; versioned scenario-submission format for external contributors; inter-annotator
  agreement (Cohen's κ) measured and cited in the paper. A self-authored corpus is a
  conformance test — external contributions make it an efficacy benchmark.
- Paper target venue: prefer one with artifact evaluation (Available/Reusable badges) —
  checked-in scenarios + byte-identical `make paper-figures` are practically designed for it.
- Experiments map: E4 → paper (i) compiler fidelity; E5 → paper (ii) tamper evidence;
  Flow 10 → paper (iii) community benchmark.
- Honest-numbers rule: the paper cites nothing the benchmark didn't produce.
  make paper-figures twice → byte-identical output.

### 5. Business

- OSS/paid split: everything that earns trust is free (engine, compiler + trust loop,
  ledger + anchoring + verify/prove/export, interceptors, escalation, dashboard, CLI,
  benchmark, policy packs). Everything that operates a fleet is paid (later):
  fleet policy distribution, ledger retention tiers + compliance evidence packs,
  Slack/Teams approval routing, SSO/SAML/SCIM.
- Billing unit: monthly active agent identities. Team tier ~$5–20K/yr, enterprise custom.
- Moats, compounding: benchmark-as-standard → policy-pack registry →
  integration lock-in → system-of-record audit dependency.

## Non-goals

Not an identity provider. Not a prompt/content filter. Not a detection/observability
platform. Not an API gateway. Not an agent framework. The wedge stays narrow:
decide + prove, at the action layer, deterministically.

## Priority order (until launch)

1. Build the system (all ten flows, four seams).
2. Run the benchmark (E1–E6, honest numbers).
3. Release (repo, docs, demo, Show HN).
4. Update the paper as progress lands (survey/gap exist; §IV/§V follow the build).
