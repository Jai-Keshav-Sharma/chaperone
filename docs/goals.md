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
  inside LangGraph (then OpenAI Agents SDK, CrewAI, ADK). Optional: AARM conformance.

### 4. Research (paper + dataset)

- Paper (draft exists: warden_paper.pdf, 5pp, CSVTU Bhilai): update §IV against the
  locked spec (remove the LLM slow path, fix the hash formula, fix latency hierarchy
  and citations) and complete §V with E1–E6 measured results.
- Dataset = the benchmark corpus (Flow 10): scenarios.jsonl + gold policies + gold SOPs,
  public, seeded, reproducible. Code Apache-2.0, data CC-BY-4.0. Closes the paper's
  open problem (iii) — the first public pre-action-authorization benchmark.
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
