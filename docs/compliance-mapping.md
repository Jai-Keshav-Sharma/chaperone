# Compliance & Standards Mapping

Status: DECIDED. Date: 2026-08-23. The compliance selling point, in one doc.
Source: the research vault's literature survey (01.01, verified Aug 22 2026) + this
repo's corrected citations. Honest-claims rule applies here as everywhere: Chaperone MAPS
to standards; it does not "certify" anything — conformance claims follow the same
discipline as docs/aarm-mapping.md.

## The one-line story

Chaperone is the enforcement machine for controls that OWASP, NIST, CSA, the EU AI Act,
and the IETF all describe but none ship: deterministic pre-action authorization with
tamper-evident receipts. Regulated enterprises don't buy "security features" — they
buy artifacts that map to the frameworks their auditors already know. This doc is the
mapping table the CISO walks through.

## OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)

(Released Dec 9 2025, OWASP GenAI Security Project's Agentic Security Initiative;
correct name — not "ASI Top 10".)

| ID | Risk | Chaperone control |
|---|---|---|
| ASI01 | Agent Goal Hijack | Policy evaluation is out-of-band from conversational context — the engine never reads the transcript |
| ASI02 | Tool Misuse & Exploitation | Parameter thresholds bound to the session (amount ≤ $200); tool-level allowlists |
| ASI03 | Identity & Privilege Abuse | Monotonic capability decay across sub-agent spawns; identity attestation (SPIFFE/WIMSE slots) |
| ASI04 | Agentic Supply Chain Compromise | Tool provenance checks; signed MCP server registry |
| ASI05 | Unexpected Code Execution | Deny-by-default egress; pre-action pattern blocks on code-exec tools |
| ASI06 | Memory & Context Poisoning | Policy-currency re-verification on every call, never at session start |
| ASI07 | Insecure Inter-Agent Communication | WIMSE Workload Proof Token; signed inter-agent envelopes |
| ASI08 | Cascading Failures | RFC 8693 scope attenuation; circuit breaker on failure counts |
| ASI09 | Human–Agent Trust Exploitation | ESCALATE path carries structured reasoning trace + time-bound, params-bound approvals (not a bare button) |
| ASI10 | Rogue Agents | Sub-5ms policy-cache invalidation; credential revocation cascade; kill switch |

Layer boundary (stated honestly): OWASP LLM Top 10 (model I/O) and MCP Top 10
(transport) are NOT Chaperone's scope — Chaperone owns the tool-execution layer between them.

## NIST AI Risk Management Framework

| Function | Chaperone's operationalization |
|---|---|
| GOVERN | Policy lifecycle: versioned, approval-gated, provenance-complete (who approved what, when) |
| MAP | Shadow mode + would-block/would-escalate telemetry = measuring real agent exposure before enforcement |
| MEASURE | Benchmark E1–E6; dashboard metrics (recall, false-block, escalation rate, latency) |
| MANAGE | The gate itself: real-time treatment of measured risk at the action layer |

Positioning: NIST AI RMF 1.0 + AI 600-1 predate agents; CAISI's Agent Standards
Initiative (Feb 2026) has its first deliverable (Interoperability Profile) due Q4 2026 —
Chaperone positions as a reference implementation ahead of it, without claiming
alignment to an unpublished document.

## Cloud Security Alliance

- **AICM v1.1** (Jun 2026, 247 controls): Chaperone implements the 24 agent-specific
  controls of the Agentic Control Supplement.
- **AIGF v1** (Agent Identity Governance Framework): Chaperone consumes its five
  identity types (orchestrator/task/tool/human-delegated/system) and implements its
  just-in-time access model (intent-declared, time-bound, scope-limited grants).
- **AGMM** (maturity model): Chaperone targets Level 3–4 organizations — the "84% fail a
  compliance audit" population.
- **AARM** — see docs/aarm-mapping.md (claim Aligned at launch; Core conformance is
  post-production).

## EU AI Act (corrected timeline)

- Art. 5 prohibitions: in force since Feb 2025. Art. 50 transparency: **in force
  Aug 2, 2026** (NOT deferred). Annex III high-risk: **deferred to Dec 2, 2027** by
  the Digital Omnibus.

| Article | Requirement | Chaperone artifact |
|---|---|---|
| Art. 9 | Continuous per-action risk management | Real-time policy evaluation on every tool call |
| Art. 10 | Data governance with provenance | Tool-parameter inspection; egress blocking; provenance in policy rows |
| Art. 11 | Technical documentation | Policy IR schema + version history (the whole policy_versions table) |
| Art. 12 | Automatic tamper-evident logging, 6-month retention | **The ledger**: hash chain + signed checkpoints + anchoring; `chaperone ledger export --format eu-ai-act` |
| Art. 13 | Transparency for deployers | Decision trace with reasoning in every ledger entry |
| Art. 14 | Human oversight | ESCALATE lifecycle: inbox, expiry, params-bound approvals, ≥2 chained entries per escalation |
| Art. 15 | Cybersecurity resilience | The pre-action gate as a security control |
| Art. 72 | Post-market monitoring | Red-team benchmark, continuous |
| Art. 73 | Incident reporting (24h/72h/15d) | Ledger enables full incident reconstruction |

Compound-system doctrine (May 2026): multi-agent pipelines are assessed end-to-end as
one system — Chaperone's unified cross-agent ledger satisfies the traceability demand
that per-agent logging cannot.

## ISO 42001 / SOC 2 (the near-term buyers)

The Digital Omnibus deferral means near-term procurement drivers are ISO 42001, SOC 2,
and buyer security questionnaires — not EU fines. `chaperone ledger export --format soc2`
produces the evidence pack; the OSS + self-host story answers the supply-chain-review
questions directly (cosign-signed releases + SBOM).

## IETF WIMSE / MCP / EMA

- WIMSE: Chaperone CONSUMES WIT/WPT — validates workload identity on intercepted calls;
  never replaces the identity layer.
- MCP 2026-07-28 + EMA: EMA makes the IdP authoritative for server access (ID-JAG
  exchange, no traffic inspection). Chaperone's line: "AuthN/coarse-grant lives in the
  IdP (EMA); per-call AuthZ + proof lives in Chaperone."

## India channel

- MeitY's India AI Governance Guidelines (Feb 2026, seven sutras) and sectoral
  guidance (RBI, SEBI, IRDAI) create the local demand curve; EY India's agentic-governance
  research (Jun 2026) documents it. Chaperone = the first-mover implementation story for
  that channel, self-hostable in-country (data residency friendly by construction).

## Honest-claims discipline

- We MAP to frameworks; we do not claim certification.
- AARM: Aligned (self-declared) at launch; Conformant only after production evidence.
- NIST CAISI: reference-implementation positioning, no alignment claim to unpublished profiles.
- Every mapping above is testable: the benchmark attacks (E1) and ledger exports (Art. 12)
  are the evidence, not the slideware.
