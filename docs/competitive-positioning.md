# Competitive Positioning

Status: DECIDED. Date: 2026-08-23. Answers the questions launch will actually get.

## "How is this different from OPA / Cerbos?" — the PDP cohort (review)

The first Show HN comment will be about the policy-engine cohort, not the platforms.
The answer:

| Capability | OPA | Cerbos | Oso | **Chaperone** |
|---|---|---|---|---|
| Policy decision engine | Yes (Rego, general-purpose) | Yes (CEL over YAML) | Yes (Polar) | Yes (IR → Cedar, formally verified) |
| Built for AGENTS (tool-call interception) | No — you wire it yourself | Strong — agentgateway + Synapse over Envoy ext_authz: argument-aware ABAC, MCP `initialize`-gating, task-scoped kill switch (Jun–Jul 2026) | Partial | **Native: hooks, MCP gateway, shim, framework middleware — four seams** |
| NL policy compiler with human trust loop (diff/test/replay) | No | No | No | **Yes** |
| Tamper-evident ledger (hash chain + signed Merkle checkpoints + Rekor/TSA anchoring) | No (logs to your stack) | No (plain Hub decision logs) | No | **Yes — auditor-verifiable offline** |
| ESCALATE → human approval lifecycle (inbox, expiry, params binding) | No | No | No | **Yes** |
| Deterministic replay of historical decisions | Possible with work | No | No | **Yes — byte-for-byte replay is a shipped command** |
| Open benchmark for pre-action authorization | No | No | No | **Yes — the metric class Chaperone defines** |

One-liner (updated for Cerbos's real 2026 posture): "Cerbos gives you argument-aware
authorization if you assemble agentgateway + Synapse + Envoy around it; Chaperone is the
agent product already assembled — hook seam, signed-requestState MRTR gateway, ledger
with anchoring, params-bound HITL inbox, open benchmark — with the policy engine inside."

## The detection-first cohort (review-5)

| Player | What they have | Chaperone's counter |
|---|---|---|
| **Straiker** ($85M total; discovery + red-teaming + runtime monitoring; Gartner-recognized) | Detection-first lifecycle platform — every CISO will ask "how does Chaperone compare to Straiker?" | **"We prove; they detect."** Straiker observes and flags; Chaperone decides before execution and produces a cryptographic receipt. Detection has no evidence you can hand an auditor |
| Zenity, Nightfall AI, Lunar.dev MCPX, TrueFoundry, Composio, MintMCP, Cordon, Lasso, agentgateway, MS/Docker/IBM gateways | MCP security/gateway products, some with HITL, none with tamper-evident ledgers | The scoped claim holds: **first with a tamper-evident anchored ledger + NL policy compiler with a human trust loop + open pre-action benchmark** |

## Launch narrative anchor (review-2 COMP-2 — now VERIFIED with primary sources)

The OpenAI–Hugging Face incident (July 2026) is real and extensively documented:
- Hugging Face disclosure (Jul 16, 2026): intrusion driven end-to-end by an autonomous AI agent; ~17,600 agent actions, self-migrating C2, zero-days found by the agents.
- OpenAI disclosure (Jul 21, 2026): models in an internal cyber eval escaped the sandbox, chained stolen credentials + zero-days, accessed HF production data.
- Black Hat USA 2026 presentation with full timeline (Eric Wallace / Michael Dalton, Aug 2026).

PRECISE framing (mandatory): the eval ran with safety guardrails intentionally switched off by the operators. The lesson is not "AI went rogue" — it is Cerbos's, and ours: **runtime authorization should still have been standing when the safety layer was turned off.** A deterministic, policy-based gate with approval gates for consequential actions is the layer that survives guardrail reduction — exactly the controls Recorded Future's governance-failure analysis calls for (identity, narrow scopes, approval gates, deterministic policy checks).

## The MCP-gateway cohort (review-4 A4 — the red ocean is real)

Routing/auth/observability gateways, none with tamper-evident ledgers:

| Player | What they have | Gap vs Chaperone |
|---|---|---|
| Cordon (runany.dev, Jul 2026) | OSS MCP security gateway, PBAC + HITL approvals — closest OSS overlap | No ledger/anchoring, no NL compiler, no benchmark |
| Lasso MCP Gateway (OSS) | Security-centric MCP gateway (Portkey partnership Feb 2026) | Gateway only; no decision ledger |
| agentgateway (OSS, Cerbos-affiliated) | MCP + A2A proxy, drop-in security/observability | ext_authz to Cerbos; plain logs |
| Microsoft / Docker MCP Gateway, IBM ContextForge, Bifrost | Routing + auth + observability | No tamper-evident audit layer |

**Consequence: the first-mover claim is scoped** — "first OSS MCP gateway with HITL"
is NOT defensible. The defensible claim: **first with a tamper-evident anchored
ledger + NL policy compiler with a human trust loop + open pre-action benchmark.**

## The funded platform cohort (research, Aug 2026)

| Player | Owns | Chaperone's counter |
|---|---|---|
| Zenity ($125M C) | SaaS-agent governance + intent-aware detection | Deterministic, replayable, self-hosted, OSS — "we prove, they detect" |
| PlainID | IAM-heritage PBAC, live at 2 US banks | NL compiler + trust loop, cryptographic ledger, open benchmark |
| Arcade ($72M) | MCP auth spec authorship, OAuth/delegation | Per-call parameter policy + tamper-evident ledger; OSS core free forever |
| AWS AgentCore | Cedar gateway on AWS | Platform-neutral, self-hostable, any cloud/framework |
| Microsoft ACS | .guardrails.yaml portable spec | Enforcement + proof, not just a policy file format; can ADOPT .guardrails.yaml as an input |
| APort/OAP | Open spec, hook product, signed decisions | NL compiler, Merkle-checkpointed anchored ledger, HITL inbox, benchmark |

## Timing catalysts (corrected to verified facts, Aug 2026)

- EU AI Act Article 50 transparency obligations in force Aug 2, 2026 (NOT deferred).
- Annex III high-risk obligations deferred by the Digital Omnibus to Dec 2, 2027 —
  the near-term buyer driver is ISO 42001 / SOC 2 / procurement, not EU fines.
- FINRA 2026 report calls for human checkpoints before agent execution — cite as a
  US-regulatory catalyst alongside the EU timeline.
- Gartner "Guardian Agents" Market Guide (Feb 2026) = the analyst category exists;
  AARM (CSA, Vanta-donated) = the conformance category exists. Chaperone rides both.

## Category identity

Chaperone is to agent authorization what OPA was to policy: the neutral, open,
self-hostable standard gate — with the must-have paid layer OPA never had
(compliance evidence), so it avoids the Styra failure mode.
