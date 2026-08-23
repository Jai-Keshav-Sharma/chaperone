# Competitive Positioning

Status: DECIDED. Date: 2026-08-23. Answers the questions launch will actually get.

## "How is this different from OPA / Cerbos?" — the PDP cohort (review)

The first Show HN comment will be about the policy-engine cohort, not the platforms.
The answer:

| Capability | OPA | Cerbos | Oso | **Warden** |
|---|---|---|---|---|
| Policy decision engine | Yes (Rego, general-purpose) | Yes (CEL over YAML) | Yes (Polar) | Yes (IR → Cedar, formally verified) |
| Built for AGENTS (tool-call interception) | No — you wire it yourself | Partial — markets agent features (kill switch, MCP tool control) | Partial | **Native: hooks, MCP gateway, shim, framework middleware — four seams** |
| NL policy compiler with human trust loop (diff/test/replay) | No | No | No | **Yes** |
| Tamper-evident ledger (hash chain + signed Merkle checkpoints + Rekor/TSA anchoring) | No (logs to your stack) | No | No | **Yes — auditor-verifiable offline** |
| ESCALATE → human approval lifecycle (inbox, expiry, params binding) | No | No | No | **Yes** |
| Deterministic replay of historical decisions | Possible with work | No | No | **Yes — byte-for-byte replay is a shipped command** |
| Open benchmark for pre-action authorization | No | No | No | **Yes — the metric class Warden defines** |

One-liner: "OPA/Cerbos are policy engines you must build an agent product around;
Warden IS the agent product — seams, ledger, approval inbox, benchmark — with a
policy engine inside."

## The funded platform cohort (research, Aug 2026)

| Player | Owns | Warden's counter |
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
  AARM (CSA, Vanta-donated) = the conformance category exists. Warden rides both.

## Category identity

Warden is to agent authorization what OPA was to policy: the neutral, open,
self-hostable standard gate — with the must-have paid layer OPA never had
(compliance evidence), so it avoids the Styra failure mode.
