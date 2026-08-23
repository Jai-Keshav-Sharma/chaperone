# Flow 6 — MCP Gateway (flagship enterprise surface)

Status: DECIDED. Date: 2026-08-23.

## Purpose

The org-wide chokepoint: one reverse proxy in front of all MCP servers governs every
agent in the company — any framework, any client — under one policy set, one inbox,
one ledger, one dashboard. Adopt at the protocol layer, coverage is company-wide.

## Positioning

MCP 2026-07-28 defines EMA (Enterprise Managed Authorization). Warden's line:
"EMA says enterprises should have a managed authorization layer; Warden is the
open-source PDP + tamper-evident ledger an EMA deployment points at — self-hosted,
verifiable, Apache-2.0."

## Spec features exploited

| MCP 2026-07-28 feature | Warden use |
|---|---|
| Stateless core | Any request hits any gateway instance behind a load balancer |
| Mcp-Method / Mcp-Name headers | Authorize on headers without parsing the body (fast path) |
| MRTR resultType input_required | Protocol-native ESCALATE pause |
| OAuth 2.1 resource-server model | Gateway transparent to auth flow — Warden adds AuthZ, never replaces AuthN |

## The flow

1. `tools/call` hits the gateway. Headers identify tool; body carries params.
2. FAST-PATH DECISION (precomputed at policy load time): the engine indexes, per tool,
   whether any active rule references params (`params_required` map). At request time:
   - params_hash is ALWAYS computed as sha256 of the raw params bytes as received —
     NEVER null. Hashing raw bytes is not deserialization; the fast path stays fast.
   - `needs_params(tool) == false` → skip body DESERIALIZATION entirely; evaluate on
     (agent, tool, context). The payload streams through byte-perfect regardless
     (the proxy always forwards raw bytes; we skip only JSON parsing into objects).
   - `needs_params(tool) == true` → deserialize once, extract operand values.
   - ESCALATE ALWAYS deserializes the body: the approver inbox needs proposed_params,
     and the escalation stores the canonical semantic hash for retry binding.
   - Property: the parse decision is DERIVED from the active rules, so it can never
     disagree with what the policy needs. Adding a parameter rule flips the index
     automatically at activation.
3. Verdict mapping:
   - ALLOW → forward to upstream, stream response back untouched
   - BLOCK → JSON-RPC error -32050 with structured reason {policy_id, rule_ids, entry_seq}
   - ESCALATE → MRTR input_required; gateway polls escalation every 2s, bounded
     ≤ min(expiry, 120s); approved → complete the ORIGINAL call (agent never re-submits);
     denied/expired/timeout → structured JSON-RPC error, ticket lives on for the retry path
4. Non-tools/call methods (initialize, tools/list, resources) pass through but are
   policy-addressable via context.mcp_method (lockdown policies possible).

## Bait-and-switch binding (review BUG-2 — resolved)

Old design: a no-param-condition escalate rule → `params_hash: null` → approval bound
to nothing → ANY params pass on retry. Resolved:

- Every decision carries params_hash = sha256(raw params bytes). Never null.
- Every ESCALATE deserializes the body (inbox visibility) and stores
  `params_binding_hash` = sha256(canonical_json(params)) for retry binding.
- Retry binding compares canonical hashes: semantically different params are always
  caught; key-ordering differences on legitimate identical retries do not false-mismatch.

## MRTR clarification (why ESCALATE is seamless)

MRTR is the TRANSPORT for HITL, not the HITL itself:
- HITL = Flow 3 (escalation ticket, inbox, human approves, expiry).
- MRTR = MCP's native "pause a request and wait for input" mechanism.
- Gateway = the glue: creates escalation, suspends call via input_required, polls inbox,
  completes the original call on approval. The agent just sees a tool that took ~40s.

## Tooling

| Concern | Choice |
|---|---|
| MCP framing | Official `mcp` Rust SDK (JSON-RPC 2.0 over streamable HTTP) |
| Proxy | `axum` reverse proxy + `reqwest` upstream client, bidirectional response streaming |
| Fast path | Mcp-Method/Mcp-Name routing; `needs_params(policy_set, tool)` from the engine |
| Escalation | MRTR input_required; poll 2s, bounded ≤ min(expiry, 120s) |
| Identity | MCP client identity → agent_id (OAuth subject / CIMD); WARDEN_AGENT_ID override; unknown-agent policy-blockable |
| OAuth | Transparent passthrough — zero changes to clients or servers |
| Config | --upstream <url>, --port, WARDEN_URL, agent-id mapping |
| Testing | fake_mcp_server fixture; e2e real MCP client session → allow/block/escalate wire behavior + ledger +N |

## Pitch

"Point your agents at Warden once, and every MCP tool call in your company is
authorized, escalated, and provably logged — without touching a single agent."
