# Flow 6 — MCP Gateway (flagship enterprise surface)

Status: DECIDED. Date: 2026-08-23.

## Purpose

The org-wide chokepoint: one reverse proxy in front of all MCP servers governs every
agent in the company — any framework, any client — under one policy set, one inbox,
one ledger, one dashboard. Adopt at the protocol layer, coverage is company-wide.

## Positioning

MCP 2026-07-28 defines EMA (Enterprise Managed Authorization). Chaperone's line:
"EMA says enterprises should have a managed authorization layer; Chaperone is the
open-source PDP + tamper-evident ledger an EMA deployment points at — self-hosted,
verifiable, Apache-2.0."

## Spec features exploited

| MCP 2026-07-28 feature | Chaperone use |
|---|---|
| Stateless core | Any request hits any gateway instance behind a load balancer |
| Mcp-Method / Mcp-Name headers | Authorize on headers without parsing the body (fast path) |
| MRTR resultType input_required | Protocol-native ESCALATE pause |
| OAuth 2.1 resource-server model | Gateway transparent to auth flow — Chaperone adds AuthZ, never replaces AuthN |

## The flow

1. `tools/call` hits the gateway. Headers identify tool; body carries params.
2. FAST-PATH DECISION (precomputed at policy load time): the engine indexes, per tool,
   whether any active rule references params (`params_required` map). At request time:
   - params_hash is ALWAYS computed as sha256 of the raw HTTP BODY bytes as received
     (the gateway preimage — defined in the table below) — NEVER null. Hashing raw
     bytes is not deserialization; the fast path stays fast.
   - `needs_params(tool) == false` → skip body DESERIALIZATION entirely; evaluate on
     (agent, tool, context). The REQUEST body is buffered regardless (bounded by
     max-body-size, fail-closed reject on oversize) because params_hash always hashes
     the raw bytes; what we skip is only JSON parsing into objects. On ALLOW the
     buffered bytes are forwarded upstream; the upstream RESPONSE streams back
     byte-perfect (requests buffered, responses streamed).
   - `needs_params(tool) == true` → deserialize once, extract operand values.
   - ESCALATE ALWAYS deserializes the body: the approver inbox needs proposed_params,
     and the escalation stores the canonical semantic hash for retry binding.
   - Property: the parse decision is DERIVED from the active rules, so it can never
     disagree with what the policy needs. Adding a parameter rule flips the index
     automatically at activation.
3. Verdict mapping:
   - ALLOW → forward to upstream, stream response back untouched
   - BLOCK → JSON-RPC error -32050 with structured reason {policy_id, rule_ids, entry_seq}
   - ESCALATE → MRTR InputRequiredResult (resultType: "input_required") with a SIGNED
     requestState (below) — the protocol-native retry pattern. Poll-and-hold (≤120s) is
     kept ONLY as a fallback for clients that mishandle MRTR.
4. Non-tools/call methods (initialize, tools/list, resources) pass through but are
   policy-addressable via context.mcp_method (lockdown policies possible).

## Bait-and-switch binding (review BUG-2 — resolved)

Old design: a no-param-condition escalate rule → `params_hash: null` → approval bound
to nothing → ANY params pass on retry. Resolved:

- Every decision carries params_hash = sha256(raw HTTP body bytes as received — the
  gateway preimage, table below). Never null.
- Every ESCALATE deserializes the body (inbox visibility) and stores
  `params_binding_hash` = sha256(canonical_json(params)) for retry binding.
- Retry binding compares canonical hashes: semantically different params are always
  caught; key-ordering differences on legitimate identical retries do not false-mismatch.

## MRTR — retry-native ESCALATE with signed requestState (review-2 SPEC-2)

The 2026-07-28 spec's native MRTR pattern (verified against the published spec): the
server returns InputRequiredResult; **the client retries the original call** carrying
`inputResponses` + the exact echoed `requestState`. The spec REQUIRES servers to treat
`requestState` as attacker-controlled and to integrity-protect it (HMAC/AEAD) whenever
it influences authorization, with the authenticated principal + short TTL + originating-
request digest inside the protected payload. Holding the request open and polling is NOT
the native pattern.

Chaperone's primary path (all ingredients already exist — hmac crate, escalation_id, TTL,
params_binding_hash):

```
requestState = HMAC(key_requestState, canonical_json({
    escalation_id, expires_at, params_binding_hash, agent_id
}))
```

Law 4 applies HERE TOO (review-4 B2): HMAC over canonical JSON of the tuple — never
`‖`-concatenation (variable-length fields with digit/hex overlap would make the parse
boundary ambiguous).

Key hygiene (review-3 P1-6): the requestState HMAC key is NOT the webhook secret.
Both are DERIVED from one root secret via HKDF with distinct labels
(derive("requestState") vs derive("webhook")) — purpose-bound keys, one root to rotate.

1. ESCALATE → return InputRequiredResult with signed requestState. The escalation ticket
   is created and ledgered as before; the human approves via the inbox (Flow 3).
2. Client retries the identical call with requestState → gateway verifies HMAC →
   validates escalation approved · unconsumed · params_binding_hash equality → forwards.
   (Single-use is enforced server-side via the consumed flag — exactly as the spec's
   one-time-redemption warning requires.)
3. Denied/expired/tampered state → structured JSON-RPC error; ticket lives on for the
   retry path.

Poll-and-hold (≤ min(expiry, 120s)) remains as a documented FALLBACK for clients that
mishandle MRTR — primary path is retry-native. This extends the bait-and-switch defense
into the protocol layer natively and eliminates the held-connection problem class.

## params_hash preimage per surface (review-3 P1-7)

"sha256 of raw params bytes as received" must be defined per transport or E6
cross-surface comparisons become philosophical:

| Surface | params_hash preimage |
|---|---|
| Gateway | sha256 of the raw HTTP body bytes as received |
| Hook | sha256 of the raw `tool_input` JSON bytes as received in the event |
| Shim | sha256 of the raw params bytes of the MCP tools/call as received |

Each surface hashes the bytes it physically received BEFORE any parsing — same
discipline as the gateway fast path.

MRTR is the TRANSPORT for HITL, not the HITL itself:
- HITL = Flow 3 (escalation ticket, inbox, human approves, expiry).
- MRTR = MCP's native pause-and-retry mechanism.
- Gateway = the glue: creates escalation, returns signed state, verifies on retry.

## Tooling

| Concern | Choice |
|---|---|
| MCP framing | Official `mcp` Rust SDK (JSON-RPC 2.0 over streamable HTTP) |
| Proxy | `axum` reverse proxy + `reqwest` upstream client, bidirectional response streaming |
| Fast path | Mcp-Method/Mcp-Name routing; `needs_params(policy_set, tool)` from the engine |
| Escalation | MRTR retry-native primary: signed requestState (HMAC over canonical_json of {escalation_id, expires_at, params_binding_hash, agent_id} — Law 4); client retries → verify → approved/unconsumed/params-bound → forward. Poll-and-hold ≤120s as fallback only |
| Identity | agent_id is PINNED to the authenticated API key server-side (agent_api_keys.agent_id) — NO request-supplied or env-var override in gateway mode (spoofing vector; review-4 B3). CHAPERONE_AGENT_ID override exists ONLY for the hook/shim local seams (single-user machines, documented best-effort per aarm-mapping R6) |
| OAuth | Transparent passthrough — zero changes to clients or servers |
| Config | --upstream <url>, --port, CHAPERONE_URL. Mode (enforce|shadow) is server-side operator config, never client-supplied (review-4 B1) |
| Body handling | params_hash requires full body buffering BEFORE the verdict: buffered by design; explicit max-body-size with fail-closed reject (memory-DoS defense). Governed calls are NOT claimed as byte-perfect streaming (review-4 D) |
| Testing | fake_mcp_server fixture; e2e real MCP client session → allow/block/escalate wire behavior + ledger +N |

## Pitch

"Point your agents at Chaperone once, and every MCP tool call in your company is
authorized, escalated, and provably logged — without touching a single agent."
