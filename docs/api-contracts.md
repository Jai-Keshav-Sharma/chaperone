# API Contracts (frozen — Law 8)

Status: DECIDED. Date: 2026-08-25. Source of truth for all wire formats.

These contracts are FROZEN: unknown fields are rejected (`extra="forbid"`); changing a
field name or type is a breaking event requiring a coordinated doc update. All decision
requests/responses use these exact shapes. Consolidated here from flows/02 + flows/06.

## DecisionRequest (interceptor → decision service)

```json
{
  "request_id":   "req_7f3a2b1c",           // UUIDv4, interceptor-generated; idempotency key
  "agent_id":     "agent_support_09",
  "tool":         "stripe.refunds.create",  // universal namespace (flows/05)
  "params":       {"amount": 150, "customer_id": "cus_123"},
  "context": {
    "session_id":       "s-42",
    "surface":          "claude_code",      // trusted boundary — hook/gateway derive
    "delegation_depth": 0,                  // trusted boundary — never agent-supplied
    "request_time":     "2026-08-25T14:00:00Z"  // RFC3339, boundary-computed, ledgered
  },
  "escalation_id": null                     // set only when re-submitting after approval
}
```

Notes:
- NO `mode` field (review-4 B1): shadow/enforce is server-side operator config
  (`chaperone.yaml`), never client-supplied. An agent cannot self-exempt.
- `context.surface` and `context.delegation_depth` are computed at the trusted
  boundary (hook/gateway), never accepted from agent-controlled payloads (Flow 2
  invariant 8).

## DecisionResponse (decision service → interceptor)

```json
{
  "decision":             "ALLOW",          // ALLOW | BLOCK | ESCALATE (+ WOULD_* in shadow)
  "reason_code":          "RULE_MATCH",     // closed enum (below)
  "determining_rule_ids": ["r-allow-small"],
  "policy_id":            "pol_refunds",    // "__none__" when no policy applies
  "policy_version":       3,
  "policy_hash":          "8f2a…64hex",     // sha256(canonical_json(ir_json))
  "entry_seq":            14921,            // ledger refs (synchronous append happened first)
  "entry_hash":           "c41d…64hex",
  "escalation_id":        null,             // set when decision == ESCALATE
  "escalation_expires_at": null,            // RFC3339, when decision == ESCALATE
  "trace":                [{"rule_id":"r-allow-small","matched":true}],
  "derived_context":      {"agent_daily_total_amount": 350.0},
  "evaluation_latency_ms": 4.1
}
```

Notes:
- `trace` is REDACTED: rule ids, match booleans, operand paths only — NEVER raw
  parameter values (Flow 2 invariant 7).
- The ledger entry exists BEFORE this response is returned (append-then-respond).
- On ESCALATE: `escalation_id` + `escalation_expires_at` are set; the interceptor
  surfaces per-seam (hook-local approval / gateway MRTR / shim tool-error).

## reason_code (closed enum, unified — the ESCALATION_* family)

| Code | Meaning |
|---|---|
| `RULE_MATCH` | A determining rule matched (allow or block) |
| `DEFAULT_DENY` | No determining rule matched → default deny |
| `NO_POLICY` | Tool governed by no active policy; `ungoverned_default: block` |
| `UNGOVERNED_ALLOW` | No active policy; `ungoverned_default: allow`; loudly ledgered |
| `EVAL_ERROR` | Missing param / type mismatch → immediate block (never skip the rule) |
| `AGENT_UNKNOWN` | agent_id not registered (ledgered) |
| `AGENT_INACTIVE` | agent registered but inactive (ledgered) |
| `FAIL_CLOSED_POLICY_UNAVAILABLE` | Policy store unreachable → block |
| `FAIL_CLOSED_LEDGER_UNAVAILABLE` | Ledger write failed → no verdict returned (503) |
| `FAIL_CLOSED_GATE_UNREACHABLE` | Interceptor synthesized block (timeout/5xx/malformed) |
| `RATE_LIMITED` | Per-key rate ceiling exceeded (429; a limited call is a non-forward) |
| `ESCALATION_APPROVED` | Retry with approved escalation_id → allow |
| `ESCALATION_DENIED` | Escalation was denied |
| `ESCALATION_EXPIRED` | Escalation expired (auto-deny) |
| `ESCALATION_PARAMS_MISMATCH` | Retry params differ from approved params_hash |
| `ESCALATION_ALREADY_CONSUMED` | Escalation already used (single-use) |

Hook-local verdict reasons (not decision-service reason codes):
- `DENY_NO_CONSOLE` — hook has no interactive console → deny with escalation ticket.

## Error model (non-2xx from the decision service)

```json
{ "error": { "code": "POLICY_NOT_FOUND", "message": "…", "detail": { } } }
```

An HTTP error from the decision endpoint means the gate failed — it is never itself a
decision. Interceptors treat it as BLOCK (fail-closed). A `FAIL_CLOSED_LEDGER_UNAVAILABLE`
is surfaced as HTTP 503 (no verdict is returned, per invariant 1).

### HTTP-level error codes (non-2xx) vs in-band decisions — the implementer's split

| Class | Transport | Examples |
|---|---|---|
| **Decision service failures** | HTTP error (non-2xx) | `POLICY_NOT_FOUND` (404), `LEDGER_UNAVAILABLE` (503), `AGENT_KEY_UNKNOWN` (401), `MALFORMED_REQUEST` (422) |
| **Rate limiting** | HTTP 429 | `RATE_LIMITED` — body: `{"error": {"code": "RATE_LIMITED", "message": "…", "detail": {"retry_after_seconds": 5}}}` |
| **Escalation consumption outcomes** | IN-BAND (HTTP 200, in DecisionResponse.reason_code) | `ESCALATION_APPROVED` / `ESCALATION_DENIED` / `ESCALATION_EXPIRED` / `ESCALATION_PARAMS_MISMATCH` / `ESCALATION_ALREADY_CONSUMED` — these are DECISIONS, not errors |
| **Verdicts** | IN-BAND (HTTP 200) | `RULE_MATCH` / `DEFAULT_DENY` / `NO_POLICY` / `UNGOVERNED_ALLOW` / `EVAL_ERROR` / `AGENT_UNKNOWN` / `AGENT_INACTIVE` — the closed enum in the reason_code table |

Rule of thumb: **anything that is a verdict about the action is in-band (HTTP 200);
anything that is a failure of the gate itself is an HTTP error.** A 4xx/5xx must never be
treated as a verdict — it is always a fail-closed trigger.

## WebSocket contract — /ws/decisions (live stream)

Message envelope (server → client, JSON text frames):

```json
{ "type": "decision", "data": { /* full DecisionResponse */ } }
```

- One message per decision event (enforce AND shadow).
- Server applies drop-on-slow-consumer: a client that falls behind is disconnected
  (never backpressures the decision path).
- No client→server messages in v1 (server pushes only).
- Client reconnect: re-subscribe; the stream carries no replay — use
  `/v1/ledger/entries?after_seq=` for history.

## Machine-readable schemas (Law 8 enforcement)

All wire models (DecisionRequest, DecisionResponse, error body, WS envelope) derive
`serde::Serialize/Deserialize` AND `schemars::JsonSchema` in `chaperone-core/models`.
The generated JSON Schemas are the machine-readable contract; CI regenerates and
diff-checks them against `docs/api-contracts.md` (a drift in the Rust types fails CI).
This is the same schemars pattern used by the compiler's schema-constrained output.

## params field constraints

- `params` is arbitrary JSON (`serde_json::Value`) — the engine evaluates it only via
  param-path operands; it is passed through raw, never restructured.
- Size bound: governed by the gateway's `max-body-size` (config; default 1 MiB).
  Oversize → fail-closed reject (HTTP 413), never truncated, never streamed-partially.
- Depth bound: 32 (safety against pathological nesting in the deserializer); deeper →
  reject (422). Arrays of 10k items are fine within the size bound.
- Hook/shim seams: the params they forward are the host-provided tool_input bytes;
  same depth rule applies at the decision service.

## context fields

- `request_time` — REQUIRED, RFC3339 UTC, boundary-computed, ledgered (determinism Law).
- `surface` — REQUIRED, trusted-boundary derived (flows/05). One of
  `claude_code | cursor | mcp_gateway | mcp_shim | sdk`.
- `delegation_depth` — REQUIRED, trusted-boundary derived; policies may target it.
- `session_id` — OPTIONAL (null allowed); PASS-THROUGH for logging/correlation only.
  It does NOT affect decisions in v1 (no session-scoped policies exist). Do not build
  policy logic on it.

## Cedar entity model (the fixed evaluation vocabulary — Phase 4 contract)

The transpiler generates Cedar policies against a FIXED entity model. The canonical
schema file is `policies/cedar_schema.cedar` (validated by cedar-policy-validator at
compile time — the single source of truth).

| IR concept | Cedar entity |
|---|---|
| principal | `Chaperone::Agent::"<agent_id>"` (attrs: role, max_delegation_depth) |
| action | `Chaperone::Action::"call"` (always this action value) |
| resource | `Chaperone::Tool::"<tool_name>"` (attr: name; glob → `resource.name like "payments.*"`) |
| context | `{params, request_time, derived}` (JSON record at request time) |

Every evaluation is `is_authorized(principal, action, resource, context)`. An
implementer of the IR→Cedar transpiler generates policy text against exactly this
vocabulary — nothing else is valid.

## Decision trace shape (the REDACTED evaluation trace)

The `trace` field in DecisionResponse is the redacted per-rule evaluation record.
Shape: ONE entry per RULE, in evaluation order (policy-load order):

```json
{
  "trace": [
    { "rule_id": "r-block-flagged",    "matched": false },
    { "rule_id": "r-block-over-1000",  "matched": false },
    { "rule_id": "r-escalate-200-1000", "matched": false },
    { "rule_id": "r-allow-small",      "matched": true,
      "operands": [ {"path": "params.amount", "kind": "param"},
                    {"path": "context.surface", "kind": "context"} ] }
  ]
}
```

Rules:
- One object per rule, `matched: true/false`.
- `operands` (optional, present when the rule evaluated a condition): the set of
  operand PATHS the condition referenced — NEVER values, NEVER raw parameters
  (Law 9 trace redaction). `kind` ∈ `param | context | value | derived`.
- No nested condition-node trees in v1 — a rule's trace is flat (matched + operand
  paths). The dashboard renders rule-level reasons only.
- Eval-error traces: `{"rule_id": "r-…", "matched": false, "error": "EVAL_ERROR_MISSING_PARAM", "operands": [{"path":"params.amount","kind":"param"}]}`.

## Idempotency

Replaying the same `request_id` returns the original decision; no double evaluation,
no double ledger append. Enforced via `UNIQUE(request_id, entry_type)` in the ledger.
