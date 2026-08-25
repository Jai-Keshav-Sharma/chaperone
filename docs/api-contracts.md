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

## Idempotency

Replaying the same `request_id` returns the original decision; no double evaluation,
no double ledger append. Enforced via `UNIQUE(request_id, entry_type)` in the ledger.
