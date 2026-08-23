# Flow 3 — Escalation & Human-in-the-Loop

Status: DECIDED. Date: 2026-08-23.

## The flow

```
Engine matches an escalate rule
  → 1. Service creates escalation row (status=pending, expires_at = now + TTL, default 900s)
       + appends DECISION ledger entry (linked to escalation_id) + responds
       {decision=ESCALATE, escalation_id, expires_at}
  → 2. Surfaced per interceptor:
       Hook:   interactive → "ask" | non-interactive → deny with WARDEN_ESCALATED message
       Gateway: MRTR resultType "input_required" (protocol-native pause; polls, bounded ≤120s)
       Shim:   structured tool error (never blocks the stdio pipe)
  → 3. Human resolves via inbox (dashboard) or CLI:
       approve/deny + note → row updated (resolver, resolved_at)
       + ESCALATION_RESOLVED ledger entry (APPROVED|DENIED) appended
       Background sweeper (30s): overdue → expired + EXPIRED ledger entry.
       SILENCE ALWAYS MEANS DENY.
  → 4. Consumption: agent retries identical call with escalation_id →
       validates: exists · approved · unconsumed · params_hash equality
       Pass → ALLOW (ESCALATION_APPROVED), status=consumed, DECISION entry appended
       Fail → BLOCK (ESCALATION_DENIED|EXPIRED|ALREADY_CONSUMED|PARAMS_MISMATCH)
  → 5. Evidence: ≥2 (usually 3) chained ledger entries = complete human-oversight story
       (EU AI Act Art. 14)
```

## Invariants

1. Poll-based, never blocking: decision API returns immediately; no held connections
   (except gateway MRTR, bounded ≤ min(expiry, 120s)).
2. Approvals are single-use and bind to exact params (params_hash) — bait-and-switch
   impossible. Any retry with different params → ESCALATION_PARAMS_MISMATCH block.
3. Expiry is automatic and silent denial is the default. Unanswered ≠ approved.
4. Every state transition is ledgered: DECISION → RESOLVED → (CONSUMED DECISION).

## Tooling

| Concern | Choice |
|---|---|
| Storage | `escalations` table (relational, sqlx): escalation_id PK, request_id, agent_id FK, policy_id+version, rule_ids JSON, tool, proposed_params JSON (full params for approver visibility — ledger keeps only the hash), params_hash, status enum, resolver, resolution_note, created_at, expires_at, resolved_at, decision_entry_seq FK, resolution_entry_seq FK. Index (status, expires_at) for the sweeper |
| Sweeper | tokio background task, 30s interval, `expire_due()` → EXPIRED ledger entries; manual `POST /v1/escalations/expire` for deterministic tests |
| Inbox API | axum routes: `GET /v1/escalations?status=pending`, `GET /v1/escalations/{id}`, `POST /v1/escalations/{id}/resolve {resolution, resolver, note}` — 409 if not pending |
| Gateway MRTR | Poll every 2s, bounded ≤ min(expiry, 120s); approved → auto re-submit with escalation_id + forward; denied/expired → JSON-RPC error |
| CLI | `warden approve <id>`, `warden deny <id>`, `warden escalations list` |
| Notifications | Generic signed webhooks (HTTP POST, HMAC-signed payload) on escalation events; Slack/Teams = webhook-format adapters over the same mechanism |
| Dashboard | Inbox UI: pending list, decision context (what/why/agent/derived context), expiry countdown, approve/deny + note |
| Config | `WARDEN_ESCALATION_TTL_SECONDS=900`, sweeper interval, webhook URL, webhook secret |

### Infrastructure stance — no queue, no external scheduler

- Sweeper = in-process tokio background task (one indexed query per 30s).
- Webhook fan-out = `tokio::spawn`-ed async sends (`reqwest`) with HMAC-signed payloads (`hmac` crate).
- Explicitly REJECTED: Celery / RabbitMQ / SQS / any external queue. A queue adds an external
  service, eventual consistency, and ops burden for work in-process async tasks handle at any
  realistic scale. Single-binary philosophy: everything Flow 3 needs runs inside shipped processes.
- Concurrent-resolution safety comes from the DB: `UPDATE ... WHERE status='pending'` row-lock;
  the loser gets 409.
- New crates for this flow: `hmac` (webhook signing). Everything else reuses Flow 2 decisions.
| Anti-fatigue | Derived-attribute budgets auto-allow within bounds; `WARN_BROAD_TARGET` lint on wide escalate rules; escalation-rate metric (target <2% of decisions); shadow mode shows would-escalate volume before enforcement |

## Evidence example

```
#14921 DECISION             ESCALATE  pol_refunds r-escalate-mid   refund $450
#14927 ESCALATION_RESOLVED  APPROVED  resolver: manager@corp     note: "verified customer"
#14933 DECISION             ALLOW     reason: ESCALATION_APPROVED refund $450
```
