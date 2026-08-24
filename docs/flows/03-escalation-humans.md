# Flow 3 — Escalation & Human-in-the-Loop

Status: DECIDED. Date: 2026-08-23.

## The flow

```
Engine matches an escalate rule
  → 1. Service creates escalation row (status=pending, expires_at = now + TTL, default 900s)
       + appends DECISION ledger entry (linked to escalation_id) + responds
       {decision=ESCALATE, escalation_id, expires_at}
  → 2. Surfaced per interceptor:
       Hook:   hook-local approval flow (below) | non-interactive → deny with
               WARDEN_ESCALATED message
       Gateway: MRTR retry-native (signed requestState; client retries; poll-and-hold
                fallback ≤120s) — see flows/06
       Shim:   structured tool error (never blocks the stdio pipe)
  → 3. Human resolves via inbox (dashboard) or CLI:
       approve/deny + note → row updated (resolver, resolved_at)
       + ESCALATION_RESOLVED ledger entry (APPROVED|DENIED) appended
       Background sweeper (30s): overdue → expired + ESCALATION_RESOLVED ledger entry
       with decision=EXPIRED (the enum has no EXPIRED entry_type — the sweeper appends
       entry_type=ESCALATION_RESOLVED, decision=EXPIRED; review-3 P1-5).
       SILENCE ALWAYS MEANS DENY.
  → 4. Consumption: agent retries identical call with escalation_id →
       validates: exists · approved · unconsumed · params_binding_hash equality
       Pass → ALLOW (ESCALATION_APPROVED), status=consumed, DECISION entry appended
       Fail → BLOCK (ESCALATION_DENIED|ESCALATION_EXPIRED|ESCALATION_ALREADY_CONSUMED|ESCALATION_PARAMS_MISMATCH)
  → 5. Evidence: ≥2 (usually 3) chained ledger entries = complete human-oversight story
       (EU AI Act Art. 14)
```

## Hook-local approval (evidence-chain fix — review BUG-1)

Interactive hook surfaces must NOT hand approval to the host UI. A host-approved
"ask" lets the host run the tool WITHOUT telling Warden — the ledger would show
ESCALATE → EXPIRED while the action actually executed, breaking invariant 4 and the
EU AI Act Art. 14 evidence story.

Instead, on ESCALATE the hook resolves the escalation ITSELF:
1. Open the user's console directly (Windows CONIN$/CONOUT$; Unix /dev/tty). The hook's
   stdin carries the event JSON, so a real TTY must be opened explicitly.
2. Prompt: what / why / expires-at + [A]pprove / [D]eny — with a HARD TIME BOUND of
   ~30s. The host kills hooks on its own timeout (~60s historically); an unbounded
   prompt would be killed mid-approval at the exact moment the flagship demo must shine.
3. Approve within the bound → POST /resolve approve → ESCALATION_RESOLVED(APPROVED)
   entry → re-submit decision with escalation_id → ALLOW (ESCALATION_APPROVED) → return allow.
4. Deny within the bound → resolve deny → ESCALATION_RESOLVED(DENIED) entry → return deny.
5. Prompt times out (or no console available) → return deny with the WARDEN_ESCALATED
   ticket message; the escalation REMAINS PENDING. Late approval arrives via the
   CLI/dashboard inbox path, and the params-bound retry path completes it.
   The prompt bound (~30s) and the escalation TTL (900s) are independent clocks —
   never assumed to coincide. No-console denies carry a DISTINCT reason code
   `DENY_NO_CONSOLE` so the evidence trail distinguishes them from human DENY
   (review-2 ADOPT-6).

Result: DECISION(ESCALATE) → RESOLVED(APPROVED) → DECISION(ALLOW, ESCALATION_APPROVED).
One approval surface, chain intact — with every clock bounded.

## Invariants

1. Poll-based, never blocking: decision API returns immediately; no held connections
   (the gateway's MRTR path is retry-native — signed requestState, client retries;
   poll-and-hold ≤120s exists only as a fallback for clients that mishandle MRTR).
2. Approvals are single-use and bind to exact params (params_binding_hash — the
   canonical semantic hash) — bait-and-switch impossible. Any retry with different
   params → ESCALATION_PARAMS_MISMATCH block.
3. Expiry is automatic and silent denial is the default. Unanswered ≠ approved.
4. Every state transition is ledgered: DECISION → RESOLVED → (CONSUMED DECISION).

## Tooling

| Concern | Choice |
|---|---|
| Storage | `escalations` table (relational, sqlx): escalation_id PK, request_id, agent_id FK, policy_id+version, rule_ids JSON, tool, proposed_params JSON (full params for approver visibility — ledger keeps only the hash), params_binding_hash (canonical semantic hash, retry binding only — NOT the ledger's raw-bytes params_hash), status enum, resolver, resolution_note, created_at, expires_at, resolved_at, decision_entry_seq FK, resolution_entry_seq FK. Index (status, expires_at) for the sweeper |
| Sweeper | tokio background task, 30s interval, `expire_due()` → EXPIRED ledger entries; manual `POST /v1/escalations/expire` for deterministic tests |
| Inbox API | axum routes: `GET /v1/escalations?status=pending`, `GET /v1/escalations/{id}`, `POST /v1/escalations/{id}/resolve {resolution, resolver, note}` — 409 if not pending |
| Gateway MRTR | Retry-native (flows/06): InputRequiredResult + signed requestState; the CLIENT retries the original call; gateway verifies HMAC → escalation approved/unconsumed/params-bound → forwards. Poll-and-hold (≤120s) = fallback ONLY for clients that mishandle MRTR |
| CLI | `warden approve <id>`, `warden deny <id>`, `warden escalations list` |
| Notifications | Generic signed webhooks (HTTP POST, HMAC-signed payload) on escalation events; Slack/Teams = webhook-format adapters over the same mechanism |
| Dashboard | Inbox UI: pending list, decision context (what/why/agent/derived context), expiry countdown, approve/deny + note. Team-mode auth: session token printed by `warden serve` at startup (SSO = paid tier later) — an approval inbox is NEVER unauthenticated (review-2 SEC-3) |
| Config | `WARDEN_ESCALATION_TTL_SECONDS=900`, sweeper interval, webhook URL, webhook secret. Retention: purge resolved escalations' `proposed_params` after N days (default 30). Webhook HMAC rotation via dual-secret overlap window (review-2 SEC-6) |
| Anti-fatigue | Derived-attribute budgets auto-allow within bounds; `WARN_BROAD_TARGET` lint on wide escalate rules; escalation-rate metric (target <2% of decisions); shadow mode shows would-escalate volume before enforcement |

### Infrastructure stance — no queue, no external scheduler

- Sweeper = in-process tokio background task (one indexed query per 30s).
- Webhook fan-out = `tokio::spawn`-ed async sends (`reqwest`) with HMAC-signed payloads (`hmac` crate).
- Explicitly REJECTED: Celery / RabbitMQ / SQS / any external queue. A queue adds an external
  service, eventual consistency, and ops burden for work in-process async tasks handle at any
  realistic scale. Single-binary philosophy: everything Flow 3 needs runs inside shipped processes.
- Concurrent-resolution safety comes from the DB: `UPDATE ... WHERE status='pending'` row-lock;
  the loser gets 409.
- New crates for this flow: `hmac` (webhook signing). Everything else reuses Flow 2 decisions.

## Evidence example

```
#14921 DECISION             ESCALATE  pol_refunds r-escalate-mid   refund $450
#14927 ESCALATION_RESOLVED  APPROVED  resolver: manager@corp     note: "verified customer"
#14933 DECISION             ALLOW     reason: ESCALATION_APPROVED refund $450
```
