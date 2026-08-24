# Flow 8 — Shadow Mode

Status: DECIDED. Date: 2026-08-23.

## Concept

Observe without blocking. Full evaluation + full ledgering happen exactly as in enforce
mode, but every interceptor proceeds regardless. Verdicts ledger as
WOULD_ALLOW / WOULD_BLOCK / WOULD_ESCALATE.

## Why (it is a sales feature, not a debug flag)

- Adoption story: run in shadow, see every action we WOULD have blocked and the false-block
  rate on YOUR traffic, zero risk. Switch to enforce when the data convinces you.
- Policy tuning: same instrument as pre-activation --replay; tune against real traffic.
- Escalation sizing: reveals would-escalate volume before the inbox exists (anti-fatigue).

## Hard rules

1. Shadow is an explicit operator choice (mode field per request / WARDEN_MODE=shadow).
   NEVER an automatic fallback. Fail-closed still governs enforce mode.
2. Same chain, same guarantees: WOULD_* entries live in the real ledger.
3. Shadow NEVER creates side effects beyond the ledger (review-3 P1-2): WOULD_ESCALATE
   is ledgered as a decision but creates NO escalation row, fires NO webhook, sends NO
   notification. Observation mode cannot spam the inbox — ledger + metrics only.

## Tooling

| Concern | Choice |
|---|---|
| Mode selection | `mode: enforce|shadow` in DecisionRequest + WARDEN_MODE env |
| Ledger | WOULD_* decision enum values, same append path |
| Dashboard | would-block / would-escalate rates vs actual |

No new infrastructure.
