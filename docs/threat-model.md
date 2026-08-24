# Threat Model

Status: DECIDED. Date: 2026-08-23. Referenced by Flow 4.

## What Warden protects against — and what it doesn't

Warden's honest scope, stated plainly. Saying what we don't protect is what makes the
protection credible.

## Layer boundaries (who can tamper with what)

| Attacker capability | Caught by |
|---|---|
| Edits a past ledger row without DB write access to every subsequent row | Hash chain (Layer 1) — linkage verification fails at the edited entry |
| DB admin rewrites the whole chain AND regenerates all hashes | Signed Merkle checkpoints (Layer 2) — old checkpoints exist outside the DB |
| Attacker also holds the checkpoint signing key | External anchoring (Layer 3) — Rekor v2 / RFC 3161 TSA receipts exist outside the system |
| Controls the decision service AT DECISION TIME (can decline to log) | NOT defended by the ledger — that boundary belongs to the interceptor and the deployment |

## The hook is a seatbelt, not a jail (adopted from review BUG-5)

Anything running on the machine — including the agent itself, or any process with
user-level access — can edit `.claude/settings.json`, remove the hook entry, or
uninstall Warden. The hook protects against a MISTAKEN or manipulated agent acting
within the configured surface. It is not a jail against an ADVERSARIAL actor with
machine access — no user-space control can be.

Per-host seam boundaries (review-3 P0):
- Claude Code: hooks run regardless of permission mode (verify per pinned version).
- Cursor: hooks DEFAULT TO FAIL-OPEN — `warden init` writes project-level
  `.cursor/hooks.json` entries with `failClosed: true` + `timeout: 35` (verified
  cursor.com/docs/hooks). Cursor cloud agents run REPO hooks but IGNORE user-level
  hooks — hence project-level install is mandatory, and the cloud-agent boundary is
  the same honest caveat as the SaaS-agents one: not fully interceptable by us.

Consequences, stated honestly:
- The hook = the seatbelt for the five-minute demo and the developer wedge.
- The gateway = the real chokepoint. A centralized, network-level enforcement point
  the agent's machine cannot edit.
- Same honest-boundary move already made for SaaS-hosted agents (they are not
  interceptable by an external proxy; that is Zenity's turf).

## Host-hook interplay (verified Aug 2026)

- Claude Code PreToolUse output must nest under `hookSpecificOutput.permissionDecision`
  (allow/deny/ask/defer). Warden emits allow/deny only (ask breaks the evidence chain —
  see Flow 3 hook-local approval).
- Hooks/permissions interplay is in flux upstream (e.g., issues #39344: hook "ask"
  silently overrides permissions.deny; #36059: hook "allow" no longer overrides ask
  rules). Build-time requirement: e2e test in `--dangerously-skip-permissions` mode
  against the installed host version before the launch demo leans on it.
- `defer` is NOT adopted: it has active severe upstream bugs (synthetic
  `[Tool result missing]` fed to the model, subagent breakage, race-dependent behavior).
  Matcher grammar is pinned to the documented canonical form (`mcp__.*`) with a CI
  assertion against the pinned host version (review-2 SPEC-3).

## Data redaction guarantee

- The ledger stores params_hash only — never raw parameters (PII hygiene).
- decision_trace contains rule ids, match booleans, and operand paths — NEVER raw
  parameter values. Redaction is a spec-level guarantee, not a reviewer's request.
- Escalations store proposed_params (the approver must see what they approve); this is
  the only place raw params persist, with its own retention policy (purge resolved
  escalations' params after N days, default 30 — review-2 SEC-6).
- Webhook HMAC secret rotation: dual-secret overlap window (new secret accepted,
  old retired after one rotation period) — same knob, one procedure.

## Escalation-key ladder (review BUG-1/2 closure)

- Hook approvals happen inside the hook (hook-local resolution): DECISION(ESCALATE) →
  RESOLVED(APPROVED) → DECISION(ALLOW, ESCALATION_APPROVED). The host UI never
  approves anything Warden can't see.
- Every decision carries params_hash = sha256(raw params bytes) — never null.
- ESCALATE always deserializes the body (inbox visibility) and binds retries via
  canonical semantic hash: bait-and-switch is impossible on every path.
