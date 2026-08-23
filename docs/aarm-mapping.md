# AARM Mapping (R1–R6, honest)

Status: DECIDED. Date: 2026-08-23. Source: AARM v1.0 (aarm.dev/spec, arXiv:2602.09433),
verified against the published spec + conformance protocol.

## Conformance reality (verified)

- AARM Core = R1–R6 (all MUST). Extended = +R7–R9 (SHOULD).
- Claiming Conformant requires: production operation with real workloads, an evidence
  package, TWG review (~14 days), community engagement, AND a recognized security
  certification (SOC 2 Type II / ISO 27001 / FedRAMP).
- Verified organizational conditions (conformance protocol): active WG engagement;
  a real production deployment serving customers — **≥5 active production customers
  running ≥3 months**; plus an ongoing benchmarking commitment. This makes the
  "post-production milestone" concrete: Core conformance is realistically a
  post-revenue objective, not a launch-week box to tick.
- "Aligned" = self-declared builder status (entry point; no verified claim).

## Launch claim

**Warden claims AARM Aligned at launch.** Core conformance evidence is a post-production
milestone. This doc is the published mapping — partial-conformance honesty is the
differentiator versus checklist-badge vendors.

## Requirement → Warden mapping

| Req | AARM requirement (MUST) | Warden status |
|---|---|---|
| R1 | Pre-execution interception; deny with no effects; no fail-open bypass | ✅ hook / gateway / shim intercept before execution; fail-closed doctrine (no fail-open mode exists) |
| R2 | Context accumulation (session context incl. stated intent + prior actions) | ⚠️ PARTIAL: derived_counters model aggregates of prior actions (budgets/velocity); stated-intent is not modeled |
| R3 | Policy evaluation with intent alignment (evaluate (action, context) tuple) | ⚠️ PARTIAL: deterministic (action, context) evaluation incl. derived attributes; no intent-alignment signal |
| R4 | Five decisions: ALLOW, DENY, MODIFY, STEP_UP, DEFER | ⚠️ THREE of five: ALLOW ✓, DENY(=BLOCK) ✓, STEP_UP(=ESCALATE) ✓. MODIFY ✗ (future: PreToolUse `updatedInput` is the natural enforcement surface — redact-and-allow roadmap line); DEFER ✗ (not in Policy IR; deliberate — upstream defer has severe client bugs, see threat-model) |
| R5 | Tamper-evident receipts per evaluated action | ✅ hash chain + Ed25519-signed Merkle checkpoints + Rekor v2 / RFC 3161 anchoring; every decision ledgered |
| R6 | Identity binding at multiple levels (human principal, service identity, agent identity, session, role scope) | ⚠️ PARTIAL: agent_id + session binding in the ledger ✓; human-principal binding depends on the seam (gateway: OAuth subject; hook: host session identity; SDK seam: best-effort) — documented, not hidden |

## Decisions

1. Launch language: "built to AARM Core (R1–R6), AARM Aligned; Core conformance
   evidence package submitted after production deployment."
2. MODIFY decision deferred: revisit when/if `updatedInput`-based redact-and-allow
   ships (SPEC-3b). DEFER deferred with documented justification.
3. R2/R3 intent modeling: not claimed; derived aggregates are the honest subset.
4. R6 gaps close as identity plumbing lands (gateway OAuth subject mapping first).

## Extended (R7–R9, SHOULD) — post-launch

R7 semantic-distance tracking, R8 OTel telemetry export (we ship OTel anyway),
R9 least-privilege enforcement — all ride-along; Extended conformance is a later
milestone, not a launch claim.
