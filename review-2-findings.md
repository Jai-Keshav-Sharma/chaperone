# Review Pass 2 — Findings & Recommendations

> **STATUS: RESOLVED.** All findings verified and applied. Item-by-item verdicts
> (including my independent web verification of AARM, MRTR, and Cerbos claims) live in
> [`docs/review-findings-resolution.md`](docs/review-findings-resolution.md)
> (this file is preserved as the original review record).

Status: OPEN. Date: 2026-08-23. Source: independent second review of all 17 locked specs,
with live web verification of every load-bearing external assumption (MCP 2026-07-28,
Claude Code hooks behavior, AARM conformance protocol, competitor moves).
Companion to review-findings.md (pass 1, RESOLVED). All pass-1 resolutions assumed applied.

## Verdict

Spec discipline remains unusually strong after pass 1 — doctrine is coherent, honest
boundaries are credibility-positive, stack choices verified current. No new spec-breaking
bug found. What this pass found instead: **one overclaimed compliance mapping (AARM),
one protocol-pattern deviation worth fixing pre-build (MRTR), two concrete demo-risk
items in the hook seam, one unowned operational footgun (local daemon lifecycle), one
stale competitive row, and a set of cheap hardening/adoption additions.**

Priority legend: P0 = fix in specs before writing code · P1 = build-time requirement · P2 = ride-along.

---

## §A Spec-level corrections (P0 — cheap in specs, expensive in code)

### SPEC-1. AARM conformance claim does not map 1:1 — restate before it becomes public

goals.md:50 claims Warden's architecture "maps 1:1 onto its requirements (R1–R6)". Against
the published spec (aarm.dev/spec, v1.0, Feb 2026) and conformance protocol (aarm.dev/conformance):

- **R4 (MUST)**: engine must produce **five** decisions — ALLOW, DENY, **MODIFY**
  (execute transformed version), STEP_UP (= your ESCALATE ✓), **DEFER**. Warden emits three.
  MODIFY and DEFER do not exist in Policy IR.
- **R2/R3 (MUST)**: context accumulation must expose *stated intent* and prior actions/data
  classifications to the policy layer. Derived counters cover aggregates of prior actions;
  intent is not modeled. Conformance tests explicitly probe context-dependent allow/deny.
- **Process reality**: claiming conformance requires operating in **production with real
  workloads**, an evidence package, and TWG review (~14 days). "AARM-conformant at launch"
  is therefore not honestly claimable on day one.

Fixes:
1. Write the actual R1–R6 → feature/flow mapping doc. Where it fails, either scope the
   launch claim ("built to AARM Core; evidence package submitted") or decide whether to
   add minimal MODIFY support. Note: Claude Code PreToolUse hooks already support
   `updatedInput` input-rewriting paired with allow — MODIFY has a natural enforcement
   surface on the flagship seam, and doubles as a future "redact-and-allow" feature (see SPEC-3b).
2. Publish the mapping as a docs page regardless — partial-conformance honesty is itself
   differentiation versus checklist-badge competitors, and it is exactly your brand move.
3. Correct goals.md wording ("maps 1:1") to the scoped claim.

Touches: goals.md, new docs/aarm-mapping.md, possibly policy-ir.md (if MODIFY adopted later).

### SPEC-2. Gateway ESCALATE: adopt the native MRTR retry pattern; sign `requestState`

flows/06 holds the HTTP request open and polls escalations every 2s (bounded ≤120s). The
MCP 2026-07-28 spec's native MRTR pattern is different: return `InputRequiredResult`
(`resultType: "input_required"`) and the **client retries the original call** carrying
`inputResponses`/`requestState`. Two spec facts drive the change:

- Clients MUST echo back exact `requestState` on retry; servers MUST treat incoming
  `requestState` as attacker-controlled input.
- Where authorization depends on `requestState`, the spec REQUIRES integrity protection
  (HMAC or AEAD) plus, inside the protected payload: authenticated principal, short TTL,
  and a digest identifying the originating request.

Warden already owns every ingredient: `hmac` crate (Flow 3 webhooks), escalation_id,
TTL, `params_binding_hash`. Fix:

```
requestState = HMAC(secret, escalation_id ‖ expires_at ‖ params_binding_hash ‖ agent_id)
```

Gateway verifies on client retry → checks escalation approved/unconsumed → forwards.
This extends the bait-and-switch defense into the protocol layer natively, removes the
held-connection class of problems entirely, and satisfies the spec's integrity mandate.
Keep poll-and-hold as a fallback for clients that mishandle MRTR — but retry-native is
the primary path. (Pass 1 said "test real clients"; this eliminates the risk instead.)

Touches: flows/06 (§MRTR clarification, Tooling), flows/03 (consumption path gains a
gateway-native variant).

### SPEC-3. Hook seam: matcher string is fragile; surface coverage has a network-egress gap

flows/05 wires `"matcher": "Bash|Write|Edit|Read|mcp__*"`. Two problems:

a. **Regex semantics.** Claude Code matchers are JS regex; the documented canonical form
   is `mcp__memory__.*`. `mcp__*` only works accidentally via unanchored substring
   matching (`mcp_` + zero-or-more `_`). If host matching changes, **every MCP tool
   silently ungates** — precisely the failure class Warden exists to prevent. Use
   `mcp__.*`. Add a CI assertion that the installed settings.json entry matches the
   current host's documented matcher grammar (you already pin host versions for e2e).

b. **Coverage gap.** Matcher omits `WebFetch`, `WebSearch`, `NotebookEdit`, `Task`.
   Starter-safety blocks outbound shell installers, but an unmatched WebFetch/WebSearch
   is a silent network-egress bypass (exfiltration primitive). Since the starter pack
   already allow-rules the benign namespace (BUG-3 fix), intercepting all
   state-changing/network tools costs little. Decide explicitly; document why pure-local
   reads (Grep/Glob/TodoWrite) stay outside the matcher (latency tax math: ~40–75 ms ×
   high-frequency calls) while `Read` stays inside deliberately (secret-read blocking
   needs it — `.env` reads are otherwise only catchable inside Bash commands).

SPEC-3b (ride-along): document `updatedInput` (host-supported input rewriting paired with
allow) as the future enforcement surface for MODIFY/redact-and-allow — one roadmap line
now, big "whoa" later, and it closes AARM R4-MODIFY (see SPEC-1).

Touches: flows/05 (wiring block, starter-pack table), threat-model.md (note the bypass
class), repo-layout CI notes.

### SPEC-4. Local-mode daemon lifecycle is unowned — biggest adoption footgun

Local mode = interceptor fail-closed + `warden serve` on localhost, but no doc describes
how serve starts, restarts, or survives reboot. Failure mode: user closes terminal /
reboots → gate unreachable → **every tool call denies** → "Warden bricked my Claude Code"
→ rage uninstall. This WILL happen in week one post-launch.

Minimum: `warden init` offers/installs user-level autostart (Windows scheduled task /
launchd user agent / systemd user unit) + hook-side failure UX that names the remedy:
`Warden: gate unreachable — run 'warden serve' or 'warden unhook'`.

Recommended additionally: **`warden doctor`** — validates hook wiring (settings merge
intact, matcher grammar OK), gate reachability, ledger health (chain verify head),
policy currency, prints fix hints. Cheap, permanent support-cost reducer, good demo beat.

Touches: flows/09 (init responsibilities), adoption-integration.md (deployment modes row),
flows/02 (fail-closed envelope error text), tech-stack CLI verb list.

### SPEC-5. Context-trust invariant: sensitive context is computed at the trusted seam

`context.surface`, `delegation_depth` (and any future intent fields) arrive in
DecisionRequest — i.e., interceptor-supplied and, in SDK/framework mode, potentially
spoofable by the governed process. One invariant line closes the family: **context fields
that influence verdicts are computed at the trusted boundary (hook/gateway derive them);
the decision API never accepts them from agent-controlled payloads. Team-mode gateway
derives delegation_depth itself.** State it in Flow 2 invariants and honor it in adapters.

Touches: flows/02 (invariants), adoption-integration.md (SDK seam note), flows/04 adapter guidance.

---

## §B Competitive / narrative updates (P0 before Show HN)

### COMP-1. The Cerbos row is stale — refresh against June–July 2026 reality

Verified: 2026-06-10 Cerbos published gateway governance with **agentgateway** (CNCF data
plane) + Synapse over Envoy ext_authz: per-call **parameter-level** MCP authorization
(refund-above-tier-cap examples), MCP-server gating at `initialize` (tool catalogs never
reach unauthorized agents), task-scoped kill switch, unified decision logging in Cerbos Hub.
competitive-positioning.md:13 currently says "Partial — markets agent features." That will
get corrected *for* you in comment #1 of Show HN.

Durable differences survive and remain strong — state them against today's Cerbos:
tamper-evident ledger with Merkle checkpoints + external anchoring (vs. plain Hub logs);
NL compiler + human trust loop; single-use params-bound HITL approvals with expiry;
byte-for-byte deterministic replay as a shipped command; coding-agent hook seam;
open benchmark with label provenance.

### COMP-2. Launch narrative anchor: the OpenAI–Hugging Face incident (July 2026)

Publicly discussed incident where the safety layer was deliberately switched off and
post-hoc detection was the only remaining control. Cerbos's own analysis argues runtime
authorization "should still have been standing when the safety layer was turned off."
That is literally Warden's thesis in news form — cite it in the README/launch post as
the motivation case alongside EU AI Act Art. 50 timing.

### COMP-3. Additional badge channels (one-liners in goals.md)

- **OWASP AISVS** (Agentic AI Security Verification Standard) referenced in 2026 industry
  coverage — map controls once AARM mapping doc exists (same exercise).
- **EMA positioning nuance** (verified): EMA makes the IdP authoritative for *server access*
  via ID-JAG exchange; it never inspects traffic. Flow 6's "open-source PDP an EMA
  deployment points at" line holds — consider adding "AuthN/coarse-grant lives in the IdP
  (EMA); per-call AuthZ + proof lives in Warden" to preempt confusion.

---

## §C Security hardening (P1 — build-time requirements)

### SEC-1. Checkpoint signing-key rotation is unstated
Add `key_id` to the checkpoint/signature envelope now (ledger_checkpoints), define rotation
procedure, and make `warden ledger verify/prove` handle multiple historical keys.
Without it, first rotation bricks offline verification. Touches: data-model.md,
flows/04, threat-model Layer 2.

### SEC-2. TLS story for team mode is unspecified
`WARDEN_URL` implies plaintext bearer keys on the LAN. One paragraph in flows/02 +
adoption-integration.md: native `rustls` option OR documented reverse-proxy termination.
Enterprise asks on day one.

### SEC-3. Dashboard authentication in team mode is unspecified
Approves escalations — never ship unauthenticated. Minimum: session token printed by
`warden serve` at startup; SSO remains paid-tier later. Touches: flows/03 (Tooling),
repo-layout dashboard note.

### SEC-4. Supply-chain hygiene is on-brand and cheap
cargo-deny/cargo-audit in CI; cosign/Sigstore-sign release artifacts (you are already a
Rekor consumer — signing your own binaries closes the trust loop); SBOM attached to
releases. A product whose pitch is cryptographic proof must be trivially verifiable itself.
Touches: repo-layout ci.yml description, goals launch assets.

### SEC-5. Fuzz the boundary parsers
proptest covers logic; add cargo-fuzz targets for: hook stdin JSON parser, gateway body
parsing, IR validator, canonical.rs. Same message as everything else: proven, not asserted.
Touches: repo-layout (testing row), flows/05–07 Testing rows.

### SEC-6. Small retention/rotation knobs left numeric-less
`proposed_params` retention policy named but no default TTL (threat-model.md:49); webhook
HMAC secret rotation procedure unstated. One sentence each; pick defaults
(e.g., purge resolved escalations' params after N days; rotate via dual-secret overlap window).

---

## §D Data-model insurance (P1, minutes each)

### DATA-1. `agent_api_keys`: add `last_used_at`, `expires_at`
Same free-insurance logic as PERF-2's tenant_id. Key hygiene queries and rotation audits
are inevitable; migrating later costs more than the two columns now.
Touch: data-model.md §2.

### DATA-2. `policies` lacks `tenant_id` while ledger + identities have it
PERF-2 sharding insurance is incomplete: fleet-mode tenancy will need policy scoping too.
Nullable column now ≈ free. Touch: data-model.md §3.

---

## §E Performance notes (P2)

### PERF-6. Group commit as scale-out step 1.5
If E2 shows SQLite commit rate below the 300/sec floor on slower disks, batching fsyncs
(group commit) raises throughput without abandoning the single-writer model — cheaper
intermediate lever than the Postgres move for some deployments. Slot between scale-out
steps 1 and 2 in scalability-targets.md. Only if measured demand appears (per your own principle).

### PERF-7. Document the matcher-overhead tradeoff consciously
Intercept-everything costs ~40–75 ms × every matched call; high-frequency read-only tools
would pay it constantly. Whatever coverage decision SPEC-3 lands on, record the latency
math next to it so the choice looks deliberate (it should be).

---

## §F Adoption additions (P1–P2)

### ADOPT-6. Windows console approval prompt needs a test matrix, not an assumption
Flow 3 hook-local approval opens CONIN$/CONOUT$ directly. Before the demo leans on it,
verify across: Windows Terminal, VS Code integrated terminal, git-bash, WSL-invoked claude.
Two known risks: host TUI redraw can garble the prompt mid-render; headless `-p` runs and
CI have no console at all → auto-deny path fires (correct behavior, but consider a distinct
ledger reason_code, e.g. `DENY_NO_CONSOLE`, vs. human DENY so the evidence trail distinguishes
them). Touches: flows/03, flows/05.

### ADOPT-7. Shim child-process lifecycle on Windows
`npx` on Windows is `npx.cmd` — spawning requires cmd-shim handling; signal semantics differ
(no SIGTERM; job-object kill needed for clean teardown). Test + document in flows/07 before
calling Windows first-class done (ADOPT-3 companion).

### ADOPT-8. Distribution: uv-style installer scripts
Alongside brew/winget/scoop/cargo: `curl … | sh` (POSIX) and a PowerShell one-liner
(Windows) pulling prebuilt binaries from GitHub releases. Cheapest funnel for the
hook wedge; npx shim stays optional/later per tech-stack.md.

### ADOPT-9. Seed the policy-pack registry with real content at launch
Registry-as-moat needs seeds: ship 3–4 packs beyond starter-safety (e.g., fintech refunds,
DB-guard, HR/PII handling, secrets hygiene). Empty registries don't compound.
Touch: goals.md §Business, repo-layout policies/.

### ADOPT-10. GitHub Action scope: diff-aware policy CI
warden-policy-test Action (ADOPT-4) should lint/test/replay **changed policies against the
PR diff** — that framing ("your SOP change gets tested in CI like code") is the sticky loop.

### ADOPT-11. Future-seam note: the host grew to ~31 hook events
Claude Code now exposes Setup, PermissionRequest, PermissionDenied, PostToolUseFailure,
SubagentStart, ConfigChange, etc. (Aug 2026). No action needed for v1 — one roadmap line
so nobody assumes PreToolUse is the only seam. PostToolUseFailure in particular pairs
naturally with ledger outcome-correlation later.

---

## Verified-this-pass: external assumption results

| Assumption | Result |
|---|---|
| MCP 2026-07-28: stateless core, EMA stable (Jun 18 2026; Anthropic/Microsoft/Okta adopting), MRTR SEP-2322 `InputRequiredResult` | ✅ Confirmed. Native pattern = client-retry with signed `requestState` → drives SPEC-2 |
| Claude Code PreToolUse contract: `hookSpecificOutput.permissionDecision`, allow/deny/ask/defer | ✅ Confirmed (BUG-4 fix correct). Flat-format output silently ignored upstream (#48760/#40380) — validates the strict nesting |
| PreToolUse `deny` holds under `--dangerously-skip-permissions` | ✅ Confirmed (Aug 2026 docs + community verification). Flagship pitch survives; keep pinned-version e2e |
| `defer` avoidance | ✅ Validated — `defer` has active severe bugs upstream (#64389: synthetic `[Tool result missing]` fed to model, subagent breakage, race-dependent). Do not adopt; note in threat-model.md |
| AARM v1.0 (arXiv 2602.09433, Feb 2026), Vanta→CSAI Foundation (Apr 29 2026), Core R1–R6 MUST / Extended R7–R9 SHOULD, conformance protocol + builders registry | ✅ Confirmed with detail → drives SPEC-1 (five-decision requirement, production-op prerequisite, 14-day TWG review) |
| Cerbos agentic push: agentgateway + Synapse, param-level MCP authz, initialize-gating, kill switch, Hub decision logs (Jun–Jul 2026) | ✅ Confirmed → drives COMP-1 |
| OpenAI–Hugging Face incident (Jul 2026) usable as runtime-authz narrative anchor | ✅ Confirmed via industry coverage → COMP-2 |
| OWASP AISVS as additional standards channel | ✅ Exists and referenced in 2026 coverage → COMP-3 |

Not re-verified (pass-1 resolution log checked same-day with sources): Rekor v2 GA,
Cedar 4.x + Cedar Analysis, crates.io `warden`/`warden-cli` taken, EU AI Act timeline
(Art. 50 in force Aug 2 2026; Annex III deferred Dec 2 2027).

---

## Priority order

1. **SPEC-1** AARM mapping doc + restated claim (it is a stated LAUNCH REQUIREMENT — cannot ship misstated).
2. **SPEC-2** MRTR signed-`requestState` retry pattern (protocol-correct, removes held-request risk).
3. **SPEC-3** matcher grammar + coverage decision; **SPEC-4** daemon lifecycle + `warden doctor`.
4. **COMP-1/2** competitive row refresh + incident narrative (pre-Show HN).
5. **SEC-1..3, DATA-1..2, ADOPT-6..7** — build-time requirements, hours total.
6. Everything else rides along (SEC-4..6, PERF-6..7, ADOPT-8..11, SPEC-5 invariant line).

Nothing found invalidates architecture, stack, or sequencing. The system you specified in
pass 1 is still the system worth building; these are the deltas that keep its claims true
under contact with the Aug 2026 ecosystem.

## Sources (verified 2026-08-23)

- MCP: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr ·
  https://modelcontextprotocol.io/specification/2026-07-28/changelog ·
  https://blog.modelcontextprotocol.io/posts/2026-07-28/ ·
  https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/ ·
  https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
- Claude Code hooks: https://code.claude.com/docs/en/hooks ·
  https://code.claude.com/docs/en/agent-sdk/hooks ·
  https://github.com/anthropics/claude-code/issues/48760 (flat-format silent discard) ·
  https://github.com/anthropics/claude-code/issues/64389 (defer breakage) ·
  https://github.com/anthropics/claude-code/issues/41791 (defer docs/resolution) ·
  https://blakecrosley.com/blog/claude-code-hooks-explained (deny-holds-in-bypass verification, 31-event survey)
- AARM: https://aarm.dev/spec · https://aarm.dev/conformance · https://aarm.dev/ ·
  https://github.com/aarm-dev/aarm ·
  https://cloudsecurityalliance.org/research/working-groups/autonomous-action-runtime-management-aarm ·
  https://cloudsecurityalliance.org/press-releases/2026/04/29/csai-foundation-announces-key-milestones-to-secure-the-agentic-control-plane ·
  https://arxiv.org/abs/2602.09433
- Competitors: https://www.cerbos.dev/blog/governing-ai-agents-at-the-gateway-with-cerbos-and-agentgateway ·
  https://www.cerbos.dev/blog/the-kill-switch-that-never-got-pressed-what-the-open-ai-hugging-face-incident-tells-us-about-agent-authorization ·
  https://www.cerbos.dev/features-benefits-and-use-cases/ai-security ·
  https://www.cerbos.dev/blog/mcp-permissions-securing-ai-agent-access-to-tools
