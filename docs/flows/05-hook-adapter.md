# Flow 5 — Hook Adapter (Claude Code / Cursor)

Status: DECIDED. Date: 2026-08-23.

## Purpose

The wow-demo surface: one command gates a coding agent's shell, file, and MCP actions,
even under `--dangerously-skip-permissions`. Hooks run regardless of permission mode —
the model gets no vote.

## Wiring (warden init)

`warden init` merges (never clobbers) one entry into `.claude/settings.json` (+ Cursor config):

```json
{ "hooks": { "PreToolUse": [
    { "matcher": "Bash|Write|Edit|Read|WebFetch|WebSearch|NotebookEdit|Task|mcp__.*",
      "hooks": [{ "type": "command", "command": "warden hook" }] }
]}}
```

Matcher coverage is deliberate (review-2 SPEC-3):
- `mcp__.*` — the documented canonical glob form for MCP tools (bare `mcp__*` works only
  accidentally via unanchored matching; if host matching semantics change, MCP coverage
  would silently ungate — a CI assertion validates the installed settings entry against
  the pinned host version's matcher grammar).
- WebFetch / WebSearch / NotebookEdit / Task included — network egress and state-changing
  tools MUST be gated (an unmatched WebFetch is a silent exfiltration primitive).
- Grep / Glob / TodoWrite deliberately OUTSIDE the matcher: pure-local, high-frequency
  reads; intercepting them would tax every call ~40–75ms for no risk reduction.
- Read stays inside deliberately: secret-read blocking (`.env`) needs file-tool
  visibility, not just Bash-command parsing.

## Cursor wiring (fail-closed by config — review-3 P0)

Cursor's hooks DEFAULT TO FAIL-OPEN (verified cursor.com/docs/hooks): crash, timeout,
or invalid JSON → action proceeds, unless the entry sets `failClosed: true`. `warden
init` therefore writes PROJECT-level `.cursor/hooks.json` entries that are explicitly
fail-closed — this is a Law-1 requirement, not a preference:

```json
{ "version": 1, "hooks": {
    "beforeShellExecution": [
      { "command": "warden hook", "timeout": 35, "failClosed": true } ],
    "beforeMCPExecution": [
      { "command": "warden hook", "timeout": 35, "failClosed": true } ],
    "beforeReadFile": [
      { "command": "warden hook", "timeout": 35, "failClosed": true } ]
}}
```

- `timeout: 35` — Cursor's timeout defaults to "platform default" and would kill the
  ~30s hook-local approval prompt mid-flow; the bound must sit ABOVE the prompt bound.
- PROJECT-level (`.cursor/hooks.json`), never user-level: Cursor cloud agents run repo
  hooks but IGNORE user-level hooks (threat-model notes this boundary).
- Cursor outcome set is allow/ask/deny; Warden emits allow/deny only (ask hands
  approval to the host UI — same evidence-chain rule as Claude Code). Exit code 2 ≡ deny.
- BUILD-TIME VERIFICATION (review-3 N4): `beforeReadFile` permission-honoring is
  UNVERIFIED — official docs list it, but independent Jul 2026 analyses report only
  beforeShellExecution/beforeMCPExecution (plus preToolUse) actually enforce. Verify
  against the pinned Cursor version; if observe-only, `.env` read-protection on Cursor
  relies on Bash-command parsing alone — document that boundary in threat-model.
- Cursor matchers are JS regex over the command string — the matcher on our entries is
  deliberately empty (gate everything the event covers); no accidental substring reliance.

## Contract

- In (stdin JSON): `{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "session_id": ...}`
- Out (stdout JSON): decision MUST be nested under hookSpecificOutput (top-level fields
  are ignored for PreToolUse — review BUG-4):
  `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"|"deny"|"ask"|"defer", "permissionDecisionReason": "..."}}`
- The host outcome set has FOUR values (allow/deny/ask/defer); Warden emits only
  allow and deny — `ask` would hand approval to the host UI and break the evidence
  chain (Flow 3 hook-local approval instead); `defer` is for chained handlers and unused.

## Steps

1. Host invokes `warden hook` per PreToolUse event (cold-start TARGET ~1ms; measured in E2 — Windows process spawn is several ms, review-3 N5).
2. Tool name normalized to the universal namespace (one policy language governs every
   surface): Bash → shell.exec, Write/Edit → fs.write, Read → fs.read,
   mcp__stripe__refund → mcp.stripe.refunds.create, WebFetch → web.fetch,
   WebSearch → web.search, NotebookEdit → notebook.edit, Task → task.spawn.
   Policies can target every gated tool by its universal name (review-3 P1-1).
3. DecisionRequest built: request_id (UUIDv4 at boundary), agent_id (WARDEN_AGENT_ID or host
   session identity), context.surface = claude_code|cursor.
4. Decision service called (localhost / WARDEN_URL), 1000ms timeout.
5. Verdict mapped:

| Warden | Hook output | User experience |
|---|---|---|
| ALLOW | allow (silent) | Zero friction, ~40–75ms total overhead |
| BLOCK | deny + "Warden BLOCK: pol r-id (ledger #14921)" | Refused; agent sees reason + ledger receipt |
| ESCALATE | Hook-local approval: interactive console prompt inside the hook → approve → resolve entry → re-submit → ALLOW (ESCALATION_APPROVED) → return allow | Approval happens INSIDE the hook so the RESOLVED entry exists before the host runs anything (Flow 3 invariant 4) |
| Gate unreachable | deny (FAIL_CLOSED_GATE_UNREACHABLE) | Fail-closed: no gate, no action |
| Shadow mode | allow + ledgered WOULD_* | Invisible observation |

## Starter-safety pack (shipped by warden init)

| Rule | Effect |
|---|---|
| rm -rf outside working directory | block |
| git push --force to protected branches | block |
| Writes to .env / secret paths (keys, pems, lockfiles) | block |
| Outbound calls to unknown hosts (curl|sh installers) | block |
| File deletions above N/hour (velocity rule via derived context) | escalate |
| Refund-like calls above threshold | escalate |
| Benign namespace — fs.read / Read tool, ls/grep/cat within the workspace, git status, safe web reads | allow |

The pack covers the FULL normalized namespace with explicit low-risk allow rules, so
nothing falls to NO_POLICY after `warden init` (review BUG-3). Single source of truth:
this table == Flow 9's pack description.

## Tooling

| Concern | Choice |
|---|---|
| Contract parsing | serde_json (strict); Claude Code PreToolUse + Cursor beforeShellExecution/beforeMCPExecution |
| Normalization | Own mapping module — single source of truth for tool namespaces, exhaustively unit-tested |
| HTTP | `ureq` (blocking, no async runtime — a one-shot hook process doesn't need tokio; faster cold start than reqwest+tokio init) + 1000ms timeout + fail-closed synthesis on any error |
| Bypass-mode verification | e2e test MUST cover `--dangerously-skip-permissions`: hook deny honored in bypass mode. Upstream hooks/permissions interplay is in flux (e.g. issues #39344, #36059) — verify against the installed host version before the launch demo leans on it |
| Windows approval matrix | Hook-local approval (Flow 3) verified across Windows Terminal, VS Code integrated terminal, git-bash, WSL-invoked claude (review-2 ADOPT-6). Headless `-p`/CI → no console → auto-deny with a DISTINCT reason code `DENY_NO_CONSOLE` (evidence trail distinguishes it from a human DENY) |
| Roadmap | `updatedInput` (host-supported input rewriting paired with allow) = future MODIFY / redact-and-allow enforcement surface (closes AARM R4-MODIFY, see docs/aarm-mapping.md). Host now exposes ~31 hook events (Setup, PermissionRequest, PermissionDenied, PostToolUseFailure, SubagentStart, ConfigChange…) — PreToolUse is not the only seam; PostToolUseFailure pairs naturally with ledger outcome-correlation later |
| Binary | Same `warden` binary (clap subcommand) — no interpreter; cold-start TARGET ~1ms, measured in E2 (review-3 N5) |
| init | Careful JSON merge; writes starter pack; prints 3-command demo; never writes outside target project dir |
| Idempotency | request_id UUIDv4 at hook boundary |
| Testing | Table-driven event→request→verdict matrix; e2e subprocess test: `rm -rf /` event → deny with ledger ref |
| Distribution | Static binary (prebuilt releases, brew, cargo install); optional npx shim later |

## Pitch

"Seatbelts for `--dangerously-skip-permissions` — one command, and your coding agent
cannot delete your files, push to main, or read your secrets, with a tamper-evident
receipt for everything it tried."
