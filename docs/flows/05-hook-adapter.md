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
    { "matcher": "Bash|Write|Edit|Read|mcp__*",
      "hooks": [{ "type": "command", "command": "warden hook" }] }
]}}
```

## Contract

- In (stdin JSON): `{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "session_id": ...}`
- Out (stdout JSON): decision MUST be nested under hookSpecificOutput (top-level fields
  are ignored for PreToolUse — review BUG-4):
  `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"|"deny"|"ask"|"defer", "permissionDecisionReason": "..."}}`
- The host outcome set has FOUR values (allow/deny/ask/defer); Warden emits only
  allow and deny — `ask` would hand approval to the host UI and break the evidence
  chain (Flow 3 hook-local approval instead); `defer` is for chained handlers and unused.

## Steps

1. Host invokes `warden hook` per PreToolUse event (~1ms startup).
2. Tool name normalized to the universal namespace: Bash → shell.exec, Write/Edit → fs.write,
   Read → fs.read, mcp__stripe__refund → mcp.stripe.refunds.create. ONE policy language
   governs every surface.
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

## Tooling

| Concern | Choice |
|---|---|
| Contract parsing | serde_json (strict); Claude Code PreToolUse + Cursor beforeShellExecution/beforeMCPExecution |
| Normalization | Own mapping module — single source of truth for tool namespaces, exhaustively unit-tested |
| HTTP | `ureq` (blocking, no async runtime — a one-shot hook process doesn't need tokio; faster cold start than reqwest+tokio init) + 1000ms timeout + fail-closed synthesis on any error |
| Bypass-mode verification | e2e test MUST cover `--dangerously-skip-permissions`: hook deny honored in bypass mode. Upstream hooks/permissions interplay is in flux (e.g. issues #39344, #36059) — verify against the installed host version before the launch demo leans on it |
| Binary | Same `warden` binary (clap subcommand) — no interpreter, ~1ms cold start |
| init | Careful JSON merge; writes starter pack; prints 3-command demo; never writes outside target project dir |
| Idempotency | request_id UUIDv4 at hook boundary |
| Testing | Table-driven event→request→verdict matrix; e2e subprocess test: `rm -rf /` event → deny with ledger ref |
| Distribution | Static binary (prebuilt releases, brew, cargo install); optional npx shim later |

## Pitch

"Seatbelts for `--dangerously-skip-permissions` — one command, and your coding agent
cannot delete your files, push to main, or read your secrets, with a tamper-evident
receipt for everything it tried."
