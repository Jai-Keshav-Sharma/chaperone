# Flow 7 — stdio Shim (desktop client seam)

Status: DECIDED. Date: 2026-08-23.

## Purpose

Desktop MCP clients configure servers as command lines over stdio, not HTTP URLs.
The shim wraps the child server process so such clients get Warden by changing one
command line.

```
BEFORE:  "command": "npx @stripe/mcp-server"
AFTER:   "command": "warden shim -- npx @stripe/mcp-server"
```

## Flow

1. Client launches the shim instead of the server; shim spawns the real server as child.
2. initialize / tools/list pass through untouched (normal tool discovery).
3. tools/call intercepted, same decision mapping as the gateway:
   - ALLOW → forward to child, stream result back (invisible)
   - BLOCK → MCP tool error with structured reason + ledger ref
   - ESCALATE → tool error: WARDEN_ESCALATED: approval required (escalation_id, expires).
     Retry the identical call after approval.

## Design trap — no MRTR pause on stdio

A stdio pipe is a single serialized channel; holding it for a human would freeze the
entire agent session (deadlock). ESCALATE is therefore poll-based, never blocking:
fail the call with the ticket message, let the agent continue, retry after approval
via the Flow 3 consumption path (params-hash makes the retry safe).

General lesson: each surface gets the escalation UX its transport can physically support —
ask in host UI (hook), MRTR pause (gateway, HTTP concurrency), poll-and-retry (shim).
Same decisions, same ledger, different wiring.

## Tooling

| Concern | Choice |
|---|---|
| Process wrapper | std::process::Command — spawn child, bridge stdio. WINDOWS (review-2 ADOPT-7): `npx` is `npx.cmd` (cmd-shim handling required); no SIGTERM — clean teardown needs job-object kill; test + document before "Windows first-class" is claimed |
| MCP transport | Official `mcp` SDK stdio transport |
| Decision mapping | Shared mapping module as hook/gateway (one code path) |
| Escalation | Structured tool error + Flow 3 retry path — never block the pipe |
| Identity | WARDEN_AGENT_ID env; fallback unknown-agent (policy-blockable) |
| Testing | Fake child MCP server fixture; e2e client session → allow/block/escalate + ledger +N |

## Pitch

"Desktop MCP clients get Warden by changing one command line — same gate, same ledger,
zero code."
