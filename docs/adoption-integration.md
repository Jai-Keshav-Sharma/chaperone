# Adoption & Integration Surfaces

Status: DECIDED. Date: 2026-08-23.

## Core principle: middleware, not migration

Warden never asks anyone to rebuild an agent. It inserts at standardized seams that
already exist in the 2026 agent ecosystem:

```
BEFORE:  Agent ───────────────→ Tool
AFTER:   Agent ──→ [WARDEN] ──→ Tool
                  check → allow/block/ask → log
```

## The four seams (ALL in scope, no time cuts)

| Seam | Component | Wiring cost for the user |
|---|---|---|
| 1. Coding-agent hooks | `warden hook` — Claude Code `PreToolUse`, Cursor `beforeShellExecution` / `beforeMCPExecution` | One command: `warden init` (writes settings.json, merges, never clobbers) |
| 2. MCP gateway | `warden gateway --upstream <url>` — streamable-HTTP reverse proxy | One URL change; one gateway in front of all org MCP servers |
| 3. Framework middleware | LangGraph `HumanInTheLoopMiddleware` backend, OpenAI Agents SDK `needs_approval`, CrewAI `@before_tool_call`, Google ADK callback | One import (~150-line adapters over the same decision API) |
| 4. SDK | `warden` library call | Three lines before tool execution |

## Deployment modes

| | Local mode (developer) | Team mode (org) |
|---|---|---|
| Runs | One binary + SQLite ledger on the dev machine | Central `warden serve` (API + ledger + inbox + dashboard) |
| Interceptor target | localhost | `WARDEN_URL` env |
| Policy management | Local (`warden policy compile ...`) | Central; changes propagate <5ms (pub/sub invalidation) |
| Approvals | Terminal (host prompt or `warden approve <id>`) | Dashboard inbox / `warden approve` |
| Buyer | Individual engineer (free, OSS) | DevSecOps / CISO (enterprise tier) |

Same binary powers both. Local adoption → team formalization is the bottom-up wedge.

## Honest boundary

SaaS-hosted agents where tool-calling happens inside a vendor's cloud (Microsoft Copilot
in M365, Salesforce Agentforce) are not interceptable by an external proxy — that is
Zenity's turf. Warden's wedge is the developer / framework / MCP layer, where the
one-command install lives.

## Native framework integration — core goal

Target: Warden as a first-class, officially documented integration inside LangGraph
(and later OpenAI Agents SDK, CrewAI, ADK), the way Arcade owns a piece of the MCP
ecosystem.

Path:
1. Ship adapters as small, well-tested Apache-2.0 packages (`warden-langgraph` crate +
   thin Python/TS wrappers) with docs and examples.
2. Earn adoption via the hook wow-demo; adapters ride along.
3. Upstream: PRs into `langchain-ai/langgraph` etc. once adoption + track record exist.
   Maintainers accept integrations with users, not before.
