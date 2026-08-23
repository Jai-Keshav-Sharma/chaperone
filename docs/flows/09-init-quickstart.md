# Flow 9 — Init & Quickstart (five-minute wow)

Status: DECIDED. Date: 2026-08-23.

## Concept

`warden init` transforms a stranger into a user in one command:

1. Creates local SQLite database (genesis entry written)
2. Loads + activates the starter-safety policy pack — which includes explicit LOW-RISK
   ALLOW rules covering the benign namespace (fs.read, ls/grep-style shell commands,
   git status, safe web reads) so nothing falls to NO_POLICY (review BUG-3)
3. Sets `ungoverned_default: allow` for THIS local deployment (warden serve defaults to
   block; ungoverned allowances are ledgered as UNGOVERNED_ALLOW and surfaced on the
   dashboard/shadow stats — loudly accounted, never silent)
4. Merges the hook entry into .claude/settings.json (+ Cursor config; merge, never clobber)
5. Prints the 3-command demo

## Demo script

```
$ warden init                              → "Warden installed. Try this:"
$ claude --dangerously-skip-permissions    → ask the agent to "clean up" with rm -rf /
   → BLOCK: "Warden BLOCK: starter-safety s-block-destructive (ledger #42)"
$ warden ledger verify                     → CHAIN OK (43 entries)
$ claude → "refund customer 123 $450"      → ESCALATE (ticket esc_…, expires 15 min)
$ warden approve esc_9f4c2b71             → APPROVED (ledger #47)
$ retry the call                           → ALLOW (ESCALATION_APPROVED, ledger #48)
```

Under five minutes, zero code changes. The user personally experiences: a block, a
tamper-evident receipt, a human approval, a completed retry. The demo IS the onboarding.

## Tooling

| Concern | Choice |
|---|---|
| Command | clap subcommand `init` |
| Settings merge | Careful JSON merge module — preserve unknown keys, never write outside target project dir |
| Starter pack | Checked-in IR (starter-safety) |
| DB bootstrap | SQLite creation + genesis |
| Demo | scripts/demo.sh mirroring the above (CI + screenshots) |

No new dependencies.
