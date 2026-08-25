# Flow 9 — Init & Quickstart (five-minute wow)

Status: DECIDED. Date: 2026-08-23.

## Concept

`chaperone init` transforms a stranger into a user in one command:

1. Creates local SQLite database (genesis entry written)
2. Loads + activates the starter-safety policy pack — which includes explicit LOW-RISK
   ALLOW rules covering the benign namespace (fs.read, ls/grep-style shell commands,
   git status, safe web reads) so nothing falls to NO_POLICY (review BUG-3)
3. Sets `ungoverned_default: allow` for THIS local deployment (chaperone serve defaults to
   block; ungoverned allowances are ledgered as UNGOVERNED_ALLOW and surfaced on the
   dashboard/shadow stats — loudly accounted, never silent)
4. Merges the hook entry into .claude/settings.json (+ Cursor config; merge, never clobber)
5. Installs user-level AUTOSTART for `chaperone serve` (Windows scheduled task / launchd
   user agent / systemd user unit) — the gate must survive terminal close and reboot,
   or the fail-closed envelope turns every call into a deny ("Chaperone bricked my Claude
   Code" is the week-one rage-uninstall risk; review-2 SPEC-4)
6. Prints the 3-command demo

## Daemon lifecycle & chaperone doctor (review-2 SPEC-4)

- Local mode's biggest footgun is the unowned daemon: terminal closes / reboot → gate
  unreachable → fail-closed → every tool call denies.
- Autostart (step 5 above) is the default; `chaperone init --no-autostart` opts out.
- Failure UX names the remedy AND the cost (review-5 §3): `Chaperone: gate unreachable —
  run 'chaperone serve' or 'chaperone unhook'. unhook means NO audit trail and NO
  protection — you are unguarded.` The escape hatch must exist; the message must
  explain what escape costs.
- Where possible, the hook logs the denial locally (JSONL spool, Flow 2 invariant 10)
  so the user has a record even when the gate is down.
- `chaperone doctor` validates the whole local chain: hook wiring (settings merge intact,
  matcher grammar OK), gate reachability, ledger health (chain-verify head), policy
  currency — prints fix hints. Permanent support-cost reducer + a good demo beat.
  Plus a LIVE ENFORCEMENT CANARY (review-4 B4): doctor installs a test rule denying a
  benign canary tool call, invokes it through the real host seam, and verifies the
  block actually held — the runtime proof that enforcement is live on THIS surface
  and version ("the only gate that proves its own enforcement is live").

## Demo script (sequence numbers are queried at runtime — never hardcoded; review-4 C3)

```
$ chaperone init                              → "Chaperone installed. Try this:"
$ claude --dangerously-skip-permissions    → ask the agent to "clean up" with rm -rf /
   → BLOCK: "Chaperone BLOCK: starter-safety s-block-destructive (ledger #N)"
$ chaperone ledger verify                     → CHAIN OK (N+1 entries)
$ claude → "refund customer 123 $450"      → ESCALATE (ticket esc_…, expires 15 min)
$ chaperone approve esc_9f4c2b71             → APPROVED (ledger #N+2)
$ retry the call                           → ALLOW (ESCALATION_APPROVED, ledger #N+3)
```

Sequence numbers are QUERIED at runtime, never hardcoded (review-4 C3). CI asserts the
SHAPE of this output (verdicts, message prefixes, chain-verify success), never the
numbers (review-4 drift-4).

Under five minutes, zero code changes. The user personally experiences: a block, a
tamper-evident receipt, a human approval, a completed retry. The demo IS the onboarding.

## Demo dependencies (review-3 P2-11)

The demo's refund ESCALATE requires a refund tool the user doesn't have. `chaperone init
--demo` bundles a tiny canned MOCK MCP server (mock-stripe: a `refunds.create` echo tool
with recorded side effects, no network) and wires it through `chaperone shim` — so minute
four happens offline on every machine. The mock is clearly labeled; it never ships in
enforce mode by default.

## Tooling

| Concern | Choice |
|---|---|
| Command | clap subcommand `init` |
| Settings merge | Careful JSON merge module — preserve unknown keys, never write outside target project dir |
| Starter pack | Checked-in IR (starter-safety) |
| DB bootstrap | SQLite creation + genesis |
| Demo | scripts/demo.sh mirroring the above (CI + screenshots) |

No new dependencies.
