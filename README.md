# Chaperone

The deterministic authorization gate for AI agents: ALLOW / BLOCK / ESCALATE before
every tool call, compiled from plain-English policy, with a tamper-evident ledger
you can hand to an auditor.

"Seatbelts for `--dangerously-skip-permissions`." Apache-2.0, single Rust binary,
self-hostable.

## Status

Under construction. This repository is currently the locked specification:

- `AGENTS.md` — executor context: the laws, build order, verified external facts
- `docs/` — the ten flows, frozen wire contracts, data model, Policy IR, build plan
- `policies/` — the canonical Cedar entity schema

## Quickstart (coming soon)

`chaperone init` → the five-minute demo: install the gate, watch a block land with
a ledger receipt, approve an escalation, retry.

## License

Apache-2.0