# Contributing to chaperone

Thanks for helping build the seatbelt.

## Ground rules

1. Read `AGENTS.md` first. It contains the eleven laws of this codebase. Any
   PR that violates one (fail-open behavior, LLM in the decision path,
   non-canonical hashing, ledger UPDATE/DELETE) will be rejected on principle.
2. `docs/` is the spec. A behavior change without a doc change in the same
   commit is incomplete.
3. Never weaken a test to make it pass. A differential mismatch is an engine
   bug, not a test bug.

## Development

```bash
make check    # fmt + clippy (-D warnings) + cargo check
make test     # cargo test --workspace
```

Windows is a first-class platform. CI runs windows-latest and ubuntu-latest.

## Commits

Conventional commits, one logical change per commit:
`feat(scope): summary` / `fix(scope): summary`.

## Good first issues

Look for issues labeled `good first issue` - typically CLI polish, dashboard
components, docs, and bench scenarios.
