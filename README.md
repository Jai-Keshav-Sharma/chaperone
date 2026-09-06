# Chaperone

**The deterministic authorization gate for AI agents.**

ALLOW / BLOCK / ESCALATE before every tool call, compiled from plain-English
policy, with a tamper-evident ledger you can hand to an auditor.

> *Seatbelts for `--dangerously-skip-permissions`.*

Apache-2.0 · single Rust binary · self-hostable · no LLM in the decision path.

---

## The problem

AI agents are about to run everywhere — customer support, code, operations. The
moment one runs with permissions turned off, or gets prompt-injected, there is
nothing between a bad instruction and real consequences. Existing tools either
ask a human every time (unusable at scale) or trust the model (unverifiable).

## What Chaperone is

Chaperone is a **pre-action authorization gate**. Before any tool executes, it
evaluates the action against a deterministic policy and returns exactly one of
three verdicts:

| Verdict | Meaning |
|---|---|
| **ALLOW** | Safe to proceed. Forward the call. |
| **BLOCK** | Deny, with no side effects. |
| **ESCALATE** | Needs a human. Bound approval to these exact parameters, with an expiry. |

Every single decision — allow, block, or escalate — is written to an
**append-only, hash-chained ledger** before the verdict is returned. No ledger
entry, no verdict, interceptor blocks. That ordering is the core invariant:
*fail-closed, always.*

## Why it's different

**Deterministic, not probabilistic.** The decision engine is a formally-verified
policy engine (Cedar). There is no LLM in the decision path, so prompt injection
cannot talk its way around a rule. A policy is compiled from plain English
*offline*, reviewed by a human, and only then activated. The runtime is 100%
reproducible.

**One gate, three seams.** The same policy engine, inbox, and ledger guard three
different surfaces:

- **`chaperone hook`** — intercepts coding agents (Claude Code, Cursor) via
  PreToolUse hooks. Shell commands, file writes, deletes, reads — every action
  is checked before it runs.
- **`chaperone gateway`** — a streamable-HTTP reverse proxy that sits in front
  of any MCP server, the org-wide chokepoint for customer-facing agents.
- **`chaperone shim`** — an MCP stdio proxy for desktop clients and local tools.

**Tamper-evident proof.** The ledger is a SHA-256 hash chain with RFC 6962
Merkle checkpoints, Ed25519-signed, with optional Rekor v2 / RFC 3161 timestamp
anchoring. After anything happens, you can prove exactly what the agent tried
and whether it was stopped — and any tampering breaks the chain.

**Human-in-the-loop that binds.** Escalations carry a *params-binding hash*: an
approval covers only the exact parameters that were escalated, nothing else.
Approvals expire, and a sweeper auto-denies stale ones.

## Compliance & standards

Chaperone is built to map to the frameworks enterprise auditors already know.
The honest claim: **it maps to standards — it does not self-certify.**

- **OWASP Top 10 for Agentic Applications (ASI01–ASI10)** — goal-hijack
  resistance, tool-misuse thresholds, identity decay, code-exec blocks, HITL
  reasoning traces, rogue-agent kill switch.
- **EU AI Act** — Art. 9 (per-action risk management), Art. 12 (automatic
  tamper-evident logging), Art. 14 (human oversight), Art. 72/73 (monitoring &
  incident reconstruction). `chaperone ledger export --format eu-ai-act`
  produces the evidence bundle.
- **NIST AI Risk Management Framework** — GOVERN / MAP / MEASURE / MANAGE
  operationalized through policy lifecycle, shadow mode, the E1–E6 benchmark,
  and the gate itself.
- **Cloud Security Alliance** — AICM v1.1 agentic controls, AIGF just-in-time
  access, and **AARM v1.0** (launch claim: *Aligned*; Core conformance is a
  post-production milestone with production evidence).
- **ISO 42001 / SOC 2** — `chaperone ledger export --format soc2` ships the
  audit-evidence pack for the near-term enterprise buyer.
- **IETF WIMSE / MCP / EMA** — consumes workload identity, integrates with the
  IdP-authoritative access model: *"AuthN/coarse-grant lives in the IdP; per-call
  AuthZ + proof lives in Chaperone."*

The full mapping table is in [`docs/compliance-mapping.md`](docs/compliance-mapping.md)
and [`docs/aarm-mapping.md`](docs/aarm-mapping.md).

## Architecture

```
crates/
  chaperone-core/     the pure library — models, IR, engine, ledger, storage,
                      cache, escalation, compiler, document parsers
  chaperone-server/   the axum app factory + routes (decisions, policies,
                      escalations, ledger, health, metrics, ws)
  chaperone-cli/      the single `chaperone` binary (clap verbs)
dashboard/            React + TypeScript (Vite): live decision stream, HITL
                      inbox, ledger explorer, policy compiler
bench/                E1–E6: attack corpus, gold policies, scenario runner
policies/             canonical Cedar entity schema + starter policy
docs/                 the locked spec — flows, wire contracts, data model,
                      policy IR, threat model, compliance mapping
```

The layering law: `models → ir | engine | ledger | storage | cache | escalation
| compiler → decision → server | cli`. The pure layers (models, IR, engine) do
zero I/O, which is what makes replay, differential testing, and the WASM demo
possible.

## Quickstart

```bash
# build
cargo build -p chaperone-cli --release

# install the gate and a starter safety policy
chaperone init

# start the gate + dashboard API
chaperone serve

# verify your enforcement is live (runs a real canary block)
chaperone doctor
```

Then open the dashboard, connect with the token printed by `init`, and watch
decisions stream in as your agent acts.

To compile a policy from a plain-English document (PDF / Markdown / DOCX /
HTML), use the Policies tab in the dashboard, or:

```bash
chaperone policy compile ./refund-sop.pdf --provider ollama
chaperone policy activate <policy-id>
```

## Commands

```
chaperone init                 install hooks + starter policy + agent registry
chaperone hook                 the PreToolUse intercept point (Claude Code/Cursor)
chaperone serve                the gate HTTP service + WebSocket stream
chaperone gateway --upstream U run an MCP streamable-HTTP chokepoint
chaperone shim                 run an MCP stdio proxy
chaperone doctor               validate hook wiring, ledger, policy, + live canary
chaperone approve <id>         approve an escalation (params-bound, single-use)
chaperone deny <id>            deny an escalation
chaperone escalations list     list the pending HITL queue
chaperone policy compile|edit|lint|test|activate
chaperone ledger verify|prove|checkpoint|export
chaperone bench                run the E1–E6 benchmark
```

## Development

```bash
make check        # fmt + clippy (-D warnings) + cargo check
make test         # cargo test --workspace
make test-all     # cargo test --workspace --all-features
make bench        # run the benchmark suite
```

Windows is a first-class platform (it's the primary dev/demo surface); CI runs
`windows-latest` + `ubuntu-latest`.

## Status

Under active development. The core is implemented and tested end-to-end:
deterministic evaluation, fail-closed interceptions on all three seams,
append-only ledger with signed checkpoints, human-in-the-loop escalations, the
NL→policy compiler, and the E1–E6 benchmark corpus. The roadmap (see
[`docs/goals.md`](docs/goals.md)) covers post-launch items like Redis tier
distribution, Postgres fleet mode, and WASM plugins.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
