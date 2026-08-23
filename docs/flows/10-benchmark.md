# Flow 10 — Benchmark (honest numbers, public artifacts)

Status: DECIDED. Date: 2026-08-23.

## Concept

A reproducible measurement harness producing every number we publish. The paper's
spine, the OSS community moat, and the honest-numbers rule made mechanical: only
numbers E1–E6 produce (with public scenario files) may be cited anywhere.

## Structure

```
bench/
  env/       12–15 mock tools (finance, CRM, files, email, HR) — in-process, deterministic,
             canned responses, recorded side effects, ZERO network
  gold/      hand-written IR policies (independent of the system under test — never
             compiler output, never derived by running the engine) + English SOP sources
  scenarios.jsonl  ≥300 rows {scenario_id, attack_class, agent, tool, params, context,
             gold_decision} — generated once, seeded, CHECKED INTO THE REPO
  attacks/   deterministic scripted generators (boundary probing, unit swaps, tool aliases,
             delegation spoofing, stale-policy rig, bait-and-switch)
  runner     boots a REAL warden serve (fresh tmp DB), activates gold policies, replays
             scenarios via the HTTP decision API directly (isolates measured latency;
             interceptor correctness has its own e2e tests)
  metrics.json  fixed key order: block_recall, false_block_rate, escalation_accuracy,
             latency p50/p95/p99, per-class breakdown, chain_verified, seed, git_sha
```

## Targets (measured, never claimed)

| Metric | Target |
|---|---|
| Violation block rate (recall) | ≥ 98.5% |
| False block rate | ≤ 1.5% |
| Escalation accuracy | ≥ 95.0% |
| P95 decision latency (incl. sync ledger append) | < 50ms |

## Attack classes (each tests a specific design decision)

benign (≥40% — powers false-block measurement), injection_overfunding, stale_policy,
privilege_leak, params_omission (validates EVAL_ERROR doctrine),
escalation_bait_and_switch (validates params-hash binding).

## Baselines

Ungated pass-through; naive regex guardrail. Honest comparisons, not perfection claims.

## Experiments (paper figures)

- E1 Enforcement efficacy — Warden vs ungated vs regex baseline
- E2 Latency overhead — P95 added latency, sqlite vs postgres, CDF plot
- E3 Policy currency — stale-policy window after mid-run activation vs cache TTL
- E4 Compiler fidelity — each gold SOP compiled 5×; agreement with gold labels + inter-run stability
- E5 Tamper evidence — mutate every field of random entries + truncate/reorder; verify locates every corruption
- E6 Determinism — full-run replay: 100% byte-identical decisions across engines and repeats

## Reproducibility

Seeds pinned (--seed 1337); N=3 repetitions; CI asserts two runs produce byte-identical
metrics.json. The scenario files ARE the dataset — public, forkable, auditable.

## Tooling

All-Rust (runner drives the real binary over HTTP): `plotters` (Rust-native figures),
`criterion` (micro-benches), serde_json fixed key ordering, cargo/make bench targets.
Zero new services.
