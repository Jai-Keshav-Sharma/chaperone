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
  scenarios.jsonl  ≥1000 rows {scenario_id, attack_class, agent, tool, params, context,
             gold_decision} — generated once, seeded, CHECKED INTO THE REPO
             (benign ≥400; review-4 C2)
  attacks/   deterministic scripted generators (boundary probing, unit swaps, tool aliases,
             delegation spoofing, stale-policy rig, bait-and-switch)
  runner     boots a REAL warden serve (fresh tmp DB), activates gold policies, replays
             scenarios via the HTTP decision API directly (isolates measured latency;
             interceptor correctness has its own e2e tests)
  metrics.json  fixed key order: block_recall, false_block_rate, escalation_accuracy,
             latency p50/p95/p99, per-class breakdown, chain_verified, seed, git_sha.
             Deterministic section: byte-identical assertion. Latency section: epsilon
             band + absolute bound. Wilson CIs published alongside point estimates.
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

## Label provenance (review ADOPT-5 — honest labels, not just honest numbers)

- Every gold_decision carries {labeler, source, date} in the scenario file.
- Versioned scenario-submission format (JSONL + docs) for external contributions.
- Inter-annotator agreement (Cohen's κ) on gold labels is measured and cited in the paper.
- Self-authored corpus alone = conformance test, not efficacy benchmark. External
  contributions are what make benchmark-as-standard compound.

## Reproducibility — split schema (review-4 C1)

Wall-clock latencies (p50/p95/p99) can NEVER be byte-identical across runs. The
assertion therefore splits:

- DETERMINISTIC section (verdicts, counts, hashes, replay results, chain_verified):
  asserted BYTE-IDENTICAL across runs (seeds pinned, N=3).
- LATENCY section: asserted within an epsilon band (e.g., p95 within ±20% of baseline)
  plus the absolute bound check against the <50ms target.

Both sections share the same metrics.json; the CI assertion applies the right
comparison to each section. Seeds pinned (--seed 1337); N=3 repetitions. The scenario
files ARE the dataset — public, forkable, auditable.

## Sample size (review-4 C2)

≥300 rows puts the headline targets at the sample's noise floor (false-block ≤1.5%
≈ 1.8 events on ~120 benign rows). Grown to **≥1,000 scenarios (benign ≥400)** —
synthetic scenarios are cheap, statistical power is not. Publish **Wilson confidence
intervals** alongside every point estimate, same discipline as the committed Cohen's κ.

## Tooling

All-Rust (runner drives the real binary over HTTP): `plotters` (Rust-native figures),
`criterion` (micro-benches), serde_json fixed key ordering, cargo/make bench targets.
Zero new services.
