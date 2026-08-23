# Repo Layout

Status: DECIDED. Date: 2026-08-23. Workspace: Cargo (Rust), one binary.

## Tree

```
warden/                              # Jai-Keshav-Sharma/warden (private until launch)
├── Cargo.toml                       # workspace root
├── Makefile                         # install | check | test | test-all | bench | serve | paper-figures
├── LICENSE / NOTICE                 # Apache-2.0 from day one
├── README.md                        # quickstart: warden init → 5-minute demo
├── AGENTS.md                        # compact context for every future session (docs index + invariants)
│
├── crates/
│   ├── warden-core/                 # the pure library — no I/O in models/ir/engine
│   │   └── src/
│   │       ├── models/              # decision, ir, ledger entry, escalation, reason codes (serde, strict)
│   │       ├── canonical.rs         # canonical_dumps + sha256_hex — the ONLY hashing path
│   │       ├── clock.rs             # Clock trait, SystemClock, FixedClock
│   │       ├── ir/                  # IR types, validation, lint (the 9 closed ops)
│   │       ├── engine/              # IR→Cedar transpile, cedar eval, reference evaluator,
│   │       │                        #   needs_params, derived-attribute computer
│   │       ├── ledger/              # chain (append/genesis/recovery), verify, merkle (RFC 6962),
│   │       │                        #   checkpoint (C2SP + Ed25519), anchor (Rekor/TSA), proof, export
│   │       ├── storage/             # schema.rs (all 8 tables), agents, policies, ledger_store, escalations
│   │       ├── cache/               # 3-tier policy cache + Redis pub/sub
│   │       ├── escalation/          # lifecycle service + sweeper
│   │       ├── compiler/            # OFFLINE: providers (anthropic | openai-compat | ollama | fixture),
│   │       │                        #   pipeline, prompts, schemars schema
│   │       ├── docs/                # document parsers (md/txt/pdf/docx/html + OCR tiers)
│   │       └── decision/            # DecisionService orchestration (Flow 2, fail-closed)
│   │
│   ├── warden-server/               # the `warden serve` binary — axum app factory + routes
│   │                                #   (decisions, policies, escalations, ledger, health, metrics, ws)
│   └── warden-cli/                  # the `warden` binary — clap: init | hook | gateway | shim |
│                                    #   policy | ledger | approve | deny | bench
│
├── policies/
│   ├── examples/                    # pol_refunds.json, starter-safety/ (checked-in IR)
│   └── tests/                       # <policy_id>.yaml test corpora ("CI for policies")
│
├── bench/                           # Flow 10
│   ├── env/                         # 12–15 mock tools, deterministic world
│   ├── gold/                        # policies/, sops/, scenarios.jsonl (seeded, checked in)
│   ├── attacks/                     # scripted generators + stale-policy rig
│   └── results/                     # gitignored
│
├── dashboard/                       # React + Vite + TS (dark terminal aesthetic, Flow 3 inbox)
├── paper/                           # experiments/ (run_all, plotters figures) + results/
├── docs/                            # the locked specs we've written (flows, data-model, policy-ir, goals…)
├── scripts/                         # demo.sh (the Flow 9 script), release scripts
├── .github/workflows/ci.yml         # lint + type + unit (sqlite) → integration → nightly bench;
│                                    #   OS matrix: windows-latest + ubuntu-latest (Windows is
│                                    #   first-class — it's the dev platform and the demo surface);
│                                    #   cargo-deny + cargo-audit in CI; release artifacts
│                                    #   cosign/Sigstore-signed + SBOM attached (review-2 SEC-4);
│                                    #   cargo-fuzz targets for hook stdin parser, gateway body
│                                    #   parsing, IR validator, canonical.rs (review-2 SEC-5)
└── .gitignore                       # target/, node_modules/, *.db, results/
```

## Design rules baked into the tree

1. Layering is a law, not a convention (enforced in CI):
   models → ir | engine | ledger | storage | cache | escalation | compiler | docs
   → decision → server | cli. Nothing imports upward; interceptors import only core + decision.
   Pure layers (models, ir, engine) do zero I/O — this makes differential testing,
   replay, and determinism experiments possible.
2. One canonical hashing path: canonical.rs is the only module allowed to serialize for
   hashing. Hashed or byte-compared → through canonical.rs. Golden vectors enforce it.
3. Benchmark and paper live in the repo: bench scenarios are checked in (the dataset IS
   the repo); make paper-figures runs the real binary and regenerates every figure.
   Paper numbers can never drift from the code.
