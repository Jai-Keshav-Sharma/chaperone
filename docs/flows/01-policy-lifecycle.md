# Flow 1 — Policy Lifecycle (SOP → enforced rules)

Status: DECIDED. Date: 2026-08-23.

## The flow

```
English SOP (.md/.txt/.pdf/.docx/.html, images via OCR)
  → DocumentParser (ingestion)
  → LLM compile (offline, temperature 0, schema-constrained)
  → IR validation (serde strict, 1 retry, then reject)
  → IR → Cedar transpile + drift check (cedar-policy parse)
  → Lint (ERROR/WARN) + Cedar schema validation + SMT analysis (optional)
  → HUMAN REVIEW: diff view (SOP sentence ⇄ rule), approve / edit / reject
  → Test corpus ("CI for policies") + ledger replay (--replay 30d)
  → ACTIVATE (transaction): supersede old → pin policy_hash → publish invalidation
```

## Guiding principle — user choice, never enforcement

We provide the *facility* to use local or cloud services at every step. The user
decides, per deployment and per policy:

- Local-first ingestion and local models by default (privacy).
- Cloud document AI (Mistral OCR, Azure, Textract) and cloud LLMs
  (OpenAI, Anthropic, Gemini, Mistral, Groq, DeepSeek...) as user-configured options.
- Never hard-code a provider. Everything sits behind traits.

## Ingestion (DocumentParser trait)

| Format | Tool |
|---|---|
| .md / .txt | std::fs (no deps) |
| .pdf (digital) | `pdf-extract` primary, `pdfium-render` fallback flag |
| .pdf (scanned) / images | OCR tiers below |
| .docx | `docx-rust` |
| .html | `scraper` |

### OCR tiers (priority order, user-configurable)

| Tier | Tool | Notes |
|---|---|---|
| 1. Text layer | pdf-extract native text | Always tried first; free, local |
| 2. Local OCR | `leptess` (Tesseract) | 100+ languages incl. Indic; offline. Verify maintenance status at build time; fallback `rusty-tesseract` or shelling to the Tesseract CLI (review: leptess looks stale) |
| 3. Cloud document AI | Mistral OCR / Azure Document Intelligence / AWS Textract | User brings own API key; best for tables/forms/handwriting; optional, never default |

## LLM compiler (CompilerClient trait)

| Adapter | Covers |
|---|---|
| `AnthropicClient` | Anthropic native (structured outputs) |
| `OpenAICompatClient` | OpenAI, Gemini, Mistral, Groq, Together, Fireworks, DeepSeek, vLLM, LM Studio, llama.cpp server (OpenAI-compatible API) |
| `OllamaClient` | Ollama native (local models) |
| `FixtureClient` | Recorded responses; zero network in CI/tests |

- Capability flag per adapter: `supports_json_schema` → strict schema path, else prompt + strict parse + retry.
- Local models = privacy story for regulated buyers ("compile your SOPs on your own machine").
- Cloud models = quality option. User chooses per deployment.

## Validation chain

1. serde strict parse (deny unknown fields) — wall 1
2. cedar-policy parse of transpiled Cedar — wall 2
3. cedar-policy-validator (schema validation) — wall 3
4. Lint (ERROR/WARN) — own module, no deps
5. Cedar Analysis (SMT, official CLI as optional subprocess) — mathematical proof, attaches to conflict report

## Review & activation tooling

| Step | Tool |
|---|---|
| Terminal diff | `similar` + `console` (side-by-side, colored) |
| Dashboard diff | React `diff2html` / Monaco |
| Interactive prompts | `inquire` (approve / edit in $EDITOR / reject) |
| Test corpus | YAML (`policies/tests/<id>.yaml`) via `serde_yaml` |
| Replay | internal ledger store read |
| Provenance | `policy_versions` row: raw_sop_text, compiler_model, created_by, approved_by, conflict_report, test_report, policy_hash, activated_at |

## Invariants

- LLM can fail loudly, never silently (validation chain + human gate).
- Activated policies are frozen bytes pinned by policy_hash; edits create new versions.
- Compiler never invents thresholds: ambiguity → escalate rule flagged → human decides.
- Two authoring paths: LLM-compiled (SOPs) and hand-written IR (warden policy edit).
