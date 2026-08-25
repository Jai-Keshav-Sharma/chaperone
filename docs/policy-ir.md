# Policy IR Specification

Status: DECIDED. Date: 2026-08-23.

The Policy IR is the single contract between the compiler (Flow 1) and the engine
(Flow 2): a small, closed, strict JSON format for authorization rules. It is the source
of truth for everything a policy does — Cedar is generated from it, hashes pin it,
humans review it, and the engine's auxiliary services (needs_params, lint) derive from it.

## Design goals

- LLM-friendly: closed set, schema-constrained output, easy for a model to generate correctly.
- Human-friendly: every rule carries a description quoting its source SOP sentence (diff view).
- Deterministic: transpiles to Cedar byte-for-byte; hashed canonically (policy_hash).
- Strict: unknown keys/ops are validation errors. Extensibility via ir_version bumps only.
- Analyzable: static properties (params-needed, lint findings) derivable without evaluation.

## Document shape

```json
{
  "ir_version": "1",
  "policy_id": "pol_refunds",
  "version": 3,
  "description": "Refund SOP for support agents",
  "rules": [ Rule, ... ]
}
```

## Rule shape

```json
{
  "rule_id": "r-allow-small-refund",
  "description": "\"Support agents may refund up to $200.\"",   // quotes/paraphrases SOP source; feeds diff
  "effect": "allow",                                          // allow | block | escalate
  "target": {
    "tools": ["stripe.refunds.create", "payments.*"],         // exact names or trailing-* glob; ["*"] = all
    "agent_roles": ["support"],                               // omitted/empty = any
    "agent_ids": []                                           // omitted/empty = any
  },
  "condition": ConditionNode                                   // null = applies to every targeted call
}
```

- Escalate-by-ambiguity convention: when the compiler cannot resolve an SOP ambiguity,
  it emits an escalate rule whose description is flagged "AMBIGUOUS: ..." — a human must
  decide before activation. The compiler NEVER invents thresholds.

## Condition nodes (closed set, tagged by "op")

| op | shape | semantics |
|---|---|---|
| and / or / not | {"op":"and","args":[C,…]} | logical; not takes exactly one arg |
| eq ne lt lte gt gte | {"op":"lte","left":O,"right":O} | comparison; numeric ops accept int/float interchangeably; NO other implicit coercion |
| in / not_in | {"op":"in","left":O,"values":[...]} | set membership |
| matches | {"op":"matches","left":O,"pattern":"^…$"} | anchored, backref-free regex (like-compatible); precompiled at policy load; used for shell commands, paths, hosts |
| exists | {"op":"exists","param":"path.to.field"} | param present and non-null |
| time_between | {"op":"time_between","start":"09:00","end":"17:00","tz":"UTC","days":["mon",...]} | evaluated against context.request_time (computed at boundary, ledgered — never wall clock) |

Operands O: {"param":"amount"} (dot path into tool params) · {"context":"request_time" | "surface" |
"delegation_depth" | "derived.<attr>"} · {"value":200} | {"value":"main"} | {"value":[...]}

Derived attributes (budgets/velocity) are declared per deployment in chaperone.yaml
(ledger_sum / ledger_count) and referenced as {"context":"derived.agent_daily_total_amount"}.

## Decision semantics (order-independent)

```
determining = rules whose target matches AND condition evaluates true
any determining block    → BLOCK      (RULE_MATCH)
else any determining escalate → ESCALATE (RULE_MATCH)
else any determining allow    → ALLOW    (RULE_MATCH)
else                          → BLOCK    (DEFAULT_DENY)
```

- Missing param / context path, or type mismatch, aborts evaluation → BLOCK (EVAL_ERROR).
  Rules are NEVER silently skipped (skipping can fall through to allow = fail-open).
- Tool targeted by no active policy → deployment-level `ungoverned_default`:
  `block` (default; chaperone serve) → BLOCK (NO_POLICY); `allow` (local quickstart) →
  ALLOW (UNGOVERNED_ALLOW), loudly ledgered. This is a POLICY choice, not a failure
  fallback — fail-closed on Chaperone/infra failure is untouched and non-negotiable.
- determining_rule_ids lists ALL matched rules, sorted — trivially explainable verdicts.

## Static properties derived from IR

- policy_hash = sha256(canonical_json(ir)) — pins every decision to exact policy bytes.
- needs_params(tool): any rule targeting tool with a condition referencing param operands.
  Precomputed per tool at load; drives the Flow 6 fast path.
- Lint: ERROR_DUPLICATE_RULE_ID, ERROR_NO_RULES, ERROR_ALLOW_ESCALATE_OVERLAP,
  ERROR_CROSS_POLICY_CONFLICT (an allow and a block/escalate rule in DIFFERENT active
  policies targeting the same tool, jointly satisfiable — checked across the active
  policy SET, not per-policy; blocks activation); WARN_UNREACHABLE_ALLOW,
  WARN_TOOL_UNGOVERNED, WARN_BROAD_TARGET (surface in conflict report).
- Cedar transpile (deterministic, snapshot-tested): allow→permit, block→forbid,
  escalate→forbid with annotation; entity model: principal=Chaperone::Agent, action=Chaperone::Action::"call",
  resource=Chaperone::Tool::"<name>", context={params, request_time, derived}.
  Tool globs → `resource.name like "payments.*"`.

## Extensibility

- ir_version field: future operator sets ship as version bumps; old versions remain
  loadable (stable evaluation semantics per version).
- Custom condition ops (e.g., WASM plugins) = future ir_version extension, not a v1 loophole.
- Unknown fields/ops rejected everywhere. Closed by design; opened deliberately.
