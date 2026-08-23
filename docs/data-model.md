# Data Model (DDL)

Status: DECIDED. Date: 2026-08-23. Engine: SQLite (WAL) / Postgres via sqlx.
Same schema on both engines; JSON columns via JSONB on Postgres.

## Design goals

- Speed: indexes cover the three hot queries — active-policy fetch, ledger append
  (max seq + insert), derived-attribute queries (tool, entry_ts, agent).
- Reliability: ledger tables are append-only (no UPDATE/DELETE); single writer enforced
  by unique constraints + advisory lock; append = one transaction (BEGIN IMMEDIATE).
- Scalability: reads replica-safe; multi-writer evolution keeps this schema unchanged.
- Extensibility: entry_type enum open; provenance + report columns as JSON; spiffe_id slot.

## Tables

### 1. agent_identities — who may act

```sql
CREATE TABLE agent_identities (
    agent_id            VARCHAR(64)  PRIMARY KEY,
    name                VARCHAR(128) NOT NULL,
    role                VARCHAR(64)  NOT NULL,
    spiffe_id           VARCHAR(256),              -- future identity binding, unused in logic
    max_delegation_depth INTEGER NOT NULL DEFAULT 1,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### 2. agent_api_keys — service auth (hashed at rest)

```sql
CREATE TABLE agent_api_keys (
    key_hash    VARCHAR(64) PRIMARY KEY,           -- sha256 of bearer key; plaintext never stored
    agent_id    VARCHAR(64) REFERENCES agent_identities(agent_id),  -- NULL = admin key
    is_admin    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  TIMESTAMP
);
```

### 3. policies — policy shells

```sql
CREATE TABLE policies (
    policy_id      VARCHAR(64) PRIMARY KEY,
    name           VARCHAR(128) NOT NULL,
    active_version INTEGER,                        -- denormalized convenience
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### 4. policy_versions — immutable policy history

```sql
CREATE TABLE policy_versions (
    policy_id       VARCHAR(64) NOT NULL REFERENCES policies(policy_id),
    version         INTEGER NOT NULL,              -- monotonic per policy
    status          VARCHAR(16) NOT NULL,          -- draft|reviewed|active|superseded|rejected
    raw_sop_text    TEXT,                          -- NL source (null for hand-authored)
    ir_json         TEXT NOT NULL,                 -- frozen canonical Policy IR bytes
    cedar_text      TEXT NOT NULL,                 -- transpiled Cedar (regenerated + drift-checked at load)
    policy_hash     VARCHAR(64) NOT NULL,          -- sha256(canonical(ir_json))
    conflict_report TEXT,                          -- lint + analysis output (JSON)
    test_report     TEXT,                          -- corpus + replay output (JSON)
    compiler_model  VARCHAR(64),                   -- provenance (null = hand-authored)
    created_by      VARCHAR(64),
    approved_by     VARCHAR(64),                   -- must be non-null before status=active
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at    TIMESTAMP,
    PRIMARY KEY (policy_id, version),
    CHECK (status IN ('draft','reviewed','active','superseded','rejected'))
);
CREATE UNIQUE INDEX ux_policy_one_active ON policy_versions(policy_id) WHERE status = 'active';
```

### 5. ledger_entries — the hash chain (APPEND-ONLY, no UPDATE/DELETE ever)

```sql
CREATE TABLE ledger_entries (
    entry_seq       INTEGER PRIMARY KEY,           -- writer-assigned, NOT autoincrement
    entry_ts        VARCHAR(32) NOT NULL,          -- RFC3339 UTC; part of preimage, stored exactly
    previous_hash   VARCHAR(64) NOT NULL,
    entry_hash      VARCHAR(64) NOT NULL UNIQUE,
    entry_type      VARCHAR(32) NOT NULL,          -- GENESIS|DECISION|ESCALATION_RESOLVED|CHECKPOINT
    request_id      VARCHAR(64) NOT NULL,
    agent_id        VARCHAR(64) NOT NULL,
    tool            VARCHAR(128) NOT NULL,
    params_hash     VARCHAR(64) NOT NULL,            -- sha256 of raw params bytes as received; NEVER null (binding)
    tenant_id       VARCHAR(64),                     -- nullable, unused in logic; sharding insurance (PERF-2)
    decision        VARCHAR(16) NOT NULL,          -- ALLOW|BLOCK|ESCALATE|WOULD_*|APPROVED|DENIED|EXPIRED
    policy_id       VARCHAR(64) NOT NULL,          -- '__none__' for NO_POLICY
    policy_version  INTEGER NOT NULL DEFAULT 0,
    policy_hash     VARCHAR(64) NOT NULL,          -- '0'*64 when no policy
    determining_rule_ids TEXT NOT NULL,            -- JSON array, sorted
    reason_code     VARCHAR(48) NOT NULL,
    decision_trace  TEXT NOT NULL,                 -- JSON; NOT in preimage; REDACTED — rule ids,
                                                   -- match booleans, operand paths only; NEVER raw param values
    evaluation_latency_ms REAL NOT NULL,
    escalation_id   VARCHAR(64)
);
CREATE UNIQUE INDEX ux_ledger_request ON ledger_entries(request_id, entry_type);
CREATE INDEX ix_ledger_agent ON ledger_entries(agent_id, entry_seq);
CREATE INDEX ix_ledger_tool_ts ON ledger_entries(tool, entry_ts);   -- derived-attribute queries
```

### 6. ledger_checkpoints — signed Merkle checkpoints + anchors

```sql
CREATE TABLE ledger_checkpoints (
    checkpoint_id   INTEGER PRIMARY KEY,
    tree_size       INTEGER NOT NULL,              -- entries covered (0..tree_size-1)
    root_hash       VARCHAR(64) NOT NULL,
    checkpoint_text TEXT NOT NULL,                 -- C2SP checkpoint body
    signature       TEXT,                          -- Ed25519 base64; NULL in unsigned dev mode
    anchored_rekor  TEXT,                          -- Rekor v2 receipt JSON, NULL if not anchored
    anchored_tsa    TEXT,                          -- RFC 3161 token, NULL if not anchored
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### 7. escalations — HITL lifecycle

```sql
CREATE TABLE escalations (
    escalation_id   VARCHAR(64) PRIMARY KEY,       -- 'esc_' + uuid4hex (generated at API boundary)
    request_id      VARCHAR(64) NOT NULL,
    agent_id        VARCHAR(64) NOT NULL REFERENCES agent_identities(agent_id),
    policy_id       VARCHAR(64) NOT NULL,
    policy_version  INTEGER NOT NULL,
    rule_ids        TEXT NOT NULL,                 -- JSON array of determining escalate rules
    tool            VARCHAR(128) NOT NULL,
    proposed_params TEXT NOT NULL,                 -- full params JSON (approver visibility; ledger keeps only hash)
    params_hash     VARCHAR(64) NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending|approved|denied|expired|consumed
    resolver        VARCHAR(64),
    resolution_note TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP NOT NULL,            -- created_at + WARDEN_ESCALATION_TTL_SECONDS (900)
    resolved_at     TIMESTAMP,
    decision_entry_seq   INTEGER REFERENCES ledger_entries(entry_seq),
    resolution_entry_seq INTEGER REFERENCES ledger_entries(entry_seq),
    CHECK (status IN ('pending','approved','denied','expired','consumed'))
);
CREATE INDEX ix_escalations_status ON escalations(status, expires_at);
```

### 8. derived_counters — materialized derived attributes (review PERF-1)

```sql
CREATE TABLE derived_counters (
    counter_key  VARCHAR(128) PRIMARY KEY,   -- hash of (agent_id, tool, window_start, param_path)
    agent_id     VARCHAR(64) NOT NULL,
    tool         VARCHAR(128) NOT NULL,
    window_ts    INTEGER NOT NULL,           -- window start epoch
    value        REAL NOT NULL,              -- running sum / count
    updated_seq  INTEGER NOT NULL            -- ledger seq of last contributing entry
);
```

Updated INSIDE the ledger append transaction. Read-acceleration index only: rebuildable
from the chain at any time; the chain remains the single source of truth, so
determinism is untouched. Avoids O(window) SUM per decision as the ledger grows.

### Engine specifics (single storage path — review PERF-5)

- One implementation via `sqlx` for BOTH SQLite and Postgres (compile-time-checked
  queries for the static set; no rusqlite). One code path for the most
  correctness-critical writes.

- SQLite: WAL journal mode; append transaction = BEGIN IMMEDIATE; exclusive lock file =
  single-writer enforcement; synchronous FULL (durability over raw speed).
- Postgres: pg_advisory_lock for single writer; JSONB for report/trace columns;
  partial unique index for one-active-policy.
- Concurrency: concurrent resolution handled by `UPDATE ... WHERE status='pending'` row-lock (loser → 409).
- No UPDATE/DELETE statements exist anywhere for ledger tables. Retention = archive-and-anchor,
  designed BEFORE production: capacity metrics + alarms on /metrics; disk-full is the
  fleet-wide off switch — fail-closed is correct, so ops must see it coming (review PERF-3).

## Runtime config (not DB)

`warden.yaml`: derived_attributes declarations (ledger_sum / ledger_count with tool, decision,
window, same_agent filters) — consumed by the derived-context computer; webhook URL + secret;
policy pack registry settings.
