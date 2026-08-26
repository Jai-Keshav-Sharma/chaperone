-- 001_initial_schema.sql — Chaperone initial schema (docs/data-model.md).
-- One migration file, compatible with BOTH SQLite and Postgres (sqlx).
-- Ledger tables are APPEND-ONLY: no update/delete exists for them anywhere.
-- Committed migrations are immutable — a schema change = a NEW migration file.

CREATE TABLE agent_identities (
    agent_id            VARCHAR(64)  PRIMARY KEY,
    name                VARCHAR(128) NOT NULL,
    role                VARCHAR(64)  NOT NULL,
    spiffe_id           VARCHAR(256),              -- future identity binding, unused in logic
    tenant_id           VARCHAR(64),               -- nullable, unused in logic; multi-tenant fleet insurance
    max_delegation_depth INTEGER NOT NULL DEFAULT 1,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE agent_api_keys (
    key_hash    VARCHAR(64) PRIMARY KEY,           -- sha256 of bearer key; plaintext never stored
    agent_id    VARCHAR(64) REFERENCES agent_identities(agent_id),  -- NULL = admin key
    is_admin    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,                        -- key hygiene + rotation audits
    expires_at  TIMESTAMP,                         -- optional key expiry
    revoked_at  TIMESTAMP
);

CREATE TABLE policies (
    policy_id      VARCHAR(64) PRIMARY KEY,
    name           VARCHAR(128) NOT NULL,
    active_version INTEGER,                        -- denormalized convenience
    tenant_id      VARCHAR(64),                    -- nullable, unused in logic; fleet tenancy insurance
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

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

-- The hash chain (APPEND-ONLY: no update/delete ever).
-- entry_seq is BIGINT (not INTEGER): at the 300-1000/sec target the chain
-- outgrows a 32-bit seq in days (docs/data-model.md).
CREATE TABLE ledger_entries (
    entry_seq       BIGINT PRIMARY KEY,            -- writer-assigned, NOT autoincrement
    entry_ts        VARCHAR(32) NOT NULL,          -- RFC3339 UTC; part of preimage, stored exactly
    previous_hash   VARCHAR(64) NOT NULL,
    entry_hash      VARCHAR(64) NOT NULL UNIQUE,
    entry_type      VARCHAR(32) NOT NULL,          -- GENESIS|DECISION|ESCALATION_RESOLVED|CHECKPOINT
    request_id      VARCHAR(64) NOT NULL,
    agent_id        VARCHAR(64) NOT NULL,
    tool            VARCHAR(128) NOT NULL,
    params_hash     VARCHAR(64) NOT NULL,          -- sha256 of RAW params bytes as received; never null
    tenant_id       VARCHAR(64),                   -- nullable, unused in logic; sharding insurance
    decision        VARCHAR(32) NOT NULL,          -- ALLOW|BLOCK|ESCALATE|WOULD_*|APPROVED|DENIED|EXPIRED
    policy_id       VARCHAR(64) NOT NULL,          -- '__none__' for NO_POLICY
    policy_version  INTEGER NOT NULL DEFAULT 0,
    policy_hash     VARCHAR(64) NOT NULL,          -- '0'*64 when no policy
    determining_rule_ids TEXT NOT NULL,            -- JSON array, sorted
    reason_code     VARCHAR(48) NOT NULL,
    decision_trace  TEXT NOT NULL,                 -- JSON; NOT in preimage; REDACTED (Law 9)
    evaluation_latency_ms REAL NOT NULL,
    escalation_id   VARCHAR(64)
);
CREATE UNIQUE INDEX ux_ledger_request ON ledger_entries(request_id, entry_type);
CREATE INDEX ix_ledger_agent ON ledger_entries(agent_id, entry_seq);
CREATE INDEX ix_ledger_tool_ts ON ledger_entries(tool, entry_ts);

CREATE TABLE ledger_checkpoints (
    checkpoint_id   BIGINT PRIMARY KEY,
    tree_size       INTEGER NOT NULL,              -- entries covered (0..tree_size-1)
    root_hash       VARCHAR(64) NOT NULL,
    checkpoint_text TEXT NOT NULL,                 -- C2SP checkpoint body
    key_id          VARCHAR(64),                   -- signing key identifier (rotation)
    signature       TEXT,                          -- Ed25519 base64; NULL in unsigned dev mode
    anchored_rekor  TEXT,                          -- Rekor v2 receipt JSON, NULL if not anchored
    anchored_tsa    TEXT,                          -- RFC 3161 token, NULL if not anchored
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE escalations (
    escalation_id   VARCHAR(64) PRIMARY KEY,       -- 'esc_' + uuid4hex (generated at API boundary)
    request_id      VARCHAR(64) NOT NULL,
    agent_id        VARCHAR(64) NOT NULL REFERENCES agent_identities(agent_id),
    policy_id       VARCHAR(64) NOT NULL,
    policy_version  INTEGER NOT NULL,
    rule_ids        TEXT NOT NULL,                 -- JSON array of determining escalate rules
    tool            VARCHAR(128) NOT NULL,
    proposed_params TEXT,                          -- full params JSON for approver visibility; NOT NULL at
                                                   -- insert; NULLed (purged) after the retention window
    params_binding_hash VARCHAR(64) NOT NULL,      -- sha256(canonical_json(params)); RETRY BINDING only.
                                                   -- Distinct from ledger_entries.params_hash (raw bytes)
    status          VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending|approved|denied|expired|consumed
    resolver        VARCHAR(64),
    resolution_note TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP NOT NULL,            -- created_at + CHAPERONE_ESCALATION_TTL_SECONDS (900)
    resolved_at     TIMESTAMP,
    decision_entry_seq   BIGINT REFERENCES ledger_entries(entry_seq),
    resolution_entry_seq BIGINT REFERENCES ledger_entries(entry_seq),
    CHECK (status IN ('pending','approved','denied','expired','consumed'))
);
CREATE INDEX ix_escalations_status ON escalations(status, expires_at);

CREATE TABLE derived_counters (
    counter_key  VARCHAR(128) PRIMARY KEY,   -- hash of (declaration_id, agent_id, tool, window_start, param_path)
    agent_id     VARCHAR(64) NOT NULL,
    tool         VARCHAR(128) NOT NULL,
    window_ts    BIGINT NOT NULL,            -- window start epoch
    value        REAL NOT NULL,              -- running sum / count
    updated_seq  BIGINT NOT NULL             -- ledger seq of last contributing entry
);