use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue, json};

/// A derived-attribute declaration (chaperone.yaml `derived_attributes`,
/// docs/data-model.md): budgets/velocity read from the materialized
/// derived_counters index. The chain remains the source of truth — counters
/// are a rebuildable read-acceleration index (docs/data-model.md PERF-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedDeclaration {
    pub id: String,
    pub kind: DerivedKind,
    /// Window in seconds (e.g. 86400 = daily budget).
    pub window_seconds: u64,
    /// Optional tool filter (None = any tool).
    #[serde(default)]
    pub tool: Option<String>,
    /// Param path the sum is taken over (e.g. "amount").
    pub param_path: String,
    /// Filter by agent (velocity-style per-agent budgets). `true` = the counter
    /// is keyed per agent; `false` = all agents share one bucket.
    #[serde(default)]
    pub same_agent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedKind {
    /// Sum of `param_path` values over contributing decisions.
    LedgerSum,
    /// Count of contributing decisions.
    LedgerCount,
}

/// One materialized counter value, keyed by declaration id (the storage layer
/// computes these inside the ledger append transaction).
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedCounterValue {
    pub declaration_id: String,
    pub value: f64,
}

/// A pending counter increment computed at the boundary, applied atomically
/// inside the ledger append transaction (docs/data-model.md PERF-1).
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedCounterUpdate {
    /// The pre-computed counter_key (see `counter_key_for`) — authoritative.
    pub counter_key: String,
    /// The normalized agent bucket (real agent_id when `same_agent`, else "").
    pub agent_id: String,
    /// The normalized tool bucket (real tool when `tool` is set, else "").
    pub tool: String,
    /// The window-start epoch.
    pub window_ts: i64,
    /// The increment to apply (sum value, or 1.0 for a count).
    pub increment: f64,
}

/// The normalized agent bucket for a declaration: the real agent when
/// `same_agent`, else the shared `""` bucket (all agents aggregate). This is
/// the single source of the convention — the write path (`counter_updates`)
/// and the read path (the counter source) MUST both use it, or a per-agent and
/// a global declaration would read/write different keys.
pub fn counter_agent_key(decl: &DerivedDeclaration, agent_id: &str) -> String {
    if decl.same_agent {
        agent_id.to_string()
    } else {
        String::new()
    }
}

/// The normalized tool bucket for a declaration: the real tool when `tool` is
/// set, else the shared `""` bucket (all tools aggregate). Same single-source
/// rule as `counter_agent_key`.
pub fn counter_tool_key(decl: &DerivedDeclaration, tool: &str) -> String {
    if decl.tool.is_some() {
        tool.to_string()
    } else {
        String::new()
    }
}

/// The deterministic counter_key for one declaration + one decision, using the
/// SAME normalized agent/tool buckets as `counter_updates`. declaration_id is
/// REQUIRED in the key — two declared attributes with different filters would
/// otherwise collide (review-4 D).
pub fn counter_key_for(
    decl: &DerivedDeclaration,
    agent_id: &str,
    tool: &str,
    request_time: &str,
) -> String {
    derived_counter_key(
        &decl.id,
        &counter_agent_key(decl, agent_id),
        &counter_tool_key(decl, tool),
        window_start(request_time, decl.window_seconds),
        &decl.param_path,
    )
}

/// The deterministic counter_key (docs/data-model.md derived_counters): a
/// SHA-256 over the canonical JSON of (declaration_id, agent_id, tool,
/// window_start, param_path). Determinism: the same request maps to the same
/// counter key forever (Law 6).
pub fn derived_counter_key(
    declaration_id: &str,
    agent_id: &str,
    tool: &str,
    window_start_epoch: i64,
    param_path: &str,
) -> String {
    let preimage = serde_json::json!({
        "declaration_id": declaration_id,
        "agent_id": agent_id,
        "tool": tool,
        "window_start": window_start_epoch,
        "param_path": param_path,
    });
    crate::canonical::sha256_hex(&crate::canonical::canonical_dumps(&preimage))
}

/// The window-start epoch for (request_time, window_seconds): the largest
/// multiple of `window_seconds` at or below the request's epoch. Boundary
/// time only (Law 6: never wall clock). A non-positive window falls back to
/// the raw epoch (a single fixed bucket); an unparseable time → 0.
pub fn window_start(request_time: &str, window_seconds: u64) -> i64 {
    let epoch = chrono::DateTime::parse_from_rfc3339(request_time)
        .map(|d| d.timestamp())
        .unwrap_or(0);
    let ws = window_seconds as i64;
    if ws <= 0 {
        return epoch;
    }
    epoch.div_euclid(ws) * ws
}

/// Compute the counter updates a single allowed decision contributes. The
/// caller (decision service) invokes this ONLY for an ALLOW verdict in enforce
/// mode — shadow mode and non-allowed verdicts contribute nothing
/// (flows/08: no side effects beyond the ledger).
///
/// A declaration contributes when its tool filter matches the decision's tool
/// (None = any tool). `LedgerSum` contributes the numeric value at
/// `param_path` (missing/non-numeric → 0.0, which is skipped); `LedgerCount`
/// contributes 1.0.
pub fn counter_updates(
    declarations: &[DerivedDeclaration],
    agent_id: &str,
    tool: &str,
    request_time: &str,
    params: &JsonValue,
) -> Vec<DerivedCounterUpdate> {
    let mut updates = Vec::new();
    for decl in declarations {
        let tool_matches = decl.tool.as_deref().map(|t| t == tool).unwrap_or(true);
        if !tool_matches {
            continue;
        }
        let increment = match decl.kind {
            DerivedKind::LedgerSum => number_at(params, &decl.param_path),
            DerivedKind::LedgerCount => 1.0,
        };
        if increment == 0.0 {
            continue;
        }
        updates.push(DerivedCounterUpdate {
            counter_key: counter_key_for(decl, agent_id, tool, request_time),
            agent_id: counter_agent_key(decl, agent_id),
            tool: counter_tool_key(decl, tool),
            window_ts: window_start(request_time, decl.window_seconds),
            increment,
        });
    }
    updates
}

/// Resolve `path` in raw params and read it as a JSON number (0.0 otherwise).
/// Missing or non-numeric params contribute nothing to a sum budget — a budget
/// can only measure what the params actually carry.
fn number_at(params: &JsonValue, path: &str) -> f64 {
    match crate::engine::resolve_path(params, path) {
        Ok(Some(JsonValue::Number(n))) => n.as_f64().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Assemble the derived context object handed to the engine, e.g.
/// {"agent_daily_total_amount": 350.0}. Declarations without a counter row
/// (no contributing decisions yet) resolve to 0.0 — a missing derived
/// attribute would otherwise abort evaluation with EVAL_ERROR on the very
/// first call after activation.
pub fn compute_derived(
    declarations: &[DerivedDeclaration],
    values: &[DerivedCounterValue],
) -> JsonValue {
    let mut out: Map<String, JsonValue> = Map::new();
    for decl in declarations {
        let v = values
            .iter()
            .find(|c| c.declaration_id == decl.id)
            .map(|c| c.value)
            .unwrap_or(0.0);
        out.insert(decl.id.clone(), json!(v));
    }
    JsonValue::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compute_derived_defaults_missing_to_zero() {
        let decls = vec![
            DerivedDeclaration {
                id: "agent_daily_total_amount".into(),
                kind: DerivedKind::LedgerSum,
                window_seconds: 86400,
                tool: Some("stripe.refunds.create".into()),
                param_path: "amount".into(),
                same_agent: true,
            },
            DerivedDeclaration {
                id: "hourly_count".into(),
                kind: DerivedKind::LedgerCount,
                window_seconds: 3600,
                tool: None,
                param_path: "".into(),
                same_agent: false,
            },
        ];
        let values = vec![DerivedCounterValue {
            declaration_id: "agent_daily_total_amount".into(),
            value: 350.0,
        }];
        assert_eq!(
            compute_derived(&decls, &values),
            json!({"agent_daily_total_amount": 350.0, "hourly_count": 0.0})
        );
    }

    #[test]
    fn window_start_buckets_by_window() {
        // 2026-08-25T14:00:00Z = 1787666400; daily floor = 1787616000 (00:00Z).
        assert_eq!(window_start("2026-08-25T14:00:00Z", 86400), 1787616000);
        // Same day, later time → same daily bucket.
        assert_eq!(window_start("2026-08-25T23:59:59Z", 86400), 1787616000);
        // Zero window → raw epoch (single bucket).
        assert_eq!(window_start("2026-08-25T14:00:00Z", 0), 1787666400);
        // Unparseable → 0.
        assert_eq!(window_start("not-a-time", 86400), 0);
    }

    #[test]
    fn counter_updates_sum_count_and_tool_filter() {
        let decls = vec![
            DerivedDeclaration {
                id: "daily_amount".into(),
                kind: DerivedKind::LedgerSum,
                window_seconds: 86400,
                tool: Some("stripe.refunds.create".into()),
                param_path: "amount".into(),
                same_agent: true,
            },
            DerivedDeclaration {
                id: "any_tool_count".into(),
                kind: DerivedKind::LedgerCount,
                window_seconds: 3600,
                tool: None,
                param_path: "".into(),
                same_agent: false,
            },
            DerivedDeclaration {
                id: "other_tool".into(),
                kind: DerivedKind::LedgerCount,
                window_seconds: 3600,
                tool: Some("email.send".into()),
                param_path: "".into(),
                same_agent: true,
            },
        ];
        let updates = counter_updates(
            &decls,
            "agent_1",
            "stripe.refunds.create",
            "2026-08-25T14:00:00Z",
            &json!({"amount": 150}),
        );
        // daily_amount (sum of amount=150) + any_tool_count (1) — other_tool filtered out.
        assert_eq!(updates.len(), 2);
        let sum = updates
            .iter()
            .find(|u| u.increment == 150.0)
            .expect("sum update");
        assert_eq!(sum.agent_id, "agent_1", "same_agent buckets per agent");
        assert_eq!(
            sum.tool, "stripe.refunds.create",
            "tool filter uses real tool"
        );
        let count = updates
            .iter()
            .find(|u| u.increment == 1.0)
            .expect("count update");
        assert_eq!(count.increment, 1.0);
        assert_eq!(
            count.agent_id, "",
            "same_agent:false aggregates across agents"
        );
        assert_eq!(count.tool, "", "tool:None aggregates across tools");
    }

    #[test]
    fn counter_key_for_matches_write_and_read() {
        let decl = DerivedDeclaration {
            id: "daily_amount".into(),
            kind: DerivedKind::LedgerSum,
            window_seconds: 86400,
            tool: Some("stripe.refunds.create".into()),
            param_path: "amount".into(),
            same_agent: true,
        };
        let expected = derived_counter_key(
            "daily_amount",
            "agent_1",
            "stripe.refunds.create",
            window_start("2026-08-25T14:00:00Z", 86400),
            "amount",
        );
        assert_eq!(
            counter_key_for(
                &decl,
                "agent_1",
                "stripe.refunds.create",
                "2026-08-25T14:00:00Z"
            ),
            expected
        );
    }

    #[test]
    fn counter_updates_missing_param_skips_sum() {
        let decls = vec![DerivedDeclaration {
            id: "daily_amount".into(),
            kind: DerivedKind::LedgerSum,
            window_seconds: 86400,
            tool: None,
            param_path: "amount".into(),
            same_agent: true,
        }];
        // No `amount` param → LedgerSum contributes 0.0 and is skipped.
        let updates = counter_updates(&decls, "a", "t", "2026-08-25T14:00:00Z", &json!({}));
        assert!(updates.is_empty());
        // Non-numeric param → skipped too.
        let updates = counter_updates(
            &decls,
            "a",
            "t",
            "2026-08-25T14:00:00Z",
            &json!({"amount": "x"}),
        );
        assert!(updates.is_empty());
    }

    #[test]
    fn declaration_deserializes_from_serde_shape() {
        // The wire/config shape uses snake_case kind + optional filters.
        let json = json!({
            "id": "daily_amount",
            "kind": "ledger_sum",
            "window_seconds": 86400,
            "tool": "stripe.refunds.create",
            "param_path": "amount",
            "same_agent": true
        });
        let decl: DerivedDeclaration = serde_json::from_value(json).expect("parse");
        assert_eq!(decl.id, "daily_amount");
        assert_eq!(decl.kind, DerivedKind::LedgerSum);
        assert_eq!(decl.window_seconds, 86400);
        assert_eq!(decl.tool.as_deref(), Some("stripe.refunds.create"));
        assert_eq!(decl.param_path, "amount");
        assert!(decl.same_agent);

        // Optional filters default when absent.
        let minimal = json!({
            "id": "count",
            "kind": "ledger_count",
            "window_seconds": 3600,
            "param_path": ""
        });
        let decl: DerivedDeclaration = serde_json::from_value(minimal).expect("parse");
        assert_eq!(decl.tool, None);
        assert!(!decl.same_agent);
    }
}
