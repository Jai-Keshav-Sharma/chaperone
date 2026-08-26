use serde_json::{Map, Value as JsonValue, json};

/// A derived-attribute declaration (chaperone.yaml `derived_attributes`,
/// docs/data-model.md): budgets/velocity read from the materialized
/// derived_counters index. The chain remains the source of truth — counters
/// are a rebuildable read-acceleration index (docs/data-model.md PERF-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedDeclaration {
    pub id: String,
    pub kind: DerivedKind,
    /// Window in seconds (e.g. 86400 = daily budget).
    pub window_seconds: u64,
    /// Optional tool filter (None = any tool).
    pub tool: Option<String>,
    /// Param path the sum is taken over (e.g. "amount").
    pub param_path: String,
    /// Filter by agent (velocity-style per-agent budgets).
    pub same_agent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedKind {
    /// Sum of `param_path` values over contributing decisions.
    LedgerSum,
    /// Count of contributing decisions.
    LedgerCount,
}

/// One materialized counter value, keyed by declaration id (the storage layer
/// computes these inside the ledger append transaction, Phase 7).
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedCounterValue {
    pub declaration_id: String,
    pub value: f64,
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
}
