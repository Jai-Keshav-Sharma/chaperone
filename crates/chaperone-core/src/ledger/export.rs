//! Evidence-pack export (docs/flows/04 export CLI, compliance-mapping):
//! `chaperone ledger export --format eu-ai-act|soc2` → a zipped bundle of
//! entries + checkpoints + proofs + policy versions + a manifest mapping the
//! regulation clauses to the artifacts. The pure core assembles the manifest
//! and items; the CLI zips them (Phase 10).

use serde_json::{Value as JsonValue, json};

use crate::ledger::checkpoint::Checkpoint;
use crate::models::ledger::LedgerEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// EU AI Act Art. 12 evidence (tamper-evident logging, 6-month retention)
    /// + Art. 14 human-oversight chain.
    EuAiAct,
    /// SOC 2 audit evidence pack.
    Soc2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportItem {
    /// Path inside the export zip, e.g. "ledger/entries.jsonl".
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportBundle {
    pub manifest: JsonValue,
    pub items: Vec<ExportItem>,
}

/// Assemble the export bundle (pure — zipping is the CLI's job).
/// `policy_versions_json` is the serialized policy_versions rows (Phase 6).
pub fn build_export(
    entries: &[LedgerEntry],
    checkpoints: &[Checkpoint],
    policy_versions_json: &JsonValue,
    format: ExportFormat,
) -> ExportBundle {
    let entries_jsonl = entries
        .iter()
        .map(|e| serde_json::to_string(e).expect("entry serializes"))
        .collect::<Vec<_>>()
        .join("\n");
    let checkpoints_jsonl = checkpoints
        .iter()
        .map(|c| {
            json!({
                "tree_size": c.tree_size,
                "root_hash": c.root_hash,
                "key_id": c.key_id,
                "signature": c.signature,
                "text": c.text,
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");

    let (clause_map, name) = match format {
        ExportFormat::EuAiAct => (
            json!({
                "Art.12 (automatic tamper-evident logging)": ["ledger/entries.jsonl", "ledger/checkpoints.jsonl"],
                "Art.14 (human oversight, >=2 chained entries per escalation)": ["ledger/entries.jsonl"],
                "Art.9 (continuous per-action risk management)": ["ledger/entries.jsonl"],
                "Art.11 (technical documentation)": ["policies/versions.json"],
            }),
            "eu-ai-act",
        ),
        ExportFormat::Soc2 => (
            json!({
                "CC6.1 (access provisioning & revocation)": ["ledger/entries.jsonl"],
                "CC6.7 (restricted access via approved authorizations)": ["ledger/entries.jsonl", "policies/versions.json"],
                "CC7.2 (monitoring)": ["ledger/checkpoints.jsonl"],
                "CC8.1 (change management)": ["policies/versions.json"],
            }),
            "soc2",
        ),
    };

    let manifest = json!({
        "format": name,
        "generated_from": "chaperone ledger export",
        "entries_count": entries.len(),
        "checkpoints_count": checkpoints.len(),
        "clauses": clause_map,
        "chain_verified_hint": "run: chaperone ledger verify",
    });

    let manifest_text = manifest.to_string();
    ExportBundle {
        manifest,
        items: vec![
            ExportItem {
                path: "ledger/entries.jsonl".into(),
                content: entries_jsonl,
            },
            ExportItem {
                path: "ledger/checkpoints.jsonl".into(),
                content: checkpoints_jsonl,
            },
            ExportItem {
                path: "policies/versions.json".into(),
                content: policy_versions_json.to_string(),
            },
            ExportItem {
                path: "manifest.json".into(),
                content: manifest_text,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry() -> LedgerEntry {
        LedgerEntry {
            entry_seq: 0,
            entry_ts: "2026-08-25T00:00:00Z".into(),
            previous_hash: "0".repeat(64),
            entry_hash: "1".repeat(64),
            entry_type: crate::models::ledger::EntryType::Genesis,
            request_id: "genesis".into(),
            agent_id: "chaperone".into(),
            tool: "chaperone".into(),
            params_hash: "0".repeat(64),
            tenant_id: None,
            decision: "GENESIS".into(),
            policy_id: "__none__".into(),
            policy_version: 0,
            policy_hash: "0".repeat(64),
            determining_rule_ids: vec![],
            reason_code: "GENESIS".into(),
            decision_trace: "[]".into(),
            evaluation_latency_ms: 0.0,
            escalation_id: None,
        }
    }

    #[test]
    fn export_bundle_assembles_manifest_and_items() {
        for format in [ExportFormat::EuAiAct, ExportFormat::Soc2] {
            let bundle = build_export(&[entry()], &[], &json!({"pol_x": [{"version": 1}]}), format);
            assert_eq!(bundle.items.len(), 4);
            let manifest: JsonValue = serde_json::from_str(
                &bundle
                    .items
                    .iter()
                    .find(|i| i.path == "manifest.json")
                    .expect("manifest")
                    .content,
            )
            .expect("manifest parses");
            assert_eq!(manifest["entries_count"], 1);
            assert!(!manifest["clauses"].as_object().expect("clauses").is_empty());
        }
        let bundle = build_export(&[entry()], &[], &json!({}), ExportFormat::EuAiAct);
        assert_eq!(bundle.manifest["format"], "eu-ai-act");
        let soc2 = build_export(&[entry()], &[], &json!({}), ExportFormat::Soc2);
        assert_eq!(soc2.manifest["format"], "soc2");
    }
}
