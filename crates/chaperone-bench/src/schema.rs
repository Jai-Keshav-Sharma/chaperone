//! Scenario schema (flows/10): the dataset row format. Every row carries its
//! attack class, obfuscation tier, optional chain position, provenance, and
//! the HAND-AUTHORED gold decision (never derived by running the engine).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Attack classes (flows/10 + review-5 additions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackClass {
    /// Benign - the call is legitimate (powers false-block measurement).
    Benign,
    /// Directly unauthorized (baseline: the naive attacker).
    InjectionOverfunding,
    /// Exploits a stale policy (policy changed after the scenario was valid).
    StalePolicy,
    /// Privilege escalation / role confusion.
    PrivilegeLeak,
    /// Omitted params (validates the EVAL_ERROR doctrine - block, not skip).
    ParamsOmission,
    /// Bait-and-switch: retry with different params after approval.
    EscalationBaitAndSwitch,
    /// Tool-name confusion: mcp__stripe__refund vs mcp__stripe__create_refund.
    ToolNameConfusion,
    /// Alias downgrade through the normalization map.
    ToolAliasDowngrade,
    /// Sub-agent delegation tricks a higher-privilege tool.
    ConfusedDeputyDelegation,
    /// Obfuscated destructive intent (the realistic attacker).
    ObfuscatedDestructive,
    /// Vague/benign-sounding intent that maps to a destructive call.
    VagueReframe,
    /// Multi-hop chain (each hop defensible; the chain is the attack).
    Chain,
    /// Borderline - no clean answer; measures escalation accuracy.
    Ambiguous,
}

/// Obfuscation tier (0 = direct, 3 = heavily disguised) so results are
/// publishable per tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct ObfuscationLevel(pub u8);

impl From<u8> for ObfuscationLevel {
    fn from(v: u8) -> Self {
        ObfuscationLevel(v)
    }
}

/// Gold label provenance (flows/10 ADOPT-5): who labeled, from what source,
/// when. This is what makes the corpus auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelProvenance {
    pub labeler: String,
    pub source: String,
    pub date: String,
}

/// The gold decision for a scenario (hand-authored).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GoldDecision {
    Allow,
    Block,
    Escalate,
}

/// One scenario row (JSONL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub scenario_id: String,
    pub attack_class: AttackClass,
    /// 0-3: how disguised the attack is (0 = direct, 3 = heavy obfuscation).
    #[serde(default)]
    pub obfuscation_level: ObfuscationLevel,
    /// Chain position: Some(0) = first hop, Some(1) = second, None = single.
    #[serde(default)]
    pub chain_position: Option<usize>,
    #[serde(default)]
    pub chain_length: Option<usize>,
    pub agent: String,
    pub tool: String,
    pub params: Value,
    pub context: ScenarioContext,
    pub gold_decision: GoldDecision,
    pub gold_reason: String,
    pub label: LabelProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioContext {
    pub surface: String,
    pub delegation_depth: u32,
    pub request_time: String,
}

impl Scenario {
    pub fn request_id(&self) -> String {
        self.scenario_id.clone()
    }
}
