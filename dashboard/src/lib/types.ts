// Wire types mirroring the frozen contracts (docs/api-contracts.md).

export type Decision =
  | "ALLOW"
  | "BLOCK"
  | "ESCALATE"
  | "WOULD_ALLOW"
  | "WOULD_BLOCK"
  | "WOULD_ESCALATE";

export type ReasonCode = string;

export interface DecisionResponse {
  decision: Decision;
  reason_code: ReasonCode;
  determining_rule_ids: string[];
  policy_id: string;
  policy_version: number;
  policy_hash: string;
  entry_seq: number;
  entry_hash: string;
  escalation_id: string | null;
  escalation_expires_at: string | null;
  trace: { rule_id: string; matched: boolean; operands?: { path: string; kind: string }[] }[];
  derived_context: Record<string, number>;
  evaluation_latency_ms: number;
}

export interface EscalationRow {
  escalation_id: string;
  request_id: string;
  agent_id: string;
  policy_id: string;
  policy_version: number;
  rule_ids: string;
  tool: string;
  proposed_params: string | null;
  params_binding_hash: string;
  status: "pending" | "approved" | "denied" | "expired" | "consumed";
  resolver: string | null;
  resolution_note: string | null;
  created_at: string;
  expires_at: string;
  resolved_at: string | null;
  decision_entry_seq: number | null;
  resolution_entry_seq: number | null;
}

export interface LedgerEntry {
  entry_seq: number;
  entry_ts: string;
  previous_hash: string;
  entry_hash: string;
  entry_type: string;
  request_id: string;
  agent_id: string;
  tool: string;
  params_hash: string;
  decision: string;
  policy_id: string;
  policy_version: number;
  policy_hash: string;
  determining_rule_ids: string[];
  reason_code: string;
  evaluation_latency_ms: number;
  escalation_id: string | null;
}

export interface VerifyResult {
  status: "ok" | "broken";
  entries: number;
  broken_at: number | null;
  reason: string | null;
}

export interface CheckpointRow {
  checkpoint_id: number;
  tree_size: number;
  root_hash: string;
  checkpoint_text: string;
  key_id: string | null;
  signature: string | null;
  anchored_rekor: string | null;
  anchored_tsa: string | null;
  created_at: string;
}

export interface PolicyShell {
  policy_id: string;
  name: string;
  active_version: number | null;
}

export interface PolicyRule {
  rule_id: string;
  description: string;
  effect: "allow" | "block" | "escalate";
  target: { tools: string[]; agent_roles: string[]; agent_ids: string[] };
  condition: unknown | null;
}

export interface Policy {
  ir_version: string;
  policy_id: string;
  version: number;
  description: string;
  rules: PolicyRule[];
}

export interface CompileResponse {
  policy: Policy;
  cedar_text: string;
  conflict_report: string;
  model: string;
}
