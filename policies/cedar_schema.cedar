// Chaperone Cedar entity schema — the fixed entity model for all policies.
// Source of truth for the IR→Cedar transpiler (docs/policy-ir.md, Phase 4).
// Validated by cedar-policy-validator at compile time.

namespace Chaperone {
  entity Agent in [Role] = {
    agent_id: String,
    role: String,
    max_delegation_depth: Long,
  };

  entity Action = {
    action_id: String,
  };

  entity Tool = {
    name: String,
  };

  entity Role;

  // context: params (arbitrary JSON), request_time, derived
  // (context is passed as a JSON record at request time, not schema-bound)
}

// Actions used by the transpiler: every policy is evaluated as
// is_authorized(principal=Agent, action=Action::"call", resource=Tool::"<name>", context)