//! The compiler prompt: the schema-constrained instruction that turns an SOP
//! into Policy IR (flows/01). The prompt IS the contract with the LLM — it
//! must stay in sync with docs/policy-ir.md (the closed op set).

/// The system prompt for the compile call. Asks for STRICT IR JSON only.
pub fn compile_prompt(sop: &str) -> String {
    format!(
        "You convert standard operating procedures (SOPs) for AI agent tool use \
         into a strict JSON policy format. Output ONLY the JSON object — no \
         prose, no markdown fences.\n\
         \n\
         The JSON shape:\n\
         {{\n\
           \"ir_version\": \"1\",\n\
           \"policy_id\": \"<snake_case id>\",\n\
           \"version\": 1,\n\
           \"description\": \"<one line>\",\n\
           \"rules\": [\n\
             {{\n\
               \"rule_id\": \"<r-...>\",\n\
               \"description\": \"<quote the SOP sentence>\",\n\
               \"effect\": \"allow|block|escalate\",\n\
               \"target\": {{\"tools\": [\"<exact or trailing-*>\"], \"agent_roles\": [], \"agent_ids\": []}},\n\
               \"condition\": <null or a condition node>\n\
             }}\n\
           ]\n\
         }}\n\
         \n\
         Condition nodes (closed set, tagged by \"op\"):\n\
         - and/or/not: {{\"op\":\"and\",\"args\":[...]}}\n\
         - comparisons: {{\"op\":\"lte\",\"left\":{{\"param\":\"amount\"}},\"right\":{{\"value\":200}}}}\n\
         - set membership: {{\"op\":\"in\",\"left\":{{\"param\":\"x\"}},\"values\":[...]}}\n\
         - wildcard match: {{\"op\":\"matches\",\"left\":{{\"param\":\"command\"}},\"pattern\":\"*rm -rf*\"}}\n\
         - existence: {{\"op\":\"exists\",\"param\":\"path.to.field\"}}\n\
         - time window: {{\"op\":\"time_between\",\"start\":\"09:00\",\"end\":\"17:00\",\"tz\":\"UTC\",\"days\":[\"mon\"]}}\n\
         \n\
         Operands: {{\"param\":\"dot.path\"}} | {{\"context\":\"surface|delegation_depth|derived.<attr>\"}} | {{\"value\":...}}\n\
         \n\
         Rules:\n\
         - effect semantics: \"allow\" = proceed automatically; \"block\" = never proceed; \"escalate\" = require human approval before proceeding. ANY sentence that says \"requires approval\", \"human review\", \"manager sign-off\", or similar is an ESCALATE rule, NEVER a block.\n\
         - Escalate-by-ambiguity: when the SOP is ambiguous, emit an ESCALATE rule whose description is flagged \"AMBIGUOUS: ...\". Never invent thresholds.\n\
         - Tool names: use the EXACT tool name the SOP names (e.g. \"stripe.refunds.create\", \"fs.write\", \"shell.exec\"). If the SOP names no tool, use \"stripe.refunds.create\" for refunds, \"fs.write\" for file writes, \"shell.exec\" for shell commands, \"web.fetch\" for web requests. NEVER invent a placeholder like \"mcp.<server>.<tool>\".\n\
         - Match patterns are Cedar-like wildcards: * matches any sequence; no regex.\n\
         - decision order is block > escalate > allow; if the SOP conflicts, flag it with an escalate rule.\n\
         \n\
         Here is a COMPLETE, CORRECT example of the exact format you must emit. \
         Copy this structure exactly — every condition MUST use the \"op\"/\"left\"/\"right\" or \"op\"/\"args\" shape shown here:\n\
         {{\"ir_version\":\"1\",\"policy_id\":\"pol_refunds\",\"version\":1,\"description\":\"refund policy\",\"rules\":[\n\
           {{\"rule_id\":\"r-allow-small\",\"description\":\"refunds up to 200 allowed\",\"effect\":\"allow\",\"target\":{{\"tools\":[\"stripe.refunds.create\"],\"agent_roles\":[],\"agent_ids\":[]}},\"condition\":{{\"op\":\"lte\",\"left\":{{\"param\":\"amount\"}},\"right\":{{\"value\":200}}}}}},\n\
           {{\"rule_id\":\"r-escalate-mid\",\"description\":\"refunds 200-1000 escalate\",\"effect\":\"escalate\",\"target\":{{\"tools\":[\"stripe.refunds.create\"],\"agent_roles\":[],\"agent_ids\":[]}},\"condition\":{{\"op\":\"and\",\"args\":[{{\"op\":\"gt\",\"left\":{{\"param\":\"amount\"}},\"right\":{{\"value\":200}}}},{{\"op\":\"lte\",\"left\":{{\"param\":\"amount\"}},\"right\":{{\"value\":1000}}}}]}}}},\n\
           {{\"rule_id\":\"r-block-large\",\"description\":\"over 1000 blocked\",\"effect\":\"block\",\"target\":{{\"tools\":[\"stripe.refunds.create\"],\"agent_roles\":[],\"agent_ids\":[]}},\"condition\":{{\"op\":\"gt\",\"left\":{{\"param\":\"amount\"}},\"right\":{{\"value\":1000}}}}}},\n\
           {{\"rule_id\":\"r-block-missing-id\",\"description\":\"missing customer blocked\",\"effect\":\"block\",\"target\":{{\"tools\":[\"stripe.refunds.create\"],\"agent_roles\":[],\"agent_ids\":[]}},\"condition\":{{\"op\":\"not\",\"args\":[{{\"op\":\"exists\",\"param\":\"customer_id\"}}]}}}}\n\
         ]}}\n\
         \n\
         SOP:\n\
         ---\n\
         {sop}\n\
         ---\n\
         Output ONLY the IR JSON now."
    )
}

/// The re-prompt after a validation failure (wall 1: exactly one retry).
/// Includes the previous error so the model can fix the specific issue.
pub fn retry_prompt(sop: &str, error_hint: &str) -> String {
    format!(
        "Your previous IR failed validation:\n{error_hint}\n\
         Fix ONLY the reported issue and output the corrected IR JSON for the SOP below.\n\
         ---\n\
         {sop}\n\
         ---\n\
         Output the IR JSON now.",
        sop = sop
    )
}
