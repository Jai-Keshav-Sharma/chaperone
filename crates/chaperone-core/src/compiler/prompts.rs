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
         - Escalate-by-ambiguity: when the SOP is ambiguous, emit an ESCALATE rule whose description is flagged \"AMBIGUOUS: ...\". Never invent thresholds.\n\
         - Tool names use the universal namespace (shell.exec, fs.read, fs.write, web.fetch, web.search, mcp.<server>.<tool>).\n\
         - Match patterns are Cedar-like wildcards: * matches any sequence; no regex.\n\
         - decision order is block > escalate > allow; if the SOP conflicts, flag it with an escalate rule.\n\
         \n\
         SOP:\n\
         ---\n\
         {sop}\n\
         ---\n\
         Output the IR JSON now."
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
