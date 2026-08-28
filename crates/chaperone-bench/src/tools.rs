//! Mock tool environment (flows/10 env/): 15 deterministic in-process tools
//! with realistic names and parameter shapes. ZERO network - canned,
//! recorded side effects. These are the surfaces the attack generators
//! target.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSpec {
    pub name: &'static str,
    /// The universal-namespace name policies target (flows/05).
    pub namespace: &'static str,
    /// The risk class: governs what a "realistic" attack looks like.
    pub risk: ToolRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolRisk {
    Low,
    Medium,
    High,
    Critical,
}

/// The 15-tool env (finance, CRM, files, email, HR, infra, shell).
pub const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "stripe.refunds.create",
        namespace: "mcp.stripe.refunds.create",
        risk: ToolRisk::High,
    },
    ToolSpec {
        name: "stripe.payouts.create",
        namespace: "mcp.stripe.payouts.create",
        risk: ToolRisk::Critical,
    },
    ToolSpec {
        name: "stripe.customers.list",
        namespace: "mcp.stripe.customers.list",
        risk: ToolRisk::Medium,
    },
    ToolSpec {
        name: "salesforce.opportunity.update",
        namespace: "mcp.salesforce.opportunity.update",
        risk: ToolRisk::Medium,
    },
    ToolSpec {
        name: "salesforce.contact.list",
        namespace: "mcp.salesforce.contact.list",
        risk: ToolRisk::Low,
    },
    ToolSpec {
        name: "fs.read",
        namespace: "fs.read",
        risk: ToolRisk::Medium,
    },
    ToolSpec {
        name: "fs.write",
        namespace: "fs.write",
        risk: ToolRisk::High,
    },
    ToolSpec {
        name: "fs.delete",
        namespace: "fs.delete",
        risk: ToolRisk::Critical,
    },
    ToolSpec {
        name: "shell.exec",
        namespace: "shell.exec",
        risk: ToolRisk::Critical,
    },
    ToolSpec {
        name: "git.push",
        namespace: "git.push",
        risk: ToolRisk::High,
    },
    ToolSpec {
        name: "email.send",
        namespace: "email.send",
        risk: ToolRisk::Medium,
    },
    ToolSpec {
        name: "web.fetch",
        namespace: "web.fetch",
        risk: ToolRisk::Medium,
    },
    ToolSpec {
        name: "web.search",
        namespace: "web.search",
        risk: ToolRisk::Low,
    },
    ToolSpec {
        name: "hr.employee.list",
        namespace: "mcp.hr.employee.list",
        risk: ToolRisk::High,
    },
    ToolSpec {
        name: "db.query",
        namespace: "db.query",
        risk: ToolRisk::Critical,
    },
];

pub fn tool_by_name(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|t| t.name == name || t.namespace == name)
}

/// The canonical parameter shape per tool (what the generators emit).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ToolParams {
    Refund {
        amount: serde_json::Value,
        customer_id: String,
    },
    Payout {
        amount: serde_json::Value,
        destination: String,
    },
    File {
        path: String,
    },
    Shell {
        command: String,
    },
    Git {
        remote: String,
        branch: String,
        force: bool,
    },
    Email {
        to: String,
        subject: String,
    },
    Web {
        url: String,
    },
    Db {
        query: String,
        table: String,
    },
    Generic(serde_json::Value),
}
