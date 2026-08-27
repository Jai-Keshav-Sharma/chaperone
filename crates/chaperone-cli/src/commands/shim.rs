//! `chaperone shim -- <child command>` — the MCP stdio shim (flows/07):
//! spawns the real server as a child, passes initialize/tools/list through,
//! intercepts tools/call for the decision path, streams results back.
//!
//! Windows (review-2 ADOPT-7): npx is npx.cmd (cmd-shim handling required);
//! no SIGTERM — clean teardown needs job-object kill. The process-wrapper
//! mechanics land with the MCP SDK stdio transport; the escalation contract
//! (poll-based, never block the pipe — flows/07) is defined here.

use clap::Args;

#[derive(Args, Debug)]
pub struct ShimArgs {
    /// The child command to wrap (e.g. `npx @stripe/mcp-server`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub child: Vec<String>,
}

pub async fn run_shim(args: ShimArgs) -> i32 {
    if args.child.is_empty() {
        eprintln!("chaperone: shim requires a child command");
        return 1;
    }
    eprintln!(
        "chaperone: shim lands with the MCP SDK stdio transport; child={:?}",
        args.child
    );
    1
}
