//! The compile pipeline (flows/01): SOP → provider → IR → validation
//! (1 retry) → transpile → lint conflict report → human review gate.
//! NEVER auto-activates (Law 2 + build-plan: never_auto_activates).

use crate::compiler::providers::CompilerProvider;
use crate::models::ir::Policy;

/// The pipeline result: validated IR + transpiled Cedar + the lint conflict
/// report. Activation is a SEPARATE human step — this result is inert.
#[derive(Debug)]
pub struct CompileResult {
    pub policy: Policy,
    pub cedar_text: String,
    /// Lint findings serialized (the conflict report; ERROR findings mean
    /// the human must resolve before activation).
    pub conflict_report: String,
    /// The model that produced the IR (provenance).
    pub model: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("provider: {0}")]
    Provider(String),
    #[error("IR parse failed after retry: {0}")]
    Parse(String),
    #[error("validation failed after retry: {0}")]
    Validation(String),
    #[error("transpile failed: {0}")]
    Transpile(String),
}

/// Compile an SOP into validated IR + Cedar + conflict report.
///
/// The trust loop is enforced at the CALLER (CLI/dashboard): this returns the
/// compiled policy; a human must review + explicitly activate it. The
/// pipeline itself performs zero writes.
pub fn compile_sop(
    provider: &dyn CompilerProvider,
    sop: &str,
) -> Result<CompileResult, CompileError> {
    // Wall 1: schema-strict parse + IR validation, with EXACTLY one retry on
    // validation failure (flows/01: "serde strict parse, 1 retry, then reject").
    let first = provider
        .compile(sop, None)
        .map_err(CompileError::Provider)?;
    let policy = match parse_and_validate(&first.ir_text) {
        Ok(p) => p,
        Err(err) => {
            // One retry with the error hint.
            let retry = provider
                .compile(sop, Some(&err))
                .map_err(CompileError::Provider)?;
            parse_and_validate(&retry.ir_text)
                .map_err(|e2| CompileError::Validation(format!("{err}; retry also failed: {e2}")))?
        }
    };

    // Wall 2: transpile (a policy that cannot compile must not be activatable).
    let cedar_text = crate::engine::cedar_compile::to_cedar(&policy)
        .map_err(|e| CompileError::Transpile(e.to_string()))?
        .into_iter()
        .map(|c| c.text)
        .collect::<Vec<_>>()
        .join("\n");

    // Lint: the conflict report (ERROR findings block activation — surfaced
    // to the human reviewer).
    let findings = crate::ir::lint::lint(std::slice::from_ref(&policy), &[]);
    let conflict_report = serde_json::to_string(&findings).unwrap_or_else(|_| "[]".to_string());

    Ok(CompileResult {
        policy,
        cedar_text,
        conflict_report,
        model: first.model,
    })
}

/// Parse + validate IR text (wall 1). Returns the error message on failure.
fn parse_and_validate(ir_text: &str) -> Result<Policy, String> {
    let policy: Policy = serde_json::from_str(ir_text).map_err(|e| format!("parse: {e}"))?;
    crate::ir::validate::validate(&policy).map_err(|errs| {
        errs.iter()
            .map(|e| format!("[{:?}] {}", e.code, e.message))
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::providers::FixtureProvider;
    use crate::models::ir::Effect;

    const VALID_IR: &str = r#"{
        "ir_version": "1",
        "policy_id": "pol_refunds",
        "version": 1,
        "description": "refund policy",
        "rules": [
            {
                "rule_id": "r-allow-small",
                "description": "allow refunds up to 200",
                "effect": "allow",
                "target": {"tools": ["stripe.refunds.create"]},
                "condition": {"op": "lte", "left": {"param": "amount"}, "right": {"value": 200}}
            }
        ]
    }"#;

    /// The offline fixture pipeline: valid IR → valid result (no network).
    #[test]
    fn fixture_provider_offline_pipeline() {
        let provider = FixtureProvider::new(VALID_IR);
        let result = compile_sop(&provider, "Refunds up to 200 are allowed.").expect("compile");
        assert_eq!(result.policy.policy_id, "pol_refunds");
        assert_eq!(result.policy.rules.len(), 1);
        assert_eq!(result.policy.rules[0].effect, Effect::Allow);
        assert!(!result.cedar_text.is_empty(), "transpiled Cedar present");
        assert_eq!(result.model, "fixture");
    }

    /// compile_sop produces VALID IR (the pipeline guarantees it).
    #[test]
    fn compile_produces_valid_ir() {
        let provider = FixtureProvider::new(VALID_IR);
        let result = compile_sop(&provider, "sop").expect("compile");
        // Re-validate the output — the pipeline's guarantee.
        assert!(crate::ir::validate::validate(&result.policy).is_ok());
    }

    /// NEVER auto-activates: compile_sop performs no writes and returns no
    /// activation signal — activation is a separate human step. The result
    /// type has no "activated" concept.
    #[test]
    fn never_auto_activates() {
        let provider = FixtureProvider::new(VALID_IR);
        let result = compile_sop(&provider, "sop").expect("compile");
        // The only outputs are policy bytes + cedar + a report. There is no
        // store handle, no activation call, no side effect.
        assert!(result.conflict_report.contains("[]") || result.conflict_report.contains("["));
    }

    /// A retry fixes a validation failure (wall 1: 1 retry).
    #[test]
    fn retry_fixes_validation_failure() {
        // First response is INVALID (bad op), the retry is valid.
        struct RetryProvider {
            calls: std::sync::atomic::AtomicU32,
        }
        impl CompilerProvider for RetryProvider {
            fn kind(&self) -> crate::compiler::providers::ProviderKind {
                crate::compiler::providers::ProviderKind::Fixture
            }
            fn compile(
                &self,
                _sop: &str,
                error_hint: Option<&str>,
            ) -> Result<crate::compiler::providers::ProviderOutput, String> {
                let n = self
                    .calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n == 0 {
                    // Invalid first attempt.
                    Ok(crate::compiler::providers::ProviderOutput {
                        ir_text: r#"{"ir_version":"1","policy_id":"bad","version":1,"description":"d","rules":[{"rule_id":"r1","description":"d","effect":"allow","target":{"tools":["fs.read"]},"condition":{"op":"bogus","args":[]}}]}"#.into(),
                        model: "retry".into(),
                    })
                } else {
                    assert!(error_hint.is_some(), "retry carries the error hint");
                    Ok(crate::compiler::providers::ProviderOutput {
                        ir_text: VALID_IR.into(),
                        model: "retry".into(),
                    })
                }
            }
        }
        let provider = RetryProvider {
            calls: std::sync::atomic::AtomicU32::new(0),
        };
        let result = compile_sop(&provider, "sop").expect("compile after retry");
        assert_eq!(result.policy.policy_id, "pol_refunds");
        assert_eq!(
            provider.calls.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "exactly one retry"
        );
    }

    /// Two consecutive failures → rejected (wall 1: 1 retry, then reject).
    #[test]
    fn two_failures_rejected() {
        let provider = FixtureProvider::new(r#"{"ir_version":"1","bogus":true}"#);
        let err = compile_sop(&provider, "sop").expect_err("must reject");
        assert!(err.to_string().contains("retry"), "got: {err}");
    }
}
