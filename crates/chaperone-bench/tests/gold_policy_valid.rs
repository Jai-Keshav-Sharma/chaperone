//! Validate the gold policies through the REAL IR validator (the same one the
//! StorePolicyProvider runs at load). The bench must never ship a policy that
//! fails at gate startup.

use chaperone_bench::gold::gold_policies;

#[test]
fn gold_policies_pass_ir_validation() {
    for policy in gold_policies() {
        let errs = chaperone_core::ir::validate::validate(&policy);
        assert!(
            errs.is_ok(),
            "policy {} failed validation: {:?}",
            policy.policy_id,
            errs.unwrap_err()
        );
    }
}

#[test]
fn gold_policies_compile_to_cedar() {
    for policy in gold_policies() {
        let compiled =
            chaperone_core::engine::cedar_compile::to_cedar(&policy).expect("cedar compile");
        assert!(!compiled.is_empty(), "empty cedar for {}", policy.policy_id);
    }
}
