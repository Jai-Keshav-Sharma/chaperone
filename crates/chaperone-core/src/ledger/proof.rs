//! Inclusion proofs (docs/flows/04 proof CLI): O(log n) proof that an entry
//! is in the tree, plus the offline-verifiable JSON bundle
//! (leaf + path + root + checkpoint + signature + pubkey).

use serde_json::{Value as JsonValue, json};

use crate::ledger::checkpoint::Checkpoint;
use crate::ledger::merkle;

/// A complete inclusion proof for one leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub tree_size: u64,
    pub leaf_index: u64,
    pub leaf_hash: String,
    /// Sibling hashes, leaf-ward first.
    pub path: Vec<String>,
    pub root_hash: String,
}

pub fn build_inclusion_proof(leaves: &[String], index: usize) -> Option<InclusionProof> {
    let path = merkle::inclusion_proof(leaves, index)?;
    Some(InclusionProof {
        tree_size: leaves.len() as u64,
        leaf_index: index as u64,
        leaf_hash: leaves[index].clone(),
        path,
        root_hash: merkle::root_hash(leaves)?,
    })
}

/// Verify the proof against a trusted root (typically the root inside a
/// signed checkpoint).
pub fn verify_inclusion_proof(proof: &InclusionProof, root_hash: &str) -> bool {
    merkle::verify_inclusion(
        root_hash,
        &proof.leaf_hash,
        proof.leaf_index as usize,
        &proof.path,
        proof.tree_size as usize,
    ) && root_hash == proof.root_hash
}

/// The `chaperone ledger prove --seq N` JSON bundle — verifiable offline with
/// the public key alone (flows/04): leaf + path + root + checkpoint text +
/// signature + pubkey.
pub fn proof_bundle_json(
    proof: &InclusionProof,
    checkpoint: &Checkpoint,
    verifying_key_hex: &str,
) -> JsonValue {
    json!({
        "entry": {
            "leaf_hash": proof.leaf_hash,
            "leaf_index": proof.leaf_index,
            "tree_size": proof.tree_size,
        },
        "path": proof.path,
        "root_hash": proof.root_hash,
        "checkpoint": {
            "text": checkpoint.text,
            "origin": checkpoint.origin,
            "tree_size": checkpoint.tree_size,
            "root_hash": checkpoint.root_hash,
            "key_id": checkpoint.key_id,
            "signature": checkpoint.signature,
        },
        "verifying_key_hex": verifying_key_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves4() -> Vec<String> {
        vec![
            "61eaf75514a57b377ee3b3ead172419206321b6d2fa2e300d907ec250a5a90e5".to_string(),
            "7e5babc927e18e223203fbad5af6a49dd6a5ac3b9746c2bd4e4c5a52e6cadc04".to_string(),
            "d2ee2798f322de5f437efb296f58304f132d4a470877a6a9735e94c868b65388".to_string(),
            "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd".to_string(),
        ]
    }

    #[test]
    fn build_and_verify_proof() {
        let leaves = leaves4();
        let proof = build_inclusion_proof(&leaves, 2).expect("proof");
        assert_eq!(proof.leaf_index, 2);
        assert_eq!(proof.tree_size, 4);
        let root = merkle::root_hash(&leaves).expect("root");
        assert!(verify_inclusion_proof(&proof, &root));
        assert!(!verify_inclusion_proof(&proof, &"0".repeat(64)));
    }

    #[test]
    fn bundle_contains_offline_verification_material() {
        let leaves = leaves4();
        let proof = build_inclusion_proof(&leaves, 0).expect("proof");
        let checkpoint = crate::ledger::checkpoint::sign_checkpoint(
            crate::ledger::checkpoint::CHECKPOINT_ORIGIN,
            4,
            &proof.root_hash,
            &ed25519_dalek::SigningKey::from_bytes(&[5; 32]),
        );
        let bundle = proof_bundle_json(&proof, &checkpoint, &"00".repeat(32));
        assert_eq!(bundle["entry"]["leaf_index"], 0);
        assert_eq!(bundle["checkpoint"]["tree_size"], 4);
        assert_eq!(bundle["checkpoint"]["root_hash"], proof.root_hash);
        assert_eq!(bundle["verifying_key_hex"], "00".repeat(32));
        assert_eq!(bundle["path"].as_array().map(Vec::len), Some(2));
    }
}
