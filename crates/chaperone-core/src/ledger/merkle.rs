//! RFC 6962 Merkle tree (docs/flows/04 Layer 2) — implemented in-house
//! (~100 lines), golden-vector-pinned against an independent Python
//! implementation, and structurally cross-checked against the reference
//! transparency-dev/merkle verification algorithm.
//!
//! Leaves are the ledger entry hashes (64-hex strings). Leaf hash =
//! SHA-256(0x00 || data); node hash = SHA-256(0x01 || left || right)
//! (domain separation — second preimage resistance).
//!
//! Proof ORDER: leaf-ward first (the RFC's "lower levels to upper" order)
//! — both inclusion and consistency proofs are emitted and consumed in this
//! order.

fn leaf_hash(data_hex: &str) -> Option<[u8; 32]> {
    let data = hex_decode(data_hex)?;
    let mut buf = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update([0x00]);
    hasher.update(data);
    buf.copy_from_slice(&hasher.finalize());
    Some(buf)
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    buf.copy_from_slice(&hasher.finalize());
    buf
}

/// Largest power of two strictly smaller than n (RFC 6962: k < n <= 2k).
fn split_k(n: usize) -> usize {
    debug_assert!(n >= 2);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

fn subtree_hash(leaves: &[String], offset: usize, size: usize) -> Option<[u8; 32]> {
    if size == 1 {
        return leaf_hash(&leaves[offset]);
    }
    let k = split_k(size);
    Some(node_hash(
        &subtree_hash(leaves, offset, k)?,
        &subtree_hash(leaves, offset + k, size - k)?,
    ))
}

/// The RFC 6962 Merkle Tree Hash over the entry hashes (hex).
pub fn root_hash(leaves: &[String]) -> Option<String> {
    if leaves.is_empty() {
        return None;
    }
    subtree_hash(leaves, 0, leaves.len()).map(|h| hex_encode(&h))
}

/// Inclusion proof (audit path) for the leaf at `index` — leaf-ward first.
pub fn inclusion_proof(leaves: &[String], index: usize) -> Option<Vec<String>> {
    let n = leaves.len();
    if index >= n {
        return None;
    }
    let mut path: Vec<String> = Vec::new();
    walk_inclusion(leaves, 0, n, index, &mut path)?;
    path.reverse(); // leaf-ward first
    Some(path)
}

fn walk_inclusion(
    leaves: &[String],
    offset: usize,
    size: usize,
    index: usize,
    path: &mut Vec<String>,
) -> Option<()> {
    if size == 1 {
        return Some(());
    }
    let k = split_k(size);
    if index < k {
        path.push(hex_encode(&subtree_hash(leaves, offset + k, size - k)?));
        walk_inclusion(leaves, offset, k, index, path)
    } else {
        path.push(hex_encode(&subtree_hash(leaves, offset, k)?));
        walk_inclusion(leaves, offset + k, size - k, index - k, path)
    }
}

/// Verify an inclusion proof (transparency-dev/merkle algorithm):
/// inner part chained against the leaf hash, then the border (left siblings
/// only) chained to the root. Requires 0 <= index < tree_size.
pub fn verify_inclusion(
    root: &str,
    leaf: &str,
    index: usize,
    proof: &[String],
    tree_size: usize,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let Some(leaf_hash) = leaf_hash(leaf) else {
        return false;
    };
    let inner = inner_proof_size(index, tree_size);
    let border = (index >> inner).count_ones() as usize;
    if proof.len() != inner + border {
        return false;
    }
    let mut seed = leaf_hash;
    seed = chain_inner(seed, &proof[..inner], index);
    seed = chain_border_right(seed, &proof[inner..]);
    root == hex_encode(&seed)
}

/// Height of the first node where the paths of leaves at `index` and
/// `size-1` diverge (bits.Len64(index ^ (size-1))).
fn inner_proof_size(index: usize, size: usize) -> usize {
    usize::BITS as usize - (index ^ (size - 1)).leading_zeros() as usize
}

fn chain_inner(seed: [u8; 32], proof: &[String], index: usize) -> [u8; 32] {
    let mut seed = seed;
    for (i, h) in proof.iter().enumerate() {
        let Some(hash) = hex_decode(h) else {
            return seed;
        };
        let mut node = [0u8; 32];
        node.copy_from_slice(&hash);
        if (index >> i) & 1 == 0 {
            seed = node_hash(&seed, &node);
        } else {
            seed = node_hash(&node, &seed);
        }
    }
    seed
}

fn chain_border_right(seed: [u8; 32], proof: &[String]) -> [u8; 32] {
    let mut seed = seed;
    for h in proof {
        let Some(hash) = hex_decode(h) else {
            return seed;
        };
        let mut node = [0u8; 32];
        node.copy_from_slice(&hash);
        seed = node_hash(&node, &seed);
    }
    seed
}

/// Consistency proof between two tree sizes (RFC 6962 §2.1.2 SUBPROOF) —
/// leaf-ward first. Requires 0 < old_size < new_size.
pub fn consistency_proof(
    leaves: &[String],
    old_size: usize,
    new_size: usize,
) -> Option<Vec<String>> {
    if old_size == 0 || old_size >= new_size || new_size > leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    subproof(leaves, 0, old_size, new_size, true, &mut proof)?;
    Some(proof)
}

/// SUBPROOF(m, D[offset:offset+n], b) — the RFC's recursive definition,
/// emitting the committed subtree hashes leaf-ward first.
fn subproof(
    leaves: &[String],
    offset: usize,
    m: usize,
    n: usize,
    b: bool,
    proof: &mut Vec<String>,
) -> Option<()> {
    if m == n {
        if !b {
            proof.push(hex_encode(&subtree_hash(leaves, offset, n)?));
        }
        return Some(());
    }
    let k = split_k(n);
    if m <= k {
        // SUBPROOF(m, D[0:k], b) : MTH(D[k:n]) — recursion first, then the
        // committed right subtree (leaf-ward first order).
        subproof(leaves, offset, m, k, b, proof)?;
        proof.push(hex_encode(&subtree_hash(leaves, offset + k, n - k)?));
        Some(())
    } else {
        // SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k])
        subproof(leaves, offset + k, m - k, n - k, false, proof)?;
        proof.push(hex_encode(&subtree_hash(leaves, offset, k)?));
        Some(())
    }
}

/// Verify a consistency proof (transparency-dev/merkle
/// RootFromConsistencyProof, translated): reconstruct the NEW root from the
/// OLD root + proof; accept iff it matches `new_root`. Requires
/// 0 < old_size <= new_size.
pub fn verify_consistency(
    old_root: &str,
    new_root: &str,
    old_size: usize,
    new_size: usize,
    proof: &[String],
) -> bool {
    if new_size < old_size || old_size == 0 {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if proof.is_empty() {
        return false;
    }
    // root_from_subtree_consistency_proof(start=0, end=old_size, size=new_size)
    let start = 0usize;
    let end = old_size;
    let size = new_size;
    let fork_level = usize::BITS as usize - ((end - 1) ^ (size - 1)).leading_zeros() as usize;
    let shift = (end - start).trailing_zeros() as usize;
    let inner = fork_level - shift;
    let (seed, p_start): ([u8; 32], usize) = if (end - start) == (1usize << shift) {
        (hex_to_32(old_root), 0)
    } else {
        (hex_to_32(&proof[0]), 1)
    };
    let border = ((end - 1) >> inner).count_ones() as usize;
    if proof.len() != p_start + inner + border {
        return false;
    }
    let proof = &proof[p_start..];
    let mask = (end - 1) >> shift;
    if p_start == 1 {
        let subtree_height = usize::BITS as usize - ((end - 1) ^ start).leading_zeros() as usize;
        let sub_inner = (subtree_height.min(fork_level)) - shift;
        let sub_border = border.saturating_sub(((end - 1) >> subtree_height).count_ones() as usize);
        let hash1 = chain_inner_right(seed, &proof[..sub_inner], mask);
        let hash1 = chain_border_right(hash1, &proof[inner..inner + sub_border]);
        if hex_encode(&hash1) != old_root {
            return false;
        }
    }
    let hash2 = chain_inner(seed, &proof[..inner], mask);
    let hash2 = chain_border_right(hash2, &proof[inner..]);
    hex_encode(&hash2) == new_root
}

fn chain_inner_right(seed: [u8; 32], proof: &[String], index: usize) -> [u8; 32] {
    let mut seed = seed;
    for (i, h) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            let Some(hash) = hex_decode(h) else {
                return seed;
            };
            let mut node = [0u8; 32];
            node.copy_from_slice(&hash);
            seed = node_hash(&node, &seed);
        }
    }
    seed
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..32)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex_decode(s).expect("64-hex string");
    out.copy_from_slice(&bytes);
    out
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden 4-leaf tree: the three chain-vector entry hashes + one
    /// synthetic leaf — independently computed and verified in Python.
    fn leaves4() -> Vec<String> {
        vec![
            "61eaf75514a57b377ee3b3ead172419206321b6d2fa2e300d907ec250a5a90e5".to_string(),
            "7e5babc927e18e223203fbad5af6a49dd6a5ac3b9746c2bd4e4c5a52e6cadc04".to_string(),
            "d2ee2798f322de5f437efb296f58304f132d4a470877a6a9735e94c868b65388".to_string(),
            "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd".to_string(),
        ]
    }

    #[test]
    fn golden_vectors() {
        let leaves = leaves4();
        assert_eq!(
            root_hash(&leaves).expect("root"),
            "3fc2db4b19e95f5d0b3c8d24721900a18265c3d789f505aa27092b1255ecd63e"
        );
        assert_eq!(
            root_hash(&leaves[..3]).expect("root3"),
            "039533e0d0f514c696295671d3f9e5a2414c0170b0f37b338f5a25f8c1650711"
        );
        // leaf-ward first
        assert_eq!(
            inclusion_proof(&leaves, 0),
            Some(vec![
                "fd1ae53e988cee0840bbde6dccf4bf21b5edec8d8038e7bdb710a219bd286c8d".to_string(),
                "30e6b46a2094ca7b7cb75fb298cb51eff35132d560813689c1b96cf94a319a5c".to_string(),
            ])
        );
        assert_eq!(
            inclusion_proof(&leaves, 2),
            Some(vec![
                "1dad23070e37cead5b43b745912be7c74011aa506be3d104a6d22888d9657fb4".to_string(),
                "2fd424c1c46cae5f88536a66cf1560ef4e995be0a19f21eef2850d0d20cd372e".to_string(),
            ])
        );
        assert_eq!(
            consistency_proof(&leaves, 2, 4),
            Some(vec![
                "30e6b46a2094ca7b7cb75fb298cb51eff35132d560813689c1b96cf94a319a5c".to_string()
            ])
        );
        assert_eq!(
            consistency_proof(&leaves, 3, 4),
            Some(vec![
                "2e53bf1a8d0767a12c7118dd0d057a7ad5bcde1b5d5b8a910e094baa1ad2c998".to_string(),
                "1dad23070e37cead5b43b745912be7c74011aa506be3d104a6d22888d9657fb4".to_string(),
                "2fd424c1c46cae5f88536a66cf1560ef4e995be0a19f21eef2850d0d20cd372e".to_string(),
            ])
        );
    }

    #[test]
    fn verify_inclusion_golden() {
        let leaves = leaves4();
        let root = root_hash(&leaves).expect("root");
        for index in [0usize, 1, 2, 3] {
            let proof = inclusion_proof(&leaves, index).expect("proof");
            assert!(verify_inclusion(&root, &leaves[index], index, &proof, 4));
            // tampered proof element fails
            let mut bad = proof.clone();
            bad[0] = "0".repeat(64);
            assert!(!verify_inclusion(&root, &leaves[index], index, &bad, 4));
        }
        // wrong tree size fails: the 4-leaf proof chains to the 4-leaf root,
        // which cannot equal the 3-leaf root
        let proof0 = inclusion_proof(&leaves, 0).expect("proof");
        let root3 = root_hash(&leaves[..3]).expect("root3");
        assert!(!verify_inclusion(&root3, &leaves[0], 0, &proof0, 3));
    }

    #[test]
    fn verify_consistency_golden() {
        let leaves = leaves4();
        let root4 = root_hash(&leaves).expect("root4");
        let root3 = root_hash(&leaves[..3]).expect("root3");
        let root2 = root_hash(&leaves[..2]).expect("root2");
        for (m, old_root, proof) in [
            (
                2usize,
                root2.clone(),
                consistency_proof(&leaves, 2, 4).expect("p2"),
            ),
            (
                3usize,
                root3.clone(),
                consistency_proof(&leaves, 3, 4).expect("p3"),
            ),
            (
                1usize,
                root_hash(&leaves[..1]).expect("root1"),
                consistency_proof(&leaves, 1, 4).expect("p1"),
            ),
        ] {
            assert!(verify_consistency(&old_root, &root4, m, 4, &proof), "m={m}");
            // tampered old root fails
            assert!(!verify_consistency(&"0".repeat(64), &root4, m, 4, &proof));
            // wrong proof element fails
            let mut bad = proof.clone();
            bad[0] = "1".repeat(64);
            assert!(!verify_consistency(&old_root, &root4, m, 4, &bad));
        }
        // same size: empty proof only
        assert!(verify_consistency(&root2, &root2, 2, 2, &[]));
        assert!(!verify_consistency(&root2, &root2, 2, 2, &["a".repeat(64)]));
        // from empty tree: meaningless
        assert!(!verify_consistency(&"0".repeat(64), &root4, 0, 4, &[]));
    }
}
