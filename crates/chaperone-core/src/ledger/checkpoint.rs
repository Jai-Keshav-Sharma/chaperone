//! C2SP-style signed checkpoints (docs/flows/04 Layer 2): the note body is
//! `origin\nsize\nroot_hash_b64\n`, the signature line is
//! `— origin key_id signature_b64\n` (U+2014 em dash). Ed25519 signatures.
//! `key_id` = hex(sha256(verifying_key_bytes)[..8]) — rotation-ready: verify
//! accepts any key from the (key_id, key) list (review-2 SEC-1).

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::canonical::sha256_hex;

pub const CHECKPOINT_ORIGIN: &str = "chaperone";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointError {
    pub message: String,
}

impl CheckpointError {
    fn new(message: impl Into<String>) -> Self {
        CheckpointError {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub tree_size: u64,
    /// 64-hex root hash (the DB column format).
    pub root_hash: String,
    pub key_id: String,
    /// Base64 Ed25519 signature; None in unsigned dev mode (data-model:
    /// `signature NULL in unsigned dev mode`).
    pub signature: Option<String>,
    /// The signed note body (origin\nsize\nhash_b64\n).
    pub body: String,
    /// The full checkpoint text (body + signature line).
    pub text: String,
}

/// Deterministic key id: hex of the first 8 bytes of sha256(pubkey).
pub fn key_id(verifying: &VerifyingKey) -> String {
    sha256_hex(&base64::engine::general_purpose::STANDARD.encode(verifying.to_bytes()))[..16]
        .to_string()
}

pub fn note_body(origin: &str, tree_size: u64, root_hash: &str) -> String {
    let root_b64 = base64::engine::general_purpose::STANDARD.encode(hex_decode(root_hash));
    format!("{origin}\n{tree_size}\n{root_b64}\n")
}

pub fn sign_checkpoint(
    origin: &str,
    tree_size: u64,
    root_hash: &str,
    signing_key: &SigningKey,
) -> Checkpoint {
    let body = note_body(origin, tree_size, root_hash);
    let signature = signing_key.sign(body.as_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let key_id = key_id(&signing_key.verifying_key());
    let text = format!("{body}\u{2014} {origin} {key_id} {signature_b64}\n");
    Checkpoint {
        origin: origin.to_string(),
        tree_size,
        root_hash: root_hash.to_string(),
        key_id,
        signature: Some(signature_b64),
        body,
        text,
    }
}

/// Build an UNSIGNED dev checkpoint (data-model: `signature NULL in unsigned
/// dev mode`). `body` + `text` are still produced so the checkpoint row is
/// well-formed and the C2SP text is inspectable; only the signature line is
/// omitted. This is the dev-mode default when no signing key is configured.
pub fn unsigned_checkpoint(origin: &str, tree_size: u64, root_hash: &str) -> Checkpoint {
    let body = note_body(origin, tree_size, root_hash);
    Checkpoint {
        origin: origin.to_string(),
        tree_size,
        root_hash: root_hash.to_string(),
        key_id: String::new(),
        signature: None,
        body: body.clone(),
        text: body,
    }
}

/// Load an Ed25519 signing key from raw 32 seed bytes (hex- or base64-encoded,
/// or raw 32 bytes as-is). The documented `checkpoint_signing_key` config is a
/// file path; the caller reads the file and passes the bytes here.
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, CheckpointError> {
    let seed = decode_key_seed(bytes)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Decode a 32-byte seed from hex, base64, or raw bytes (the three encodings a
/// key file may use). Errors on anything that is not exactly 32 bytes.
fn decode_key_seed(bytes: &[u8]) -> Result<[u8; 32], CheckpointError> {
    let trimmed = {
        let s = std::str::from_utf8(bytes).map_err(|_| CheckpointError::new("key is not UTF-8"))?;
        s.trim().as_bytes().to_vec()
    };
    if trimmed.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&trimmed);
        return Ok(seed);
    }
    if trimmed.len() == 64 && trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(std::str::from_utf8(&trimmed[i * 2..i * 2 + 2]).unwrap(), 16)
                    .map_err(|e| CheckpointError::new(format!("bad hex key: {e}")))?;
        }
        return Ok(seed);
    }
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed)
        && decoded.len() == 32
    {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&decoded);
        return Ok(seed);
    }
    Err(CheckpointError::new(
        "signing key must be 32 raw bytes, 64 hex chars, or base64 of 32 bytes",
    ))
}

/// Verify a checkpoint against the known keys (any key_id in the list —
/// historical keys stay verifiable after rotation, review-2 SEC-1).
/// Returns the key_id that verified.
pub fn verify_checkpoint(
    checkpoint_text: &str,
    expected_origin: &str,
    keys: &[(String, VerifyingKey)],
) -> Result<(String, u64, String), CheckpointError> {
    let body = extract_body(checkpoint_text)?;
    let signature_line = extract_signature_line(checkpoint_text)?;
    let signature_b64 = signature_line
        .split_whitespace()
        .last()
        .ok_or_else(|| CheckpointError::new("signature line has no signature"))?;
    let key_id = signature_line
        .split_whitespace()
        .nth(2)
        .ok_or_else(|| CheckpointError::new("signature line has no key_id"))?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| CheckpointError::new(format!("bad signature base64: {e}")))?;
    let mut sig_arr = [0u8; 64];
    if signature_bytes.len() != 64 {
        return Err(CheckpointError::new("signature is not 64 bytes"));
    }
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let (_, verifying) = keys
        .iter()
        .find(|(kid, _)| kid == key_id)
        .ok_or_else(|| CheckpointError::new(format!("unknown key_id {key_id:?}")))?;
    verifying
        .verify_strict(body.as_bytes(), &signature)
        .map_err(|e| CheckpointError::new(format!("signature verification failed: {e}")))?;

    // parse the body: origin\nsize\nhash_b64\n
    let mut lines = body.lines();
    let origin = lines
        .next()
        .ok_or_else(|| CheckpointError::new("empty body"))?;
    if origin != expected_origin {
        return Err(CheckpointError::new(format!(
            "origin mismatch: {origin:?} != {expected_origin:?}"
        )));
    }
    let size: u64 = lines
        .next()
        .ok_or_else(|| CheckpointError::new("body missing size"))?
        .parse()
        .map_err(|e| CheckpointError::new(format!("bad tree size: {e}")))?;
    let root_b64 = lines
        .next()
        .ok_or_else(|| CheckpointError::new("body missing root"))?;
    let root_bytes = base64::engine::general_purpose::STANDARD
        .decode(root_b64)
        .map_err(|e| CheckpointError::new(format!("bad root base64: {e}")))?;
    let root_hex = hex_encode(&root_bytes);
    Ok((key_id.to_string(), size, root_hex))
}

fn extract_body(text: &str) -> Result<String, CheckpointError> {
    let mut lines = text.lines();
    let mut body = String::new();
    for _ in 0..3 {
        let line = lines
            .next()
            .ok_or_else(|| CheckpointError::new("checkpoint body truncated"))?;
        body.push_str(line);
        body.push('\n');
    }
    Ok(body)
}

fn extract_signature_line(text: &str) -> Result<String, CheckpointError> {
    text.lines()
        .nth(3)
        .filter(|l| l.starts_with('\u{2014}'))
        .map(|l| l.to_string())
        .ok_or_else(|| CheckpointError::new("checkpoint has no signature line"))
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn checkpoint_format_pinned() {
        // The exact C2SP text shape — pinned as a literal (format stability
        // is the golden aspect; signature correctness comes from ed25519-dalek,
        // verified in the roundtrip test below).
        let key = test_key(7);
        let checkpoint = sign_checkpoint(
            CHECKPOINT_ORIGIN,
            4,
            "3fc2db4b19e95f5d0b3c8d24721900a18265c3d789f505aa27092b1255ecd63e",
            &key,
        );
        let lines: Vec<&str> = checkpoint.text.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "chaperone");
        assert_eq!(lines[1], "4");
        assert!(
            lines[2].chars().all(|c| {
                "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=".contains(c)
            }),
            "got line2: {:?}",
            lines[2]
        );
        assert!(lines[3].starts_with('\u{2014}'), "got: {}", lines[3]);
        assert!(lines[3].starts_with(&format!("\u{2014} chaperone {}", checkpoint.key_id)));
        assert_eq!(checkpoint.key_id, key_id(&key.verifying_key()));
        // body is exactly the 3 lines with trailing newlines
        assert_eq!(checkpoint.body, format!("chaperone\n4\n{}\n", lines[2]));
        assert!(checkpoint.text.ends_with('\n'));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = test_key(7);
        let checkpoint = sign_checkpoint(
            CHECKPOINT_ORIGIN,
            4,
            "3fc2db4b19e95f5d0b3c8d24721900a18265c3d789f505aa27092b1255ecd63e",
            &key,
        );
        let keys = vec![(checkpoint.key_id.clone(), key.verifying_key())];
        let (verified_key_id, size, root) =
            verify_checkpoint(&checkpoint.text, CHECKPOINT_ORIGIN, &keys).expect("verify");
        assert_eq!(verified_key_id, checkpoint.key_id);
        assert_eq!(size, 4);
        assert_eq!(root, checkpoint.root_hash);
    }

    #[test]
    fn verify_rejects_wrong_key_and_tamper() {
        let key = test_key(7);
        let other = test_key(9);
        let checkpoint = sign_checkpoint(
            CHECKPOINT_ORIGIN,
            4,
            "3fc2db4b19e95f5d0b3c8d24721900a18265c3d789f505aa27092b1255ecd63e",
            &key,
        );
        // wrong key (even with the right key_id claimed)
        let keys = vec![(checkpoint.key_id.clone(), other.verifying_key())];
        assert!(verify_checkpoint(&checkpoint.text, CHECKPOINT_ORIGIN, &keys).is_err());
        // tampered tree size
        let tampered = checkpoint.text.replacen("\n4\n", "\n5\n", 1);
        assert!(
            verify_checkpoint(
                &tampered,
                CHECKPOINT_ORIGIN,
                &[(checkpoint.key_id.clone(), key.verifying_key())]
            )
            .is_err()
        );
        // wrong origin
        assert!(
            verify_checkpoint(
                &checkpoint.text,
                "other",
                &[(checkpoint.key_id.clone(), key.verifying_key())]
            )
            .is_err()
        );
        // unsigned text (dev mode) cannot verify
        let unsigned = format!(
            "{}\n\u{2014} chaperone {} \n",
            checkpoint.body, checkpoint.key_id
        );
        assert!(
            verify_checkpoint(
                &unsigned,
                CHECKPOINT_ORIGIN,
                &[(checkpoint.key_id.clone(), key.verifying_key())]
            )
            .is_err()
        );
    }

    #[test]
    fn rotation_keeps_old_keys_verifiable() {
        let old_key = test_key(1);
        let new_key = test_key(2);
        let old_checkpoint = sign_checkpoint(
            CHECKPOINT_ORIGIN,
            3,
            "572daacac3528353d8386152d810c55080962ce4c5d5111e7fa00806f733b5e2",
            &old_key,
        );
        let new_checkpoint = sign_checkpoint(
            CHECKPOINT_ORIGIN,
            4,
            "3fc2db4b19e95f5d0b3c8d24721900a18265c3d789f505aa27092b1255ecd63e",
            &new_key,
        );
        // verify both with the CURRENT key list (old keys remain listed)
        let keys = vec![
            (key_id(&new_key.verifying_key()), new_key.verifying_key()),
            (key_id(&old_key.verifying_key()), old_key.verifying_key()),
        ];
        assert!(verify_checkpoint(&old_checkpoint.text, CHECKPOINT_ORIGIN, &keys).is_ok());
        assert!(verify_checkpoint(&new_checkpoint.text, CHECKPOINT_ORIGIN, &keys).is_ok());
    }
}
