use serde_json::Value;
use sha2::{Digest, Sha256};

/// The ONLY serialization-for-hashing path in the codebase (Law 4).
///
/// RFC 8785-style canonical JSON: object keys sorted lexicographically, fixed
/// separators (no whitespace), raw UTF-8 output (non-ASCII never escaped as
/// \uXXXX). Deterministic across runs and implementations.
pub fn canonical_dumps(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).expect("serializing a string cannot fail"))
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(*key).expect("serializing a key cannot fail"));
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// SHA-256 hex digest, lowercase — the only hash function in the codebase.
pub fn sha256_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    hex(digest.as_slice())
}

fn hex(bytes: &[u8]) -> String {
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
    use serde_json::json;

    #[test]
    fn key_order_stable() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonical_dumps(&v), r#"{"a":2,"b":1}"#);

        let nested = json!({"z": {"y": 1, "x": 2}, "a": []});
        assert_eq!(canonical_dumps(&nested), r#"{"a":[],"z":{"x":2,"y":1}}"#);
    }

    #[test]
    fn non_ascii_preserved() {
        assert_eq!(
            canonical_dumps(&json!({"name": "café"})),
            "{\"name\":\"café\"}"
        );
    }

    #[test]
    fn number_formatting_stable() {
        assert_eq!(
            canonical_dumps(&json!({"n": 150, "f": 1.5})),
            r#"{"f":1.5,"n":150}"#
        );
    }

    #[test]
    fn golden_vector_entry_hash() {
        let preimage = json!({
            "ts": "2026-08-25T14:00:00Z",
            "seq": 14921,
            "prev": "0000000000000000000000000000000000000000000000000000000000000000",
            "entry_type": "DECISION",
            "request_id": "req_7f3a2b1c",
            "agent_id": "agent_support_09",
            "tool": "stripe.refunds.create",
            "params_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091",
            "decision": "ALLOW",
            "policy_id": "pol_refunds",
            "policy_version": 3,
            "policy_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "determining_rule_ids": ["r-allow-small"],
            "reason_code": "RULE_MATCH"
        });
        let canonical = canonical_dumps(&preimage);
        assert_eq!(
            canonical,
            r#"{"agent_id":"agent_support_09","decision":"ALLOW","determining_rule_ids":["r-allow-small"],"entry_type":"DECISION","params_hash":"a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091","policy_hash":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","policy_id":"pol_refunds","policy_version":3,"prev":"0000000000000000000000000000000000000000000000000000000000000000","reason_code":"RULE_MATCH","request_id":"req_7f3a2b1c","seq":14921,"tool":"stripe.refunds.create","ts":"2026-08-25T14:00:00Z"}"#
        );
        let digest = sha256_hex(&canonical);
        assert_eq!(
            digest,
            "23cd05c91e3e42d96ad71165aa16af690ba889e537a04e6c9490fb38e7440408"
        );
    }

    #[test]
    fn sha256_kat_empty() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
