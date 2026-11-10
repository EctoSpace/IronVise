//! Keep LLM providers' encrypted reasoning out of the ledger.
//!
//! Providers hand out their hidden chain-of-thought as opaque blobs so a
//! client can send it back on the next turn. arXiv 2608.09867 showed those
//! blobs work across sessions, users and models of the same provider, so one
//! found anywhere can be replayed into an attacker's own session and read.
//! The ledger is append-only and exported: a blob written there cannot be
//! taken back. So each one is replaced by a marker naming its SHA-256, which
//! still proves what passed through and cannot be replayed.
//!
//! What is recognised (and nothing else is touched, least of all
//! IronVise's own `signature` fields):
//!
//! | Provider shape | Removed |
//! |---|---|
//! | OpenAI `encrypted_content` | the value |
//! | Anthropic `redacted_thinking` block | `data` |
//! | Anthropic `thinking` block | `signature` (the thinking text itself is plaintext) |
//! | OpenRouter `reasoning.encrypted` / `reasoning.text` | `data` / `signature` |
//! | Gemini `thought_signature` / `thoughtSignature` | the value |

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Keys whose string value is always an encrypted provider blob.
const ENCRYPTED_KEYS: &[&str] = &["encrypted_content", "thought_signature", "thoughtSignature"];

/// Block types, and the field in each that carries the encrypted part.
const ENCRYPTED_FIELD_BY_TYPE: &[(&str, &str)] = &[
    ("redacted_thinking", "data"),
    ("thinking", "signature"),
    ("reasoning.encrypted", "data"),
    ("reasoning.text", "signature"),
];

/// Replace every encrypted reasoning blob in `value` with a marker. Returns
/// how many were removed. Strings holding JSON are searched too, since
/// clients often send a provider response already serialised.
pub fn strip(value: &mut Value) -> usize {
    match value {
        Value::Object(map) => {
            let mut removed = 0;
            let block_field = map.get("type").and_then(Value::as_str).and_then(|t| {
                ENCRYPTED_FIELD_BY_TYPE
                    .iter()
                    .find(|(ty, _)| *ty == t)
                    .map(|(_, field)| *field)
            });
            for (key, v) in map.iter_mut() {
                let encrypted =
                    ENCRYPTED_KEYS.contains(&key.as_str()) || block_field == Some(key.as_str());
                match v {
                    Value::String(s) if encrypted && !is_marker(s) => {
                        *s = marker(s);
                        removed += 1;
                    }
                    _ => removed += strip(v),
                }
            }
            removed
        }
        Value::Array(items) => items.iter_mut().map(strip).sum(),
        Value::String(s) => strip_embedded(s),
        _ => 0,
    }
}

/// [`strip`] over a string that may hold JSON. Rewritten only when something
/// was removed, so ordinary text keeps its exact bytes.
fn strip_embedded(s: &mut String) -> usize {
    let t = s.trim_start();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return 0;
    }
    let Ok(mut inner) = serde_json::from_str::<Value>(s) else {
        return 0;
    };
    let removed = strip(&mut inner);
    if removed > 0 {
        *s = inner.to_string();
    }
    removed
}

const MARKER_PREFIX: &str = "[removed: provider-encrypted reasoning, sha256:";

fn marker(blob: &str) -> String {
    format!(
        "{MARKER_PREFIX}{}, {} bytes]",
        hex::encode(Sha256::digest(blob.as_bytes())),
        blob.len()
    )
}

fn is_marker(s: &str) -> bool {
    s.starts_with(MARKER_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BLOB: &str = "gAAAAABoEXAMPLEciphertextthatmustnotsurvive";

    fn stripped(mut v: Value) -> (Value, usize) {
        let n = strip(&mut v);
        (v, n)
    }

    fn assert_gone(v: &Value) {
        let text = v.to_string();
        assert!(!text.contains(BLOB), "blob survived: {text}");
        assert!(
            text.contains(&hex::encode(Sha256::digest(BLOB))),
            "marker missing: {text}"
        );
    }

    #[test]
    fn each_provider_shape_loses_its_blob_and_keeps_a_hash() {
        let cases = [
            // OpenAI Responses API reasoning item
            json!({ "output": [{ "type": "reasoning", "summary": [], "encrypted_content": BLOB }] }),
            // Anthropic Messages
            json!({ "content": [{ "type": "redacted_thinking", "data": BLOB }] }),
            json!({ "content": [{ "type": "thinking", "thinking": "plan", "signature": BLOB }] }),
            // OpenRouter reasoning_details
            json!({ "choices": [{ "message": { "content": null, "reasoning_details": [
                { "type": "reasoning.encrypted", "data": BLOB }] } }] }),
            json!({ "reasoning_details": [{ "type": "reasoning.text", "text": "t", "signature": BLOB }] }),
            // Gemini, both spellings
            json!({ "parts": [{ "text": "x", "thoughtSignature": BLOB }] }),
            json!({ "extra_content": { "google": { "thought_signature": BLOB } } }),
        ];
        for case in cases {
            let (v, n) = stripped(case.clone());
            assert_eq!(n, 1, "{case}");
            assert_gone(&v);
        }
    }

    #[test]
    fn plaintext_and_ecto_ledgers_own_signatures_are_untouched() {
        let own = json!({
            "type": "action",
            "signature": "ed25519-hex",
            "thinking": "visible reasoning stays",
            "content": [{ "type": "text", "text": "hello", "signature": "not a provider blob" }],
        });
        let (v, n) = stripped(own.clone());
        assert_eq!(n, 0);
        assert_eq!(v, own);
    }

    #[test]
    fn a_serialised_response_inside_a_string_is_searched() {
        let inner = json!({ "content": [{ "type": "redacted_thinking", "data": BLOB }] });
        let (v, n) = stripped(json!({ "type": "observation", "content": inner.to_string() }));
        assert_eq!(n, 1);
        assert_gone(&v);
        let plain = json!({ "content": "{not json at all" });
        assert_eq!(stripped(plain.clone()), (plain, 0));
    }

    #[test]
    fn stripping_twice_changes_nothing_more() {
        let (once, n1) = stripped(json!({ "encrypted_content": BLOB }));
        let (twice, n2) = stripped(once.clone());
        assert_eq!((n1, n2), (1, 0));
        assert_eq!(once, twice);
    }

    #[test]
    fn a_non_string_value_under_an_encrypted_key_is_searched_not_replaced() {
        let (v, n) =
            stripped(json!({ "encrypted_content": { "nested": { "encrypted_content": BLOB } } }));
        assert_eq!(n, 1);
        assert_gone(&v);
    }
}
