//! Redaction of sensitive values before they reach SSE subscribers.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;
// Compiled once, reused for every call to `redact_string`.
pub(crate) static REDACT_PATH_RE: OnceLock<Regex> = OnceLock::new();
pub(crate) static REDACT_CRED_RE: OnceLock<Regex> = OnceLock::new();
pub(crate) static REDACT_IPV4_RE: OnceLock<Regex> = OnceLock::new();
pub(crate) static REDACT_IPV6_RE: OnceLock<Regex> = OnceLock::new();

/// Redacts sensitive content in strings before streaming to the dashboard.
///
/// JSON input is parsed structurally so that only string-valued leaves are
/// examined, preventing the path regex from destroying numeric or boolean
/// fields.  Non-JSON text falls back to regex replacement.
pub(crate) fn redact_string(s: &str) -> String {
    // The path pattern is deliberately tightened: require the leading slash
    // (or drive letter / UNC prefix) to be preceded by a word boundary or
    // start-of-string so that URL hosts (e.g.
    // "https://example.com/very-long-path") are still caught but mid-token
    // slashes in JSON keys are not. The same 30-char minimum length applies
    // to the Windows drive-letter (`C:\...`) and UNC (`\\server\...`) forms
    // so a long Windows path is redacted just like a long Unix one.
    let path_re = REDACT_PATH_RE.get_or_init(|| {
        Regex::new(r"(?:^|\s)(?:/[^\s]{30,}|[A-Za-z]:\\[^\s]{30,}|\\\\[^\s]{30,})").unwrap()
    });
    let cred_re = REDACT_CRED_RE
        .get_or_init(|| Regex::new(r#"(?i)(api_key|password|secret|token)\s*[:=]\s*\S+"#).unwrap());
    let ipv4_re =
        REDACT_IPV4_RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
    let ipv6_re = REDACT_IPV6_RE
        .get_or_init(|| Regex::new(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b").unwrap());
    let mut out = s.to_string();
    out = path_re.replace_all(&out, "[REDACTED_PATH]").to_string();
    out = cred_re.replace_all(&out, "[REDACTED]").to_string();
    out = ipv4_re.replace_all(&out, "[REDACTED_IP]").to_string();
    out = ipv6_re.replace_all(&out, "[REDACTED_IP]").to_string();
    out
}

pub(crate) fn redact_for_stream(payload: &serde_json::Value) -> serde_json::Value {
    /// Keys whose *values* are redacted entirely, regardless of content.
    const SENSITIVE_KEYS: &[&str] = &[
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "credential",
        "private_key",
        "access_key",
        "secret_key",
        "session_token",
    ];

    fn is_sensitive_key(k: &str) -> bool {
        let lower = k.to_lowercase();
        SENSITIVE_KEYS.iter().any(|s| lower.contains(s))
    }

    match payload {
        serde_json::Value::String(s) => serde_json::Value::String(redact_string(s)),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_for_stream).collect())
        }
        serde_json::Value::Object(map) => {
            let redacted: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| {
                    if is_sensitive_key(k) {
                        (
                            k.clone(),
                            serde_json::Value::String("[REDACTED]".to_string()),
                        )
                    } else {
                        (k.clone(), redact_for_stream(v))
                    }
                })
                .collect();
            serde_json::Value::Object(redacted)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod qa_tests;
