use super::*;
use serde_json::json;

#[test]
fn empty_string_is_unchanged() {
    assert_eq!(redact_string(""), "");
}

#[test]
fn unicode_text_without_secrets_passes_through() {
    let s = "日本語のメッセージ 🔒 café";
    assert_eq!(redact_string(s), s);
}

#[test]
fn a_long_unix_path_is_redacted() {
    let out = redact_string("report at /home/alice/projects/ecto/very/long/path/report.txt");
    assert!(out.contains("[REDACTED_PATH]"));
    assert!(!out.contains("alice"));
}

#[test]
fn credential_like_phrases_are_redacted() {
    for phrase in [
        "api_key=sk-abcdef1234567890",
        "password: hunter2",
        "secret=xyz",
    ] {
        assert!(redact_string(phrase).contains("[REDACTED]"), "{phrase}");
    }
}

#[test]
fn ipv4_and_ipv6_addresses_are_redacted() {
    assert!(redact_string("connect to 10.0.0.5 now").contains("[REDACTED_IP]"));
    assert!(redact_string("connect to fe80::1 now").contains("[REDACTED_IP]"));
}

#[test]
fn a_windows_style_path_is_redacted_like_a_unix_path() {
    let out = redact_string(
        "report at C:\\Users\\alice\\project\\very\\long\\path\\that\\exceeds\\thirty.txt",
    );
    assert!(out.contains("[REDACTED_PATH]"));
    assert!(!out.contains("alice"));
}

#[test]
fn a_long_unc_path_is_redacted() {
    let out =
        redact_string(r"share at \\fileserver\shared\projects\ecto\very\long\path\report.txt");
    assert!(out.contains("[REDACTED_PATH]"));
    assert!(!out.contains("fileserver"));
}

#[test]
fn a_short_windows_drive_path_is_not_redacted() {
    let out = redact_string("log at C:\\temp\\a.txt");
    assert_eq!(out, "log at C:\\temp\\a.txt");
}

#[test]
fn an_ordinary_url_is_not_redacted() {
    let out = redact_string("see https://example.com/docs for details");
    assert_eq!(out, "see https://example.com/docs for details");
}

#[test]
fn a_short_string_is_untouched() {
    let out = redact_string("status: ok, 42 items");
    assert_eq!(out, "status: ok, 42 items");
}

#[test]
fn empty_json_value_round_trips() {
    assert_eq!(redact_for_stream(&json!(null)), json!(null));
    assert_eq!(redact_for_stream(&json!({})), json!({}));
    assert_eq!(redact_for_stream(&json!("")), json!(""));
}

#[test]
fn unicode_values_are_preserved_when_not_sensitive() {
    let input = json!({ "message": "こんにちは 🌍" });
    assert_eq!(redact_for_stream(&input), input);
}

#[test]
fn nested_objects_and_arrays_are_redacted_recursively() {
    let input = json!({
        "outer": {
            "items": [
                { "secret": "s3cr3t" },
                { "note": "fine /home/bob/some/very/long/path/here.txt" }
            ]
        }
    });
    let out = redact_for_stream(&input);
    assert_eq!(out["outer"]["items"][0]["secret"], json!("[REDACTED]"));
    assert!(
        out["outer"]["items"][1]["note"]
            .as_str()
            .unwrap()
            .contains("[REDACTED_PATH]")
    );
}

#[test]
fn a_sensitive_key_with_a_non_string_value_is_still_fully_redacted() {
    let input = json!({ "tokens": 150, "secret": { "nested": true } });
    let out = redact_for_stream(&input);
    assert_eq!(out["tokens"], json!("[REDACTED]"));
    assert_eq!(out["secret"], json!("[REDACTED]"));
}

#[test]
fn sensitive_key_match_is_a_substring_match_not_an_exact_match() {
    let input = json!({ "my_api_key_backup": "value", "authorization_header": "value" });
    let out = redact_for_stream(&input);
    assert_eq!(out["my_api_key_backup"], json!("[REDACTED]"));
    assert_eq!(out["authorization_header"], json!("[REDACTED]"));
}
