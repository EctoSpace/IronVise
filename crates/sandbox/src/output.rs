//! Shared output formatting for all execution tiers (host, Docker, Firecracker).
//!
//! Every tier MUST return observations in the same canonical format so the
//! cognitive loop / LLM sees a consistent interface regardless of where a
//! command ran.  This module provides `format_sandbox_output` for that purpose,
//! plus the shared byte-cap constants consumed by each tier.

/// Maximum bytes of stdout or stderr forwarded to the cognitive loop.
/// Larger output is truncated with a trailing `...` marker.
pub const CMD_MAX_OUTPUT_BYTES: usize = 32 * 1024;

/// Trim a string to at most `max_bytes`, splitting on a UTF-8 char boundary.
/// Appends `...` when truncation occurs.
pub fn trim_to_max(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}...", &s[..boundary])
}

/// Canonical observation format shared by all execution tiers.
///
/// Both `stdout` and `stderr` are trimmed to [`CMD_MAX_OUTPUT_BYTES`] and
/// trailing whitespace is stripped.  The resulting string always contains all
/// three fields (`exit_code`, `stdout`, `stderr`) so callers can parse
/// observations with a single regex regardless of tier.
pub fn format_sandbox_output(exit_code: Option<i32>, stdout: &str, stderr: &str) -> String {
    let out_trim = trim_to_max(stdout.trim_end(), CMD_MAX_OUTPUT_BYTES);
    let err_trim = trim_to_max(stderr.trim_end(), CMD_MAX_OUTPUT_BYTES);
    format!("exit_code: {exit_code:?}; stdout: {out_trim}; stderr: {err_trim}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_includes_all_fields() {
        let out = format_sandbox_output(Some(0), "hello", "");
        assert!(out.starts_with("exit_code: Some(0)"));
        assert!(out.contains("stdout: hello"));
        assert!(out.contains("stderr: "));
    }

    #[test]
    fn format_trims_large_stdout() {
        let big = "x".repeat(CMD_MAX_OUTPUT_BYTES + 100);
        let out = format_sandbox_output(Some(0), &big, "");
        assert!(out.contains("..."));
        assert!(out.len() < CMD_MAX_OUTPUT_BYTES * 3);
    }

    #[test]
    fn format_trims_large_stderr() {
        let big = "e".repeat(CMD_MAX_OUTPUT_BYTES + 200);
        let out = format_sandbox_output(Some(1), "", &big);
        assert!(out.contains("..."));
    }

    #[test]
    fn format_none_exit_code() {
        let out = format_sandbox_output(None, "out", "err");
        assert!(out.starts_with("exit_code: None"));
    }

    #[test]
    fn trim_to_max_noop_when_small() {
        assert_eq!(trim_to_max("abc", 10), "abc");
    }

    #[test]
    fn trim_to_max_truncates() {
        let result = trim_to_max("abcdefgh", 4);
        assert_eq!(result, "abcd...");
    }

    #[test]
    fn trim_to_max_respects_char_boundary() {
        // é is 2 bytes in UTF-8; cutting at byte 3 would split it
        let result = trim_to_max("aé", 2);
        // Should back up to byte 1
        assert_eq!(result, "a...");
    }

    #[test]
    fn trim_to_max_on_an_empty_string_appends_nothing() {
        assert_eq!(trim_to_max("", 0), "");
        assert_eq!(trim_to_max("", 10), "");
    }

    #[test]
    fn trim_to_max_of_zero_still_appends_the_marker() {
        assert_eq!(trim_to_max("abc", 0), "...");
    }

    #[test]
    fn trim_to_max_at_the_exact_byte_length_is_not_truncated() {
        assert_eq!(trim_to_max("abcd", 4), "abcd");
    }

    #[test]
    fn trim_to_max_one_byte_over_the_length_truncates() {
        assert_eq!(trim_to_max("abcd", 3), "abc...");
    }

    #[test]
    fn trim_to_max_backs_up_over_a_multibyte_character_straddling_the_boundary() {
        // The firework emoji is a single 4-byte UTF-8 scalar sitting between
        // two single-byte ASCII characters, at byte offsets 1..=4.
        let s = "a\u{1F389}b";
        assert_eq!(s.len(), 6);

        assert_eq!(trim_to_max(s, 0), "...");
        assert_eq!(trim_to_max(s, 1), "a...");
        assert_eq!(trim_to_max(s, 2), "a...");
        assert_eq!(trim_to_max(s, 3), "a...");
        assert_eq!(trim_to_max(s, 4), "a...");
        assert_eq!(trim_to_max(s, 5), "a\u{1F389}...");
        assert_eq!(trim_to_max(s, 6), s);
    }

    #[test]
    fn trim_to_max_handles_the_replacement_characters_from_lossy_invalid_utf8() {
        // Two lone invalid bytes each become their own 3-byte U+FFFD when
        // decoded lossily, exactly as the Docker/Firecracker output paths do.
        let s = String::from_utf8_lossy(&[0xFF, 0xFE, b'a']).into_owned();
        assert_eq!(s, "\u{FFFD}\u{FFFD}a");
        assert_eq!(s.len(), 7);

        assert_eq!(trim_to_max(&s, 0), "...");
        assert_eq!(trim_to_max(&s, 2), "...");
        assert_eq!(trim_to_max(&s, 3), "\u{FFFD}...");
        assert_eq!(trim_to_max(&s, 5), "\u{FFFD}...");
        assert_eq!(trim_to_max(&s, 6), "\u{FFFD}\u{FFFD}...");
        assert_eq!(trim_to_max(&s, 7), s);
    }
}
