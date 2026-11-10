//! The goal itself, before the loop starts: banned commands, injection
//! phrases and encoded payloads.

use super::*;

impl Tripwire {
    /// Scan a raw user prompt for embedded dangerous patterns.
    ///
    /// This is a defense-in-depth check that runs **before** the cognitive loop
    /// even starts.  It catches adversarial prompts that contain banned command
    /// patterns, prompt-injection markers, or exfiltration keywords - regardless
    /// of whether the LLM would actually propose a matching action.
    ///
    /// Returns `Ok(())` for benign prompts, or `Err(TripwireError::BannedCommand(..))`
    /// when a dangerous pattern is detected.
    pub fn scan_prompt(&self, prompt: &str) -> Result<(), TripwireError> {
        let lower = prompt.to_lowercase();

        // 1. Check against configured banned command patterns, as whole words
        //    the way commands are checked: "dd" bans `dd`, not "address".
        for banned in &self.banned_command_patterns {
            let banned_lower = banned.to_lowercase();
            if banned_pattern_matches(&lower, &banned_lower) {
                return Err(TripwireError::BannedCommand(format!(
                    "prompt contains banned pattern '{banned}'"
                )));
            }
        }

        // 2. Detect common prompt-injection / exfiltration markers.
        static DANGEROUS_PHRASES: &[&str] = &[
            "ignore all previous",
            "ignore your instructions",
            "disregard all previous",
            "override your system prompt",
            "you are now in maintenance mode",
            "disable all security",
            "do anything now",
            "exfiltrate",
            "/etc/shadow",
            "/etc/passwd",
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "169.254.169.254",
        ];
        for phrase in DANGEROUS_PHRASES {
            if lower.contains(phrase) {
                return Err(TripwireError::BannedCommand(format!(
                    "prompt contains dangerous phrase '{phrase}'"
                )));
            }
        }

        // 3. Detect Base64 / Hex encoded smuggling.
        //    Attackers encode shell commands or URLs in Base64 or hex to evade
        //    the regex-based banned-pattern and dangerous-phrase checks above.
        //    Flag any contiguous encoded blob that exceeds a plausible "random
        //    noise" threshold (32+ Base64 chars = 8+ groups of 4, or 32+ hex
        //    chars = 16+ pairs of 2).
        static B64_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        static HEX_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let b64_re = B64_RE.get_or_init(|| {
            // Match 8+ groups-of-4 Base64 chars, an optional 2-3 char remainder,
            // and optional `=` padding.  Trailing `\b` is omitted because `=` is
            // a non-word char and would prevent the boundary from matching when
            // the blob is followed by whitespace.
            Regex::new(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2,3})?={0,2}")
                .expect("invalid b64 scanner pattern")
        });
        let hex_re = HEX_RE.get_or_init(|| {
            Regex::new(r"\b(?:[0-9a-fA-F]{2}){16,}\b").expect("invalid hex scanner pattern")
        });
        if b64_re
            .find_iter(prompt)
            .any(|m| is_suspected_base64_payload(m.as_str()))
        {
            return Err(TripwireError::BannedCommand(
                "prompt contains suspected base64-encoded payload".to_string(),
            ));
        }
        if hex_re.is_match(prompt) {
            return Err(TripwireError::BannedCommand(
                "prompt contains suspected hex-encoded payload".to_string(),
            ));
        }

        Ok(())
    }
}

/// A long run of base64 characters in a prompt. Filesystem paths are such runs
/// too (letters, digits and `/`), so one with two or more `/` separators counts
/// only if it decodes to readable text, as a smuggled command or URL does; a
/// path decodes to noise. A run with at most one `/` counts as before, binary
/// payloads included.
pub(super) fn is_suspected_base64_payload(run: &str) -> bool {
    if run.bytes().filter(|&b| b == b'/').count() <= 1 {
        return true;
    }
    use base64::Engine as _;
    let core = run.trim_end_matches('=');
    let padded = format!("{core}{}", "=".repeat((4 - core.len() % 4) % 4));
    base64::engine::general_purpose::STANDARD
        .decode(padded)
        .is_ok_and(|bytes| {
            let readable = bytes
                .iter()
                .filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t')
                .count();
            bytes.len() >= 12 && readable * 10 >= bytes.len() * 9
        })
}
