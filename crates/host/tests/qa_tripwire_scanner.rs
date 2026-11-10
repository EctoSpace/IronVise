use ectoledger::tripwire::{
    Tripwire, TripwireError, default_banned_command_patterns, validate_path_strict,
};

fn tripwire_no_allowlist() -> Tripwire {
    Tripwire::new(
        vec![std::env::temp_dir()],
        vec!["example.com".to_string()],
        default_banned_command_patterns(),
        8,
        true,
    )
}

fn tripwire_with_allowlist(allowed: &[&str]) -> Tripwire {
    Tripwire::new(
        vec![std::env::temp_dir()],
        vec!["example.com".to_string()],
        default_banned_command_patterns(),
        8,
        true,
    )
    .with_allowed_command_executables(allowed.iter().map(|s| s.to_string()).collect())
}

fn intent_run(cmd: &str) -> ectoledger::intent::ProposedIntent {
    ectoledger::intent::ProposedIntent {
        action: "run_command".to_string(),
        params: serde_json::json!({ "command": cmd }),
        justification: "justification that is definitely long enough".to_string(),
        reasoning: "qa".to_string(),
    }
}

mod trailing_space_path_traversal {
    use super::*;

    #[test]
    fn a_trailing_space_dotdot_component_is_not_treated_as_parent_dir_up_front() {
        let dir = tempfile::tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        std::fs::create_dir_all(&allowed).unwrap();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, b"outside the allowed prefix").unwrap();

        let candidate = allowed.join(".. ").join("secret.txt");
        let result =
            validate_path_strict(candidate.to_str().unwrap(), std::slice::from_ref(&allowed));

        match result {
            Err(TripwireError::PathTraversal(_)) => {}
            Err(TripwireError::PathNotAllowed(_)) | Err(TripwireError::SymlinkEscape(_)) => {}
            Ok(resolved) => {
                let resolved_secret_bytes = std::fs::read(&resolved).ok();
                let is_actually_the_secret =
                    resolved_secret_bytes.as_deref() == Some(b"outside the allowed prefix");
                assert!(
                    !is_actually_the_secret,
                    "validate_path_strict returned Ok({}) for a trailing-space '..' \
                     component, and that path's contents are the file OUTSIDE the \
                     allowed prefix: a path-traversal bypass",
                    resolved.display()
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }
}

mod nul_and_oversized_commands {
    use super::*;

    #[test]
    fn a_nul_byte_inside_a_command_does_not_panic() {
        let tw = tripwire_with_allowlist(&["echo"]);
        let intent = intent_run("echo before\u{0}after");
        let _ = tw.validate(&intent);
    }

    #[test]
    fn a_hundred_kilobyte_command_is_rejected_or_accepted_quickly_without_panicking() {
        let tw = tripwire_no_allowlist();
        let padding = "a".repeat(100 * 1024);
        let intent = intent_run(&format!("echo {padding}"));
        let started = std::time::Instant::now();
        let _ = tw.validate(&intent);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "100KB command validation took too long: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_empty_command_string_is_rejected_as_missing_not_a_panic() {
        let tw = tripwire_no_allowlist();
        let intent = intent_run("");
        assert!(matches!(
            tw.validate(&intent),
            Err(TripwireError::MissingParam("command"))
        ));
    }

    #[test]
    fn a_whitespace_only_command_string_is_rejected_as_missing_not_a_panic() {
        let tw = tripwire_no_allowlist();
        let intent = intent_run("   ");
        assert!(matches!(
            tw.validate(&intent),
            Err(TripwireError::MissingParam("command"))
        ));
    }
}

mod percent_variable_markers {
    use super::*;

    #[test]
    fn percent_variable_syntax_is_treated_as_a_literal_token_not_expanded() {
        let tw = tripwire_with_allowlist(&["echo"]);
        let intent = intent_run("echo %USERPROFILE%");
        assert!(tw.validate(&intent).is_ok());
    }

    #[test]
    fn a_percent_wrapped_banned_word_is_still_caught_as_a_substring() {
        let tw = tripwire_no_allowlist();
        let intent = intent_run("echo %sudo%");
        assert!(matches!(
            tw.validate(&intent),
            Err(TripwireError::BannedCommand(_))
        ));
    }
}

mod cross_os_executable_resolution {
    use super::*;

    #[test]
    fn a_windows_style_absolute_path_to_a_banned_executable_is_rejected_on_any_platform() {
        let tw = tripwire_no_allowlist();
        let intent = intent_run("C:/Windows/System32/sudo.exe");
        assert!(matches!(
            tw.validate(&intent),
            Err(TripwireError::BannedCommand(_))
        ));
    }

    #[test]
    fn a_windows_style_backslash_path_is_not_mangled_before_the_banned_check() {
        let tw = tripwire_no_allowlist();
        let intent = intent_run(r"C:\Windows\System32\sudo.exe");
        assert!(matches!(
            tw.validate(&intent),
            Err(TripwireError::BannedCommand(_))
        ));
    }

    #[test]
    fn an_allowlisted_basename_matches_regardless_of_leading_path_style() {
        let tw = tripwire_with_allowlist(&["cat"]);
        let unix_style = intent_run("/usr/bin/cat file.txt");
        assert!(tw.validate(&unix_style).is_ok());
    }
}

mod banned_pattern_word_boundary {
    use super::*;

    #[test]
    fn sudo_as_a_standalone_token_is_banned() {
        let tw = tripwire_no_allowlist();
        let intent = intent_run("sudo id");
        assert!(matches!(
            tw.validate(&intent),
            Err(TripwireError::BannedCommand(_))
        ));
    }

    #[test]
    fn a_word_that_merely_starts_with_a_banned_token_is_not_banned() {
        let tw = tripwire_with_allowlist(&["sudoku"]);
        let intent = intent_run("sudoku --solve puzzle.txt");
        assert!(tw.validate(&intent).is_ok());
    }
}

mod powershell_encoded_command {
    use super::*;

    #[test]
    fn an_allowlist_blocks_powershell_encoded_command_even_though_no_banned_pattern_does() {
        let tw = tripwire_with_allowlist(&["cat", "echo"]);
        let intent = intent_run("powershell -EncodedCommand aQBkAAoA");
        assert!(matches!(
            tw.validate(&intent),
            Err(TripwireError::BannedCommand(_))
        ));
    }

    #[test]
    fn without_an_allowlist_powershell_encoded_command_is_not_caught_by_default_banned_patterns() {
        let tw = tripwire_no_allowlist();
        let intent = intent_run("powershell -EncodedCommand aQBkAAoA");
        assert!(
            tw.validate(&intent).is_ok(),
            "documenting current behaviour: banned_command_patterns alone does not \
             recognise PowerShell's -EncodedCommand; an executable allowlist is required \
             for this case"
        );
    }
}

mod output_scanner_edge_cases {
    use ectoledger::output_scanner::{ScannerSensitivity, scan_observation_with_sensitivity};

    #[test]
    fn a_large_base64_blob_in_observation_output_is_flagged() {
        let blob = "A".repeat(500);
        let result = scan_observation_with_sensitivity(
            &format!("here is some output: {blob} end"),
            ScannerSensitivity::Medium,
        );
        assert!(result.is_suspicious);
    }

    #[test]
    fn a_realistic_length_base64_secret_in_observation_output_is_flagged() {
        let blob = "QUtJQVNFQ1JFVEFDQ0VTU0tFWUVYQU1QTEUxMjM0NTY3ODkwQUJDREVGR0g=";
        let result = scan_observation_with_sensitivity(
            &format!("here is some output: {blob} end"),
            ScannerSensitivity::Medium,
        );
        assert!(result.is_suspicious);
    }

    #[test]
    fn a_hex_secret_in_observation_output_is_flagged() {
        let blob = "a".repeat(64);
        let result =
            scan_observation_with_sensitivity(&format!("token={blob}"), ScannerSensitivity::Medium);
        assert!(result.is_suspicious);
    }

    #[test]
    fn a_sha1_commit_id_is_not_flagged() {
        let blob = "d6cfa4d9a8f02527f2c3a1dc7e0e3b16e5b3b71a"; // 40 hex chars
        let result = scan_observation_with_sensitivity(
            &format!("commit {blob}"),
            ScannerSensitivity::Medium,
        );
        assert!(!result.is_suspicious);
    }

    #[test]
    fn a_uuid_is_not_flagged() {
        let blob = "123e4567-e89b-12d3-a456-426614174000";
        let result =
            scan_observation_with_sensitivity(&format!("id={blob}"), ScannerSensitivity::Medium);
        assert!(!result.is_suspicious);
    }

    #[test]
    fn a_sha256_checksum_line_without_a_key_name_is_not_flagged() {
        let digest = format!("d41d8cd98f00b204e9800998ecf8427e{}", "0".repeat(32)); // 64 hex chars
        let result = scan_observation_with_sensitivity(
            &format!("{digest}  empty.bin"),
            ScannerSensitivity::Medium,
        );
        assert!(!result.is_suspicious);
    }

    #[test]
    fn a_slash_heavy_unix_path_is_not_flagged_as_a_base64_secret() {
        let result = scan_observation_with_sensitivity(
            "building /Users/user01/git/IronVise/crates/host/src/executor",
            ScannerSensitivity::Medium,
        );
        assert!(!result.is_suspicious);
    }

    #[test]
    fn a_long_camel_case_identifier_without_digits_is_not_flagged() {
        let result = scan_observation_with_sensitivity(
            "TheQuickBrownFoxJumpsOverTheLazyDogRepeatedlyWithoutPause",
            ScannerSensitivity::Medium,
        );
        assert!(!result.is_suspicious);
    }

    #[test]
    fn ordinary_short_output_is_not_flagged() {
        let result =
            scan_observation_with_sensitivity("the file has 42 lines", ScannerSensitivity::Medium);
        assert!(!result.is_suspicious);
    }

    #[test]
    fn a_nul_byte_in_observation_output_does_not_panic() {
        let _ = scan_observation_with_sensitivity("before\u{0}after", ScannerSensitivity::Medium);
    }

    #[test]
    fn a_hundred_kilobyte_observation_is_scanned_quickly_without_panicking() {
        let big = "benign text ".repeat(10_000);
        let started = std::time::Instant::now();
        let _ = scan_observation_with_sensitivity(&big, ScannerSensitivity::High);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn right_to_left_override_character_is_flagged_like_other_zero_width_tricks() {
        let result = scan_observation_with_sensitivity(
            "safe-looking\u{202E}txt.exe",
            ScannerSensitivity::Medium,
        );
        assert!(result.is_suspicious);
    }
}
