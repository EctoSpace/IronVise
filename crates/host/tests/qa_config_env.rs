use ectoledger::config::{
    bind_host, bind_port, canonical_allowed_prefixes, cors_extra_origins, database_pool_size,
    guard_denial_limit, justification_failure_limit, key_rotation_interval_steps, llm_timeout_secs,
    max_steps, session_rate_limit_burst, session_rate_limit_per_second, sse_keepalive_secs,
    sse_rate_limit_burst, sse_rate_limit_per_second, token_budget_max, vc_audience, webhook_config,
    webhook_hmac_secret, webhook_include_guard, webhook_include_tripwire, webhook_legacy_signature,
    webhook_rate_limit_per_second,
};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_var<T>(key: &str, value: &str, f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let previous = std::env::var(key).ok();
    // SAFETY: serialised by ENV_LOCK for the duration of this call.
    unsafe { std::env::set_var(key, value) };
    let result = f();
    match previous {
        // SAFETY: serialised by ENV_LOCK for the duration of this call.
        Some(v) => unsafe { std::env::set_var(key, v) },
        None => unsafe { std::env::remove_var(key) },
    }
    result
}

fn without_var<T>(key: &str, f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let previous = std::env::var(key).ok();
    // SAFETY: serialised by ENV_LOCK for the duration of this call.
    unsafe { std::env::remove_var(key) };
    let result = f();
    if let Some(v) = previous {
        // SAFETY: serialised by ENV_LOCK for the duration of this call.
        unsafe { std::env::set_var(key, v) };
    }
    result
}

mod numeric_fallback_on_malformed_env {
    use super::*;

    #[test]
    fn guard_denial_limit_falls_back_to_default_on_garbage() {
        assert_eq!(
            with_var(
                "AGENT_GUARD_DENIAL_LIMIT",
                "not-a-number",
                guard_denial_limit
            ),
            3
        );
    }

    #[test]
    fn justification_failure_limit_falls_back_to_default_on_garbage() {
        assert_eq!(
            with_var(
                "AGENT_JUSTIFICATION_FAILURE_LIMIT",
                "nope",
                justification_failure_limit
            ),
            3
        );
    }

    #[test]
    fn max_steps_falls_back_to_default_on_garbage() {
        assert_eq!(with_var("AGENT_MAX_STEPS", "lots", max_steps), 20);
    }

    #[test]
    fn max_steps_falls_back_to_default_on_negative_value() {
        assert_eq!(with_var("AGENT_MAX_STEPS", "-5", max_steps), 20);
    }

    #[test]
    fn token_budget_max_is_none_on_garbage() {
        assert_eq!(
            with_var("AGENT_TOKEN_BUDGET_MAX", "unlimited", token_budget_max),
            None
        );
    }

    #[test]
    fn token_budget_max_parses_a_valid_value() {
        assert_eq!(
            with_var("AGENT_TOKEN_BUDGET_MAX", "4096", token_budget_max),
            Some(4096)
        );
    }

    #[test]
    fn webhook_rate_limit_falls_back_to_default_on_garbage() {
        assert_eq!(
            with_var(
                "WEBHOOK_RATE_LIMIT_PER_SECOND",
                "fast",
                webhook_rate_limit_per_second
            ),
            10
        );
    }

    #[test]
    fn session_rate_limit_per_second_falls_back_to_default_on_garbage() {
        assert_eq!(
            with_var(
                "SESSION_RATE_LIMIT_PER_SECOND",
                "x",
                session_rate_limit_per_second
            ),
            2
        );
    }

    #[test]
    fn session_rate_limit_burst_falls_back_to_default_on_garbage() {
        assert_eq!(
            with_var("SESSION_RATE_LIMIT_BURST", "x", session_rate_limit_burst),
            5
        );
    }

    #[test]
    fn sse_keepalive_secs_falls_back_to_default_on_garbage() {
        assert_eq!(with_var("SSE_KEEPALIVE_SECS", "x", sse_keepalive_secs), 15);
    }

    #[test]
    fn sse_rate_limit_per_second_falls_back_to_default_on_garbage() {
        assert_eq!(
            with_var("SSE_RATE_LIMIT_PER_SECOND", "x", sse_rate_limit_per_second),
            4
        );
    }

    #[test]
    fn sse_rate_limit_burst_falls_back_to_default_on_garbage() {
        assert_eq!(
            with_var("SSE_RATE_LIMIT_BURST", "x", sse_rate_limit_burst),
            10
        );
    }
}

mod key_rotation_interval {
    use super::*;

    #[test]
    fn unset_is_disabled() {
        assert_eq!(
            without_var("AGENT_KEY_ROTATION_STEPS", key_rotation_interval_steps),
            None
        );
    }

    #[test]
    fn zero_is_treated_as_disabled_not_an_infinite_loop() {
        assert_eq!(
            with_var("AGENT_KEY_ROTATION_STEPS", "0", key_rotation_interval_steps),
            None
        );
    }

    #[test]
    fn garbage_is_disabled() {
        assert_eq!(
            with_var(
                "AGENT_KEY_ROTATION_STEPS",
                "often",
                key_rotation_interval_steps
            ),
            None
        );
    }

    #[test]
    fn a_positive_value_is_honoured() {
        assert_eq!(
            with_var(
                "AGENT_KEY_ROTATION_STEPS",
                "50",
                key_rotation_interval_steps
            ),
            Some(50)
        );
    }
}

mod llm_timeout {
    use super::*;

    #[test]
    fn unset_defaults_to_300() {
        assert_eq!(without_var("ECTO_LLM_TIMEOUT_SECS", llm_timeout_secs), 300);
    }

    #[test]
    fn zero_falls_back_to_the_default_instead_of_an_instant_timeout() {
        assert_eq!(
            with_var("ECTO_LLM_TIMEOUT_SECS", "0", llm_timeout_secs),
            300
        );
    }

    #[test]
    fn garbage_falls_back_to_the_default() {
        assert_eq!(
            with_var("ECTO_LLM_TIMEOUT_SECS", "forever", llm_timeout_secs),
            300
        );
    }

    #[test]
    fn negative_falls_back_to_the_default() {
        assert_eq!(
            with_var("ECTO_LLM_TIMEOUT_SECS", "-5", llm_timeout_secs),
            300
        );
    }

    #[test]
    fn whitespace_falls_back_to_the_default() {
        assert_eq!(
            with_var("ECTO_LLM_TIMEOUT_SECS", "  300  ", llm_timeout_secs),
            300
        );
    }

    #[test]
    fn a_positive_value_is_honoured() {
        assert_eq!(
            with_var("ECTO_LLM_TIMEOUT_SECS", "120", llm_timeout_secs),
            120
        );
    }
}

mod bind_port_contract {
    use super::*;

    #[test]
    fn unset_defaults_to_3000() {
        assert_eq!(without_var("ECTO_BIND_PORT", bind_port), 3000);
    }

    #[test]
    fn a_valid_port_is_honoured() {
        assert_eq!(with_var("ECTO_BIND_PORT", "8080", bind_port), 8080);
    }

    #[test]
    fn zero_is_honoured_for_os_assigned_ports() {
        assert_eq!(with_var("ECTO_BIND_PORT", "0", bind_port), 0);
    }

    #[test]
    #[should_panic(expected = "is not a valid u16 port number")]
    fn a_non_numeric_value_panics_rather_than_silently_falling_back() {
        with_var("ECTO_BIND_PORT", "not-a-port", bind_port);
    }

    #[test]
    #[should_panic(expected = "is not a valid u16 port number")]
    fn a_value_above_u16_range_panics() {
        with_var("ECTO_BIND_PORT", "99999", bind_port);
    }
}

mod bind_host_and_cors {
    use super::*;

    #[test]
    fn bind_host_defaults_to_loopback() {
        assert_eq!(without_var("ECTO_BIND_HOST", bind_host), "127.0.0.1");
    }

    #[test]
    fn cors_extra_origins_defaults_to_empty() {
        assert_eq!(
            without_var("ECTO_CORS_ALLOWED_ORIGINS", cors_extra_origins),
            Vec::<String>::new()
        );
    }

    #[test]
    fn cors_extra_origins_trims_entries_and_drops_blanks() {
        let origins = with_var(
            "ECTO_CORS_ALLOWED_ORIGINS",
            "https://a.example, , https://b.example ,",
            cors_extra_origins,
        );
        assert_eq!(origins, vec!["https://a.example", "https://b.example"]);
    }
}

mod webhook_config_construction {
    use super::*;

    #[test]
    fn unset_webhook_url_disables_egress() {
        let result = without_var("WEBHOOK_URL", webhook_config);
        assert!(result.is_none());
    }

    #[test]
    fn empty_webhook_url_is_treated_as_unset() {
        let result = with_var("WEBHOOK_URL", "", webhook_config);
        assert!(result.is_none());
    }

    #[test]
    fn a_set_webhook_url_defaults_to_json_format_with_no_bearer_token() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous_url = std::env::var("WEBHOOK_URL").ok();
        let previous_token = std::env::var("WEBHOOK_BEARER_TOKEN").ok();
        let previous_format = std::env::var("SIEM_FORMAT").ok();
        // SAFETY: serialised by ENV_LOCK for the duration of this test.
        unsafe {
            std::env::set_var("WEBHOOK_URL", "https://siem.example/ingest");
            std::env::remove_var("WEBHOOK_BEARER_TOKEN");
            std::env::remove_var("SIEM_FORMAT");
        }
        let config = webhook_config().unwrap();
        assert_eq!(config.url, "https://siem.example/ingest");
        assert_eq!(config.bearer_token, None);
        assert_eq!(config.siem_format, "json");
        // SAFETY: serialised by ENV_LOCK; restoring prior state.
        unsafe {
            match previous_url {
                Some(v) => std::env::set_var("WEBHOOK_URL", v),
                None => std::env::remove_var("WEBHOOK_URL"),
            }
            match previous_token {
                Some(v) => std::env::set_var("WEBHOOK_BEARER_TOKEN", v),
                None => std::env::remove_var("WEBHOOK_BEARER_TOKEN"),
            }
            match previous_format {
                Some(v) => std::env::set_var("SIEM_FORMAT", v),
                None => std::env::remove_var("SIEM_FORMAT"),
            }
        }
    }

    #[test]
    fn an_empty_bearer_token_is_treated_as_absent() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous_url = std::env::var("WEBHOOK_URL").ok();
        let previous_token = std::env::var("WEBHOOK_BEARER_TOKEN").ok();
        // SAFETY: serialised by ENV_LOCK for the duration of this test.
        unsafe {
            std::env::set_var("WEBHOOK_URL", "https://siem.example/ingest");
            std::env::set_var("WEBHOOK_BEARER_TOKEN", "");
        }
        let config = webhook_config().unwrap();
        assert_eq!(config.bearer_token, None);
        // SAFETY: serialised by ENV_LOCK; restoring prior state.
        unsafe {
            match previous_url {
                Some(v) => std::env::set_var("WEBHOOK_URL", v),
                None => std::env::remove_var("WEBHOOK_URL"),
            }
            match previous_token {
                Some(v) => std::env::set_var("WEBHOOK_BEARER_TOKEN", v),
                None => std::env::remove_var("WEBHOOK_BEARER_TOKEN"),
            }
        }
    }
}

mod webhook_secret_and_audience_trimming {
    use super::*;

    #[test]
    fn webhook_hmac_secret_empty_is_disabled() {
        assert_eq!(
            with_var("WEBHOOK_HMAC_SECRET", "", webhook_hmac_secret),
            None
        );
    }

    #[test]
    fn webhook_hmac_secret_present_is_returned_verbatim() {
        assert_eq!(
            with_var("WEBHOOK_HMAC_SECRET", "s3cr3t", webhook_hmac_secret),
            Some("s3cr3t".to_string())
        );
    }

    #[test]
    fn vc_audience_whitespace_only_is_none() {
        assert_eq!(with_var("ECTO_VC_AUDIENCE", "   ", vc_audience), None);
    }

    #[test]
    fn vc_audience_is_trimmed() {
        assert_eq!(
            with_var("ECTO_VC_AUDIENCE", "  my-aud  ", vc_audience),
            Some("my-aud".to_string())
        );
    }
}

mod webhook_legacy_signature_parsing {
    use super::*;

    #[test]
    fn unset_is_disabled() {
        assert!(!without_var(
            "WEBHOOK_LEGACY_SIGNATURE",
            webhook_legacy_signature
        ));
    }

    #[test]
    fn uppercase_true_is_honoured() {
        assert!(with_var(
            "WEBHOOK_LEGACY_SIGNATURE",
            "TRUE",
            webhook_legacy_signature
        ));
    }

    #[test]
    fn yes_is_honoured() {
        assert!(with_var(
            "WEBHOOK_LEGACY_SIGNATURE",
            "yes",
            webhook_legacy_signature
        ));
    }

    #[test]
    fn garbage_is_disabled() {
        assert!(!with_var(
            "WEBHOOK_LEGACY_SIGNATURE",
            "sure",
            webhook_legacy_signature
        ));
    }
}

mod webhook_include_flags_case_sensitivity {
    use super::*;

    #[test]
    fn unset_includes_by_default() {
        assert!(without_var("WEBHOOK_INCLUDE_GUARD", webhook_include_guard));
        assert!(without_var(
            "WEBHOOK_INCLUDE_TRIPWIRE",
            webhook_include_tripwire
        ));
    }

    #[test]
    fn lowercase_false_excludes() {
        assert!(!with_var(
            "WEBHOOK_INCLUDE_GUARD",
            "false",
            webhook_include_guard
        ));
        assert!(!with_var(
            "WEBHOOK_INCLUDE_TRIPWIRE",
            "false",
            webhook_include_tripwire
        ));
    }

    #[test]
    fn the_digit_zero_excludes() {
        assert!(!with_var(
            "WEBHOOK_INCLUDE_GUARD",
            "0",
            webhook_include_guard
        ));
    }

    #[test]
    fn uppercase_false_also_excludes() {
        assert!(!with_var(
            "WEBHOOK_INCLUDE_GUARD",
            "FALSE",
            webhook_include_guard
        ));
    }
}

mod database_pool_size_clamp {
    use super::*;

    #[test]
    fn an_excessive_value_is_clamped_to_the_upper_bound() {
        assert_eq!(
            with_var("DATABASE_POOL_SIZE", "100000", database_pool_size),
            50
        );
    }

    #[test]
    fn a_tiny_value_is_clamped_to_the_lower_bound() {
        assert_eq!(with_var("DATABASE_POOL_SIZE", "1", database_pool_size), 5);
    }

    #[test]
    fn zero_is_clamped_to_the_lower_bound() {
        assert_eq!(with_var("DATABASE_POOL_SIZE", "0", database_pool_size), 5);
    }

    #[test]
    fn garbage_falls_back_to_the_cpu_based_default_within_bounds() {
        let size = with_var("DATABASE_POOL_SIZE", "not-a-number", database_pool_size);
        assert!((5..=50).contains(&size));
    }

    #[test]
    fn a_mid_range_value_passes_through_unclamped() {
        assert_eq!(with_var("DATABASE_POOL_SIZE", "17", database_pool_size), 17);
    }
}

mod canonical_allowed_prefixes_behaviour {
    use super::*;

    #[test]
    fn empty_and_whitespace_entries_are_dropped() {
        let result = canonical_allowed_prefixes(&["".to_string(), "   ".to_string()]);
        assert!(result.is_empty());
    }

    #[test]
    fn a_nonexistent_path_falls_back_to_the_raw_path_instead_of_erroring() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist-yet");
        let result = canonical_allowed_prefixes(&[missing.to_string_lossy().to_string()]);
        assert_eq!(result, vec![missing]);
    }

    #[test]
    fn an_existing_path_is_canonicalized() {
        let dir = tempfile::tempdir().unwrap();
        let result = canonical_allowed_prefixes(&[dir.path().to_string_lossy().to_string()]);
        assert_eq!(result, vec![dir.path().canonicalize().unwrap()]);
    }
}

mod load_tripwire_config_defaults_and_invalid_file {
    use ectoledger::config::{load_tripwire_config, tripwire_config_path};
    use std::sync::Mutex;

    static DATA_DIR_LOCK: Mutex<()> = Mutex::new(());

    struct IsolatedDataDir {
        _dir: tempfile::TempDir,
        previous: Option<String>,
    }

    impl IsolatedDataDir {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let previous = std::env::var("ECTO_DATA_DIR").ok();
            // SAFETY: caller holds DATA_DIR_LOCK for the lifetime of this guard.
            unsafe { std::env::set_var("ECTO_DATA_DIR", dir.path()) };
            Self {
                _dir: dir,
                previous,
            }
        }
    }

    impl Drop for IsolatedDataDir {
        fn drop(&mut self) {
            match self.previous.take() {
                // SAFETY: caller holds DATA_DIR_LOCK for the lifetime of this guard.
                Some(v) => unsafe { std::env::set_var("ECTO_DATA_DIR", v) },
                None => unsafe { std::env::remove_var("ECTO_DATA_DIR") },
            }
        }
    }

    #[test]
    fn missing_file_falls_back_to_defaults() {
        let _lock = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _isolated = IsolatedDataDir::new();
        let cfg = load_tripwire_config();
        assert_eq!(cfg.min_justification_length, 5);
        assert!(cfg.require_https);
        assert!(cfg.allowed_mcp_tools.is_empty());
        assert_eq!(cfg.allowed_paths.len(), 1);
    }

    #[test]
    #[should_panic(expected = "has invalid JSON syntax")]
    fn invalid_json_in_the_file_panics_rather_than_silently_using_defaults() {
        let _lock = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _isolated = IsolatedDataDir::new();
        let path = tripwire_config_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not valid json").unwrap();
        load_tripwire_config();
    }
}
