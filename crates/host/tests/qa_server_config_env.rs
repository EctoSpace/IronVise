fn with_env<T>(name: &str, value: Option<&str>, body: impl FnOnce() -> T) -> T {
    let previous = std::env::var(name).ok();
    unsafe {
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
    let result = body();
    unsafe {
        match previous {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
    result
}

#[test]
fn rate_limit_env_vars_parse_or_fall_back_to_defaults() {
    let cases: &[(&str, u64, u64)] = &[
        ("5", 5, 60),
        ("0", 0, 60),
        ("-1", 60, 60),
        ("not-a-number", 60, 60),
        ("", 60, 60),
        ("3.5", 60, 60),
        (" 5", 60, 60),
    ];
    for (raw, expected, default) in cases {
        let got = with_env(
            "API_RATE_LIMIT_PER_SECOND",
            Some(raw),
            ectoledger::config::api_rate_limit_per_second,
        );
        assert_eq!(got, *expected, "input {raw:?}, default is {default}");
    }
    let unset = with_env(
        "API_RATE_LIMIT_PER_SECOND",
        None,
        ectoledger::config::api_rate_limit_per_second,
    );
    assert_eq!(unset, 60);
}

#[test]
fn burst_env_vars_parse_or_fall_back_to_defaults() {
    let cases: &[(&str, u32)] = &[("10", 10), ("0", 0), ("-1", 120), ("abc", 120), ("", 120)];
    for (raw, expected) in cases {
        let got = with_env(
            "API_RATE_LIMIT_BURST",
            Some(raw),
            ectoledger::config::api_rate_limit_burst,
        );
        assert_eq!(got, *expected, "input {raw:?}");
    }
}

#[test]
fn session_and_sse_rate_limit_env_vars_parse_or_fall_back() {
    assert_eq!(
        with_env(
            "SESSION_RATE_LIMIT_PER_SECOND",
            Some("0"),
            ectoledger::config::session_rate_limit_per_second
        ),
        0
    );
    assert_eq!(
        with_env(
            "SESSION_RATE_LIMIT_PER_SECOND",
            Some("-3"),
            ectoledger::config::session_rate_limit_per_second
        ),
        2
    );
    assert_eq!(
        with_env(
            "SESSION_RATE_LIMIT_BURST",
            Some("nope"),
            ectoledger::config::session_rate_limit_burst
        ),
        5
    );
    assert_eq!(
        with_env(
            "SSE_RATE_LIMIT_PER_SECOND",
            Some("0"),
            ectoledger::config::sse_rate_limit_per_second
        ),
        0
    );
    assert_eq!(
        with_env(
            "SSE_RATE_LIMIT_BURST",
            Some("-5"),
            ectoledger::config::sse_rate_limit_burst
        ),
        10
    );
}
