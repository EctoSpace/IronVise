use super::*;

/// The table from the release plan: the exact strings LM Studio,
/// llama.cpp and OpenAI put in front of their users. Row 3 is the
/// regression - it is what every local-server UI prints, and appending
/// `/v1` to it unconditionally is what produced `/v1/v1` and a 404.
#[test]
fn normalises_the_urls_users_actually_paste() {
    let cases = [
        ("http://localhost:1234", "http://localhost:1234/v1"),
        ("http://localhost:1234/", "http://localhost:1234/v1"),
        ("http://localhost:1234/v1", "http://localhost:1234/v1"),
        ("http://localhost:1234/v1/", "http://localhost:1234/v1"),
        ("https://api.openai.com", "https://api.openai.com/v1"),
    ];
    for (input, want) in cases {
        assert_eq!(normalize_openai_base(input), want, "input: {input:?}");
    }
}

#[test]
fn is_idempotent() {
    // Normalising an already-normalised URL must not add a second segment.
    for input in [
        "http://localhost:1234",
        "http://localhost:1234/v1",
        "https://api.openai.com/",
    ] {
        let once = normalize_openai_base(input);
        assert_eq!(normalize_openai_base(&once), once, "input: {input:?}");
    }
}

#[test]
fn strips_a_pasted_full_endpoint() {
    // Server UIs show a curl example against the full route; users paste it
    // into a field labelled "base URL".
    for input in [
        "http://localhost:1234/v1/chat/completions",
        "http://localhost:1234/v1/chat/completions/",
    ] {
        assert_eq!(normalize_openai_base(input), "http://localhost:1234/v1");
    }
    // Without the version segment, the route still comes off and /v1 is added.
    assert_eq!(
        normalize_openai_base("http://localhost:1234/chat/completions"),
        "http://localhost:1234/v1"
    );
}

#[test]
fn surrounding_whitespace_is_ignored() {
    assert_eq!(
        normalize_openai_base("  http://localhost:1234/v1 \n"),
        "http://localhost:1234/v1"
    );
}

#[test]
fn collapses_repeated_trailing_slashes() {
    assert_eq!(
        normalize_openai_base("http://localhost:1234///"),
        "http://localhost:1234/v1"
    );
    assert_eq!(
        normalize_openai_base("http://localhost:1234/v1//"),
        "http://localhost:1234/v1"
    );
}

#[test]
fn a_v1_prefixed_path_is_preserved() {
    // Reverse proxies commonly mount the API under a sub-path.
    assert_eq!(
        normalize_openai_base("https://gateway.example.com/openai/v1"),
        "https://gateway.example.com/openai/v1"
    );
    assert_eq!(
        normalize_openai_base("https://gateway.example.com/openai"),
        "https://gateway.example.com/openai/v1"
    );
}

#[test]
fn only_a_whole_v1_segment_counts_as_versioned() {
    // `v1` must be the entire final segment, not a suffix of it, or these
    // would be left unversioned and 404 on the real route.
    assert_eq!(
        normalize_openai_base("https://apiv1.example.com"),
        "https://apiv1.example.com/v1"
    );
    assert_eq!(
        normalize_openai_base("https://example.com/openai-v1"),
        "https://example.com/openai-v1/v1"
    );
}

#[test]
fn uppercase_version_segment_is_recognised() {
    assert_eq!(
        normalize_openai_base("http://localhost:1234/V1"),
        "http://localhost:1234/V1"
    );
}

#[test]
fn empty_input_stays_empty() {
    // The caller distinguishes "unset" from "set to something odd"; do not
    // invent a host here.
    assert_eq!(normalize_openai_base(""), "");
    assert_eq!(normalize_openai_base("   "), "");
    assert_eq!(normalize_openai_base("/"), "");
    assert_eq!(normalize_openai_base("///"), "");
}

#[test]
fn chat_completions_url_never_doubles_the_version_segment() {
    // The bug this module exists to prevent, pinned at the call site.
    for input in [
        "http://localhost:1234",
        "http://localhost:1234/",
        "http://localhost:1234/v1",
        "http://localhost:1234/v1/",
    ] {
        assert_eq!(
            chat_completions_url(input),
            "http://localhost:1234/v1/chat/completions",
            "input: {input:?}"
        );
    }
    assert_eq!(
        chat_completions_url("https://api.openai.com"),
        "https://api.openai.com/v1/chat/completions"
    );
}

#[test]
fn a_base_that_already_names_its_version_is_kept() {
    for base in [
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "https://api.groq.com/openai/v1",
        "https://gateway.example.com/v2/openai",
        "https://gateway.example.com/V1/openai",
    ] {
        assert_eq!(normalize_openai_base(base), base, "input: {base:?}");
    }
    assert_eq!(
        chat_completions_url("https://generativelanguage.googleapis.com/v1beta/openai/"),
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    );
}

#[test]
fn a_version_word_in_the_host_or_a_longer_segment_is_not_a_version() {
    for (base, want) in [
        ("https://v2.example.com", "https://v2.example.com/v1"),
        (
            "https://gateway.example.com/openai-v1",
            "https://gateway.example.com/openai-v1/v1",
        ),
        (
            "https://gateway.example.com/version",
            "https://gateway.example.com/version/v1",
        ),
        (
            "https://gateway.example.com/v1gamma",
            "https://gateway.example.com/v1gamma/v1",
        ),
    ] {
        assert_eq!(normalize_openai_base(base), want, "input: {base:?}");
    }
}
