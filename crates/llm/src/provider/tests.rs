use super::*;
use std::collections::HashSet;

#[test]
fn every_preset_from_the_config_decision_resolves() {
    // The preset list is a published config surface: dropping or renaming
    // one silently breaks the `.env` files of everyone using it.
    let expected = [
        "ollama",
        "lmstudio",
        "llamacpp",
        "vllm",
        "mlx",
        "localai",
        "openai",
        "anthropic",
        "gemini",
        "azure-openai",
        "mistral",
        "groq",
        "openrouter",
        "deepseek",
        "xai",
        "openai-compatible",
    ];
    for id in expected {
        let spec = resolve(id).unwrap_or_else(|| panic!("preset {id:?} no longer resolves"));
        assert_eq!(spec.id, id);
    }
    assert_eq!(
        PRESETS.len(),
        expected.len(),
        "a preset was added or removed without updating this contract test"
    );
}

#[test]
fn preset_ids_are_unique() {
    let ids: HashSet<_> = preset_ids().collect();
    assert_eq!(ids.len(), PRESETS.len(), "duplicate preset id");
}

#[test]
fn lookup_ignores_case_and_punctuation() {
    for spelling in ["lmstudio", "LM Studio", "lm-studio", "LM_STUDIO"] {
        assert_eq!(
            resolve(spelling).map(|s| s.id),
            Some("lmstudio"),
            "spelling: {spelling:?}"
        );
    }
    for spelling in ["llamacpp", "llama.cpp", "LLAMA_CPP", "llama-cpp-server"] {
        assert_eq!(
            resolve(spelling).map(|s| s.id),
            Some("llamacpp"),
            "spelling: {spelling:?}"
        );
    }
    assert_eq!(resolve("MLX-LM").map(|s| s.id), Some("mlx"));
    assert_eq!(
        resolve("OpenAI_Compatible").map(|s| s.id),
        Some("openai-compatible")
    );
}

#[test]
fn unknown_provider_is_none_rather_than_a_silent_default() {
    // Falling back to ollama here would run the audit against a model the
    // operator did not choose. Better to fail and name the supported set.
    for unknown in ["bard", "", "   ", "openai2", "lmstudioo"] {
        assert!(
            resolve(unknown).is_none(),
            "unexpectedly resolved {unknown:?}"
        );
    }
}

#[test]
fn only_three_transports_exist() {
    // The point of the table is that presets are defaults, not new code
    // paths. If a fourth transport appears, a backend was added and this
    // module is no longer just a lookup.
    let transports: HashSet<_> = PRESETS.iter().map(|s| s.transport.as_str()).collect();
    assert!(
        transports.is_subset(&HashSet::from([
            "ollama-native",
            "openai-compatible",
            "anthropic"
        ])),
        "unexpected transport in the preset table: {transports:?}"
    );
}

#[test]
fn ollama_is_the_only_native_preset() {
    let native: Vec<_> = PRESETS
        .iter()
        .filter(|s| s.transport == Transport::OllamaNative)
        .map(|s| s.id)
        .collect();
    assert_eq!(native, ["ollama"]);
}

#[test]
fn only_hosted_presets_require_a_key() {
    // Local servers must never be gated behind an API key; that is the
    // friction this table exists to remove.
    let required: Vec<_> = PRESETS
        .iter()
        .filter(|s| s.api_key_required)
        .map(|s| s.id)
        .collect();
    assert_eq!(
        required,
        [
            "openai",
            "anthropic",
            "gemini",
            "azure-openai",
            "mistral",
            "groq",
            "openrouter",
            "deepseek",
            "xai"
        ]
    );
    for spec in PRESETS.iter().filter(|s| s.api_key_required) {
        let base = spec.default_base_url.unwrap_or("https://");
        assert!(
            base.starts_with("https://"),
            "{} is hosted: {base}",
            spec.id
        );
    }
}

#[test]
fn the_names_people_call_a_provider_resolve_to_it() {
    for (spelling, id) in [
        ("Google", "gemini"),
        ("Gemini", "gemini"),
        ("Azure", "azure-openai"),
        ("azure_openai", "azure-openai"),
        ("Mistral AI", "mistral"),
        ("Grok", "xai"),
        ("x.ai", "xai"),
        ("OpenRouter", "openrouter"),
        ("DeepSeek", "deepseek"),
    ] {
        assert_eq!(resolve(spelling).map(|s| s.id), Some(id), "{spelling:?}");
    }
}

#[test]
fn only_azure_sends_its_key_in_an_api_key_header() {
    let api_key_header: Vec<_> = PRESETS
        .iter()
        .filter(|s| s.auth == Auth::ApiKeyHeader)
        .map(|s| s.id)
        .collect();
    assert_eq!(api_key_header, ["azure-openai"]);
}

#[test]
fn every_hosted_key_variable_is_the_providers_own() {
    for spec in PRESETS.iter().filter(|s| s.api_key_required) {
        let env = spec.api_key_env.unwrap();
        assert!(env.ends_with("_API_KEY"), "{}: {env}", spec.id);
    }
    let mut envs: Vec<_> = PRESETS
        .iter()
        .filter(|s| s.api_key_required)
        .filter_map(|s| s.api_key_env)
        .collect();
    let all = envs.len();
    envs.dedup();
    assert_eq!(envs.len(), all, "two hosted presets share a key variable");
}

#[test]
fn a_preset_requiring_a_key_names_the_variable_holding_it() {
    for spec in PRESETS.iter().filter(|s| s.api_key_required) {
        assert!(
            spec.api_key_env.is_some(),
            "{} requires a key but names no variable for it",
            spec.id
        );
    }
}

#[test]
fn openai_compatible_defaults_are_already_normalised() {
    // These strings are handed straight to the OpenAI transport, so they
    // must survive normalisation unchanged or they would 404 on /v1/v1.
    for spec in PRESETS
        .iter()
        .filter(|s| s.transport == Transport::OpenAiCompatible)
    {
        let Some(base) = spec.default_base_url else {
            continue;
        };
        assert_eq!(
            crate::url::normalize_openai_base(base),
            base,
            "{} default base URL is not in canonical form",
            spec.id
        );
    }
}

#[test]
fn every_default_base_url_is_absolute() {
    for spec in PRESETS {
        let Some(base) = spec.default_base_url else {
            continue;
        };
        assert!(
            base.starts_with("http://") || base.starts_with("https://"),
            "{} default base URL is not absolute: {base}",
            spec.id
        );
    }
}
