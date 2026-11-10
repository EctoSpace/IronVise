use super::*;
use std::env;

#[test]
fn database_url_default_and_override() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // database_url() requires ECTO_DEV_MODE to return the default when
    // DATABASE_URL is absent (production mode returns Err).
    unsafe { env::set_var("ECTO_DEV_MODE", "true") };
    unsafe { env::remove_var("DATABASE_URL") };
    assert_eq!(
        database_url().unwrap(),
        "postgres://ectoledger:ectoledger@localhost:5432/ectoledger"
    );
    unsafe { env::set_var("DATABASE_URL", "postgres://example") };
    assert_eq!(database_url().unwrap(), "postgres://example");
    // Clean up
    unsafe { env::remove_var("ECTO_DEV_MODE") };
}

#[test]
fn guard_config_logic() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _settings = isolate_settings();
    unsafe { env::remove_var("GUARD_REQUIRED") };
    unsafe { env::remove_var("GUARD_LLM_BACKEND") };
    unsafe { env::remove_var("GUARD_LLM_MODEL") };
    assert!(guard_required());
    assert!(ensure_guard_config().is_err());
    unsafe { env::set_var("GUARD_REQUIRED", "false") };
    assert!(!guard_required());
    assert!(ensure_guard_config().is_ok());
    unsafe { env::remove_var("GUARD_REQUIRED") };
}

/// Write a settings file into the isolated `ECTO_DATA_DIR`.
fn write_settings(json: &str) {
    let path = settings_config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("settings dir");
    }
    std::fs::write(&path, json).expect("write settings");
}

/// The defect this rule exists for: a desktop `guard_required: false` used
/// to override an operator's `GUARD_REQUIRED=true`, silently.
#[test]
fn a_settings_file_cannot_switch_off_a_guard_the_environment_requires() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _settings = isolate_settings();
    write_settings(r#"{"guard_required": false}"#);
    unsafe { env::set_var("GUARD_REQUIRED", "true") };

    let (value, source) = guard_required_effective();
    assert!(value, "the environment's requirement must survive");
    assert_eq!(source, SettingSource::StricterOfTwo);

    unsafe { env::remove_var("GUARD_REQUIRED") };
}

#[test]
fn the_environment_cannot_switch_off_a_guard_the_settings_file_requires() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _settings = isolate_settings();
    write_settings(r#"{"guard_required": true}"#);
    unsafe { env::set_var("GUARD_REQUIRED", "false") };

    let (value, source) = guard_required_effective();
    assert!(value);
    assert_eq!(source, SettingSource::StricterOfTwo);

    unsafe { env::remove_var("GUARD_REQUIRED") };
}

/// Most-restrictive-wins must not turn the guard *on* where nobody asked
/// for it: a single source saying false is not a disagreement.
#[test]
fn one_source_saying_false_still_disables_the_guard() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _settings = isolate_settings();

    write_settings(r#"{"guard_required": false}"#);
    unsafe { env::remove_var("GUARD_REQUIRED") };
    assert_eq!(
        guard_required_effective(),
        (false, SettingSource::SettingsFile),
        "a GUI toggle must keep working when the environment is silent"
    );

    write_settings(r#"{}"#);
    unsafe { env::set_var("GUARD_REQUIRED", "false") };
    assert_eq!(
        guard_required_effective(),
        (false, SettingSource::Environment)
    );

    write_settings(r#"{"guard_required": false}"#);
    assert_eq!(guard_required_effective(), (false, SettingSource::Both));

    unsafe { env::remove_var("GUARD_REQUIRED") };
}

#[test]
fn with_nothing_configured_the_guard_is_required() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _settings = isolate_settings();
    unsafe { env::remove_var("GUARD_REQUIRED") };
    assert_eq!(guard_required_effective(), (true, SettingSource::Default));
}

/// The insecure-mode banner must name every active weakening, and stay
/// silent for a hardened configuration.
#[test]
fn insecure_mode_reasons_reflect_env() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { env::set_var("GUARD_REQUIRED", "false") };
    unsafe { env::set_var("ECTO_DEV_MODE", "true") };
    let reasons = insecure_mode_reasons();
    assert_eq!(
        reasons.len(),
        2,
        "both weakenings must be reported: {reasons:?}"
    );
    assert!(reasons.iter().any(|r| r.contains("GUARD_REQUIRED")));
    assert!(reasons.iter().any(|r| r.contains("ECTO_DEV_MODE")));

    // Hardened: guard required, dev mode off → nothing to announce.
    unsafe { env::set_var("GUARD_REQUIRED", "true") };
    unsafe { env::remove_var("ECTO_DEV_MODE") };
    assert!(
        insecure_mode_reasons().is_empty(),
        "a hardened configuration must not log the insecure-mode banner"
    );

    unsafe { env::remove_var("GUARD_REQUIRED") };
}

#[test]
fn snapshot_interval_and_other_defaults() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { env::remove_var("AGENT_SNAPSHOT_INTERVAL") };
    assert_eq!(snapshot_interval(), 50);
    unsafe { env::set_var("AGENT_SNAPSHOT_INTERVAL", "123") };
    assert_eq!(snapshot_interval(), 123);
    unsafe { env::remove_var("OLLAMA_BASE_URL") };
    assert!(ollama_base_url().contains("127.0.0.1"));
    unsafe { env::remove_var("LLM_BACKEND") };
    unsafe { env::remove_var("LLM_PROVIDER") };
    assert_eq!(llm_provider(), "ollama");
}

// `LLM_BACKEND` is deprecated in 0.8.0 and still read; no removal is planned.
// The contract is that an existing `.env` behaves exactly as it did, so these
// pin the precedence rather than leaving it to be rediscovered.

fn clear_llm_vars() {
    unsafe { env::remove_var("LLM_PROVIDER") };
    unsafe { env::remove_var("LLM_BACKEND") };
}

#[test]
fn llm_provider_defaults_to_ollama_when_neither_is_set() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_llm_vars();
    assert_eq!(llm_provider(), "ollama");
}

#[test]
fn deprecated_llm_backend_alias_still_works() {
    // The whole point of the deprecation window: an untouched .env file
    // from 0.6.4 must select the same provider it always did.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_llm_vars();
    unsafe { env::set_var("LLM_BACKEND", "anthropic") };
    assert_eq!(llm_provider(), "anthropic");
    clear_llm_vars();
}

#[test]
fn llm_provider_is_preferred_over_the_deprecated_alias() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_llm_vars();
    unsafe { env::set_var("LLM_PROVIDER", "lmstudio") };
    unsafe { env::set_var("LLM_BACKEND", "ollama") };
    assert_eq!(
        llm_provider(),
        "lmstudio",
        "LLM_PROVIDER must win when both are set"
    );
    clear_llm_vars();
}

#[test]
fn an_empty_value_is_treated_as_unset() {
    // `LLM_BACKEND=` in a .env file must not select a provider named "".
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_llm_vars();
    unsafe { env::set_var("LLM_PROVIDER", "") };
    assert_eq!(llm_provider(), "ollama");

    unsafe { env::set_var("LLM_BACKEND", "openai") };
    assert_eq!(
        llm_provider(),
        "openai",
        "an empty LLM_PROVIDER must fall through to the alias"
    );
    clear_llm_vars();
}

#[test]
fn every_legacy_backend_name_is_still_a_valid_preset() {
    // The three names 0.6.4 accepted in LLM_BACKEND must all resolve
    // against the new preset table, or the alias would be cosmetic.
    for legacy in ["ollama", "openai", "anthropic"] {
        assert!(
            ectoledger_llm::provider::resolve(legacy).is_some(),
            "legacy backend name {legacy:?} no longer resolves to a preset"
        );
    }
}

/// Point `ECTO_DATA_DIR` at an empty temp dir so a developer `settings.json`
/// cannot override `LLM_PROVIDER` / `openai_base_url` during these tests.
fn isolate_settings() -> IsolatedSettings {
    let prev = env::var("ECTO_DATA_DIR").ok();
    let tmp = tempfile::tempdir().expect("tempdir");
    unsafe { env::set_var("ECTO_DATA_DIR", tmp.path()) };
    IsolatedSettings { _tmp: tmp, prev }
}

struct IsolatedSettings {
    _tmp: tempfile::TempDir,
    prev: Option<String>,
}

impl Drop for IsolatedSettings {
    fn drop(&mut self) {
        unsafe {
            match &self.prev {
                Some(v) => env::set_var("ECTO_DATA_DIR", v),
                None => env::remove_var("ECTO_DATA_DIR"),
            }
        }
    }
}

fn clear_openai_url_vars() {
    clear_llm_vars();
    unsafe { env::remove_var("OPENAI_BASE_URL") };
}

#[test]
fn openai_guard_url_does_not_inherit_the_ollama_primary() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _tmp = isolate_settings();
    clear_openai_url_vars();
    unsafe { env::set_var("LLM_PROVIDER", "ollama") };

    assert_eq!(
        openai_base_url_for("openai"),
        "https://api.openai.com/v1",
        "an OpenAI guard must not inherit Ollama's default URL"
    );
    assert!(
        openai_base_url().contains("11434"),
        "the primary helper still follows LLM_PROVIDER; got {}",
        openai_base_url()
    );

    clear_openai_url_vars();
}

#[test]
fn openai_guard_url_ignores_the_primary_openai_base_url_env() {
    // Primary is LM Studio; OPENAI_BASE_URL is how that preset is pointed
    // at localhost. An OpenAI guard must still hit api.openai.com.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _tmp = isolate_settings();
    clear_openai_url_vars();
    unsafe { env::set_var("LLM_PROVIDER", "lmstudio") };
    unsafe { env::set_var("OPENAI_BASE_URL", "http://127.0.0.1:1234/v1") };

    assert_eq!(
        openai_base_url(),
        "http://127.0.0.1:1234/v1",
        "the primary still honours OPENAI_BASE_URL"
    );
    assert_eq!(
        openai_base_url_for("openai"),
        "https://api.openai.com/v1",
        "a different-preset guard must not inherit OPENAI_BASE_URL"
    );

    unsafe { env::remove_var("OPENAI_BASE_URL") };
    clear_llm_vars();
}

#[test]
fn primary_openai_still_honours_openai_base_url() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _tmp = isolate_settings();
    clear_openai_url_vars();
    unsafe { env::set_var("LLM_PROVIDER", "openai") };
    unsafe { env::set_var("OPENAI_BASE_URL", "https://proxy.example/v1") };

    assert_eq!(openai_base_url(), "https://proxy.example/v1");
    assert_eq!(openai_base_url_for("openai"), "https://proxy.example/v1");

    unsafe { env::remove_var("OPENAI_BASE_URL") };
    clear_llm_vars();
}

#[test]
fn lmstudio_primary_falls_back_to_the_preset_port() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _tmp = isolate_settings();
    clear_openai_url_vars();
    unsafe { env::set_var("LLM_PROVIDER", "lmstudio") };

    assert_eq!(openai_base_url(), "http://127.0.0.1:1234/v1");

    clear_llm_vars();
}
