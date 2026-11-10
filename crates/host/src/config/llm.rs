//! The model provider: preset, address, model and timeout, for the agent
//! and for a guard on a different provider.

use super::*;

pub fn ollama_base_url() -> String {
    load_settings_config()
        .and_then(|c| c.ollama_base_url)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("OLLAMA_BASE_URL").ok())
        .filter(|s| !s.trim().is_empty())
        // 127.0.0.1, not localhost: on Windows with WSL, localhost resolves
        // to ::1 first, where the WSL relay forwards to a different (often
        // empty) Ollama inside WSL.
        .unwrap_or_else(|| "http://127.0.0.1:11434".to_string())
}

pub fn ollama_model() -> String {
    model_for(&llm_provider())
}

/// Model for `provider`.
///
/// The saved `ollama_model` in `.ectoledger/settings.json` describes the
/// primary provider only; a guard on a different preset reads that preset's
/// environment variable (`OPENAI_MODEL`, `ANTHROPIC_MODEL`, `OLLAMA_MODEL`)
/// or built-in default instead.
pub fn model_for(provider: &str) -> String {
    configured_model_for(provider)
        .or_else(|| {
            ectoledger_llm::resolve_provider(provider)
                .and_then(|s| s.default_model)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "mistral".to_string())
}

/// The model the settings file or the environment names for `provider`,
/// without the preset's default.
pub fn configured_model_for(provider: &str) -> Option<String> {
    if openai_url_config_applies_to(provider)
        && let Some(from_settings) = load_settings_config()
            .and_then(|c| c.ollama_model)
            .filter(|s| !s.trim().is_empty())
    {
        return Some(from_settings);
    }
    let env_name = match ectoledger_llm::resolve_provider(provider).map(|s| s.transport) {
        Some(ectoledger_llm::Transport::OpenAiCompatible) => "OPENAI_MODEL",
        Some(ectoledger_llm::Transport::Anthropic) => "ANTHROPIC_MODEL",
        _ => "OLLAMA_MODEL",
    };
    std::env::var(env_name)
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// Selected LLM provider preset. Env: `LLM_PROVIDER`, default `ollama`.
///
/// `LLM_BACKEND` is accepted as a deprecated alias so existing `.env` files
/// keep working unchanged; removing it is not planned. When both are set,
/// `LLM_PROVIDER` wins - it is the name that survives - and the conflict is
/// logged rather than resolved silently.
///
/// The returned string is the raw preset name. Mapping it onto a transport and
/// its defaults is [`ectoledger_llm::provider::resolve`]'s job.
pub fn llm_provider() -> String {
    if let Some(from_settings) = load_settings_config()
        .and_then(|c| c.llm_backend)
        .filter(|s| !s.trim().is_empty())
    {
        return from_settings;
    }

    let provider = std::env::var("LLM_PROVIDER").ok().filter(|s| !s.is_empty());
    let legacy = std::env::var("LLM_BACKEND").ok().filter(|s| !s.is_empty());

    match (provider, legacy) {
        (Some(provider), Some(legacy)) if provider != legacy => {
            warn_once(
                &LLM_ALIAS_CONFLICT_WARNED,
                format!(
                    "Both LLM_PROVIDER ({provider}) and the deprecated LLM_BACKEND ({legacy}) \
                     are set and disagree. Using LLM_PROVIDER={provider}. Remove LLM_BACKEND."
                ),
            );
            provider
        }
        (Some(provider), _) => provider,
        (None, Some(legacy)) => {
            warn_once(
                &LLM_BACKEND_DEPRECATED_WARNED,
                format!(
                    "LLM_BACKEND is deprecated; use LLM_PROVIDER. \
                     Rename it to LLM_PROVIDER (currently {legacy})."
                ),
            );
            legacy
        }
        (None, None) => "ollama".to_string(),
    }
}

/// Deprecated name for [`llm_provider`]. Retained so existing call sites keep
/// compiling while they migrate; it reads the same two variables.
#[deprecated(note = "renamed to llm_provider; LLM_BACKEND is a deprecated env alias")]
pub fn llm_backend() -> String {
    llm_provider()
}

/// Total per-request HTTP timeout for every LLM call (seconds).
/// Env: [`ectoledger_llm::LLM_TIMEOUT_ENV`] (`ECTO_LLM_TIMEOUT_SECS`). Default: `300`.
///
/// One `reqwest::Client` is built per process and shared across the primary
/// LLM backend *and* the Guard backend - whichever transport (Ollama,
/// OpenAI-compatible, Anthropic) they resolve to - so there is one timeout,
/// not one per provider. 300s is sized for a large local Ollama model under
/// load (the 60s hard-coded default this replaces made every call to a 26B
/// model fail with "error sending request for url (...)"); hosted providers
/// answer far sooner in practice but share the same client, and splitting
/// that client per-backend to give hosted providers a shorter default would
/// mean threading two clients everywhere `backend_from_env`/
/// `guard_backend_from_env` are called today - not worth it for a timeout
/// that simply isn't reached in the hosted case.
///
/// Garbage, unset, negative and `0` all fall back to the default: `0` would
/// make `reqwest` time out every request instantly, so it is rejected the
/// same way `AGENT_KEY_ROTATION_STEPS=0` is rejected by
/// [`key_rotation_interval_steps`], rather than taken literally the way most
/// other numeric getters here take a literal `0`.
pub fn llm_timeout_secs() -> u64 {
    std::env::var(ectoledger_llm::LLM_TIMEOUT_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(300)
}

pub(super) static LLM_BACKEND_DEPRECATED_WARNED: std::sync::Once = std::sync::Once::new();

pub(super) static LLM_ALIAS_CONFLICT_WARNED: std::sync::Once = std::sync::Once::new();

/// Emit a configuration warning at most once per process.
///
/// `llm_provider()` is called on every session start; without this the log
/// would carry one deprecation line per session for the life of the process.
pub(super) fn warn_once(once: &std::sync::Once, message: String) {
    once.call_once(|| tracing::warn!("{message}"));
}

/// Guard LLM backend (for guard-worker). Env: GUARD_LLM_BACKEND. Required when GUARD_REQUIRED=true.
pub fn guard_llm_backend() -> Option<String> {
    load_settings_config()
        .and_then(|c| c.guard_llm_backend)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("GUARD_LLM_BACKEND")
                .ok()
                .filter(|s| !s.is_empty())
        })
}

/// Guard LLM model. Env: GUARD_LLM_MODEL. Required when GUARD_REQUIRED=true.
pub fn guard_llm_model() -> Option<String> {
    load_settings_config()
        .and_then(|c| c.guard_llm_model)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("GUARD_LLM_MODEL")
                .ok()
                .filter(|s| !s.is_empty())
        })
}

/// Base URL for the OpenAI-compatible transport of the *primary* provider.
///
/// Precedence: the saved setting, then `OPENAI_BASE_URL`, then that provider's
/// default. Callers should normalise it with
/// [`ectoledger_llm::normalize_openai_base`] rather than appending `/v1`.
///
/// A guard on a different preset must use [`openai_base_url_for`] with that
/// preset's name. This helper always follows [`llm_provider`].
pub fn openai_base_url() -> String {
    openai_base_url_for(&llm_provider())
}

/// Base URL for the OpenAI-compatible transport of `provider`.
///
/// Settings and `OPENAI_BASE_URL` describe the primary endpoint only. A guard
/// running a different preset must not inherit them - otherwise
/// `GUARD_LLM_BACKEND=openai` with `LLM_PROVIDER=ollama` sends OpenAI-format
/// requests to Ollama's default URL.
pub fn openai_base_url_for(provider: &str) -> String {
    configured_openai_base_url_for(provider)
        .or_else(|| {
            ectoledger_llm::resolve_provider(provider)
                .and_then(|s| s.default_base_url)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "https://api.openai.com".to_string())
}

/// The OpenAI-compatible base URL the settings file or `OPENAI_BASE_URL`
/// names for `provider`, without the preset's default.
pub fn configured_openai_base_url_for(provider: &str) -> Option<String> {
    if !openai_url_config_applies_to(provider) {
        return None;
    }
    load_settings_config()
        .and_then(|c| c.openai_base_url)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("OPENAI_BASE_URL").ok())
        .filter(|s| !s.trim().is_empty())
}

pub(super) fn openai_url_config_applies_to(provider: &str) -> bool {
    let primary = llm_provider();
    match (
        ectoledger_llm::resolve_provider(provider),
        ectoledger_llm::resolve_provider(&primary),
    ) {
        (Some(asked), Some(primary_spec)) => asked.id == primary_spec.id,
        _ => provider == primary,
    }
}
