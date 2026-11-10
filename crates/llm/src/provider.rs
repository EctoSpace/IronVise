//! Provider presets: the lookup table behind `LLM_PROVIDER`.
//!
//! `LLM_BACKEND=openai` became actively misleading once "openai" meant *any*
//! server speaking the OpenAI wire format, including a llama.cpp binary on
//! localhost. This module replaces that overloaded name with a preset table.
//!
//! A preset is **not** a new backend. There are only three transports -
//! [`Transport::OllamaNative`], [`Transport::OpenAiCompatible`] and
//! [`Transport::Anthropic`] - and every hosted API except Anthropic's speaks
//! the OpenAI wire format too. A preset only supplies sensible defaults (which
//! transport, which base URL, which API-key variable, which header carries the
//! key) so the user does not have to know that LM Studio, Groq and Gemini are
//! all "openai" underneath.
//!
//! Resolution is pure: nothing here reads the environment or the network. The
//! caller layers explicit configuration over the returned defaults.

/// How to talk to a provider. Every preset maps onto one of these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Ollama's own `/api/chat` protocol.
    OllamaNative,
    /// The OpenAI `/v1/chat/completions` wire format.
    OpenAiCompatible,
    /// Anthropic's Messages API.
    Anthropic,
}

impl Transport {
    /// Stable identifier, for logs, the API surface, and the GUI.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::OllamaNative => "ollama-native",
            Transport::OpenAiCompatible => "openai-compatible",
            Transport::Anthropic => "anthropic",
        }
    }
}

/// How the API key travels with each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// `Authorization: Bearer <key>`, as OpenAI and nearly everyone else.
    Bearer,
    /// `api-key: <key>`, as Azure OpenAI expects for key authentication.
    ApiKeyHeader,
}

/// Defaults for one provider preset.
///
/// `default_base_url` is `None` where there is no meaningful default and the
/// user must supply one - a hosted LocalAI instance or an arbitrary
/// OpenAI-compatible gateway could be anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSpec {
    /// Canonical preset id, as written in `LLM_PROVIDER`.
    pub id: &'static str,
    /// Human-readable name, for the GUI preset picker.
    pub label: &'static str,
    pub transport: Transport,
    pub default_base_url: Option<&'static str>,
    pub default_model: Option<&'static str>,
    /// Environment variable holding the API key, where one applies.
    pub api_key_env: Option<&'static str>,
    /// Whether a key is mandatory. Local servers often accept any non-empty
    /// value, or none at all, so this is false for every localhost preset.
    pub api_key_required: bool,
    pub auth: Auth,
}

/// Every supported preset, in the order the GUI should offer them: local
/// runtimes first, hosted APIs next, generic escape hatch last.
///
/// The hosted presets other than OpenAI and Anthropic were built from each
/// provider's API reference and are tested against recorded request shapes,
/// not run live here. A model that names an alias (`-latest`, `auto`) follows
/// the provider's current model without a release of this table.
///
/// Jan is deliberately absent. It speaks the same OpenAI-compatible protocol as
/// the rest, so `openai-compatible` with its base URL already works - a named
/// preset would only be a default port, and shipping one implies a level of
/// verification nobody here has done. Re-add it when someone has actually run
/// an audit against it.
pub const PRESETS: &[ProviderSpec] = &[
    ProviderSpec {
        id: "ollama",
        label: "Ollama",
        transport: Transport::OllamaNative,
        default_base_url: Some("http://127.0.0.1:11434"),
        default_model: None,
        api_key_env: None,
        api_key_required: false,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "lmstudio",
        label: "LM Studio",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("http://127.0.0.1:1234/v1"),
        default_model: None,
        api_key_env: Some("OPENAI_API_KEY"),
        api_key_required: false,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "llamacpp",
        label: "llama.cpp server",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("http://127.0.0.1:8080/v1"),
        default_model: None,
        api_key_env: Some("OPENAI_API_KEY"),
        api_key_required: false,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "vllm",
        label: "vLLM",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("http://127.0.0.1:8000/v1"),
        default_model: None,
        api_key_env: Some("OPENAI_API_KEY"),
        api_key_required: false,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "mlx",
        label: "MLX-LM",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("http://127.0.0.1:8080/v1"),
        default_model: None,
        api_key_env: Some("OPENAI_API_KEY"),
        api_key_required: false,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "localai",
        label: "LocalAI",
        transport: Transport::OpenAiCompatible,
        default_base_url: None,
        default_model: None,
        api_key_env: Some("OPENAI_API_KEY"),
        api_key_required: false,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "openai",
        label: "OpenAI",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("https://api.openai.com/v1"),
        default_model: Some("gpt-6-astra"),
        api_key_env: Some("OPENAI_API_KEY"),
        api_key_required: true,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "anthropic",
        label: "Anthropic",
        transport: Transport::Anthropic,
        default_base_url: Some("https://api.anthropic.com"),
        default_model: Some("claude-opus-5-5"),
        api_key_env: Some("ANTHROPIC_API_KEY"),
        api_key_required: true,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "gemini",
        label: "Google Gemini",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("https://generativelanguage.googleapis.com/v1beta/openai"),
        default_model: Some("gemini-flash-latest"),
        api_key_env: Some("GEMINI_API_KEY"),
        api_key_required: true,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "azure-openai",
        label: "Azure OpenAI",
        transport: Transport::OpenAiCompatible,
        // The resource's own address, https://<resource>.openai.azure.com/openai/v1,
        // and the model is the deployment name: neither has a default.
        default_base_url: None,
        default_model: None,
        api_key_env: Some("AZURE_OPENAI_API_KEY"),
        api_key_required: true,
        auth: Auth::ApiKeyHeader,
    },
    ProviderSpec {
        id: "mistral",
        label: "Mistral AI",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("https://api.mistral.ai/v1"),
        default_model: Some("mistral-large-latest"),
        api_key_env: Some("MISTRAL_API_KEY"),
        api_key_required: true,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "groq",
        label: "Groq",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("https://api.groq.com/openai/v1"),
        default_model: Some("openai/gpt-oss-120b"),
        api_key_env: Some("GROQ_API_KEY"),
        api_key_required: true,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "openrouter",
        label: "OpenRouter",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("https://openrouter.ai/api/v1"),
        default_model: Some("openrouter/auto"),
        api_key_env: Some("OPENROUTER_API_KEY"),
        api_key_required: true,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "deepseek",
        label: "DeepSeek",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("https://api.deepseek.com/v1"),
        default_model: Some("deepseek-chat"),
        api_key_env: Some("DEEPSEEK_API_KEY"),
        api_key_required: true,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "xai",
        label: "xAI",
        transport: Transport::OpenAiCompatible,
        default_base_url: Some("https://api.x.ai/v1"),
        // xAI retires model names on a schedule and has no stable alias, so
        // the model is the operator's choice.
        default_model: None,
        api_key_env: Some("XAI_API_KEY"),
        api_key_required: true,
        auth: Auth::Bearer,
    },
    ProviderSpec {
        id: "openai-compatible",
        label: "Custom (OpenAI-compatible)",
        transport: Transport::OpenAiCompatible,
        default_base_url: None,
        default_model: None,
        api_key_env: Some("OPENAI_API_KEY"),
        api_key_required: false,
        auth: Auth::Bearer,
    },
];

/// Spellings accepted for a preset id, beyond the canonical one.
///
/// These are the names the tools use for themselves, so they are what users
/// will type. Matching is case-insensitive and ignores `-`, `_` and `.`, so
/// this table only needs entries that differ by more than punctuation.
const ALIASES: &[(&str, &str)] = &[
    ("lmstudio", "lmstudio"),
    ("llamacpp", "llamacpp"),
    ("llama", "llamacpp"),
    ("llamacppserver", "llamacpp"),
    ("mlx", "mlx"),
    ("mlxlm", "mlx"),
    ("openaicompatible", "openai-compatible"),
    ("custom", "openai-compatible"),
    ("openwebui", "openai-compatible"),
    ("textgenerationwebui", "openai-compatible"),
    ("oobabooga", "openai-compatible"),
    ("google", "gemini"),
    ("googlegemini", "gemini"),
    ("azure", "azure-openai"),
    ("azureopenai", "azure-openai"),
    ("mistralai", "mistral"),
    ("grok", "xai"),
];

/// Reduce a user-supplied name to a comparable form: lowercase, no separators.
fn canonical_key(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Look up a provider preset by name.
///
/// Accepts the canonical id, any alias, and any casing or punctuation variant
/// (`LM-Studio`, `llama.cpp`, `MLX_LM`). Returns `None` for an unknown name so
/// the caller can produce an error naming the supported set, rather than
/// silently falling back to a default the user did not ask for.
pub fn resolve(provider: &str) -> Option<&'static ProviderSpec> {
    let key = canonical_key(provider);
    if key.is_empty() {
        return None;
    }
    let target = ALIASES
        .iter()
        .find(|(alias, _)| *alias == key)
        .map(|(_, id)| *id);
    PRESETS.iter().find(|spec| match target {
        Some(id) => spec.id == id,
        None => canonical_key(spec.id) == key,
    })
}

/// Every canonical preset id, for error messages and the GUI.
pub fn preset_ids() -> impl Iterator<Item = &'static str> {
    PRESETS.iter().map(|spec| spec.id)
}

#[cfg(test)]
mod tests;
