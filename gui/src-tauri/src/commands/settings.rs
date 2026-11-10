//! Settings: the config the Settings screen loads and saves, and the model
//! providers (presets, model lists, connection tests).

#[allow(unused_imports)]
use super::*;

#[tauri::command]
pub async fn get_config() -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/api/config", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!(
            "Failed to load config: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize, serde::Deserialize)]
// A misnamed field must fail, not vanish (see ipc_contract_tests).
#[serde(deny_unknown_fields)]
pub struct ConfigPayload {
    pub database_url: Option<String>,
    pub llm_backend: Option<String>,
    pub ollama_base_url: Option<String>,
    pub openai_base_url: Option<String>,
    pub ollama_model: Option<String>,
    pub guard_required: Option<bool>,
    pub guard_llm_backend: Option<String>,
    pub guard_llm_model: Option<String>,
    pub max_steps: Option<u32>,
    pub agent_allowed_domains: Option<Vec<String>>,
    pub show_developer_tools: Option<bool>,
    /// The policy Home → Run uses, by name; "" clears it.
    pub active_policy: Option<String>,
}

#[tauri::command]
pub async fn save_config(payload: ConfigPayload) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .put(format!("{}/api/config", base_url()))
        .headers(auth_headers().clone())
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        let detail = sanitize_error_body(&body);
        let detail = detail.trim();
        let hint = "Try running the app as administrator, or ensure the config directory is writable (e.g. ECTO_DATA_DIR or the app data folder).";
        let message = if detail.is_empty() {
            format!("Configuration could not be saved (server returned {status}). {hint}")
        } else {
            format!("Configuration could not be saved: {detail}. {hint}")
        };
        return Err(message);
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(serde::Deserialize, Default)]
// A misnamed field must fail, not vanish (see ipc_contract_tests).
#[serde(deny_unknown_fields)]
pub struct GetOllamaModelsArgs {
    #[serde(rename = "baseUrlOverride")]
    pub base_url_override: Option<String>,
}

/// What `/api/show` says about chat, if it says anything: `Some(true)` when
/// the model lists the `completion` capability, `Some(false)` when it lists
/// capabilities without it (embedding models), `None` when the field is
/// absent (Ollama before capabilities were reported).
fn ollama_capabilities_allow_chat(show: &serde_json::Value) -> Option<bool> {
    let caps = show.get("capabilities")?.as_array()?;
    Some(caps.iter().any(|c| c.as_str() == Some("completion")))
}

/// Fallback when `/api/show` is unavailable: embedding models are BERT
/// family or carry "embed" in their name (nomic-embed-text, mxbai-embed-large,
/// all-minilm is bert).
fn ollama_entry_looks_like_embedding(entry: &serde_json::Value) -> bool {
    let name = entry.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let details = entry.get("details");
    let family = details
        .and_then(|d| d.get("family"))
        .and_then(|f| f.as_str())
        .into_iter();
    let families = details
        .and_then(|d| d.get("families"))
        .and_then(|f| f.as_array())
        .into_iter()
        .flatten()
        .filter_map(|f| f.as_str());
    name.to_ascii_lowercase().contains("embed")
        || family
            .chain(families)
            .any(|f| f.to_ascii_lowercase().contains("bert"))
}

/// The `/api/tags` entries an agent can chat with. Ollama lists embedding
/// models (nomic-embed-text, …) next to chat models; offering one as the
/// agent's model fails on the first step.
async fn ollama_chat_models(
    client: &reqwest::Client,
    base: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let base = base.trim_end_matches('/');
    let res = client
        .get(format!("{base}/api/tags"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Ollama not reachable at {base}: {}", res.status()));
    }
    let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    let entries = body
        .get("models")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    let mut chat = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let show = client
            .post(format!("{base}/api/show"))
            .json(&serde_json::json!({ "model": name }))
            .send()
            .await
            .ok();
        let show = match show {
            Some(r) if r.status().is_success() => r.json::<serde_json::Value>().await.ok(),
            _ => None,
        };
        let can_chat = show
            .as_ref()
            .and_then(ollama_capabilities_allow_chat)
            .unwrap_or_else(|| !ollama_entry_looks_like_embedding(&entry));
        if can_chat {
            chat.push(entry);
        }
    }
    Ok(chat)
}

#[tauri::command]
pub async fn get_ollama_models(args: GetOllamaModelsArgs) -> Result<serde_json::Value, String> {
    let has_override = args.base_url_override.is_some();
    let url = args
        .base_url_override
        .unwrap_or_else(|| {
            std::env::var("OLLAMA_BASE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string())
        })
        .trim_end_matches('/')
        .to_string();

    // SSRF protection: only allow requests to localhost / loopback addresses
    // when the URL comes from user input (base_url_override).
    if has_override {
        let parsed_url = url::Url::parse(&url).map_err(|_| "Invalid URL format".to_string())?;
        let host = parsed_url.host_str().unwrap_or("");
        let is_local =
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
        if !is_local {
            return Err(format!(
                "Ollama URL must point to localhost (got '{host}'); set OLLAMA_BASE_URL env var for remote hosts"
            ));
        }
    }

    let client = http_client();
    let models = ollama_chat_models(client, &url).await?;
    Ok(serde_json::json!({ "models": models }))
}

// The list is served from the Rust preset table rather than copied into
// TypeScript: a copied list is how the webhook filter picker ended up
// offering ten kinds the server never emitted, and there is no second place
// for this one to drift to. Serving it keeps every OpenAI-compatible backend
// (LM Studio, llama.cpp, vLLM, MLX-LM, LocalAI) visible in the GUI alongside
// Ollama, rather than a hardcoded list quietly falling behind what the
// server actually supports.

#[derive(serde::Serialize)]
pub struct ProviderPreset {
    pub id: String,
    pub label: String,
    pub transport: String,
    pub default_base_url: Option<String>,
    pub default_model: Option<String>,
    pub api_key_env: Option<String>,
    pub api_key_required: bool,
}

/// Every provider preset, in the order the GUI should offer them.
#[tauri::command]
pub fn get_provider_presets() -> Vec<ProviderPreset> {
    ectoledger::llm::PRESETS
        .iter()
        .map(|p| ProviderPreset {
            id: p.id.to_string(),
            label: p.label.to_string(),
            transport: p.transport.as_str().to_string(),
            default_base_url: p.default_base_url.map(str::to_string),
            default_model: p.default_model.map(str::to_string),
            api_key_env: p.api_key_env.map(str::to_string),
            api_key_required: p.api_key_required,
        })
        .collect()
}

/// The webview sends `baseUrl` / `apiKey`. Without the rename serde would
/// ignore both and every probe and model list would use the preset's default
/// address, not the one typed in Settings. The snake_case names are still
/// accepted.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
// A misnamed field must fail, not vanish (see ipc_contract_tests).
#[serde(deny_unknown_fields)]
pub struct ProviderProbeArgs {
    pub provider: String,
    #[serde(alias = "base_url")]
    pub base_url: Option<String>,
    #[serde(alias = "api_key")]
    pub api_key: Option<String>,
}

/// A hosted provider's own address (e.g. `https://api.openai.com/v1` against
/// the preset's `https://api.openai.com/v1` or with a trailing slash) is not
/// an internal host; compare hosts, not strings.
fn is_preset_host(url: &str, preset_default: Option<&str>) -> bool {
    let host = |u: &str| {
        url::Url::parse(u)
            .ok()
            .and_then(|p| p.host_str().map(str::to_string))
    };
    match (host(url), preset_default.and_then(host)) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(&b),
        _ => false,
    }
}

/// Guard user-supplied URLs. Same rule the Ollama command already applied: a
/// URL typed into the GUI may only point at the loopback interface, so the
/// desktop app cannot be talked into probing an internal host. Values coming
/// from the environment are the operator's own choice and are left alone.
fn require_loopback(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "Invalid URL format".to_string())?;
    let host = parsed.host_str().unwrap_or("");
    let local = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if local {
        Ok(())
    } else {
        Err(format!(
            "Base URL must point at localhost (got '{host}'). Set the base URL \
             through the environment for a remote host."
        ))
    }
}

/// Models a provider reports. Replaces `get_ollama_models` for every transport.
#[tauri::command]
pub async fn get_provider_models(args: ProviderProbeArgs) -> Result<Vec<String>, String> {
    let spec = ectoledger::llm::resolve_provider(&args.provider)
        .ok_or_else(|| format!("Unknown provider preset '{}'", args.provider))?;

    let base = args
        .base_url
        .filter(|s| !s.trim().is_empty())
        .or_else(|| spec.default_base_url.map(str::to_string))
        .ok_or_else(|| format!("{} needs a base URL", spec.label))?;
    require_loopback(&base).or_else(|e| {
        // A hosted provider's own address is not an internal host.
        if is_preset_host(&base, spec.default_base_url) {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    // The key the backend would use: the credential store, then the environment.
    let api_key = args
        .api_key
        .filter(|k| !k.trim().is_empty())
        .or_else(|| spec.api_key_env.and_then(ectoledger::llm::api_key::resolve))
        .unwrap_or_default();

    let client = http_client();
    match spec.transport {
        ectoledger::llm::Transport::OllamaNative => Ok(ollama_chat_models(client, &base)
            .await?
            .iter()
            .filter_map(|m| m.get("name").and_then(|n| n.as_str()))
            .map(str::to_string)
            .collect()),
        ectoledger::llm::Transport::Anthropic => {
            if api_key.is_empty() {
                return Err(format!(
                    "{} lists its models only with an API key, and this app has none.",
                    spec.label
                ));
            }
            let res = client
                .get(format!("{}/v1/models", base.trim_end_matches('/')))
                .header("x-api-key", &api_key)
                .header("anthropic-version", "2023-06-01")
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !res.status().is_success() {
                return Err(format!(
                    "{} refused the request: {}",
                    spec.label,
                    res.status()
                ));
            }
            let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
            Ok(body
                .get("data")
                .and_then(|d| d.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|m| m.get("id").and_then(|n| n.as_str()))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default())
        }
        _ => ectoledger::llm::list_models_openai_compatible(client, &base, &api_key, spec.auth)
            .await
            .map_err(|e| e.to_string()),
    }
}

/// Reachability + model list, for the Settings "Test connection" button.
#[tauri::command]
pub async fn test_provider_connection(args: ProviderProbeArgs) -> Result<String, String> {
    let label = ectoledger::llm::resolve_provider(&args.provider)
        .map(|s| s.label.to_string())
        .unwrap_or_else(|| args.provider.clone());
    let models = get_provider_models(args).await?;
    if models.is_empty() {
        // Not an error: several servers do not implement a list route. Say what
        // was and was not established rather than implying a full success.
        Ok(format!(
            "{label} is reachable, but lists no chat models. Load or download a model there, then Refresh."
        ))
    } else {
        Ok(format!(
            "{label} is reachable - {} model{} available.",
            models.len(),
            if models.len() == 1 { "" } else { "s" }
        ))
    }
}

#[cfg(test)]
mod ollama_model_filter_tests {
    use super::{ollama_capabilities_allow_chat, ollama_entry_looks_like_embedding};
    use serde_json::json;

    #[test]
    fn capabilities_decide_when_present() {
        assert_eq!(
            ollama_capabilities_allow_chat(&json!({ "capabilities": ["embedding"] })),
            Some(false)
        );
        assert_eq!(
            ollama_capabilities_allow_chat(&json!({ "capabilities": ["tools", "completion"] })),
            Some(true)
        );
        assert_eq!(
            ollama_capabilities_allow_chat(&json!({ "details": {} })),
            None
        );
    }

    #[test]
    fn without_capabilities_bert_and_embed_names_are_embedding() {
        let nomic = json!({ "name": "nomic-embed-text:latest",
            "details": { "family": "nomic-bert", "families": ["nomic-bert"] } });
        let minilm = json!({ "name": "all-minilm:latest", "details": { "family": "bert" } });
        let qwen = json!({ "name": "qwen2.5:7b", "details": { "family": "qwen2" } });
        let bare = json!({ "name": "phi3" });
        assert!(ollama_entry_looks_like_embedding(&nomic));
        assert!(ollama_entry_looks_like_embedding(&minilm));
        assert!(!ollama_entry_looks_like_embedding(&qwen));
        assert!(!ollama_entry_looks_like_embedding(&bare));
    }
}

#[cfg(test)]
mod provider_probe_tests {
    use super::{ProviderProbeArgs, is_preset_host};

    #[test]
    fn the_webview_s_camel_case_fields_arrive() {
        let a: ProviderProbeArgs = serde_json::from_str(
            r#"{"provider":"lmstudio","baseUrl":"http://localhost:1234/v1","apiKey":"k"}"#,
        )
        .unwrap();
        assert_eq!(a.base_url.as_deref(), Some("http://localhost:1234/v1"));
        assert_eq!(a.api_key.as_deref(), Some("k"));
        let b: ProviderProbeArgs =
            serde_json::from_str(r#"{"provider":"ollama","base_url":"http://127.0.0.1:11434"}"#)
                .unwrap();
        assert_eq!(b.base_url.as_deref(), Some("http://127.0.0.1:11434"));
    }

    #[test]
    fn a_hosted_preset_s_own_host_passes_and_others_do_not() {
        let openai = Some("https://api.openai.com/v1");
        assert!(is_preset_host("https://api.openai.com/v1/", openai));
        assert!(is_preset_host("https://API.openai.com", openai));
        assert!(!is_preset_host("http://10.0.0.5:8080/v1", openai));
        assert!(!is_preset_host(
            "https://api.openai.com.evil.example/v1",
            openai
        ));
        assert!(!is_preset_host("http://localhost:1234/v1", None));
    }
}
