// Re-export everything from the standalone ectoledger-llm crate so that
// existing `crate::llm::*` paths resolve without changes across the host.
pub use ectoledger_llm::*;

use crate::schema::{EventPayload, RestoredState};
use async_trait::async_trait;
use serde_json::json;

pub fn state_to_prompt(state: &RestoredState, max_events: usize) -> String {
    let mut out = String::new();
    if let Some(obj) = state.snapshot_payload.as_object() {
        if let Some(c) = obj.get("event_count").and_then(|v| v.as_u64()) {
            out.push_str(&format!("Event count: {c}\n"));
        }
        if let Some(s) = obj.get("last_sequence").and_then(|v| v.as_i64()) {
            out.push_str(&format!("Last sequence: {s}\n"));
        }
    }
    out.push_str("\nRecent events:\n");
    let start = state.replayed_events.len().saturating_sub(max_events);
    for ev in state.replayed_events.iter().skip(start) {
        // The number a finding cites in `evidence_sequence`.
        out.push_str(&format!("  #{} ", ev.sequence));
        match &ev.payload {
            EventPayload::Genesis { message, .. } => {
                out.push_str(&format!("[genesis] {message}\n"));
            }
            EventPayload::PromptInput { content } => {
                out.push_str(&format!("[prompt] {content}\n"));
            }
            EventPayload::Thought { content } => {
                out.push_str(&format!("[thought] {content}\n"));
            }
            EventPayload::GuardDenial { action, reason, .. } => {
                out.push_str(&format!(
                    "[guard_denial] {} refused: {}\n",
                    action.as_deref().unwrap_or("action"),
                    reason
                ));
            }
            EventPayload::TripwireRejection {
                action,
                reason,
                stage,
                ..
            } => {
                out.push_str(&format!(
                    "[tripwire_rejection] {} rejected at {}: {}\n",
                    action.as_deref().unwrap_or("prompt"),
                    stage,
                    reason
                ));
            }
            EventPayload::DataReceipt {
                tool,
                source,
                text_bytes,
                ..
            } => {
                out.push_str(&format!(
                    "[data_receipt] {tool} {} ({text_bytes} bytes received, hashed)\n",
                    source.as_deref().unwrap_or("")
                ));
            }
            EventPayload::SchemaError {
                message,
                attempt,
                max_attempts,
            } => {
                out.push_str(&format!(
                    "[schema_error] ({attempt}/{max_attempts}) {message}\n"
                ));
            }
            EventPayload::CircuitBreaker {
                reason,
                consecutive_failures,
            } => {
                out.push_str(&format!(
                    "[circuit_breaker] ({consecutive_failures} failures) {reason}\n"
                ));
            }
            EventPayload::Action { name, params } => {
                out.push_str(&format!("[action] {name} {params:?}\n"));
            }
            EventPayload::Observation { content } => {
                let trunc = if content.len() > 200 {
                    let mut b = 200;
                    while b > 0 && !content.is_char_boundary(b) {
                        b -= 1;
                    }
                    format!("{}...", &content[..b])
                } else {
                    content.clone()
                };
                out.push_str(&format!("[observation] {trunc}\n"));
            }
            EventPayload::ApprovalRequired { .. } | EventPayload::ApprovalDecision { .. } => {
                out.push_str("[approval]\n");
            }
            EventPayload::CrossLedgerSeal { seal_hash, .. } => {
                out.push_str(&format!(
                    "[cross_ledger_seal] {}\n",
                    &seal_hash[..16.min(seal_hash.len())]
                ));
            }
            EventPayload::Anchor {
                ledger_tip_hash, ..
            } => {
                out.push_str(&format!(
                    "[anchor] tip {}\n",
                    &ledger_tip_hash[..16.min(ledger_tip_hash.len())]
                ));
            }
            EventPayload::KeyRotation {
                new_public_key,
                rotation_index,
            } => {
                out.push_str(&format!(
                    "[key_rotation] index {} new_key {}\n",
                    rotation_index,
                    &new_public_key[..16.min(new_public_key.len())]
                ));
            }
            EventPayload::KeyRevocation {
                revoked_public_key,
                reason,
            } => {
                out.push_str(&format!(
                    "[key_revocation] key {} reason: {}\n",
                    &revoked_public_key[..16.min(revoked_public_key.len())],
                    reason
                ));
            }
            EventPayload::VerifiableCredential { .. } => {
                out.push_str("[verifiable_credential]\n");
            }
            EventPayload::ChatMessage { role, content, .. } => {
                out.push_str(&format!("[chat:{role}] {content}\n"));
            }
        }
    }
    out.push_str("\nPropose the next action as a single JSON object (action + params only).");
    out
}

/// Deterministic backend used by integration tests.
struct MockBackend;

#[async_trait]
impl LlmBackend for MockBackend {
    async fn propose(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<ectoledger_core::intent::ProposedIntent, LlmError> {
        Ok(ectoledger_core::intent::ProposedIntent {
            action: "complete".to_string(),
            params: json!({ "findings": [] }),
            justification: "Mock backend deterministic completion".to_string(),
            reasoning: "No external LLM available in this environment.".to_string(),
        })
    }

    async fn raw_call(&self, _system: &str, user: &str) -> Result<String, LlmError> {
        Ok(format!("mock: {user}"))
    }

    fn backend_name(&self) -> &str {
        "mock"
    }

    fn model_name(&self) -> &str {
        "mock-v1"
    }
}

// Factory functions below depend on the host crate's config module.
pub fn backend_from_env(client: &reqwest::Client) -> Result<Box<dyn LlmBackend>, LlmError> {
    backend_for(&crate::config::llm_provider(), client, None)
}

/// Creates a Guard LLM backend from environment variables.
///
/// Reads `GUARD_LLM_BACKEND` (default: same as `LLM_PROVIDER`) and
/// `GUARD_LLM_MODEL` to allow the guard to run on a separate, isolated model.
pub fn guard_backend_from_env(client: &reqwest::Client) -> Result<Box<dyn LlmBackend>, LlmError> {
    let name = crate::config::guard_llm_backend().unwrap_or_else(crate::config::llm_provider);
    backend_for(&name, client, crate::config::guard_llm_model())
}

/// Build a backend from a preset name.
///
/// The GUI offers `lmstudio`, `llamacpp`, `vllm`, `mlx`, `localai`, and
/// `openai-compatible`. Those are not separate implementations - they all
/// speak one of three transports. Resolving the preset here is what makes
/// selecting LM Studio in Settings actually run against LM Studio, instead of
/// failing with `unsupported LLM backend: lmstudio`.
fn backend_for(
    name: &str,
    client: &reqwest::Client,
    model_override: Option<String>,
) -> Result<Box<dyn LlmBackend>, LlmError> {
    if name == "mock" {
        return Ok(Box::new(MockBackend));
    }
    let spec =
        resolve_provider(name).ok_or_else(|| LlmError::UnsupportedBackend(name.to_string()))?;
    let model = match model_override.or_else(|| crate::config::configured_model_for(name)) {
        Some(model) => model,
        // A hosted API has no "mistral" to fall back on: without a default
        // (xAI, an Azure deployment) the operator names the model.
        None if spec.api_key_required && spec.default_model.is_none() => {
            return Err(LlmError::Setup(format!(
                "{} needs a model: set OPENAI_MODEL{} or choose one in Settings.",
                spec.label,
                if spec.auth == ectoledger_llm::Auth::ApiKeyHeader {
                    " (the deployment name)"
                } else {
                    ""
                }
            )));
        }
        None => crate::config::model_for(name),
    };

    // All three transports share the one `client` the caller built, so the
    // timeout it reports in a `LlmError::Timeout` message is the same number
    // that client was actually constructed with - see `config::llm_timeout_secs`.
    let timeout_secs = crate::config::llm_timeout_secs();
    match spec.transport {
        Transport::OllamaNative => {
            let mut backend = OllamaBackend::from_env(client);
            backend.override_base_url(crate::config::ollama_base_url());
            backend.override_model(model);
            backend.override_timeout_secs(timeout_secs);
            Ok(Box::new(backend))
        }
        Transport::OpenAiCompatible => {
            // Resolved against `name`, not the primary provider: a guard on
            // `openai` while `LLM_PROVIDER=ollama` must hit api.openai.com,
            // not Ollama's port. A preset with no default address (Azure,
            // LocalAI, a custom gateway) needs one configured; falling back
            // to api.openai.com would send its key to the wrong company.
            let base_url = crate::config::configured_openai_base_url_for(name)
                .or_else(|| spec.default_base_url.map(str::to_string))
                .ok_or_else(|| {
                    LlmError::Setup(format!(
                        "{} needs a base URL: set OPENAI_BASE_URL or the URL in Settings.",
                        spec.label
                    ))
                })?;
            let mut backend = OpenAiBackend::from_env(client);
            backend.override_base_url(base_url);
            backend.override_model(model);
            backend.override_timeout_secs(timeout_secs);
            if let Some(env_name) = spec.api_key_env {
                let key = ectoledger_llm::api_key::resolve(env_name).unwrap_or_default();
                backend.override_api_key(key, spec.auth);
            }
            Ok(Box::new(backend))
        }
        Transport::Anthropic => {
            let mut backend = AnthropicBackend::from_env(client);
            backend.override_model(model);
            backend.override_timeout_secs(timeout_secs);
            Ok(Box::new(backend))
        }
    }
}

#[cfg(test)]
mod prompt_tests;

#[cfg(test)]
mod factory_tests {
    use super::*;

    #[test]
    fn every_published_preset_constructs() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let client = reqwest::Client::new();
        for spec in PRESETS {
            match backend_for(spec.id, &client, Some("test-model".into())) {
                Ok(backend) => {
                    assert_eq!(backend.model_name(), "test-model", "preset {}", spec.id)
                }
                // Azure, LocalAI and a custom gateway have no address of
                // their own; none is configured here.
                Err(LlmError::Setup(msg)) if spec.default_base_url.is_none() => {
                    assert!(msg.contains("needs a base URL"), "{}: {msg}", spec.id)
                }
                Err(e) => panic!("preset {} failed to construct: {e}", spec.id),
            }
        }
    }

    #[test]
    fn a_hosted_preset_without_a_default_model_asks_for_one() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("OPENAI_MODEL").ok();
        // SAFETY: serialised by ENV_LOCK.
        unsafe { std::env::remove_var("OPENAI_MODEL") };
        let client = reqwest::Client::new();
        let outcome = backend_for("xai", &client, None);
        if let Some(v) = prev {
            unsafe { std::env::set_var("OPENAI_MODEL", v) };
        }
        match outcome {
            Err(LlmError::Setup(msg)) => assert!(msg.contains("xAI needs a model"), "{msg}"),
            Ok(b) => panic!("expected a setup error, got model {}", b.model_name()),
            Err(e) => panic!("expected a setup error, got {e}"),
        }
    }

    #[test]
    fn a_hosted_preset_sends_its_own_key_to_its_own_address() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let client = reqwest::Client::new();
        for (id, address) in [
            ("groq", "https://api.groq.com/openai/v1/chat/completions"),
            (
                "gemini",
                "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            ),
            ("mistral", "https://api.mistral.ai/v1/chat/completions"),
            (
                "openrouter",
                "https://openrouter.ai/api/v1/chat/completions",
            ),
            ("deepseek", "https://api.deepseek.com/v1/chat/completions"),
            ("xai", "https://api.x.ai/v1/chat/completions"),
        ] {
            let backend = backend_for(id, &client, Some("m".into())).unwrap();
            let base = backend.endpoint_url().expect("an address");
            assert_eq!(
                ectoledger_llm::url::chat_completions_url(base),
                address,
                "{id}"
            );
        }
    }

    #[test]
    fn an_unknown_preset_is_an_error_not_a_silent_ollama() {
        let client = reqwest::Client::new();
        match backend_for("bard", &client, None) {
            Err(LlmError::UnsupportedBackend(name)) => assert_eq!(name, "bard"),
            Ok(_) => panic!("expected UnsupportedBackend, got Ok"),
            Err(e) => panic!("expected UnsupportedBackend, got {e}"),
        }
    }

    #[test]
    fn an_openai_guard_does_not_point_at_the_ollama_primary() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let prev_data_dir = std::env::var("ECTO_DATA_DIR").ok();
        struct RestoreEnv(Option<String>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                unsafe {
                    std::env::remove_var("GUARD_LLM_BACKEND");
                    std::env::remove_var("GUARD_LLM_MODEL");
                    std::env::remove_var("LLM_PROVIDER");
                    std::env::remove_var("OPENAI_BASE_URL");
                    match &self.0 {
                        Some(v) => std::env::set_var("ECTO_DATA_DIR", v),
                        None => std::env::remove_var("ECTO_DATA_DIR"),
                    }
                }
            }
        }
        let _restore = RestoreEnv(prev_data_dir);
        unsafe {
            std::env::set_var("ECTO_DATA_DIR", tmp.path());
            std::env::remove_var("OPENAI_BASE_URL");
            std::env::remove_var("LLM_BACKEND");
            std::env::set_var("LLM_PROVIDER", "ollama");
            std::env::set_var("GUARD_LLM_BACKEND", "openai");
            std::env::set_var("GUARD_LLM_MODEL", "gpt-4o-mini");
        }

        let client = reqwest::Client::new();
        let guard = guard_backend_from_env(&client).expect("openai guard constructs");
        let url = guard
            .endpoint_url()
            .expect("openai transport has an endpoint");
        assert!(
            url.starts_with("https://api.openai.com"),
            "OpenAI guard inherited the primary provider's URL: {url}"
        );
        assert!(
            !url.contains("11434"),
            "OpenAI guard pointed at Ollama: {url}"
        );

        unsafe {
            std::env::remove_var("GUARD_LLM_MODEL");
            std::env::remove_var("OPENAI_MODEL");
        }
        let guard_default =
            guard_backend_from_env(&client).expect("openai guard with default model");
        assert_eq!(
            guard_default.model_name(),
            "gpt-6-astra",
            "OpenAI guard should use OpenAI's default model, not the primary provider's model"
        );
    }
}
