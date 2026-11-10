use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{LlmBackend, LlmError};
use ectoledger_core::intent::ProposedIntent;

const ANTHROPIC_API: &str = "https://api.anthropic.com";

/// Room for adaptive thinking plus the intent JSON. Current models think
/// before answering, and thinking tokens count against this limit.
const MAX_TOKENS: u32 = 16_000;

/// Server-side refusal fallback: a request a safety classifier declines is
/// re-run on the model Anthropic recommends for that refusal category.
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallbacks: Option<&'static str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    stop_details: Option<StopDetails>,
}

#[derive(Debug, Deserialize)]
struct StopDetails {
    #[serde(default)]
    category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

pub struct AnthropicBackend {
    base_url: String,
    model: String,
    api_key: String,
    client: reqwest::Client,
    /// The `client`'s configured per-request timeout, in seconds; see
    /// `OllamaBackend::timeout_secs` for why this is carried separately from
    /// the client.
    timeout_secs: Option<u64>,
}

impl AnthropicBackend {
    pub fn from_env(client: &reqwest::Client) -> Self {
        let preset = crate::provider::resolve("anthropic");
        let base_url = std::env::var("ANTHROPIC_BASE_URL").unwrap_or_else(|_| {
            preset
                .and_then(|p| p.default_base_url)
                .unwrap_or(ANTHROPIC_API)
                .to_string()
        });
        let model = std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| {
            preset
                .and_then(|p| p.default_model)
                .unwrap_or_default()
                .to_string()
        });
        let api_key = crate::api_key::resolve("ANTHROPIC_API_KEY").unwrap_or_default();
        Self {
            base_url,
            model,
            api_key,
            client: client.clone(),
            timeout_secs: None,
        }
    }

    fn build_request(&self, system: &str, user: &str) -> ChatRequest {
        ChatRequest {
            model: self.model.clone(),
            max_tokens: MAX_TOKENS,
            system: system.to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: user.to_string(),
            }],
            fallbacks: self.uses_server_side_fallback().then_some("default"),
            stream: false,
        }
    }

    /// `fallbacks` exists only on the Claude API itself, and only the Opus 5,
    /// Sonnet 5.5 and Fable 5.1 lines accept the `"default"` form. A proxy or
    /// gateway in `ANTHROPIC_BASE_URL` may not forward it, so it is left off.
    fn uses_server_side_fallback(&self) -> bool {
        const LINES: [&str; 3] = ["claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-1"];
        self.base_url.trim_end_matches('/') == ANTHROPIC_API
            && LINES.iter().any(|line| self.model.starts_with(line))
    }

    pub fn override_model(&mut self, model: String) {
        self.model = model;
    }

    /// Records the `client`'s configured per-request timeout (seconds); see
    /// `OllamaBackend::override_timeout_secs`.
    pub fn override_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = Some(secs);
    }

    /// Point this backend at a different server.
    ///
    /// Mirrors `OpenAiBackend`/`OllamaBackend`: the host resolves the base
    /// URL from the saved settings file first and the environment second, so
    /// it has to be able to override what `from_env` read.
    pub fn override_base_url(&mut self, base_url: String) {
        self.base_url = base_url;
    }
}

impl AnthropicBackend {
    async fn reply(&self, system: &str, user: &str) -> Result<crate::Reply, LlmError> {
        let response = self.request(self.build_request(system, user)).await?;
        let chat: ChatResponse = response
            .json()
            .await
            .map_err(|e| crate::classify_model_call_error(e, self.timeout_secs))?;
        answer_text(chat)
    }

    /// The Messages API response, checked for an error status; its body is
    /// server-sent events when the request asks to stream.
    async fn request(&self, body: ChatRequest) -> Result<reqwest::Response, LlmError> {
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));

        let mut req = self.client.post(&url).json(&body);
        if !self.api_key.is_empty() {
            req = req.header("x-api-key", &self.api_key);
            req = req.header("anthropic-version", "2023-06-01");
        }
        if body.fallbacks.is_some() {
            req = req.header("anthropic-beta", FALLBACK_BETA);
        }
        let response = req
            .send()
            .await
            .map_err(|e| crate::classify_model_call_error(e, self.timeout_secs))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(LlmError::HttpStatus(status.as_u16(), text));
        }
        Ok(response)
    }
}

#[async_trait]
impl LlmBackend for AnthropicBackend {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError> {
        self.reply(system, user).await?.into_intent()
    }

    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError> {
        self.reply(system, user).await?.into_text()
    }

    async fn stream_raw(&self, system: &str, user: &str) -> Result<crate::TextStream, LlmError> {
        let body = ChatRequest {
            stream: true,
            ..self.build_request(system, user)
        };
        let response = self.request(body).await?;
        Ok(crate::stream::text_stream(
            response,
            crate::stream::anthropic_line,
        ))
    }

    fn backend_name(&self) -> &str {
        "anthropic"
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn endpoint_url(&self) -> Option<&str> {
        Some(&self.base_url)
    }

    async fn ensure_ready(&self, client: &reqwest::Client) -> Result<(), LlmError> {
        if self.api_key.is_empty() {
            return Err(LlmError::Setup(
                "ANTHROPIC_API_KEY is not set; the Anthropic API cannot be used without it."
                    .to_string(),
            ));
        }
        let url = format!("{}/v1/models", self.base_url.trim_end_matches('/'));
        crate::probe_reachable(client, "Anthropic", &url).await
    }

    async fn list_models(&self, client: &reqwest::Client) -> Result<Vec<String>, LlmError> {
        let url = format!("{}/v1/models", self.base_url.trim_end_matches('/'));
        let mut req = client.get(&url);
        if !self.api_key.is_empty() {
            req = req
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01");
        }
        let response = req.send().await.map_err(LlmError::Http)?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(LlmError::Setup(format!(
                "{url} refused the request ({status}); check the API key."
            )));
        }
        if !status.is_success() {
            return Ok(Vec::new());
        }

        #[derive(Deserialize)]
        struct ModelList {
            #[serde(default)]
            data: Vec<ModelEntry>,
        }
        #[derive(Deserialize)]
        struct ModelEntry {
            id: String,
        }

        let list: ModelList = response.json().await.map_err(LlmError::Http)?;
        Ok(list
            .data
            .into_iter()
            .map(|m| m.id)
            .filter(|id| crate::is_chat_model_id(id))
            .collect())
    }
}

/// The model's answer: the first `text` block. Thinking blocks come first on
/// current models and carry no text field.
fn answer_text(chat: ChatResponse) -> Result<crate::Reply, LlmError> {
    if chat.stop_reason.as_deref() == Some("refusal") {
        return Err(LlmError::Refused {
            category: chat.stop_details.and_then(|d| d.category),
        });
    }
    Ok(crate::Reply {
        truncated: chat.stop_reason.as_deref() == Some("max_tokens"),
        text: chat
            .content
            .into_iter()
            .filter(|block| block.block_type == "text")
            .find_map(|block| block.text),
    })
}

#[cfg(test)]
mod tests;
