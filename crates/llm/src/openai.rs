use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{LlmBackend, LlmError};
use ectoledger_core::intent::ProposedIntent;

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    /// `{"type":"json_object"}` when JSON mode is being attempted. Omitted
    /// entirely on the retry, because some servers reject the field outright.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
}

#[derive(Debug, Serialize, Clone, Copy)]
struct ResponseFormat {
    #[serde(rename = "type")]
    kind: &'static str,
}

const JSON_OBJECT: ResponseFormat = ResponseFormat {
    kind: "json_object",
};

#[derive(Debug, Serialize, Clone)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ChoiceMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
    /// Set instead of `content` when the model declines (OpenAI refusals).
    #[serde(default)]
    refusal: Option<String>,
}

/// The first choice's text, or why there is none.
fn answer_text(chat: ChatResponse) -> Result<crate::Reply, LlmError> {
    let choice = chat
        .choices
        .into_iter()
        .next()
        .ok_or(LlmError::EmptyResponse)?;
    if choice.message.refusal.is_some_and(|r| !r.trim().is_empty()) {
        return Err(LlmError::Refused { category: None });
    }
    if choice.finish_reason.as_deref() == Some("content_filter") {
        return Err(LlmError::Refused {
            category: Some("content_filter".to_string()),
        });
    }
    Ok(crate::Reply {
        text: choice.message.content,
        truncated: choice.finish_reason.as_deref() == Some("length"),
    })
}

pub struct OpenAiBackend {
    base_url: String,
    model: String,
    api_key: String,
    auth: crate::Auth,
    client: reqwest::Client,
    /// The `client`'s configured per-request timeout, in seconds; see
    /// `OllamaBackend::timeout_secs` for why this is carried separately from
    /// the client.
    timeout_secs: Option<u64>,
}

impl OpenAiBackend {
    pub fn from_env(client: &reqwest::Client) -> Self {
        let base_url = std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com".to_string());
        let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| {
            crate::provider::resolve("openai")
                .and_then(|p| p.default_model)
                .unwrap_or_default()
                .to_string()
        });
        let api_key = crate::api_key::resolve("OPENAI_API_KEY").unwrap_or_default();
        Self {
            base_url,
            model,
            api_key,
            auth: crate::Auth::Bearer,
            client: client.clone(),
            timeout_secs: None,
        }
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
    /// The host resolves the base URL from the saved settings file first and
    /// the environment second, so it has to be able to override what
    /// `from_env` read - otherwise a URL set in the GUI would be stored and
    /// silently ignored.
    pub fn override_base_url(&mut self, base_url: String) {
        self.base_url = base_url;
    }

    /// Use `api_key`, sent as `auth` says. A hosted preset reads its own
    /// variable (`GROQ_API_KEY`, `AZURE_OPENAI_API_KEY`), not `OPENAI_API_KEY`.
    pub fn override_api_key(&mut self, api_key: String, auth: crate::Auth) {
        self.api_key = api_key;
        self.auth = auth;
    }

    async fn send(
        &self,
        url: &str,
        messages: &[ChatMessage],
        response_format: Option<ResponseFormat>,
    ) -> Result<crate::Reply, LlmError> {
        let response = self.request(url, messages, response_format, false).await?;
        let chat: ChatResponse = response
            .json()
            .await
            .map_err(|e| crate::classify_model_call_error(e, self.timeout_secs))?;
        answer_text(chat)
    }

    /// The `chat/completions` response, checked for an error status; its body
    /// is server-sent events when `stream` is set.
    async fn request(
        &self,
        url: &str,
        messages: &[ChatMessage],
        response_format: Option<ResponseFormat>,
        stream: bool,
    ) -> Result<reqwest::Response, LlmError> {
        let body = ChatRequest {
            model: self.model.clone(),
            messages: messages.to_vec(),
            response_format,
            stream,
        };

        let req = crate::with_api_key(self.client.post(url).json(&body), &self.api_key, self.auth);
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

    fn messages(system: &str, user: &str) -> Vec<ChatMessage> {
        vec![
            ChatMessage {
                role: "system".to_string(),
                content: system.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: user.to_string(),
            },
        ]
    }

    /// One chat completion. With `json_mode`, JSON mode is asked for first:
    /// without it, local models wrap an object in prose often enough to break
    /// the parser. llama.cpp and older vLLM builds reject the field with a 400,
    /// so a rejection is retried once without it. Free-form replies (the
    /// guard's verdict, chat, a red-team array) must not ask for it: JSON mode
    /// forces a single object.
    async fn chat(
        &self,
        system: &str,
        user: &str,
        json_mode: bool,
    ) -> Result<crate::Reply, LlmError> {
        // `chat_completions_url` is the only place the `/v1` segment is
        // appended. LM Studio, llama.cpp and vLLM all print
        // `http://localhost:PORT/v1` as "the base URL", so appending
        // unconditionally produced `/v1/v1/chat/completions` and a 404 for
        // exactly the string those users paste.
        let url = crate::url::chat_completions_url(&self.base_url);
        let messages = Self::messages(system, user);

        if !json_mode {
            return self.send(&url, &messages, None).await;
        }
        match self.send(&url, &messages, Some(JSON_OBJECT)).await {
            Err(LlmError::HttpStatus(400, body)) => {
                tracing::debug!(
                    "server rejected response_format=json_object (400: {}); \
                     retrying without JSON mode",
                    body.chars().take(200).collect::<String>()
                );
                self.send(&url, &messages, None).await
            }
            other => other,
        }
    }
}

#[async_trait]
impl LlmBackend for OpenAiBackend {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError> {
        self.chat(system, user, true).await?.into_intent()
    }

    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError> {
        self.chat(system, user, false).await?.into_text()
    }

    async fn stream_raw(&self, system: &str, user: &str) -> Result<crate::TextStream, LlmError> {
        let url = crate::url::chat_completions_url(&self.base_url);
        let response = self
            .request(&url, &Self::messages(system, user), None, true)
            .await?;
        Ok(crate::stream::text_stream(
            response,
            crate::stream::openai_line,
        ))
    }

    fn backend_name(&self) -> &str {
        "openai"
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn endpoint_url(&self) -> Option<&str> {
        Some(&self.base_url)
    }

    async fn ensure_ready(&self, client: &reqwest::Client) -> Result<(), LlmError> {
        // Probe /models rather than the chat route: it is a GET, costs the
        // server nothing, and a wrong base URL fails here in milliseconds
        // instead of halfway through an audit.
        let url = format!(
            "{}/models",
            crate::url::normalize_openai_base(&self.base_url)
        );
        crate::probe_reachable(client, "OpenAI-compatible server", &url).await
    }

    async fn list_models(&self, client: &reqwest::Client) -> Result<Vec<String>, LlmError> {
        crate::list_models_openai_compatible(client, &self.base_url, &self.api_key, self.auth).await
    }
}

#[cfg(test)]
mod tests;
