use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{LlmBackend, LlmError};
use ectoledger_core::intent::ProposedIntent;

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(alias = "message")]
    message: Option<ChatResponseMessage>,
    #[serde(alias = "response")]
    response: Option<String>,
    /// `"length"` when the answer stopped at the token limit.
    #[serde(default)]
    done_reason: Option<String>,
}

/// The reply text (`/api/chat` message, or `/api/generate` response).
fn answer_text(chat: ChatResponse) -> crate::Reply {
    crate::Reply {
        truncated: chat.done_reason.as_deref() == Some("length"),
        text: chat.message.and_then(|m| m.content).or(chat.response),
    }
}

#[derive(Debug, Deserialize)]
struct ChatResponseMessage {
    content: Option<String>,
}

pub struct OllamaBackend {
    base_url: String,
    model: String,
    client: reqwest::Client,
    /// The `client`'s configured per-request timeout, in seconds, so a
    /// timeout error can name the number the operator actually set. `None`
    /// until the host calls `override_timeout_secs` - reqwest exposes no
    /// public getter for a client's own timeout.
    timeout_secs: Option<u64>,
}

impl OllamaBackend {
    pub fn from_env(client: &reqwest::Client) -> Self {
        let base_url = std::env::var("OLLAMA_BASE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
        let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "mistral".to_string());
        Self {
            base_url,
            model,
            client: client.clone(),
            timeout_secs: None,
        }
    }

    pub fn override_model(&mut self, model: String) {
        self.model = model;
    }

    /// Records the `client`'s configured per-request timeout (seconds) so a
    /// `reqwest::Error::is_timeout()` can be reported as "did not answer
    /// within N s" instead of a generic transport error.
    pub fn override_timeout_secs(&mut self, secs: u64) {
        self.timeout_secs = Some(secs);
    }

    /// Point this backend at a different Ollama server.
    ///
    /// The host resolves the base URL from the saved settings file first, so
    /// a URL set in the GUI has to be injectable after `from_env`.
    pub fn override_base_url(&mut self, base_url: String) {
        self.base_url = base_url;
    }
}

impl OllamaBackend {
    /// One `/api/chat` call; `json_mode` asks Ollama to constrain the reply
    /// to a JSON object, which only the intent call wants.
    async fn reply(
        &self,
        system: &str,
        user: &str,
        json_mode: bool,
    ) -> Result<crate::Reply, LlmError> {
        let response = self.request(system, user, json_mode, false).await?;
        let chat: ChatResponse = response
            .json()
            .await
            .map_err(|e| crate::classify_model_call_error(e, self.timeout_secs))?;
        Ok(answer_text(chat))
    }

    /// The `/api/chat` response, checked for an error status; its body is one
    /// object, or one object per line when `stream` is set.
    async fn request(
        &self,
        system: &str,
        user: &str,
        json_mode: bool,
        stream: bool,
    ) -> Result<reqwest::Response, LlmError> {
        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let body = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system.to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user.to_string(),
                },
            ],
            stream,
            format: json_mode.then(|| "json".to_string()),
        };

        let response = self
            .client
            .post(&url)
            .json(&body)
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
impl LlmBackend for OllamaBackend {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError> {
        self.reply(system, user, true).await?.into_intent()
    }

    async fn stream_raw(&self, system: &str, user: &str) -> Result<crate::TextStream, LlmError> {
        let response = self.request(system, user, false, true).await?;
        Ok(crate::stream::text_stream(
            response,
            crate::stream::ollama_line,
        ))
    }

    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError> {
        Ok(self
            .reply(system, user, false)
            .await?
            .into_text()?
            .trim()
            .to_string())
    }

    fn backend_name(&self) -> &str {
        "ollama"
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn endpoint_url(&self) -> Option<&str> {
        Some(&self.base_url)
    }

    async fn ensure_ready(&self, client: &reqwest::Client) -> Result<(), LlmError> {
        crate::ollama_setup::ensure_ollama_ready(&self.base_url, &self.model, client)
            .await
            .map_err(|e| LlmError::Setup(e.to_string()))
    }

    async fn list_models(&self, client: &reqwest::Client) -> Result<Vec<String>, LlmError> {
        // Ollama predates the OpenAI list route and uses its own.
        let url = format!("{}/api/tags", self.base_url.trim_end_matches('/'));
        let response = client.get(&url).send().await.map_err(LlmError::Http)?;
        if !response.status().is_success() {
            // Unlike the OpenAI-compatible route, /api/tags is Ollama's only
            // listing endpoint, so a non-success status is a real failure,
            // not a server that simply lacks the feature - do not swallow it
            // as an empty (and misleadingly "successful") list.
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(LlmError::HttpStatus(status.as_u16(), text));
        }

        #[derive(serde::Deserialize)]
        struct Tags {
            #[serde(default)]
            models: Vec<Tag>,
        }
        #[derive(serde::Deserialize)]
        struct Tag {
            name: String,
        }

        let tags: Tags = response.json().await.map_err(LlmError::Http)?;
        Ok(tags.models.into_iter().map(|m| m.name).collect())
    }
}

#[cfg(test)]
mod tests;
