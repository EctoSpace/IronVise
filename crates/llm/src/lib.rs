//! LLM backend abstraction and provider implementations for IronVise.
//!
//! This crate defines the [`LlmBackend`] trait and concrete implementations for
//! Ollama, OpenAI, and Anthropic.  The host crate re-exports this module so
//! existing `crate::llm::*` paths continue to resolve.

mod anthropic;
pub mod api_key;
mod ollama_backend;
pub mod ollama_setup;
mod openai;
pub mod provider;
#[cfg(test)]
mod replay_tests;
pub mod stream;
#[cfg(test)]
mod test_support;
pub mod url;

pub use stream::TextStream;

pub use anthropic::AnthropicBackend;
pub use ollama_backend::OllamaBackend;
pub use ollama_setup::{OllamaSetupError, ensure_ollama_ready};
pub use openai::OpenAiBackend;
pub use provider::{Auth, PRESETS, ProviderSpec, Transport, resolve as resolve_provider};
pub use url::{chat_completions_url, normalize_openai_base};

use async_trait::async_trait;
use ectoledger_core::intent::ProposedIntent;

/// Env var the host reads to configure the per-request timeout for every LLM
/// HTTP client (`crates/host/src/config.rs::llm_timeout_secs`). Named here,
/// not duplicated in the host, so the getter and the error message that
/// names it can never drift apart.
pub const LLM_TIMEOUT_ENV: &str = "ECTO_LLM_TIMEOUT_SECS";

pub const DEFAULT_SYSTEM_PROMPT: &str = r#"You are a security-audit agent. Your response must be exactly one JSON object with no surrounding text.

Goal: Achieve the user's current goal (stated at the start of the user message).

Allowed actions and params:
- run_command: params.command (string) - run a single shell command
- read_file: params.path (string) - read a file path
- http_get: params.url (string) - fetch a URL
- complete: no params or empty params - finish the audit

Security rules:
- Propose only actions necessary for the stated goal.
- Do not run destructive or off-goal commands.

Anti-loop rule:
- Do not repeat the same action with the same parameters. If an action did not advance the goal, try a different action or complete with your findings.

Output format (JSON only - you MUST use this exact structure):
{"action": "<action>", "params": {...}, "justification": "<why this action is needed, at least 5 chars>", "reasoning": "<one or two sentences on how this step serves the goal>"}
Every response MUST include all four fields: "action", "params", "justification", and "reasoning". If "justification" is missing or shorter than 5 characters your response will be rejected.
When you complete, include in params an optional \"findings\" array. Each finding must have \"severity\", \"title\", \"evidence\", \"recommendation\", and for high/critical must include \"evidence_sequence\" (array of the #N numbers of the [observation] lines that support this finding: the observation itself, not the [action] that produced it) and \"evidence_quotes\" (array of exact substrings from those observations).

Example for step 1 (reading a file):
{\"action\": \"read_file\", \"params\": {\"path\": \"server_config.txt\"}, \"justification\": \"Reading the config file to identify misconfigurations.\", \"reasoning\": \"Reading config to inspect settings.\"}"#;

/// Few-shot examples injected during the first steps to anchor weaker models
/// and prevent them from producing off-format or looping output.
pub fn few_shot_examples() -> &'static str {
    r#"
--- FEW-SHOT EXAMPLES (follow this exact format) ---

Example 1 - reading a file:
User: "Current goal: Audit server_config.txt\n\nRecent events:\n  [genesis] initialized"
Assistant: {"action":"read_file","params":{"path":"server_config.txt"},"justification":"Need to inspect server configuration for audit findings.","reasoning":"The goal is to audit server_config.txt, so reading it is the first logical step."}

Example 2 - running a command:
User: "Current goal: Check open ports\n\nRecent events:\n  [observation] file contents: ..."
Assistant: {"action":"run_command","params":{"command":"ss -tlnp"},"justification":"Listing TCP listening ports to identify exposed services.","reasoning":"After reading config, enumerating listening ports confirms which services are active."}

Example 3 - completing the audit:
User: "Current goal: Audit server_config.txt\n\nRecent events:\n  [observation] port 22 open"
Assistant: {"action":"complete","params":{"findings":[{"severity":"medium","title":"SSH exposed","evidence":"port 22 open","recommendation":"Restrict SSH access via firewall rules."}]},"justification":"All planned checks done.","reasoning":"Sufficient evidence gathered to produce findings."}

--- END EXAMPLES ---
"#
}

pub fn strip_markdown_fences(s: &str) -> &str {
    let s = s.trim();
    if !s.starts_with("```") {
        return s;
    }
    let after_open = s.trim_start_matches('`');
    let after_lang = after_open
        .trim_start_matches("json")
        .trim_start_matches("JSON")
        .trim_start_matches('\n')
        .trim_start_matches('\r');
    match after_lang.rfind("```") {
        // `rfind` locates the last three backticks of the closing fence, but a
        // fence may be longer than three - Markdown's way of nesting a block
        // whose own content contains a triple fence is to open with four or
        // more. Trimming only what `rfind` matched would leave the surplus
        // backticks attached to the body, and `serde_json` then rejects the
        // whole response over a stray '`'. Trim the entire run.
        //
        // Safe for JSON payloads: valid JSON never ends in a backtick, so this
        // cannot eat real content - including backticks *inside* a string,
        // which are followed by the closing quote and brace.
        Some(end) => after_lang[..end].trim_end_matches('`').trim(),
        None => after_lang.trim(),
    }
}

/// What a provider returned for one request: the answer text, if any, and
/// whether the provider says it stopped at the output-token limit.
pub(crate) struct Reply {
    pub(crate) text: Option<String>,
    pub(crate) truncated: bool,
}

impl Reply {
    /// The answer text. Cut-off text is still text, and a free-form caller
    /// (the guard, chat) can use it; only a cut-off reply with no text at all
    /// is `Truncated`.
    pub(crate) fn into_text(self) -> Result<String, LlmError> {
        match self.text {
            Some(text) if !(self.truncated && text.trim().is_empty()) => Ok(text),
            _ if self.truncated => Err(LlmError::Truncated),
            _ => Err(LlmError::EmptyResponse),
        }
    }

    /// The answer as an intent. Text that fails to parse because it was cut
    /// off is reported as `Truncated`, which says what to change; a complete
    /// but broken answer keeps its parse error.
    pub(crate) fn into_intent(self) -> Result<ProposedIntent, LlmError> {
        let truncated = self.truncated;
        let text = self.into_text()?;
        parse_intent_repairing_justification(&text)
            .map_err(|e| if truncated { LlmError::Truncated } else { e })
    }
}

/// Parse raw model output into a [`ProposedIntent`], repairing a missing
/// justification.
///
/// Small models routinely omit `justification`, and the strict schema validator
/// rejects the intent when they do. Ollama's backend has always repaired this;
/// the OpenAI path did not, so the *same model* behaved worse through LM Studio
/// than through Ollama purely because of which transport it was reached by.
/// Shared here so every backend behaves identically.
///
/// The repair only ever fills an empty field - it never overwrites what the
/// model actually said.
pub fn parse_intent_repairing_justification(raw: &str) -> Result<ProposedIntent, LlmError> {
    let json_str = strip_markdown_fences(raw.trim());
    let mut intent: ProposedIntent =
        serde_json::from_str(json_str).map_err(LlmError::InvalidJson)?;

    if intent.justification.trim().is_empty() {
        intent.justification = if intent.reasoning.trim().is_empty() {
            // Last resort: synthesise something minimal from the action itself
            // so a harmless prompt does not trip the validator.
            format!(
                "Executing '{}' action to advance the stated goal.",
                intent.action
            )
        } else {
            intent.reasoning.clone()
        };
    }
    Ok(intent)
}

#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError>;
    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError>;
    fn backend_name(&self) -> &str;
    fn model_name(&self) -> &str;

    /// The free-form reply of [`raw_call`](Self::raw_call), streamed as it is
    /// generated. The default sends the whole reply as one piece, for
    /// backends with nothing to stream.
    async fn stream_raw(&self, system: &str, user: &str) -> Result<TextStream, LlmError> {
        let text = self.raw_call(system, user).await?;
        Ok(Box::pin(futures_util::stream::once(
            async move { Ok(text) },
        )))
    }

    /// HTTP endpoint this backend will call, when it has one.
    ///
    /// Default `None` (mock / in-process). OpenAI-compatible backends return
    /// the resolved base URL so the host factory can assert a guard on a
    /// different preset does not inherit the primary provider's endpoint.
    fn endpoint_url(&self) -> Option<&str> {
        None
    }

    /// Confirm the backend can actually be reached before a session starts.
    ///
    /// The default is a no-op only for backends that have nothing to check.
    /// Every transport should implement it: discovering a wrong base URL as a
    /// failed audit halfway through a run is far worse than discovering it at
    /// startup, and the error must name the provider and the URL, because
    /// "connection refused" on its own tells the operator nothing.
    async fn ensure_ready(&self, client: &reqwest::Client) -> Result<(), LlmError> {
        let _ = client;
        Ok(())
    }

    /// Model identifiers the backend reports.
    ///
    /// Every OpenAI-compatible server exposes `GET /v1/models` - LM Studio,
    /// llama.cpp, vLLM, MLX-LM and LocalAI included - so one
    /// implementation covers all of them; Ollama uses its own `/api/tags`.
    /// An OpenAI-compatible server that answers with a non-auth error status
    /// here is treated as "does not support listing" rather than an error, so
    /// the operator can still type a model name; Ollama has no such optional
    /// route, so `OllamaBackend` returns `Err` instead on a non-success
    /// status from `/api/tags`.
    async fn list_models(&self, client: &reqwest::Client) -> Result<Vec<String>, LlmError> {
        let _ = client;
        Ok(Vec::new())
    }
}

/// `GET {base}/models` against an OpenAI-compatible server.
///
/// Shared by every `openai-compatible` preset. `base` is normalised first, so
/// this is correct whether the caller stored `…:1234` or `…:1234/v1`.
pub async fn list_models_openai_compatible(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    auth: Auth,
) -> Result<Vec<String>, LlmError> {
    let url = format!("{}/models", url::normalize_openai_base(base_url));
    let req = with_api_key(client.get(&url), api_key, auth);
    let response = req.send().await.map_err(LlmError::Http)?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        // A refused key is not "this server cannot list": say so, or the
        // picker shows an empty list as if nothing were installed.
        return Err(LlmError::Setup(format!(
            "{url} refused the request ({status}); check the API key."
        )));
    }
    if !status.is_success() {
        // Not every server implements /models. Treat it as "cannot list"
        // rather than "broken".
        return Ok(Vec::new());
    }

    #[derive(serde::Deserialize)]
    struct ModelList {
        #[serde(default)]
        data: Vec<ModelEntry>,
    }
    #[derive(serde::Deserialize)]
    struct ModelEntry {
        id: String,
    }

    let list: ModelList = response.json().await.map_err(LlmError::Http)?;
    Ok(list
        .data
        .into_iter()
        .map(|m| m.id)
        .filter(|id| is_chat_model_id(id))
        .collect())
}

/// `request` with `api_key` in the header `auth` names; unchanged without a key.
pub(crate) fn with_api_key(
    request: reqwest::RequestBuilder,
    api_key: &str,
    auth: Auth,
) -> reqwest::RequestBuilder {
    if api_key.is_empty() {
        return request;
    }
    match auth {
        Auth::Bearer => request.header("Authorization", format!("Bearer {api_key}")),
        Auth::ApiKeyHeader => request.header("api-key", api_key),
    }
}

/// Whether a `/models` id can be an agent's chat model. Servers list
/// embedding, speech, image and moderation models in the same list (LM
/// Studio's `text-embedding-nomic-embed-text-v1.5`, OpenAI's `whisper-1`);
/// none of them can drive the agent, so the model picker leaves them out.
pub fn is_chat_model_id(id: &str) -> bool {
    let id = id.to_ascii_lowercase();
    ![
        "embed",
        "whisper",
        "tts",
        "dall-e",
        "moderation",
        "transcribe",
        "rerank",
    ]
    .iter()
    .any(|kind| id.contains(kind))
}

/// Reachability probe naming the provider and the URL it actually tried.
pub async fn probe_reachable(
    client: &reqwest::Client,
    provider: &str,
    url: &str,
) -> Result<(), LlmError> {
    match client.get(url).send().await {
        // Any HTTP response proves something is listening. A 401 or 404 means
        // reachable-but-unauthorised or reachable-but-different-route, which is
        // a configuration problem the operator can see and fix; it is not the
        // "nothing is there" case this probe exists to catch.
        Ok(_) => Ok(()),
        Err(e) => Err(LlmError::Setup(format!(
            "{provider} is not reachable at {url}: {e}. \
             Check the server is running and that the base URL is correct."
        ))),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("http status {0}: {1}")]
    HttpStatus(u16, String),
    #[error("empty response")]
    EmptyResponse,
    /// A provider safety classifier declined the request (Anthropic
    /// `stop_reason: "refusal"`), after any server-side fallback.
    #[error("the model declined the request{}", category.as_deref().map(|c| format!(" ({c})")).unwrap_or_default())]
    Refused { category: Option<String> },
    /// The answer hit the output-token limit before it was complete.
    #[error("the model's answer was cut off at the output-token limit")]
    Truncated,
    #[error("invalid json: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported LLM backend: {0}")]
    UnsupportedBackend(String),
    #[error("setup: {0}")]
    Setup(String),
    /// The configured per-request HTTP client timeout elapsed while waiting
    /// on the model. Distinguished from the generic [`LlmError::Http`] so the
    /// agent's "LLM error: ..." thought names the actual cause (a slow local
    /// model, commonly) and the env var that controls it, instead of
    /// reqwest's generic "operation timed out".
    #[error("the model did not answer within {secs} s ({LLM_TIMEOUT_ENV})")]
    Timeout { secs: u64 },
}

/// Classifies a transport-level `reqwest::Error` from a backend's model call.
///
/// A timeout only has a meaningful number to report when the backend was
/// told what its client's configured timeout is (`timeout_secs`); backends
/// built directly (tests, or a caller that skipped `override_timeout_secs`)
/// fall back to the generic [`LlmError::Http`].
fn classify_model_call_error(e: reqwest::Error, timeout_secs: Option<u64>) -> LlmError {
    match (e.is_timeout(), timeout_secs) {
        (true, Some(secs)) => LlmError::Timeout { secs },
        _ => LlmError::Http(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_model_list_keeps_chat_models_only() {
        for id in [
            "qwen2.5-7b-instruct",
            "gpt-4o-mini",
            "meta-llama-3.1-8b-instruct",
            "mistral-nemo",
        ] {
            assert!(is_chat_model_id(id), "{id}");
        }
        for id in [
            "text-embedding-nomic-embed-text-v1.5",
            "text-embedding-3-small",
            "whisper-1",
            "tts-1-hd",
            "dall-e-3",
            "omni-moderation-latest",
            "gpt-4o-transcribe",
        ] {
            assert!(!is_chat_model_id(id), "{id}");
        }
    }

    // `strip_markdown_fences` runs on raw model output before it is handed to
    // `serde_json::from_str`, in all three provider backends. Everything it sees
    // is untrusted, so its edge cases are pinned here rather than discovered in
    // production.

    const OBJ: &str = r#"{"action":"complete","params":{}}"#;

    #[test]
    fn unfenced_json_passes_through_unchanged() {
        assert_eq!(strip_markdown_fences(OBJ), OBJ);
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(strip_markdown_fences("  \n\t{\"a\":1}\n  "), r#"{"a":1}"#);
    }

    #[test]
    fn strips_json_tagged_fence() {
        assert_eq!(strip_markdown_fences(&format!("```json\n{OBJ}\n```")), OBJ);
    }

    #[test]
    fn strips_uppercase_json_tagged_fence() {
        assert_eq!(strip_markdown_fences(&format!("```JSON\n{OBJ}\n```")), OBJ);
    }

    #[test]
    fn strips_untagged_fence() {
        assert_eq!(strip_markdown_fences(&format!("```\n{OBJ}\n```")), OBJ);
    }

    #[test]
    fn strips_fence_with_crlf_line_endings() {
        // The trims run '\n' before '\r', so CRLF is not consumed in order;
        // the final trim is what actually saves this case. Pin it so a future
        // refactor that drops the trailing trim fails loudly.
        assert_eq!(
            strip_markdown_fences(&format!("```json\r\n{OBJ}\r\n```")),
            OBJ
        );
    }

    #[test]
    fn strips_fence_with_no_newline_after_tag() {
        assert_eq!(strip_markdown_fences(&format!("```json{OBJ}```")), OBJ);
    }

    #[test]
    fn handles_more_than_three_backticks() {
        assert_eq!(
            strip_markdown_fences(&format!("````json\n{OBJ}\n````")),
            OBJ
        );
    }

    #[test]
    fn unterminated_fence_still_yields_the_body() {
        // Truncated model output: opening fence, no closing one.
        assert_eq!(strip_markdown_fences(&format!("```json\n{OBJ}")), OBJ);
    }

    #[test]
    fn backticks_inside_a_json_string_are_preserved() {
        // rfind targets the LAST ``` - the real closing fence - so a fenced
        // payload whose own content contains backticks survives intact.
        let with_ticks = r#"{"justification":"ran ```ls``` first"}"#;
        assert_eq!(
            strip_markdown_fences(&format!("```json\n{with_ticks}\n```")),
            with_ticks
        );
    }

    #[test]
    fn leading_prose_before_a_fence_is_not_stripped() {
        // Only a leading fence is recognised. Prose first means the whole
        // string is returned, and JSON parsing then fails loudly - which is
        // the safe outcome, rather than silently extracting a fragment.
        let input = format!("Here is the answer:\n```json\n{OBJ}\n```");
        assert_eq!(strip_markdown_fences(&input), input.trim());
    }

    #[test]
    fn empty_and_degenerate_inputs_do_not_panic() {
        assert_eq!(strip_markdown_fences(""), "");
        assert_eq!(strip_markdown_fences("   "), "");
        assert_eq!(strip_markdown_fences("```"), "");
        assert_eq!(strip_markdown_fences("``````"), "");
        assert_eq!(strip_markdown_fences("```json"), "");
        assert_eq!(strip_markdown_fences("```json\n```"), "");
    }

    #[test]
    fn is_idempotent_on_already_stripped_output() {
        let fenced = format!("```json\n{OBJ}\n```");
        let once = strip_markdown_fences(&fenced);
        assert_eq!(strip_markdown_fences(once), once);
    }

    #[test]
    fn multibyte_content_is_not_split_mid_character() {
        // Slicing by a byte index found via rfind must land on a char boundary,
        // otherwise this panics.
        let unicode = r#"{"justification":"überprüft - 検査済み ✅"}"#;
        assert_eq!(
            strip_markdown_fences(&format!("```json\n{unicode}\n```")),
            unicode
        );
    }

    //
    // The system prompt is the only thing telling the model to emit the four
    // fields `ProposedIntent` requires. Editing it carelessly breaks every
    // audit at runtime, with no compile-time signal - so assert the contract.

    #[test]
    fn system_prompt_names_every_required_intent_field() {
        for field in ["action", "params", "justification", "reasoning"] {
            assert!(
                DEFAULT_SYSTEM_PROMPT.contains(field),
                "DEFAULT_SYSTEM_PROMPT no longer mentions the required field {field:?}"
            );
        }
    }

    #[test]
    fn system_prompt_lists_every_allowed_action() {
        for action in ["run_command", "read_file", "http_get", "complete"] {
            assert!(
                DEFAULT_SYSTEM_PROMPT.contains(action),
                "DEFAULT_SYSTEM_PROMPT no longer documents the {action:?} action"
            );
        }
    }

    #[test]
    fn few_shot_examples_parse_as_the_intent_schema() {
        // Every `Assistant:` line is advertised to the model as a correct
        // response. If one stops deserialising, we are teaching bad output.
        let examples = few_shot_examples();
        let mut checked = 0;
        for line in examples.lines() {
            let Some(json) = line.trim().strip_prefix("Assistant:") else {
                continue;
            };
            let value: serde_json::Value = serde_json::from_str(json.trim())
                .unwrap_or_else(|e| panic!("few-shot example is not valid JSON: {e}\n{json}"));
            for field in ["action", "params", "justification", "reasoning"] {
                assert!(
                    value.get(field).is_some(),
                    "few-shot example is missing required field {field:?}: {json}"
                );
            }
            checked += 1;
        }
        assert_eq!(checked, 3, "expected 3 few-shot examples, found {checked}");
    }

    // Every backend shares this repair, so a small model behaves the same
    // through Ollama, LM Studio and the hosted providers.

    #[test]
    fn missing_justification_is_filled_from_reasoning() {
        let raw = r#"{"action":"read_file","params":{"path":"a"},"reasoning":"Need to inspect the config."}"#;
        let intent = parse_intent_repairing_justification(raw).expect("parses");
        assert_eq!(intent.justification, "Need to inspect the config.");
    }

    #[test]
    fn blank_justification_is_treated_as_missing() {
        let raw =
            r#"{"action":"read_file","params":{},"justification":"   ","reasoning":"Because."}"#;
        let intent = parse_intent_repairing_justification(raw).expect("parses");
        assert_eq!(intent.justification, "Because.");
    }

    #[test]
    fn with_neither_field_a_minimal_justification_is_synthesised() {
        let raw = r#"{"action":"http_get","params":{"url":"https://example.com"}}"#;
        let intent = parse_intent_repairing_justification(raw).expect("parses");
        assert!(
            intent.justification.contains("http_get"),
            "synthesised justification should name the action: {:?}",
            intent.justification
        );
        assert!(
            intent.justification.len() >= 5,
            "must clear the validator floor"
        );
    }

    #[test]
    fn a_real_justification_is_never_overwritten() {
        // The repair exists to fill a gap, not to edit the model's words.
        let raw = r#"{"action":"read_file","params":{},"justification":"Stated reason.","reasoning":"Different text."}"#;
        let intent = parse_intent_repairing_justification(raw).expect("parses");
        assert_eq!(intent.justification, "Stated reason.");
    }

    #[test]
    fn repair_still_strips_markdown_fences() {
        let raw = "```json\n{\"action\":\"complete\",\"params\":{},\"reasoning\":\"Done.\"}\n```";
        let intent = parse_intent_repairing_justification(raw).expect("parses");
        assert_eq!(intent.action, "complete");
        assert_eq!(intent.justification, "Done.");
    }

    #[test]
    fn genuinely_malformed_output_still_errors() {
        assert!(parse_intent_repairing_justification("not json at all").is_err());
    }

    /// Every backend must reach the shared parser, and "documents itself as
    /// shared" is not the same as being called.
    ///
    /// `propose` is an HTTP round trip, so the only way to check this without a
    /// live server is to read the source - which is what the schema/docs
    /// agreement tests in the host crate do for the same reason.
    #[test]
    fn every_backend_parses_through_the_shared_repairing_parser() {
        for (name, src) in [
            ("anthropic", include_str!("anthropic.rs")),
            ("ollama", include_str!("ollama_backend.rs")),
            ("openai", include_str!("openai.rs")),
        ] {
            let propose = src
                .split_once("async fn propose(")
                .expect("every backend has a propose")
                .1;
            let body = propose
                .split_once("async fn raw_call(")
                .map(|(before, _)| before)
                .unwrap_or(propose);
            assert!(
                body.contains("parse_intent_repairing_justification")
                    || body.contains(".into_intent()"),
                "{name}'s propose() parses on its own instead of calling \
                 parse_intent_repairing_justification, so it will reject intents \
                 the other backends repair"
            );
        }
    }

    #[test]
    fn error_messages_carry_their_context() {
        assert_eq!(
            LlmError::HttpStatus(429, "rate limited".into()).to_string(),
            "http status 429: rate limited"
        );
        assert_eq!(LlmError::EmptyResponse.to_string(), "empty response");
        assert_eq!(
            LlmError::UnsupportedBackend("gemini".into()).to_string(),
            "unsupported LLM backend: gemini"
        );
        assert_eq!(
            LlmError::Setup("ollama missing".into()).to_string(),
            "setup: ollama missing"
        );
        let msg = LlmError::Timeout { secs: 300 }.to_string();
        assert!(msg.contains("300"), "{msg}");
        assert!(msg.contains(LLM_TIMEOUT_ENV), "{msg}");
    }
}
