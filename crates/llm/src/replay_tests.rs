//! Replay recorded provider response bodies through each backend against MockServer.
//!
//! Fixtures live under `tests/fixtures/` so they stay next to other integration
//! assets; `test_support` is `pub(crate)` only, so the replay itself runs here.

use crate::test_support::{MockServer, ScriptedResponse, generous_client};
use crate::{AnthropicBackend, LlmBackend, LlmError, OllamaBackend, OpenAiBackend};
use ectoledger_core::intent::ProposedIntent;

/// Intent shared by every successful equivalent fixture across providers.
const SHARED_INTENT: &str = r#"{"action":"read_file","params":{"path":"server_config.txt"},"justification":"Need to inspect server configuration for audit findings.","reasoning":"The goal is to audit server_config.txt, so reading it is the first logical step."}"#;

fn expected_shared_intent() -> ProposedIntent {
    serde_json::from_str(SHARED_INTENT).expect("shared intent fixture text is valid JSON")
}

fn anthropic(base_url: &str) -> AnthropicBackend {
    let client = generous_client();
    let mut b = AnthropicBackend::from_env(&client);
    // Point at the mock and ignore whatever ANTHROPIC_* the developer shell has.
    b.override_base_url(base_url.to_string());
    b.override_model("claude-opus-5-5".to_string());
    b
}

fn openai(base_url: &str) -> OpenAiBackend {
    let client = generous_client();
    let mut b = OpenAiBackend::from_env(&client);
    b.override_base_url(base_url.to_string());
    b.override_model("gpt-6-astra".to_string());
    b
}

fn ollama(base_url: &str) -> OllamaBackend {
    let client = generous_client();
    let mut b = OllamaBackend::from_env(&client);
    b.override_base_url(base_url.to_string());
    b.override_model("mistral:7b".to_string());
    b
}

macro_rules! fixture {
    ($path:literal) => {
        include_str!(concat!("../tests/fixtures/", $path))
    };
}

async fn propose_anthropic(body: &str) -> Result<ProposedIntent, LlmError> {
    let server = MockServer::single(ScriptedResponse::ok(body)).await;
    anthropic(&server.url).propose("system", "user").await
}

async fn propose_openai(body: &str) -> Result<ProposedIntent, LlmError> {
    let server = MockServer::single(ScriptedResponse::ok(body)).await;
    openai(&server.url).propose("system", "user").await
}

async fn propose_ollama(body: &str) -> Result<ProposedIntent, LlmError> {
    let server = MockServer::single(ScriptedResponse::ok(body)).await;
    ollama(&server.url).propose("system", "user").await
}

fn assert_shared(intent: &ProposedIntent) {
    assert_eq!(intent, &expected_shared_intent());
}

// --- Anthropic ---------------------------------------------------------------

#[tokio::test]
async fn anthropic_thinking_then_text_yields_the_shared_intent() {
    let intent = propose_anthropic(fixture!("anthropic/thinking_then_text.json"))
        .await
        .expect("thinking then text");
    assert_shared(&intent);
}

#[tokio::test]
async fn anthropic_text_only_yields_the_shared_intent() {
    let intent = propose_anthropic(fixture!("anthropic/text_only.json"))
        .await
        .expect("text only");
    assert_shared(&intent);
}

#[tokio::test]
async fn anthropic_refusal_maps_to_refused_with_category() {
    let err = propose_anthropic(fixture!("anthropic/refusal_stop_details.json"))
        .await
        .expect_err("refusal");
    assert!(matches!(
        &err,
        LlmError::Refused {
            category: Some(c)
        } if c == "cyber"
    ));
}

#[tokio::test]
async fn anthropic_max_tokens_maps_to_truncated() {
    let err = propose_anthropic(fixture!("anthropic/max_tokens_truncation.json"))
        .await
        .expect_err("max_tokens");
    assert!(matches!(err, LlmError::Truncated));
}

#[tokio::test]
async fn anthropic_tool_use_before_text_still_yields_the_shared_intent() {
    let intent = propose_anthropic(fixture!("anthropic/tool_use_before_text.json"))
        .await
        .expect("tool_use then text");
    assert_shared(&intent);
}

#[tokio::test]
async fn anthropic_empty_content_maps_to_empty_response() {
    let err = propose_anthropic(fixture!("anthropic/empty_content.json"))
        .await
        .expect_err("empty content");
    assert!(matches!(err, LlmError::EmptyResponse));
}

#[tokio::test]
async fn anthropic_non_success_status_maps_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(
        429,
        r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#,
    ))
    .await;
    let err = anthropic(&server.url)
        .propose("system", "user")
        .await
        .expect_err("429");
    assert!(matches!(err, LlmError::HttpStatus(429, _)));
}

// --- OpenAI ------------------------------------------------------------------

#[tokio::test]
async fn openai_normal_yields_the_shared_intent() {
    let intent = propose_openai(fixture!("openai/normal.json"))
        .await
        .expect("normal");
    assert_shared(&intent);
}

#[tokio::test]
async fn openai_json_mode_body_yields_the_shared_intent() {
    let intent = propose_openai(fixture!("openai/json_mode.json"))
        .await
        .expect("json mode");
    assert_shared(&intent);
}

#[tokio::test]
async fn openai_finish_reason_length_is_truncated() {
    let err = propose_openai(fixture!("openai/finish_reason_length.json"))
        .await
        .expect_err("length");
    assert!(matches!(err, LlmError::Truncated), "{err:?}");
}

#[tokio::test]
async fn openai_refusal_field_is_refused() {
    let err = propose_openai(fixture!("openai/content_null_refusal.json"))
        .await
        .expect_err("refusal");
    assert!(
        matches!(err, LlmError::Refused { category: None }),
        "{err:?}"
    );
}

#[tokio::test]
async fn openai_choices_empty_maps_to_empty_response() {
    let err = propose_openai(fixture!("openai/choices_empty.json"))
        .await
        .expect_err("empty choices");
    assert!(matches!(err, LlmError::EmptyResponse));
}

#[tokio::test]
async fn openai_non_success_status_maps_to_http_status() {
    // First attempt asks for JSON mode; a non-400 error must not be retried.
    let server = MockServer::single(ScriptedResponse::status(
        503,
        r#"{"error":{"message":"overloaded","type":"server_error"}}"#,
    ))
    .await;
    let err = openai(&server.url)
        .propose("system", "user")
        .await
        .expect_err("503");
    assert!(matches!(err, LlmError::HttpStatus(503, _)));
    assert_eq!(server.request_count(), 1);
}

// --- Ollama ------------------------------------------------------------------

#[tokio::test]
async fn ollama_normal_yields_the_shared_intent() {
    let intent = propose_ollama(fixture!("ollama/normal.json"))
        .await
        .expect("normal");
    assert_shared(&intent);
}

#[tokio::test]
async fn ollama_done_reason_length_is_truncated() {
    let err = propose_ollama(fixture!("ollama/done_reason_length.json"))
        .await
        .expect_err("length");
    assert!(matches!(err, LlmError::Truncated), "{err:?}");
}

#[tokio::test]
async fn ollama_message_missing_maps_to_empty_response() {
    let err = propose_ollama(fixture!("ollama/message_missing.json"))
        .await
        .expect_err("missing message");
    assert!(matches!(err, LlmError::EmptyResponse));
}

#[tokio::test]
async fn ollama_non_success_status_maps_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(500, "internal")).await;
    let err = ollama(&server.url)
        .propose("system", "user")
        .await
        .expect_err("500");
    assert!(matches!(err, LlmError::HttpStatus(500, body) if body == "internal"));
}

// --- Cross-provider equivalence ---------------------------------------------

#[tokio::test]
async fn equivalent_success_fixtures_agree_across_providers() {
    let anthropic_cases = [
        fixture!("anthropic/thinking_then_text.json"),
        fixture!("anthropic/text_only.json"),
        fixture!("anthropic/tool_use_before_text.json"),
    ];
    let openai_cases = [
        fixture!("openai/normal.json"),
        fixture!("openai/json_mode.json"),
    ];
    let ollama_cases = [fixture!("ollama/normal.json")];

    let expected = expected_shared_intent();
    for body in anthropic_cases {
        assert_eq!(propose_anthropic(body).await.unwrap(), expected);
    }
    for body in openai_cases {
        assert_eq!(propose_openai(body).await.unwrap(), expected);
    }
    for body in ollama_cases {
        assert_eq!(propose_ollama(body).await.unwrap(), expected);
    }
}
