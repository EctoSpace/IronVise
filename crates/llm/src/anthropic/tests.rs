use super::*;
use crate::test_support::{MockServer, ScriptedResponse, client_with_timeout, generous_client};
use std::time::Duration;

fn backend(base_url: &str, api_key: &str) -> AnthropicBackend {
    AnthropicBackend {
        base_url: base_url.to_string(),
        model: "claude-test".to_string(),
        api_key: api_key.to_string(),
        client: generous_client(),
        timeout_secs: None,
    }
}

#[tokio::test]
async fn raw_call_sends_the_expected_headers_and_body() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"content":[{"type":"text","text":"hello"}]}"#,
    ))
    .await;
    let b = backend(&server.url, "sk-ant-secret-123");

    let out = b.raw_call("be careful", "do the thing").await.unwrap();
    assert_eq!(out, "hello");

    let req = server.request(0);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v1/messages");
    assert_eq!(req.header("x-api-key"), Some("sk-ant-secret-123"));
    assert_eq!(req.header("anthropic-version"), Some("2023-06-01"));
    assert!(req.body_str().contains("do the thing"));

    let body = req.body_json();
    assert_eq!(body["model"], "claude-test");
    assert_eq!(body["max_tokens"], MAX_TOKENS);
    assert!(
        body.get("fallbacks").is_none(),
        "only the Claude API takes fallbacks"
    );
    assert_eq!(req.header("anthropic-beta"), None);
    assert_eq!(body["system"], "be careful");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "do the thing");
}

#[tokio::test]
async fn raw_call_omits_auth_headers_when_the_api_key_is_empty() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"content":[{"type":"text","text":"hi"}]}"#,
    ))
    .await;
    let b = backend(&server.url, "");

    b.raw_call("s", "u").await.unwrap();

    let req = server.request(0);
    assert_eq!(req.header("x-api-key"), None);
    assert_eq!(req.header("anthropic-version"), None);
}

#[tokio::test]
async fn raw_call_never_leaks_the_api_key_in_a_401_error() {
    let server = MockServer::single(ScriptedResponse::status(
        401,
        r#"{"error":"authentication_error"}"#,
    ))
    .await;
    let secret = "sk-ant-TOP-SECRET-999";
    let b = backend(&server.url, secret);

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(401, _)));
    assert!(!format!("{err}").contains(secret));
    assert!(!format!("{err:?}").contains(secret));
}

#[tokio::test]
async fn raw_call_maps_429_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(429, "rate limited")).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(429, body) if body == "rate limited"));
}

#[tokio::test]
async fn raw_call_maps_500_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(500, "internal error")).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(500, body) if body == "internal error"));
}

#[tokio::test]
async fn raw_call_times_out_when_the_server_stalls() {
    let server = MockServer::single(ScriptedResponse::delayed(
        200,
        r#"{"content":[{"text":"too late"}]}"#,
        Duration::from_secs(2),
    ))
    .await;
    let mut b = backend(&server.url, "key");
    b.client = client_with_timeout(100);

    // No `timeout_secs` recorded: falls back to the generic Http variant,
    // same as before `classify_model_call_error` existed.
    let err = b.raw_call("s", "u").await.unwrap_err();
    match err {
        LlmError::Http(inner) => assert!(inner.is_timeout(), "{inner}"),
        other => panic!("expected a timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn raw_call_times_out_with_the_configured_seconds_and_env_var_in_the_message() {
    let server = MockServer::single(ScriptedResponse::delayed(
        200,
        r#"{"content":[{"type":"text","text":"too late"}]}"#,
        Duration::from_secs(2),
    ))
    .await;
    let mut b = backend(&server.url, "key");
    b.client = client_with_timeout(100);
    b.override_timeout_secs(300);

    let err = b.raw_call("s", "u").await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("300"), "{msg}");
    assert!(msg.contains(crate::LLM_TIMEOUT_ENV), "{msg}");
    match err {
        LlmError::Timeout { secs } => assert_eq!(secs, 300),
        other => panic!("expected LlmError::Timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn raw_call_errors_on_a_connection_truncated_before_the_full_body_arrives() {
    let url = crate::test_support::truncated_body_server(
        200,
        10_000,
        r#"{"content":[{"type":"text","text":"onl"#,
    );
    let b = backend(&url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::Http(_)), "{err:?}");
}

#[tokio::test]
async fn raw_call_errors_on_a_non_json_body() {
    let server = MockServer::single(ScriptedResponse::ok("not json at all")).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    match err {
        LlmError::Http(inner) => assert!(inner.is_decode(), "{inner}"),
        other => panic!("expected a decode error, got {other:?}"),
    }
}

#[tokio::test]
async fn raw_call_errors_on_truncated_json_syntax() {
    let server = MockServer::single(ScriptedResponse::ok(r#"{"content":[{"type":"text","#)).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    match err {
        LlmError::Http(inner) => assert!(inner.is_decode(), "{inner}"),
        other => panic!("expected a decode error, got {other:?}"),
    }
}

#[tokio::test]
async fn raw_call_errors_on_an_empty_content_array() {
    let server = MockServer::single(ScriptedResponse::ok(r#"{"content":[]}"#)).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::EmptyResponse));
}

#[tokio::test]
async fn the_answer_is_the_first_text_block_after_any_thinking() {
    let server = MockServer::single(ScriptedResponse::ok(
            r#"{"content":[{"type":"thinking","thinking":""},{"type":"text","text":"answer"}],"stop_reason":"end_turn"}"#,
        ))
        .await;
    let b = backend(&server.url, "key");

    assert_eq!(b.raw_call("s", "u").await.unwrap(), "answer");
}

#[tokio::test]
async fn a_reply_without_a_text_block_is_empty() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"content":[{"type":"thinking","thinking":""}],"stop_reason":"end_turn"}"#,
    ))
    .await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::EmptyResponse));
}

#[tokio::test]
async fn a_refusal_is_reported_with_its_category() {
    let server = MockServer::single(ScriptedResponse::ok(
            r#"{"content":[],"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber"}}"#,
        ))
        .await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(&err, LlmError::Refused { category: Some(c) } if c == "cyber"));
    assert_eq!(err.to_string(), "the model declined the request (cyber)");
}

#[tokio::test]
async fn an_answer_cut_off_at_the_token_limit_is_not_parsed() {
    let body = r#"{"content":[{"type":"text","text":"{\"action\": \"read_fi"}],"stop_reason":"max_tokens"}"#;
    let server = MockServer::single(ScriptedResponse::ok(body)).await;
    let err = backend(&server.url, "key")
        .propose("s", "u")
        .await
        .unwrap_err();
    assert!(matches!(err, LlmError::Truncated), "{err:?}");

    // Free-form callers still get the text that did arrive.
    let server = MockServer::single(ScriptedResponse::ok(body)).await;
    let text = backend(&server.url, "key")
        .raw_call("s", "u")
        .await
        .unwrap();
    assert_eq!(text, r#"{"action": "read_fi"#);
}

#[test]
fn server_side_fallback_is_used_only_on_the_claude_api_for_models_that_take_it() {
    let on = |base_url: &str, model: &str| {
        AnthropicBackend {
            base_url: base_url.to_string(),
            model: model.to_string(),
            ..backend("", "key")
        }
        .uses_server_side_fallback()
    };

    assert!(on("https://api.anthropic.com", "claude-opus-5-5"));
    assert!(on("https://api.anthropic.com/", "claude-sonnet-5-5"));
    assert!(on("https://api.anthropic.com", "claude-fable-5-1"));
    assert!(!on("https://api.anthropic.com", "claude-haiku-5-5"));
    assert!(!on("https://api.anthropic.com", "claude-sonnet-4-6"));
    assert!(!on("http://127.0.0.1:8080", "claude-opus-5-5"));
}

#[test]
fn a_claude_api_request_for_opus_asks_for_the_default_fallback() {
    let b = AnthropicBackend {
        base_url: ANTHROPIC_API.to_string(),
        model: "claude-opus-5-5".to_string(),
        ..backend("", "key")
    };
    let body = serde_json::to_value(b.build_request("s", "u")).unwrap();
    assert_eq!(body["fallbacks"], "default");
    assert_eq!(body["max_tokens"], MAX_TOKENS);
}

#[test]
fn the_default_model_is_current() {
    let preset = crate::provider::resolve("anthropic").unwrap();
    assert_eq!(preset.default_model, Some("claude-opus-5-5"));
}

#[tokio::test]
async fn list_models_filters_non_chat_ids_through_the_shared_openai_route() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"data":[{"id":"claude-3-5-sonnet"},{"id":"claude-3-haiku-tts"}]}"#,
    ))
    .await;
    let b = backend(&server.url, "key");

    let models = b.list_models(&generous_client()).await.unwrap();
    assert_eq!(models, vec!["claude-3-5-sonnet".to_string()]);
    let req = server.request(0);
    assert_eq!(req.header("x-api-key"), Some("key"));
    assert_eq!(req.header("anthropic-version"), Some("2023-06-01"));
}

#[tokio::test]
async fn ensure_ready_errors_without_making_a_request_when_the_key_is_unset() {
    let b = backend("http://127.0.0.1:1", "");
    let err = b.ensure_ready(&generous_client()).await.unwrap_err();
    match err {
        LlmError::Setup(msg) => assert!(msg.contains("ANTHROPIC_API_KEY")),
        other => panic!("expected a setup error, got {other:?}"),
    }
}

#[tokio::test]
async fn ensure_ready_succeeds_once_the_models_route_answers() {
    let server = MockServer::single(ScriptedResponse::ok("{}")).await;
    let b = backend(&server.url, "key");
    b.ensure_ready(&generous_client()).await.unwrap();
}

#[tokio::test]
async fn ensure_ready_errors_when_the_server_is_unreachable() {
    let url = crate::test_support::closed_port_url();
    let b = backend(&url, "key");

    let err = b.ensure_ready(&generous_client()).await.unwrap_err();
    match err {
        LlmError::Setup(msg) => assert!(msg.contains("Anthropic") && msg.contains(&url)),
        other => panic!("expected a setup error, got {other:?}"),
    }
}

#[test]
fn override_base_url_replaces_the_configured_server() {
    let mut b = backend("http://a.example", "key");
    b.override_base_url("http://b.example".to_string());
    assert_eq!(b.base_url, "http://b.example");
}

#[tokio::test]
async fn override_base_url_redirects_subsequent_requests() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"content":[{"type":"text","text":"hi"}]}"#,
    ))
    .await;
    let mut b = backend("http://127.0.0.1:1", "key");
    b.override_base_url(server.url.clone());

    b.raw_call("s", "u").await.unwrap();
    assert_eq!(server.request(0).path, "/v1/messages");
}

#[test]
fn override_model_replaces_the_configured_model() {
    let mut b = backend("http://a.example", "key");
    b.override_model("claude-x".to_string());
    assert_eq!(b.model_name(), "claude-x");
}
