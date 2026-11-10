use super::*;
use crate::test_support::{MockServer, ScriptedResponse, client_with_timeout, generous_client};
use std::time::Duration;

fn backend(base_url: &str, api_key: &str) -> OpenAiBackend {
    OpenAiBackend {
        base_url: base_url.to_string(),
        model: "gpt-test".to_string(),
        api_key: api_key.to_string(),
        auth: crate::Auth::Bearer,
        client: generous_client(),
        timeout_secs: None,
    }
}

#[tokio::test]
async fn propose_sends_json_mode_with_bearer_auth_on_the_first_attempt() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"choices":[{"message":{"content":"{\"action\":\"complete\",\"params\":{},\"justification\":\"nothing left to check\"}"}}]}"#,
    ))
    .await;
    let b = backend(&server.url, "sk-openai-secret");

    let intent = b.propose("system prompt", "user prompt").await.unwrap();
    assert_eq!(intent.action, "complete");

    let req = server.request(0);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v1/chat/completions");
    assert_eq!(req.header("Authorization"), Some("Bearer sk-openai-secret"));

    let body = req.body_json();
    assert_eq!(body["model"], "gpt-test");
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["messages"][0]["content"], "system prompt");
    assert_eq!(body["messages"][1]["role"], "user");
    assert_eq!(body["response_format"]["type"], "json_object");
}

#[tokio::test]
async fn raw_call_omits_the_bearer_header_when_the_api_key_is_empty() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"choices":[{"message":{"content":"ok"}}]}"#,
    ))
    .await;
    let b = backend(&server.url, "");

    b.raw_call("s", "u").await.unwrap();
    assert_eq!(server.request(0).header("Authorization"), None);
}

/// Azure OpenAI takes its key in `api-key`; a Bearer header carrying a key
/// is read as an Entra token and refused.
#[tokio::test]
async fn an_api_key_header_preset_sends_the_key_in_api_key_only() {
    let server = MockServer::start(vec![
        ScriptedResponse::ok(r#"{"choices":[{"message":{"content":"ok"}}]}"#),
        ScriptedResponse::ok(r#"{"data":[{"id":"gpt-deployment"}]}"#),
    ])
    .await;
    let mut b = backend(&server.url, "");
    b.override_api_key("azure-secret".to_string(), crate::Auth::ApiKeyHeader);

    b.raw_call("s", "u").await.unwrap();
    let models = b.list_models(&generous_client()).await.unwrap();
    assert_eq!(models, vec!["gpt-deployment".to_string()]);
    for req in server.requests() {
        assert_eq!(req.header("api-key"), Some("azure-secret"), "{}", req.path);
        assert_eq!(req.header("Authorization"), None, "{}", req.path);
    }
}

/// A hosted preset's own key replaces whatever OPENAI_API_KEY held.
#[tokio::test]
async fn an_overridden_key_is_the_one_sent() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"choices":[{"message":{"content":"ok"}}]}"#,
    ))
    .await;
    let mut b = backend(&server.url, "sk-openai-secret");
    b.override_api_key("gsk-groq-secret".to_string(), crate::Auth::Bearer);

    b.raw_call("s", "u").await.unwrap();
    assert_eq!(
        server.request(0).header("Authorization"),
        Some("Bearer gsk-groq-secret")
    );
}

#[tokio::test]
async fn propose_retries_without_json_mode_after_a_400() {
    let server = MockServer::start(vec![
        ScriptedResponse::status(400, "response_format is not supported"),
        ScriptedResponse::ok(r#"{"choices":[{"message":{"content":"{\"action\":\"complete\",\"params\":{},\"justification\":\"nothing left to check\"}"}}]}"#),
    ])
    .await;
    let b = backend(&server.url, "key");

    let intent = b.propose("s", "u").await.unwrap();
    assert_eq!(intent.action, "complete");
    assert_eq!(server.request_count(), 2);

    let first = server.request(0).body_json();
    assert_eq!(first["response_format"]["type"], "json_object");

    let second = server.request(1).body_json();
    assert!(
        second.get("response_format").is_none(),
        "the retry must omit response_format entirely, got {second:?}"
    );
}

#[tokio::test]
async fn propose_does_not_retry_a_second_time_when_both_attempts_are_rejected() {
    let server = MockServer::start(vec![
        ScriptedResponse::status(400, "still rejected: first"),
        ScriptedResponse::status(400, "still rejected: second"),
    ])
    .await;
    let b = backend(&server.url, "key");

    let err = b.propose("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(400, body) if body == "still rejected: second"));
    assert_eq!(server.request_count(), 2);
}

#[tokio::test]
async fn raw_call_does_not_retry_on_401() {
    let server = MockServer::single(ScriptedResponse::status(401, "unauthorized")).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(401, _)));
    assert_eq!(server.request_count(), 1);
}

#[tokio::test]
async fn raw_call_never_leaks_the_api_key_in_error_text() {
    let server = MockServer::single(ScriptedResponse::status(
        401,
        r#"{"error":"invalid_api_key"}"#,
    ))
    .await;
    let secret = "sk-openai-TOP-SECRET";
    let b = backend(&server.url, secret);

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(!format!("{err}").contains(secret));
    assert!(!format!("{err:?}").contains(secret));
}

#[tokio::test]
async fn raw_call_maps_429_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(429, "slow down")).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(429, body) if body == "slow down"));
}

#[tokio::test]
async fn raw_call_maps_500_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(500, "boom")).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(500, body) if body == "boom"));
}

#[tokio::test]
async fn raw_call_times_out_when_the_server_stalls() {
    let server = MockServer::single(ScriptedResponse::delayed(
        200,
        r#"{"choices":[{"message":{"content":"too late"}}]}"#,
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
        r#"{"choices":[{"message":{"content":"too late"}}]}"#,
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
        r#"{"choices":[{"message":{"content":"onl"#,
    );
    let b = backend(&url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::Http(_)), "{err:?}");
}

#[tokio::test]
async fn raw_call_errors_on_a_non_json_body() {
    let server = MockServer::single(ScriptedResponse::ok("definitely not json")).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    match err {
        LlmError::Http(inner) => assert!(inner.is_decode(), "{inner}"),
        other => panic!("expected a decode error, got {other:?}"),
    }
}

#[tokio::test]
async fn raw_call_errors_on_an_empty_choices_array() {
    let server = MockServer::single(ScriptedResponse::ok(r#"{"choices":[]}"#)).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::EmptyResponse));
}

#[tokio::test]
async fn raw_call_errors_when_the_message_content_is_null() {
    let server = MockServer::single(ScriptedResponse::ok(r#"{"choices":[{"message":{}}]}"#)).await;
    let b = backend(&server.url, "key");

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::EmptyResponse));
}

#[tokio::test]
async fn raw_call_uses_the_chat_completions_route_regardless_of_a_trailing_v1() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"choices":[{"message":{"content":"ok"}}]}"#,
    ))
    .await;
    let base_with_v1 = format!("{}/v1", server.url);
    let b = backend(&base_with_v1, "key");

    b.raw_call("s", "u").await.unwrap();
    assert_eq!(server.request(0).path, "/v1/chat/completions");
}

#[tokio::test]
async fn ensure_ready_errors_when_the_server_is_unreachable() {
    let url = crate::test_support::closed_port_url();
    let b = backend(&url, "key");

    let err = b.ensure_ready(&generous_client()).await.unwrap_err();
    match err {
        LlmError::Setup(msg) => {
            assert!(msg.contains("OpenAI-compatible server"));
        }
        other => panic!("expected a setup error, got {other:?}"),
    }
}

#[tokio::test]
async fn ensure_ready_succeeds_once_the_models_route_answers() {
    let server = MockServer::single(ScriptedResponse::ok("{}")).await;
    let b = backend(&server.url, "key");
    b.ensure_ready(&generous_client()).await.unwrap();
}

#[test]
fn override_base_url_replaces_the_configured_server() {
    let mut b = backend("http://a.example", "");
    b.override_base_url("http://b.example".to_string());
    assert_eq!(b.endpoint_url(), Some("http://b.example"));
}

#[test]
fn override_model_replaces_the_configured_model() {
    let mut b = backend("http://a.example", "");
    b.override_model("gpt-x".to_string());
    assert_eq!(b.model_name(), "gpt-x");
}

#[tokio::test]
async fn a_free_form_call_never_asks_for_json_mode() {
    // The guard's verdict, chat and the red-team array are not JSON objects;
    // JSON mode would force one.
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"choices":[{"message":{"content":"ALLOW"}}]}"#,
    ))
    .await;
    let b = backend(&server.url, "key");

    assert_eq!(b.raw_call("s", "u").await.unwrap(), "ALLOW");
    assert!(
        server
            .request(0)
            .body_json()
            .get("response_format")
            .is_none()
    );
    assert_eq!(server.request_count(), 1);
}

#[tokio::test]
async fn a_complete_answer_at_the_length_limit_is_still_the_answer() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"choices":[{"message":{"content":"ALLOW"},"finish_reason":"length"}]}"#,
    ))
    .await;
    let b = backend(&server.url, "key");
    assert_eq!(b.raw_call("s", "u").await.unwrap(), "ALLOW");
}
