use super::*;
use crate::test_support::{MockServer, ScriptedResponse, client_with_timeout, generous_client};
use std::time::Duration;

fn backend(base_url: &str) -> OllamaBackend {
    OllamaBackend {
        base_url: base_url.to_string(),
        model: "mistral-test".to_string(),
        client: generous_client(),
        timeout_secs: None,
    }
}

#[tokio::test]
async fn propose_sends_the_expected_request_shape() {
    let server = MockServer::single(ScriptedResponse::ok(
            r#"{"message":{"content":"{\"action\":\"complete\",\"params\":{},\"reasoning\":\"done\"}"}}"#,
        ))
        .await;
    let b = backend(&server.url);

    let intent = b.propose("system prompt", "user prompt").await.unwrap();
    assert_eq!(intent.action, "complete");
    assert_eq!(intent.justification, "done");

    let req = server.request(0);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/chat");
    let body = req.body_json();
    assert_eq!(body["model"], "mistral-test");
    assert_eq!(body["stream"], false);
    assert_eq!(body["format"], "json");
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["messages"][0]["content"], "system prompt");
    assert_eq!(body["messages"][1]["role"], "user");
    assert_eq!(body["messages"][1]["content"], "user prompt");
}

#[tokio::test]
async fn propose_falls_back_to_the_response_field_when_message_is_absent() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"response":"{\"action\":\"complete\"}"}"#,
    ))
    .await;
    let b = backend(&server.url);

    let intent = b.propose("s", "u").await.unwrap();
    assert_eq!(intent.action, "complete");
}

#[tokio::test]
async fn propose_errors_when_both_message_and_response_are_absent() {
    let server = MockServer::single(ScriptedResponse::ok("{}")).await;
    let b = backend(&server.url);

    let err = b.propose("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::EmptyResponse));
}

#[tokio::test]
async fn raw_call_omits_the_format_field_and_trims_whitespace() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"message":{"content":"  {\"x\":1}  \n"}}"#,
    ))
    .await;
    let b = backend(&server.url);

    let out = b.raw_call("s", "u").await.unwrap();
    assert_eq!(out, r#"{"x":1}"#);

    let body = server.request(0).body_json();
    assert!(
        body.get("format").is_none(),
        "raw_call must not request JSON mode, got {body:?}"
    );
}

#[tokio::test]
async fn raw_call_maps_401_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(401, "nope")).await;
    let b = backend(&server.url);

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(401, body) if body == "nope"));
}

#[tokio::test]
async fn raw_call_maps_429_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(429, "slow down")).await;
    let b = backend(&server.url);

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(429, body) if body == "slow down"));
}

#[tokio::test]
async fn raw_call_maps_500_to_http_status() {
    let server = MockServer::single(ScriptedResponse::status(500, "boom")).await;
    let b = backend(&server.url);

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(500, body) if body == "boom"));
}

#[tokio::test]
async fn raw_call_times_out_when_the_server_stalls() {
    let server = MockServer::single(ScriptedResponse::delayed(
        200,
        r#"{"message":{"content":"too late"}}"#,
        Duration::from_secs(2),
    ))
    .await;
    let mut b = backend(&server.url);
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
        r#"{"message":{"content":"too late"}}"#,
        Duration::from_secs(2),
    ))
    .await;
    let mut b = backend(&server.url);
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
    let url =
        crate::test_support::truncated_body_server(200, 10_000, r#"{"message":{"content":"onl"#);
    let b = backend(&url);

    let err = b.raw_call("s", "u").await.unwrap_err();
    assert!(matches!(err, LlmError::Http(_)), "{err:?}");
}

#[tokio::test]
async fn raw_call_errors_on_a_non_json_body() {
    let server = MockServer::single(ScriptedResponse::ok("not json")).await;
    let b = backend(&server.url);

    let err = b.raw_call("s", "u").await.unwrap_err();
    match err {
        LlmError::Http(inner) => assert!(inner.is_decode(), "{inner}"),
        other => panic!("expected a decode error, got {other:?}"),
    }
}

#[tokio::test]
async fn list_models_parses_the_tags_route() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"models":[{"name":"mistral:7b"},{"name":"llama3"}]}"#,
    ))
    .await;
    let b = backend(&server.url);

    let models = b.list_models(&generous_client()).await.unwrap();
    assert_eq!(models, vec!["mistral:7b".to_string(), "llama3".to_string()]);
    assert_eq!(server.request(0).path, "/api/tags");
}

#[tokio::test]
async fn list_models_defaults_to_empty_when_the_models_field_is_missing() {
    let server = MockServer::single(ScriptedResponse::ok("{}")).await;
    let b = backend(&server.url);

    let models = b.list_models(&generous_client()).await.unwrap();
    assert!(models.is_empty());
}

#[tokio::test]
async fn list_models_errors_on_a_non_success_status_instead_of_returning_empty() {
    let server = MockServer::single(ScriptedResponse::status(404, "not found")).await;
    let b = backend(&server.url);

    let err = b.list_models(&generous_client()).await.unwrap_err();
    assert!(matches!(err, LlmError::HttpStatus(404, body) if body == "not found"));
}

#[tokio::test]
async fn ensure_ready_succeeds_when_the_model_is_already_present() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"models":[{"name":"mistral-test"}]}"#,
    ))
    .await;
    let b = backend(&server.url);

    b.ensure_ready(&generous_client()).await.unwrap();
}

#[tokio::test]
async fn ensure_ready_errors_when_the_server_is_unreachable() {
    let url = crate::test_support::closed_port_url();
    let b = backend(&url);

    let err = b.ensure_ready(&generous_client()).await.unwrap_err();
    assert!(matches!(err, LlmError::Setup(_)));
}

#[test]
fn override_base_url_and_override_model_update_the_backend() {
    let mut b = backend("http://a.example");
    b.override_base_url("http://b.example".to_string());
    b.override_model("llama3".to_string());
    assert_eq!(b.model_name(), "llama3");
}
