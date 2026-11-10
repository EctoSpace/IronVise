use super::*;
use crate::test_support::{MockServer, ScriptedResponse, generous_client};
use crate::{
    LlmBackend, anthropic::AnthropicBackend, ollama_backend::OllamaBackend, openai::OpenAiBackend,
};

fn response_from_chunks(chunks: Vec<&'static [u8]>) -> reqwest::Response {
    let body = futures_util::stream::iter(
        chunks
            .into_iter()
            .map(|c| Ok::<_, std::io::Error>(bytes::Bytes::from_static(c))),
    );
    reqwest::Response::from(http::Response::new(reqwest::Body::wrap_stream(body)))
}

async fn pieces(stream: TextStream) -> Vec<Result<String, String>> {
    stream.map(|r| r.map_err(|e| e.to_string())).collect().await
}

#[tokio::test]
async fn a_character_split_across_chunks_arrives_whole() {
    // "é" is 0xC3 0xA9; the network may cut between the two bytes.
    let response = response_from_chunks(vec![
        b"{\"message\":{\"content\":\"caf\xC3",
        b"\xA9\"},\"done\":false}\n{\"message\":{\"content\":\"!\"},\"done\":true}\n",
    ]);
    let text = collect(text_stream(response, ollama_line)).await.unwrap();
    assert_eq!(text, "café!");
}

#[tokio::test]
async fn a_last_line_without_a_newline_is_read() {
    let response = response_from_chunks(vec![
        b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}",
    ]);
    assert_eq!(
        collect(text_stream(response, openai_line)).await.unwrap(),
        "hi"
    );
}

#[tokio::test]
async fn a_stream_with_no_text_is_an_empty_response_or_truncated() {
    let empty = response_from_chunks(vec![b"data: [DONE]\n"]);
    assert!(matches!(
        collect(text_stream(empty, openai_line)).await,
        Err(LlmError::EmptyResponse)
    ));
    let cut = response_from_chunks(vec![
        b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n",
    ]);
    assert!(matches!(
        collect(text_stream(cut, openai_line)).await,
        Err(LlmError::Truncated)
    ));
}

#[test]
fn openai_lines() {
    assert_eq!(openai_line(": keep-alive").unwrap(), vec![]);
    assert_eq!(openai_line("").unwrap(), vec![]);
    assert_eq!(openai_line("data: [DONE]").unwrap(), vec![Piece::End]);
    assert_eq!(
        openai_line(r#"data: {"choices":[{"delta":{"content":"a"},"finish_reason":"length"}]}"#)
            .unwrap(),
        vec![Piece::Text("a".into()), Piece::Truncated]
    );
    assert_eq!(
        openai_line(r#"data: {"choices":[],"usage":{"total_tokens":3}}"#).unwrap(),
        vec![]
    );
    assert!(matches!(
        openai_line(r#"data: {"choices":[{"delta":{"refusal":"I can't help"}}]}"#),
        Err(LlmError::Refused { category: None })
    ));
    assert!(matches!(
        openai_line(r#"data: {"choices":[{"delta":{},"finish_reason":"content_filter"}]}"#),
        Err(LlmError::Refused { category: Some(_) })
    ));
    match openai_line(r#"data: {"error":{"message":"rate limited"}}"#) {
        Err(LlmError::HttpStatus(502, m)) => assert_eq!(m, "rate limited"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        openai_line("data: {not json"),
        Err(LlmError::InvalidJson(_))
    ));
}

#[test]
fn anthropic_lines() {
    assert_eq!(
        anthropic_line("event: content_block_delta").unwrap(),
        vec![]
    );
    assert_eq!(
        anthropic_line(r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hi"}}"#).unwrap(),
        vec![Piece::Text("Hi".into())]
    );
    // Thinking is not part of the reply.
    assert_eq!(
        anthropic_line(r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}"#).unwrap(),
        vec![]
    );
    assert_eq!(
        anthropic_line(r#"data: {"type":"message_delta","delta":{"stop_reason":"max_tokens"}}"#)
            .unwrap(),
        vec![Piece::Truncated]
    );
    assert_eq!(
        anthropic_line(r#"data: {"type":"message_stop"}"#).unwrap(),
        vec![Piece::End]
    );
    match anthropic_line(
        r#"data: {"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"category":"cyber"}}}"#,
    ) {
        Err(LlmError::Refused { category }) => assert_eq!(category.as_deref(), Some("cyber")),
        other => panic!("{other:?}"),
    }
    match anthropic_line(
        r#"data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
    ) {
        Err(LlmError::HttpStatus(502, m)) => assert_eq!(m, "Overloaded"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn ollama_lines() {
    assert_eq!(
        ollama_line(r#"{"message":{"role":"assistant","content":"x"},"done":false}"#).unwrap(),
        vec![Piece::Text("x".into())]
    );
    assert_eq!(
        ollama_line(r#"{"message":{"content":""},"done":true,"done_reason":"length"}"#).unwrap(),
        vec![Piece::Text(String::new()), Piece::Truncated, Piece::End]
    );
    match ollama_line(r#"{"error":"model 'x' not found"}"#) {
        Err(LlmError::HttpStatus(502, m)) => assert_eq!(m, "model 'x' not found"),
        other => panic!("{other:?}"),
    }
}

const OPENAI_SSE: &str = "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n\
data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n\
data: {\"choices\":[{\"delta\":{\"content\":\", world\"},\"finish_reason\":\"stop\"}]}\n\n\
data: [DONE]\n\n";

#[tokio::test]
async fn openai_streams_and_asks_for_a_stream() {
    let server = MockServer::single(ScriptedResponse::ok(OPENAI_SSE)).await;
    let mut backend = OpenAiBackend::from_env(&generous_client());
    backend.override_base_url(server.url.clone());
    backend.override_model("m".into());
    let got = pieces(backend.stream_raw("s", "u").await.unwrap()).await;
    assert_eq!(
        got,
        vec![Ok("Hello".to_string()), Ok(", world".to_string())]
    );
    let body = server.request(0).body_json();
    assert_eq!(body["stream"], true);
    assert!(
        body.get("response_format").is_none(),
        "free text, not JSON mode"
    );
}

#[tokio::test]
async fn openai_without_streaming_sends_no_stream_field() {
    let server = MockServer::single(ScriptedResponse::ok(
        r#"{"choices":[{"message":{"content":"ok"}}]}"#,
    ))
    .await;
    let mut backend = OpenAiBackend::from_env(&generous_client());
    backend.override_base_url(server.url.clone());
    backend.raw_call("s", "u").await.unwrap();
    assert!(server.request(0).body_json().get("stream").is_none());
}

#[tokio::test]
async fn anthropic_streams_the_text_and_not_the_thinking() {
    let sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Let me think\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Four\"}}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    let server = MockServer::single(ScriptedResponse::ok(sse)).await;
    let mut backend = AnthropicBackend::from_env(&generous_client());
    backend.override_base_url(server.url.clone());
    let got = collect(backend.stream_raw("s", "u").await.unwrap())
        .await
        .unwrap();
    assert_eq!(got, "Four");
    assert_eq!(server.request(0).body_json()["stream"], true);
}

#[tokio::test]
async fn ollama_streams_ndjson() {
    let ndjson = "{\"message\":{\"content\":\"one \"},\"done\":false}\n{\"message\":{\"content\":\"two\"},\"done\":false}\n{\"message\":{\"content\":\"\"},\"done\":true,\"done_reason\":\"stop\"}\n";
    let server = MockServer::single(ScriptedResponse::ok(ndjson)).await;
    let mut backend = OllamaBackend::from_env(&generous_client());
    backend.override_base_url(server.url.clone());
    let got = collect(backend.stream_raw("s", "u").await.unwrap())
        .await
        .unwrap();
    assert_eq!(got, "one two");
    assert_eq!(server.request(0).body_json()["stream"], true);
}

#[tokio::test]
async fn an_error_status_fails_before_any_text() {
    let server = MockServer::single(ScriptedResponse::status(401, "bad key")).await;
    let mut backend = OpenAiBackend::from_env(&generous_client());
    backend.override_base_url(server.url.clone());
    match backend.stream_raw("s", "u").await {
        Err(LlmError::HttpStatus(401, body)) => assert_eq!(body, "bad key"),
        Err(e) => panic!("expected 401, got {e}"),
        Ok(_) => panic!("expected 401, got a stream"),
    }
}
