//! A reply streamed as it is generated: the pieces of text a provider's
//! stream carries, in order, ending with an error when the answer is refused
//! or arrives empty.
//!
//! OpenAI-format servers and Anthropic stream server-sent events; Ollama
//! streams one JSON object per line. Both are line-based, so one reader splits
//! the body into lines and a small parser per provider reads each line.

use crate::LlmError;
use futures_util::{Stream, StreamExt};
use serde_json::Value;
use std::pin::Pin;

/// Text as it arrives. The concatenation of the items is the whole reply.
pub type TextStream = Pin<Box<dyn Stream<Item = Result<String, LlmError>> + Send>>;

/// What one line of a provider's stream says.
#[derive(Debug, PartialEq)]
pub(crate) enum Piece {
    Text(String),
    /// The answer reached the output-token limit.
    Truncated,
    /// The provider says the reply is complete.
    End,
}

type Parser = fn(&str) -> Result<Vec<Piece>, LlmError>;

/// `response`'s body as text pieces, read line by line with `parse`.
///
/// Like a non-streamed reply, a stream that carried no text fails: with
/// `Truncated` when it ran out of tokens first, `EmptyResponse` otherwise.
pub(crate) fn text_stream(response: reqwest::Response, parse: Parser) -> TextStream {
    struct State {
        lines: Pin<Box<dyn Stream<Item = Result<String, LlmError>> + Send>>,
        parse: Parser,
        pending: std::collections::VecDeque<Piece>,
        emitted: bool,
        truncated: bool,
        done: bool,
    }
    let state = State {
        lines: Box::pin(lines(response)),
        parse,
        pending: Default::default(),
        emitted: false,
        truncated: false,
        done: false,
    };
    Box::pin(futures_util::stream::unfold(state, |mut s| async move {
        loop {
            if s.done {
                return None;
            }
            match s.pending.pop_front() {
                Some(Piece::Text(text)) if !text.is_empty() => {
                    s.emitted = true;
                    return Some((Ok(text), s));
                }
                Some(Piece::Text(_)) => continue,
                Some(Piece::Truncated) => {
                    s.truncated = true;
                    continue;
                }
                Some(Piece::End) => {}
                None => match s.lines.next().await {
                    Some(Ok(line)) => {
                        match (s.parse)(&line) {
                            Ok(pieces) => s.pending.extend(pieces),
                            Err(e) => {
                                s.done = true;
                                return Some((Err(e), s));
                            }
                        }
                        continue;
                    }
                    Some(Err(e)) => {
                        s.done = true;
                        return Some((Err(e), s));
                    }
                    None => {}
                },
            }
            // The end of the reply, by the provider's word or the body's.
            s.done = true;
            if s.emitted {
                return None;
            }
            let empty = if s.truncated {
                LlmError::Truncated
            } else {
                LlmError::EmptyResponse
            };
            return Some((Err(empty), s));
        }
    }))
}

/// The body as lines, without their line endings. Bytes are buffered until a
/// newline, so a character split across network chunks is decoded whole.
fn lines(response: reqwest::Response) -> impl Stream<Item = Result<String, LlmError>> + Send {
    let bytes = Box::pin(response.bytes_stream());
    futures_util::stream::unfold(
        (bytes, Vec::<u8>::new(), false),
        |(mut bytes, mut buffer, mut ended)| async move {
            loop {
                if let Some(end) = buffer.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buffer.drain(..=end).collect();
                    let line = String::from_utf8_lossy(&line)
                        .trim_end_matches(['\r', '\n'])
                        .to_string();
                    return Some((Ok(line), (bytes, buffer, ended)));
                }
                if ended {
                    if buffer.is_empty() {
                        return None;
                    }
                    let line = String::from_utf8_lossy(&buffer).into_owned();
                    buffer.clear();
                    return Some((Ok(line), (bytes, buffer, ended)));
                }
                match bytes.next().await {
                    Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                    Some(Err(e)) => {
                        ended = true;
                        buffer.clear();
                        return Some((Err(LlmError::Http(e)), (bytes, buffer, ended)));
                    }
                    None => ended = true,
                }
            }
        },
    )
}

/// The JSON after `data:` on a server-sent-event line; other lines (event
/// names, comments, keep-alives, blank separators) carry nothing to read.
fn sse_data(line: &str) -> Option<&str> {
    line.strip_prefix("data:").map(str::trim)
}

fn provider_error(value: &Value) -> Option<LlmError> {
    let error = value.get("error")?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| error.as_str().map(str::to_string))
        .unwrap_or_else(|| error.to_string());
    Some(LlmError::HttpStatus(502, message))
}

/// One line of an OpenAI-format `chat/completions` stream.
pub(crate) fn openai_line(line: &str) -> Result<Vec<Piece>, LlmError> {
    let Some(data) = sse_data(line) else {
        return Ok(Vec::new());
    };
    if data == "[DONE]" {
        return Ok(vec![Piece::End]);
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(data)?;
    if let Some(e) = provider_error(&value) {
        return Err(e);
    }
    let Some(choice) = value.get("choices").and_then(|c| c.get(0)) else {
        // A usage-only chunk, sent last when usage reporting is on.
        return Ok(Vec::new());
    };
    let delta = &choice["delta"];
    if delta["refusal"]
        .as_str()
        .is_some_and(|r| !r.trim().is_empty())
    {
        return Err(LlmError::Refused { category: None });
    }
    let mut pieces = Vec::new();
    if let Some(text) = delta["content"].as_str() {
        pieces.push(Piece::Text(text.to_string()));
    }
    match choice["finish_reason"].as_str() {
        Some("content_filter") => {
            return Err(LlmError::Refused {
                category: Some("content_filter".to_string()),
            });
        }
        Some("length") => pieces.push(Piece::Truncated),
        _ => {}
    }
    Ok(pieces)
}

/// One line of an Anthropic Messages stream. Thinking arrives as its own
/// deltas and is left out, as it is from a non-streamed reply.
pub(crate) fn anthropic_line(line: &str) -> Result<Vec<Piece>, LlmError> {
    let Some(data) = sse_data(line) else {
        return Ok(Vec::new());
    };
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(data)?;
    match value["type"].as_str() {
        Some("content_block_delta") if value["delta"]["type"] == "text_delta" => {
            let text = value["delta"]["text"].as_str().unwrap_or_default();
            Ok(vec![Piece::Text(text.to_string())])
        }
        Some("message_delta") => match value["delta"]["stop_reason"].as_str() {
            Some("refusal") => Err(LlmError::Refused {
                category: value["delta"]["stop_details"]["category"]
                    .as_str()
                    .map(str::to_string),
            }),
            Some("max_tokens") => Ok(vec![Piece::Truncated]),
            _ => Ok(Vec::new()),
        },
        Some("message_stop") => Ok(vec![Piece::End]),
        Some("error") => Err(provider_error(&value).unwrap_or(LlmError::EmptyResponse)),
        _ => Ok(Vec::new()),
    }
}

/// One line of an Ollama `/api/chat` stream: a JSON object per line.
pub(crate) fn ollama_line(line: &str) -> Result<Vec<Piece>, LlmError> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(line)?;
    if let Some(e) = provider_error(&value) {
        return Err(e);
    }
    let mut pieces = Vec::new();
    if let Some(text) = value["message"]["content"].as_str() {
        pieces.push(Piece::Text(text.to_string()));
    }
    if value["done"].as_bool() == Some(true) {
        if value["done_reason"] == "length" {
            pieces.push(Piece::Truncated);
        }
        pieces.push(Piece::End);
    }
    Ok(pieces)
}

/// Collects a stream into the whole reply.
pub async fn collect(mut stream: TextStream) -> Result<String, LlmError> {
    let mut reply = String::new();
    while let Some(piece) = stream.next().await {
        reply.push_str(&piece?);
    }
    Ok(reply)
}

#[cfg(test)]
mod tests;
