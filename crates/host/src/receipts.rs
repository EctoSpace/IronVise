//! Data receipts: what a tool returned, recorded by hash.
//!
//! A decision records what an agent was allowed to do; a receipt records what
//! it then received. Only hashes go into the ledger: SHA-256 of the whole
//! response, and of each text the agent read (a file's contents, command
//! output, page text, MCP text blocks), so whoever holds the data can later
//! show it is exactly what was read, and nobody can read it from the ledger.
//!
//! The hashing happens where the tool ran: the Claude Code hook and
//! `mcp-proxy` build the receipt and send only that to the Observer, so the
//! data never leaves the agent's machine, and a large result costs a receipt
//! of the same few hundred bytes as a small one. The Observer checks the
//! receipt's shape ([`accept`]) and signs it.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::schema::EventPayload;

/// The receipt for one tool result. `input` is what the tool was called
/// with (for the source); `response` is what it returned.
pub fn receipt(tool: &str, input: &Value, response: &Value, call_id: Option<&str>) -> EventPayload {
    let texts = texts(response);
    EventPayload::DataReceipt {
        tool: tool_name(tool),
        source: source(input),
        call_id: call_id.map(str::to_string),
        response_sha256: sha256_hex(
            ectoledger_elc::canonical_json(response)
                .unwrap_or_default()
                .as_bytes(),
        ),
        text_sha256: texts.iter().map(|t| sha256_hex(t.as_bytes())).collect(),
        text_bytes: texts.iter().map(|t| t.len() as u64).sum(),
    }
}

/// Longest `tool` and `source` a receipt may name. A source is a path, a URL
/// or a command; one longer than this is not a name for what was read.
const MAX_TOOL: usize = 256;
const MAX_SOURCE: usize = 4096;

/// A receipt sent by a hook or proxy, checked and bound to the tool use it
/// answers: only a `data_receipt` whose hashes are SHA-256 hex digests is
/// accepted, and its `call_id` is the request's `tool_use_id`, whatever the
/// client put there.
pub fn accept(claim: EventPayload, tool_use_id: Option<&str>) -> Result<EventPayload, String> {
    let EventPayload::DataReceipt {
        tool,
        source,
        response_sha256,
        text_sha256,
        text_bytes,
        ..
    } = claim
    else {
        return Err("`receipt` must be a data_receipt".into());
    };
    if tool.trim().is_empty() || tool.len() > MAX_TOOL {
        return Err(format!("`tool` must be 1 to {MAX_TOOL} bytes"));
    }
    if source.as_ref().is_some_and(|s| s.len() > MAX_SOURCE) {
        return Err(format!("`source` is longer than {MAX_SOURCE} bytes"));
    }
    let is_digest =
        |h: &str| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if let Some(bad) = std::iter::once(&response_sha256)
        .chain(&text_sha256)
        .find(|h| !is_digest(h))
    {
        return Err(format!(
            "`{bad}` is not a SHA-256 digest (64 lowercase hex digits)"
        ));
    }
    if text_sha256.is_empty() && text_bytes != 0 {
        return Err("`text_bytes` counts texts that `text_sha256` does not list".into());
    }
    Ok(EventPayload::DataReceipt {
        tool,
        source,
        call_id: tool_use_id.map(str::to_string),
        response_sha256,
        text_sha256,
        text_bytes,
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Claude Code names MCP tools `mcp__<server>__<tool>`; the ledger uses the
/// policy vocabulary, `mcp:<server>/<tool>`.
fn tool_name(tool: &str) -> String {
    match tool.strip_prefix("mcp__").and_then(|r| r.split_once("__")) {
        Some((server, name)) => format!("{}{server}/{name}", crate::tripwire::MCP_ACTION_PREFIX),
        None => tool.to_string(),
    }
}

/// The first argument that names what was read.
fn source(input: &Value) -> Option<String> {
    [
        "file_path",
        "notebook_path",
        "path",
        "uri",
        "url",
        "command",
        "pattern",
        "query",
    ]
    .iter()
    .find_map(|k| input.get(k).and_then(Value::as_str))
    .map(str::to_string)
}

/// The text of one content block: a string, `{text}`, or `{resource: {text}}`.
fn block_text(block: &Value) -> Option<&str> {
    block
        .as_str()
        .or_else(|| block.get("text").and_then(Value::as_str))
        .or_else(|| block.get("resource")?.get("text")?.as_str())
}

/// The texts the agent received, in the shapes Claude Code and MCP servers
/// return. Anything else is covered by `response_sha256` alone.
fn texts(response: &Value) -> Vec<&str> {
    match response {
        Value::String(s) => vec![s],
        // MCP content blocks, as Claude Code passes them for an MCP tool.
        Value::Array(blocks) => blocks.iter().filter_map(block_text).collect(),
        Value::Object(o) => {
            // An MCP `tools/call` result.
            if let Some(Value::Array(blocks)) = o.get("content") {
                return blocks.iter().filter_map(block_text).collect();
            }
            // Claude Code's Read.
            if let Some(text) = o
                .get("file")
                .and_then(|f| f.get("content"))
                .and_then(Value::as_str)
            {
                return vec![text];
            }
            // Claude Code's Bash.
            if o.contains_key("stdout") {
                return ["stdout", "stderr"]
                    .iter()
                    .filter_map(|k| o.get(*k).and_then(Value::as_str))
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            // WebFetch's result, Grep's content, and the like.
            ["result", "content", "text", "output"]
                .iter()
                .find_map(|k| o.get(*k).and_then(Value::as_str))
                .into_iter()
                .collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
