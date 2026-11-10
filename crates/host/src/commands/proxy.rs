//! `ironvise proxy` - an OpenAI-compatible **recording** proxy.
//!
//! # This records. It does not enforce.
//!
//! Point any agent's `OPENAI_BASE_URL` at this and every prompt and completion
//! passing through is written to the hash chain. That covers Codex CLI, Cursor,
//! Aider, Continue, OpenClaw and anything else with a configurable endpoint,
//! with no per-tool work.
//!
//! What it cannot do is stop anything, and the reason is architectural rather
//! than unfinished. The proxy sees **text, not actions**. It never sees a shell
//! command execute; it sees a model saying it would like to run one, and by the
//! time the agent acts on that the proxy is no longer in the path. Calling this
//! a firewall, a guard, or protection would be false.
//!
//! For actual prevention use `ironvise hook`, which Claude Code consults
//! *before* a tool runs and which honours a deny. The two surfaces are compared
//! row by row in `docs/guides/integrations.md`, and they must never be described as
//! one thing - the moment they blur, the project's central claim stops being
//! checkable.
//!
//! # What is recorded
//!
//! One `prompt_input` event for the request and one `llm_response`-shaped
//! `observation` for the reply, both in a session labelled `proxy` so an
//! auditor can tell them from cognitive-loop events. `Tripwire::scan_prompt`
//! runs over the outbound prompt: a match is recorded as a
//! `tripwire_rejection` with `enforced: false`, because flagging is honestly
//! all that happened.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::pool::DatabasePool;
use crate::schema::EventPayload;
use crate::tripwire::Tripwire;

/// Session label, so proxy-mediated events are distinguishable at a glance.
const PROXY_BACKEND_LABEL: &str = "proxy";

struct ProxyState {
    pool: DatabasePool,
    upstream: String,
    client: reqwest::Client,
    tripwire: Tripwire,
    session_id: Uuid,
    signing_key: Arc<ed25519_dalek::SigningKey>,
}

/// Extract the prompt text from an OpenAI-shaped chat request.
///
/// Best-effort by design: a body this does not understand is still forwarded
/// and still recorded verbatim. Refusing to proxy an unfamiliar shape would
/// make the proxy a availability risk for the agent it is observing.
fn extract_prompt(body: &serde_json::Value) -> String {
    body.get("messages")
        .and_then(|m| m.as_array())
        .map(|msgs| {
            msgs.iter()
                .filter_map(|m| {
                    let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("?");
                    let content = m.get("content").and_then(|c| c.as_str())?;
                    Some(format!("[{role}] {content}"))
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_else(|| body.to_string())
}

/// Extract the assistant text from an OpenAI-shaped chat response.
fn extract_completion(body: &serde_json::Value) -> String {
    body.get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| body.to_string())
}

async fn record(state: &ProxyState, payload: EventPayload) {
    if let Err(e) = state
        .pool
        .append_event(
            payload,
            Some(state.session_id),
            None,
            Some(state.signing_key.as_ref()),
        )
        .await
    {
        // Recording failure must not take the agent down: this is an observer,
        // and an observer that can halt the thing it observes is a worse
        // component than one with a gap. The gap is logged loudly.
        tracing::error!("proxy: FAILED to record an event - the audit trail now has a gap: {e}");
    }
}

/// Forward any `/v1/*` call upstream, recording chat completions on the way.
async fn forward(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: Bytes,
) -> impl IntoResponse {
    let path = uri.path();
    let url = format!("{}{}", state.upstream.trim_end_matches('/'), path);

    // Stripped before anything is recorded; the forwarded bytes are untouched.
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&body).ok().map(|mut v| {
        crate::encrypted_reasoning::strip(&mut v);
        v
    });
    let is_chat = path.ends_with("/chat/completions");

    if is_chat && let Some(req) = &parsed {
        let prompt = extract_prompt(req);

        // The correct check for this layer, and the only one available: the
        // proxy can read the text going past. Recorded as NOT enforced, because
        // it was not - the request is forwarded either way.
        if let Err(e) = state.tripwire.scan_prompt(&prompt) {
            record(
                &state,
                EventPayload::TripwireRejection {
                    action: None,
                    reason: format!("{e} (flagged only: the proxy cannot block)"),
                    stage: "prompt_scan".to_string(),
                    enforced: false,
                },
            )
            .await;
        }

        record(&state, EventPayload::PromptInput { content: prompt }).await;
    }

    let mut req = state.client.post(&url).body(body.clone());
    // Pass the caller's credentials through; the proxy holds none of its own.
    for name in ["authorization", "content-type", "accept"] {
        if let Some(v) = headers.get(name) {
            req = req.header(name, v);
        }
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("IronVise proxy: upstream {url} unreachable: {e}"),
            )
                .into_response();
        }
    };

    let status = upstream.status();
    let bytes = upstream.bytes().await.unwrap_or_default();

    if is_chat
        && status.is_success()
        && let Ok(mut resp) = serde_json::from_slice::<serde_json::Value>(&bytes)
    {
        crate::encrypted_reasoning::strip(&mut resp);
        record(
            &state,
            EventPayload::Observation {
                content: extract_completion(&resp),
            },
        )
        .await;
    }

    (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response()
}

fn router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/v1/{*path}", post(forward))
        .route(
            "/health",
            get(|| async { "IronVise recording proxy: records, does not block" }),
        )
        .with_state(state)
}

/// The proxy has no authentication: whoever reaches it writes to the ledger
/// and relays through it. So every address `bind` resolves to must be
/// loopback unless remote clients were asked for explicitly.
fn check_bind(addrs: &[std::net::SocketAddr], allow_remote: bool) -> Result<(), String> {
    if addrs.is_empty() {
        return Err("the bind address resolved to nothing".into());
    }
    match addrs.iter().find(|a| !a.ip().is_loopback()) {
        Some(a) if !allow_remote => Err(format!(
            "refusing to listen on {a}: the recording proxy has no authentication, so \
             anyone who can reach it can write to this ledger. Bind to 127.0.0.1, or \
             pass --allow-remote if that is intended."
        )),
        _ => Ok(()),
    }
}

pub async fn run(
    pool: DatabasePool,
    bind: &str,
    upstream: &str,
    allow_remote: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(bind).await?.collect();
    check_bind(&addrs, allow_remote)?;
    let (session, key) = pool
        .create_session(
            &format!("Recording proxy to {upstream}"),
            PROXY_BACKEND_LABEL,
            "n/a",
            None,
        )
        .await?;

    let state = Arc::new(ProxyState {
        pool,
        upstream: upstream.to_string(),
        client: reqwest::Client::new(),
        tripwire: Tripwire::from_operator_config(),
        session_id: session.id,
        signing_key: Arc::new(key),
    });

    let app = router(state);
    let listener = TcpListener::bind(addrs.as_slice()).await?;
    println!("IronVise recording proxy");
    println!("  listening on  http://{bind}");
    println!("  forwarding to {upstream}");
    println!("  ledger session {}", session.id);
    println!();
    println!("  This RECORDS. It cannot block: it sees text, not actions.");
    println!("  For enforcement use `ironvise hook` (Claude Code PreToolUse).");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
