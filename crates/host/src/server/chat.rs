//! Direct LLM chat endpoints (no agent loop, no guard, no tripwire).
//!
//! Each exchange is recorded: the user's message as a `chat_message` event
//! before the model is called, and the whole reply after it. The streaming
//! routes send the reply as it is generated and record it once complete.

use super::*;

#[derive(Deserialize)]
pub(crate) struct ChatRequest {
    message: String,
}

const SYSTEM: &str =
    "You are a helpful AI assistant. Respond naturally and concisely to the user's message.";

type ChatError = (StatusCode, String);

/// `POST /api/chat` - One-shot LLM chat.
///
/// Sends the user's message directly to the configured LLM backend and returns
/// the raw text response.  No session is created, no guard or tripwire checks
/// are applied.  This is the happy-path "just talk to the model" endpoint used
/// by the dashboard's Test Prompt panel.
pub(crate) async fn chat(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::Json(body): axum::Json<ChatRequest>,
) -> Result<axum::Json<serde_json::Value>, ChatError> {
    let exchange = Exchange::open(&state, role, None, &body).await?;
    let reply = exchange
        .llm
        .raw_call(SYSTEM, &exchange.message)
        .await
        .map_err(|e| {
            tracing::error!("LLM chat call failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("LLM call failed: {e}"),
            )
        })?;
    exchange.finish(&state, reply).await.map(axum::Json)
}

/// `POST /api/sessions/{session_id}/chat` - Chat scoped to a specific session.
///
/// Appends the user's message as a `ChatMessage` event to the given session,
/// calls the LLM, and appends the assistant's reply to the same session.
pub(crate) async fn session_chat(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<ChatRequest>,
) -> Result<axum::Json<serde_json::Value>, ChatError> {
    let exchange = Exchange::open(&state, role, Some(session_id), &body).await?;
    let reply = exchange
        .llm
        .raw_call(SYSTEM, &exchange.message)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("LLM call failed: {e}")))?;
    exchange.finish(&state, reply).await.map(axum::Json)
}

/// `POST /api/chat/stream` - `/api/chat`, answered as server-sent events.
///
/// `delta` events carry `{"text"}` as the model generates it; the last event
/// is `done` with `{"reply", "backend", "model"}`, or `error` with
/// `{"message"}`. A failure before the first token is an HTTP error instead.
pub(crate) async fn chat_stream(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::Json(body): axum::Json<ChatRequest>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, ChatError> {
    stream_exchange(state, role, None, body).await
}

/// `POST /api/sessions/{session_id}/chat/stream` - the session's chat,
/// streamed like `/api/chat/stream`.
pub(crate) async fn session_chat_stream(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<ChatRequest>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, ChatError> {
    stream_exchange(state, role, Some(session_id), body).await
}

async fn stream_exchange(
    state: Arc<AppState>,
    role: Role,
    session: Option<Uuid>,
    body: ChatRequest,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, ChatError> {
    let exchange = Exchange::open(&state, role, session, &body).await?;
    let mut text = exchange
        .llm
        .stream_raw(SYSTEM, &exchange.message)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("LLM call failed: {e}")))?;
    let events = async_stream::stream! {
        let mut reply = String::new();
        while let Some(piece) = text.next().await {
            match piece {
                Ok(piece) => {
                    reply.push_str(&piece);
                    yield Ok(sse_event("delta", serde_json::json!({ "text": piece })));
                }
                Err(e) => {
                    tracing::error!("LLM chat stream failed: {e}");
                    let message = format!("LLM call failed: {e}");
                    yield Ok(sse_event("error", serde_json::json!({ "message": message })));
                    return;
                }
            }
        }
        match exchange.finish(&state, reply).await {
            Ok(done) => yield Ok(sse_event("done", done)),
            Err((_, message)) => {
                yield Ok(sse_event("error", serde_json::json!({ "message": message })));
            }
        }
    };
    Ok(Sse::new(events).keep_alive(axum::response::sse::KeepAlive::default()))
}

fn sse_event(name: &str, data: serde_json::Value) -> Event {
    Event::default().event(name).data(data.to_string())
}

/// One chat exchange: the checked message, its session, and the backend that
/// answers it. Opening it records the user's message.
struct Exchange {
    message: String,
    session: Option<Uuid>,
    llm: Box<dyn llm::LlmBackend>,
}

impl Exchange {
    async fn open(
        state: &AppState,
        role: Role,
        session: Option<Uuid>,
        body: &ChatRequest,
    ) -> Result<Self, ChatError> {
        // Chat writes `chat_message` events, so the read-only auditor may not.
        if role == Role::Auditor {
            return Err((
                StatusCode::FORBIDDEN,
                "Auditor role cannot chat: it would write to the ledger".into(),
            ));
        }
        let message = body.message.trim();
        if message.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "Message must not be empty".into()));
        }
        let llm = ready_backend(state).await?;
        let exchange = Self {
            message: message.to_string(),
            session,
            llm,
        };
        exchange
            .record("user", exchange.message.clone(), None)
            .append(state)
            .await
            .map_err(|e| {
                tracing::error!("Failed to append user chat event to audit ledger: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to log chat event: {e}"),
                )
            })?;
        Ok(exchange)
    }

    /// Records the whole reply and returns the response body.
    async fn finish(
        &self,
        state: &AppState,
        reply: String,
    ) -> Result<serde_json::Value, ChatError> {
        let backend = self.llm.backend_name().to_string();
        let model = self.llm.model_name().to_string();
        self.record(
            "assistant",
            reply.clone(),
            Some((backend.clone(), model.clone())),
        )
        .append(state)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to append assistant chat event to audit ledger: {}",
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to log chat reply: {e}"),
            )
        })?;
        Ok(serde_json::json!({
            "reply": reply,
            "backend": backend,
            "model": model,
        }))
    }

    fn record(&self, role: &str, content: String, by: Option<(String, String)>) -> ChatRecord {
        let (backend, model) = by.unzip();
        ChatRecord {
            payload: EventPayload::ChatMessage {
                role: role.into(),
                content,
                backend,
                model,
            },
            session: self.session,
        }
    }
}

struct ChatRecord {
    payload: EventPayload,
    session: Option<Uuid>,
}

impl ChatRecord {
    async fn append(self, state: &AppState) -> Result<(), crate::ledger::AppendError> {
        state
            .pool
            .append_event(self.payload, self.session, None, None)
            .await
            .map(drop)
    }
}

/// The configured backend, checked reachable. Demo mode provisions a small
/// local model through Ollama, so the real pipeline runs without API keys.
async fn ready_backend(state: &AppState) -> Result<Box<dyn llm::LlmBackend>, ChatError> {
    if let Some(factory) = &state.llm_factory {
        return Ok(factory());
    }
    let client = &state.http_client;
    let backend = llm::backend_from_env(client).map_err(|e| {
        tracing::error!("LLM setup failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("LLM setup failed: {e}"),
        )
    })?;
    backend.ensure_ready(client).await.map_err(|e| {
        tracing::error!("LLM not ready: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("LLM not ready: {e}. Is your LLM backend running?"),
        )
    })?;
    Ok(backend)
}
