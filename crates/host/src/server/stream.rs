//! Server-sent-event streaming of ledger events.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;

/// Global SSE wakeup sender, used to wake SSE clients when new ledger events
/// are written. Set once during router construction. A plain
/// `OnceLock<broadcast::Sender>` with no Mutex needed, because
/// `broadcast::Sender` is already `Clone + Send + Sync` and `send()` is
/// wait-free.
pub(crate) static SSE_WAKEUP: OnceLock<broadcast::Sender<()>> = OnceLock::new();

/// Wake all SSE stream handlers. Called after any ledger event is appended.
/// Safe to call from any context; silently no-ops if the server is not running.
pub fn notify_sse_subscribers() {
    if let Some(tx) = SSE_WAKEUP.get() {
        let _ = tx.send(());
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct StreamEvent {
    id: i64,
    sequence: i64,
    previous_hash: String,
    content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
    created_at: String,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct StreamQuery {
    after: Option<i64>,
    /// Alias for `after` - clients can use `?since=<last_sequence>` to reconnect
    /// without replaying the full event history.
    since: Option<i64>,
    session_id: Option<Uuid>,
}

pub(crate) async fn stream_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StreamQuery>,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let pool = state.pool.clone();
    // `since` takes precedence over `after` for forwards-compat; both work.
    let mut last_id = q.since.or(q.after).unwrap_or(0);
    let session_id = q.session_id;
    // Subscribe before entering the loop so we don't miss a wakeup that races
    // with the initial fetch below.
    let mut rx = state.sse_tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            let rows: Vec<crate::schema::LedgerEventRow> = {
                let query_result = pool.stream_events_since(last_id, session_id).await;
                match query_result {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!("SSE DB poll failed: {}", e);
                        yield Ok(Event::default().event("error").data("db_error"));
                        break;
                    }
                }
            };

            let more_waiting = rows.len() >= crate::pool::STREAM_BATCH_SIZE;
            for row in rows {
                last_id = row.id;
                let payload_value = serde_json::to_value(&row.payload).unwrap_or(serde_json::Value::Null);
                let payload_redacted = redact_for_stream(&payload_value);
                let ev = StreamEvent {
                    id: row.id,
                    sequence: row.sequence,
                    previous_hash: row.previous_hash,
                    content_hash: row.content_hash,
                    payload: Some(payload_redacted),
                    created_at: row.created_at.to_rfc3339(),
                };
                if let Ok(data) = serde_json::to_string(&ev) {
                    yield Ok(Event::default().event("event").id(row.id.to_string()).data(data));
                }
            }

            // A full batch: the backlog is not drained yet, so fetch again now.
            // Waiting here would hand a reconnecting client 100 events per write.
            if more_waiting {
                continue;
            }
            // Sleep until the ledger writer signals a new event, or 30 s pass.
            tokio::select! {
                recv_result = rx.recv() => {
                    match recv_result {
                        Ok(_) => {
                            // Normal wakeup - drain accumulated signals before re-polling.
                            while rx.try_recv().is_ok() {}
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // Only wakeups were dropped: the next fetch reads from `last_id`.
                            tracing::debug!("SSE client lagged by {} broadcast signals; catching up via DB", n);
                            while rx.try_recv().is_ok() {}
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // The broadcast sender was dropped - server is shutting down.
                            tracing::debug!("SSE wakeup channel closed; terminating stream");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    // Fallback heartbeat - ensures we eventually detect if the sender is dropped.
                }
            }
        }
    };

    let stream = stream.map(|r| r.map_err(|_: Infallible| unreachable!()));
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(crate::config::sse_keepalive_secs()))
            .text("keep-alive"),
    )
}

/// `GET /api/sessions/{session_id}/events/stream` - SSE stream scoped to a session.
///
/// Alias for the generic `/api/stream?session_id=<id>` endpoint, used by the
/// Python SDK which encodes the session ID in the path instead of a query param.
pub(crate) async fn stream_events_by_session(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let query = StreamQuery {
        after: None,
        since: None,
        session_id: Some(session_id),
    };
    stream_events(State(state), Query(query), ConnectInfo(addr)).await
}
