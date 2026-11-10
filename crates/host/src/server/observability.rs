//! Prometheus metrics and the security-metrics summary.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;

#[derive(serde::Serialize)]
pub(crate) struct SecurityMetricsResponse {
    injection_attempts_detected_7d: u64,
    injection_attempts_by_layer: std::collections::HashMap<String, u64>,
    sessions_aborted_circuit_breaker: u64,
    chain_verification_failures: u64,
    /// Rows in the ledger, not process counters: what Home shows survives a
    /// restart. Home read these names from the start; the response never
    /// carried them, so the desktop app showed 0 sessions on every ledger.
    total_sessions: u64,
    total_events: u64,
    /// Process counters since this server started.
    guard_denials: u64,
    tripwire_rejections: u64,
}

/// `(sessions, events)` in the ledger. A count that fails reads as 0 rather
/// than failing the whole summary: the other numbers are still true.
async fn ledger_counts(pool: &crate::pool::DatabasePool) -> (u64, u64) {
    async fn one(pool: &crate::pool::DatabasePool, sql: &'static str) -> u64 {
        let n: Result<i64, sqlx::Error> = match pool {
            crate::pool::DatabasePool::Postgres(pg) => sqlx::query_scalar(sql).fetch_one(pg).await,
            crate::pool::DatabasePool::Sqlite(sq) => sqlx::query_scalar(sql).fetch_one(sq).await,
        };
        n.ok().and_then(|n| u64::try_from(n).ok()).unwrap_or(0)
    }
    (
        one(pool, "SELECT count(*) FROM agent_sessions").await,
        one(pool, "SELECT count(*) FROM agent_events").await,
    )
}

pub(crate) async fn security_metrics(
    State(state): State<Arc<AppState>>,
    axum::Extension(_role): axum::Extension<Role>,
) -> Result<axum::Json<SecurityMetricsResponse>, StatusCode> {
    // Read-only summary counters - accessible to any authenticated role.
    let m = &state.metrics;
    let mut by_layer = std::collections::HashMap::new();
    by_layer.insert(
        "tripwire".to_string(),
        m.tripwire_rejections
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    by_layer.insert(
        "guard_llm".to_string(),
        m.guard_denials.load(std::sync::atomic::Ordering::Relaxed),
    );
    let (total_sessions, total_events) = ledger_counts(&state.pool).await;
    let guard_denials = m.guard_denials.load(std::sync::atomic::Ordering::Relaxed);
    let tripwire_rejections = m
        .tripwire_rejections
        .load(std::sync::atomic::Ordering::Relaxed);
    Ok(axum::Json(SecurityMetricsResponse {
        injection_attempts_detected_7d: tripwire_rejections + guard_denials,
        injection_attempts_by_layer: by_layer,
        sessions_aborted_circuit_breaker: 0,
        chain_verification_failures: 0,
        total_sessions,
        total_events,
        guard_denials,
        tripwire_rejections,
    }))
}

pub(crate) async fn metrics_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    headers: axum::http::HeaderMap,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let body = state.metrics.prometheus_text();

    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);

    if wants_html {
        let html = format!(
            r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IronVise - Metrics</title>
<style>
  body{{margin:0;background:#0d1117;color:#c9d1d9;font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:13px;padding:16px;}}
  h2{{color:#58a6ff;font-size:14px;margin-bottom:12px;}}
  pre{{white-space:pre-wrap;word-break:break-all;background:#161b22;padding:16px;border-radius:4px;border:1px solid #21262d;}}
  a{{color:#58a6ff;font-size:12px;}}
</style>
</head><body>
<h2>IronVise - Prometheus Metrics</h2>
<pre>{body}</pre>
<a href="/">&larr; Observer dashboard</a>
</body></html>"#
        );
        Ok((
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        ))
    } else {
        Ok((
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            body,
        ))
    }
}
