//! PostgreSQL `LISTEN/NOTIFY` helpers for cross-instance SSE fanout.
//!
//! When multiple IronVise instances share a PostgreSQL database the
//! in-process `tokio::sync::broadcast` channel only wakes SSE clients
//! connected to the local instance.  This module bridges the gap:
//!
//! 1. **[`notify_new_event`]** - Called after each event append to issue
//!    `NOTIFY ectoledger_events`.  This is a no-op for SQLite.
//! 2. **[`spawn_pg_listener`]** - Spawns a background task that
//!    `LISTEN`s on the channel and calls `on_notify` whenever a notification
//!    arrives from any instance (including self).
//!
//! The server starts one listener per process on PostgreSQL, alongside the
//! in-process wakeup. Multi-instance deployment as a whole is not supported
//! yet (see `docs/guides/scaling.md`); this closes the SSE part of it.

use sqlx::PgPool;

/// The PostgreSQL channel name used for cross-instance event wakeups.
pub const CHANNEL: &str = "ectoledger_events";

/// Send a `NOTIFY` on the `ectoledger_events` channel.
///
/// This is intentionally fire-and-forget: a failed NOTIFY should not
/// block or error the event-append path.  The worst case is a slightly
/// delayed SSE update on other instances (they will catch up via their
/// periodic poll or on the next successful NOTIFY).
pub async fn notify_new_event(pool: &PgPool) {
    // A channel cannot be a bind parameter; CHANNEL is a constant.
    let result = sqlx::query(sqlx::AssertSqlSafe(format!("NOTIFY {CHANNEL}")))
        .execute(pool)
        .await;
    if let Err(e) = result {
        tracing::warn!("pg NOTIFY failed (non-fatal): {}", e);
    }
}

/// Spawn a background task that listens for PostgreSQL notifications and
/// calls `on_notify` for each, until `cancel` fires.
pub fn spawn_pg_listener(
    pool: &PgPool,
    cancel: tokio_util::sync::CancellationToken,
    on_notify: impl Fn() + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let pool = pool.clone();
    tokio::spawn(async move {
        let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    "Failed to create PgListener: {}. Cross-instance SSE wakeups disabled.",
                    e
                );
                return;
            }
        };
        if let Err(e) = listener.listen(CHANNEL).await {
            tracing::error!(
                "LISTEN {} failed: {}. Cross-instance SSE wakeups disabled.",
                CHANNEL,
                e
            );
            return;
        }
        tracing::info!("Listening on pg channel '{CHANNEL}' for cross-instance SSE wakeups");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                received = listener.recv() => match received {
                    Ok(_) => on_notify(),
                    // PgListener reconnects on transient errors.
                    Err(e) => tracing::warn!("PgListener recv error (will retry): {e}"),
                },
            }
        }
    })
}
