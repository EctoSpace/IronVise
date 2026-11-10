//! Cross-instance SSE wakeups on PostgreSQL: a NOTIFY sent on another
//! connection, as another instance's append sends it, reaches the listener.

mod common;

use common::spawn_test_pool;
use ectoledger::pg_notify::{notify_new_event, spawn_pg_listener};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[cfg_attr(
    not(feature = "integration"),
    ignore = "needs PostgreSQL; run with --features integration"
)]
async fn a_notify_from_another_connection_wakes_the_listener() {
    let (pool, _db) = spawn_test_pool().await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let listener = spawn_pg_listener(&pool, cancel.clone(), move || {
        let _ = tx.send(());
    });

    // LISTEN registers asynchronously, so notify until one is heard.
    let heard = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            notify_new_event(&pool).await;
            if tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_ok()
            {
                return;
            }
        }
    })
    .await;
    assert!(heard.is_ok(), "the listener never heard a NOTIFY");

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), listener)
        .await
        .expect("the listener stops when cancelled")
        .expect("listener task");
}
