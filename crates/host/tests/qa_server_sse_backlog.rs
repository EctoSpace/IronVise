//! A client that connects behind a long backlog receives all of it at once.
//!
//! The stream reads `STREAM_BATCH_SIZE` events per query. It used to wait for
//! the next ledger write (or a 30 s heartbeat) after every batch, so a client
//! reconnecting 250 events behind got 100 and then stalled.

mod qa_server_common;

use ectoledger::schema::EventPayload;
use qa_server_common::{
    ADMIN_TOKEN, StubBackend, bearer, ensure_guard_disabled, fresh_pool, seed_token,
    wait_until_ready,
};
use std::sync::Arc;

const BACKLOG: usize = 250;
const _: () = assert!(BACKLOG > 2 * ectoledger::pool::STREAM_BATCH_SIZE);

#[tokio::test]
async fn a_backlog_longer_than_one_batch_streams_without_another_write() {
    ensure_guard_disabled();
    let pool = fresh_pool().await;
    seed_token(&pool, ADMIN_TOKEN, "admin").await;

    // Written through the pool: the HTTP API's rate limit would stop a
    // backlog this long, and the stream is what is under test.
    let goal = "sse backlog";
    let (session, key) = pool
        .create_session(goal, "mock", "mock-v1", None)
        .await
        .unwrap();
    for i in 0..BACKLOG {
        pool.append_event(
            EventPayload::Observation {
                content: format!("backlog {i}"),
            },
            Some(session.id),
            Some(goal),
            Some(&key),
        )
        .await
        .unwrap();
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let metrics = Arc::new(ectoledger::metrics::Metrics::default());
    tokio::spawn(ectoledger::start_server_with_llm(
        pool,
        metrics,
        listener,
        Arc::new(|| Box::new(StubBackend)),
    ));
    wait_until_ready(&base).await;

    let mut resp = reqwest::Client::new()
        .get(format!("{base}/api/stream?session_id={}", session.id))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .send()
        .await
        .unwrap();
    let mut body = String::new();
    let received = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while body.matches("backlog ").count() < BACKLOG {
            let chunk = resp.chunk().await.unwrap().expect("stream stays open");
            body.push_str(&String::from_utf8_lossy(&chunk));
        }
    })
    .await;
    assert!(
        received.is_ok(),
        "only {} of {BACKLOG} backlog events arrived within 5 s",
        body.matches("backlog ").count()
    );
}
