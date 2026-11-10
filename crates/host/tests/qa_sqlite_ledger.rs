use ectoledger::pool::{DatabasePool, create_sqlite_pool};
use ectoledger::schema::EventPayload;
use std::path::Path;
use uuid::Uuid;

async fn memory_pool() -> DatabasePool {
    create_sqlite_pool(Path::new(":memory:"))
        .await
        .expect("create in-memory sqlite pool")
}

async fn file_pool(label: &str) -> (tempfile::TempDir, DatabasePool) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join(format!("{label}.db"));
    let pool = create_sqlite_pool(&db_path)
        .await
        .expect("create file-backed sqlite pool");
    (dir, pool)
}

fn thought(content: &str) -> EventPayload {
    EventPayload::Thought {
        content: content.to_string(),
    }
}

mod empty_ledger {
    use super::*;

    #[tokio::test]
    async fn get_latest_on_an_empty_ledger_is_none() {
        let pool = memory_pool().await;
        let latest = ectoledger::ledger::sqlite::get_latest_sqlite(pool.as_sqlite().unwrap())
            .await
            .unwrap();
        assert!(latest.is_none());
    }
}

mod genesis {
    use super::*;

    #[tokio::test]
    async fn ensure_genesis_called_twice_returns_the_same_event() {
        let pool = memory_pool().await;
        let first = pool.ensure_genesis().await.expect("first genesis");
        let second = pool.ensure_genesis().await.expect("second genesis");
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 0);
        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(first.id, second.id);
    }
}

mod finish_twice {
    use super::*;

    async fn status_of(pool: &DatabasePool, id: Uuid) -> String {
        pool.list_sessions()
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.id == id)
            .unwrap()
            .status
    }

    #[tokio::test]
    async fn finishing_a_session_twice_with_the_same_status_is_not_an_error() {
        let pool = memory_pool().await;
        let (session, _) = pool
            .create_session("qa finish twice", "mock", "mock-v1", None)
            .await
            .unwrap();
        pool.finish_session(session.id, "completed").await.unwrap();
        pool.finish_session(session.id, "completed").await.unwrap();
        assert_eq!(status_of(&pool, session.id).await, "completed");
    }

    #[tokio::test]
    async fn finishing_a_session_twice_with_different_statuses_keeps_the_last_write() {
        let pool = memory_pool().await;
        let (session, _) = pool
            .create_session("qa finish twice differing", "mock", "mock-v1", None)
            .await
            .unwrap();
        pool.finish_session(session.id, "completed").await.unwrap();
        pool.finish_session(session.id, "failed").await.unwrap();
        assert_eq!(status_of(&pool, session.id).await, "failed");
    }
}

mod payload_edge_cases {
    use super::*;

    #[tokio::test]
    async fn a_nul_byte_in_the_payload_round_trips_and_the_chain_still_verifies() {
        let pool = memory_pool().await;
        let (session, key) = pool
            .create_session("qa nul payload", "mock", "mock-v1", None)
            .await
            .unwrap();
        pool.append_event(
            thought("before\u{0}after"),
            Some(session.id),
            Some("qa nul payload"),
            Some(&key),
        )
        .await
        .expect("append with embedded NUL");

        let events = pool.get_events_by_session(session.id).await.unwrap();
        assert_eq!(events[0].payload, thought("before\u{0}after"));
        assert!(pool.verify_chain_for_session(session.id).await.unwrap());
    }

    #[tokio::test]
    async fn unicode_payload_round_trips_and_the_chain_still_verifies() {
        let pool = memory_pool().await;
        let (session, key) = pool
            .create_session("qa unicode payload", "mock", "mock-v1", None)
            .await
            .unwrap();
        let content = "héllo \u{1F600} \u{0410}\u{0411}\u{0412} \u{200B}zero-width";
        pool.append_event(
            thought(content),
            Some(session.id),
            Some("qa unicode payload"),
            Some(&key),
        )
        .await
        .expect("append unicode");

        let events = pool.get_events_by_session(session.id).await.unwrap();
        assert_eq!(events[0].payload, thought(content));
        assert!(pool.verify_chain_for_session(session.id).await.unwrap());
    }

    #[tokio::test]
    async fn a_one_megabyte_payload_round_trips_and_the_chain_still_verifies() {
        let pool = memory_pool().await;
        let (session, key) = pool
            .create_session("qa huge payload", "mock", "mock-v1", None)
            .await
            .unwrap();
        let content = "x".repeat(1024 * 1024);
        pool.append_event(
            thought(&content),
            Some(session.id),
            Some("qa huge payload"),
            Some(&key),
        )
        .await
        .expect("append 1MB payload");

        let events = pool.get_events_by_session(session.id).await.unwrap();
        assert_eq!(events[0].payload, thought(&content));
        assert!(pool.verify_chain_for_session(session.id).await.unwrap());
    }
}

mod interleaved_sessions {
    use super::*;

    #[tokio::test]
    async fn two_sessions_interleaved_in_the_global_chain_each_verify_independently() {
        let pool = memory_pool().await;
        let (session_a, key_a) = pool
            .create_session("qa interleave a", "mock", "mock-v1", None)
            .await
            .unwrap();
        let (session_b, key_b) = pool
            .create_session("qa interleave b", "mock", "mock-v1", None)
            .await
            .unwrap();

        for i in 0..5 {
            pool.append_event(
                thought(&format!("a-{i}")),
                Some(session_a.id),
                Some("qa interleave a"),
                Some(&key_a),
            )
            .await
            .unwrap();
            pool.append_event(
                thought(&format!("b-{i}")),
                Some(session_b.id),
                Some("qa interleave b"),
                Some(&key_b),
            )
            .await
            .unwrap();
        }

        let events_a = pool.get_events_by_session(session_a.id).await.unwrap();
        let events_b = pool.get_events_by_session(session_b.id).await.unwrap();
        assert_eq!(events_a.len(), 5);
        assert_eq!(events_b.len(), 5);
        assert!(pool.verify_chain_for_session(session_a.id).await.unwrap());
        assert!(pool.verify_chain_for_session(session_b.id).await.unwrap());

        let mut global_sequences: Vec<i64> = events_a
            .iter()
            .chain(events_b.iter())
            .map(|e| e.sequence)
            .collect();
        global_sequences.sort_unstable();
        global_sequences.dedup();
        assert_eq!(
            global_sequences.len(),
            10,
            "sequences must be globally unique"
        );
    }
}

mod concurrent_appends {
    use super::*;

    #[tokio::test]
    async fn concurrent_appends_from_many_tasks_keep_the_global_chain_linear() {
        let (_dir, pool) = file_pool("concurrent-append").await;
        let pool = std::sync::Arc::new(pool);
        let (session, key) = pool
            .create_session("qa concurrent append", "mock", "mock-v1", None)
            .await
            .unwrap();
        let key = std::sync::Arc::new(key);

        let mut handles = Vec::new();
        for i in 0..20 {
            let pool = pool.clone();
            let key = key.clone();
            let session_id = session.id;
            handles.push(tokio::spawn(async move {
                pool.append_event(
                    thought(&format!("task-{i}")),
                    Some(session_id),
                    Some("qa concurrent append"),
                    Some(&key),
                )
                .await
            }));
        }
        let mut appended = Vec::new();
        for h in handles {
            appended.push(h.await.unwrap().expect("concurrent append must not fail"));
        }

        let mut sequences: Vec<i64> = appended.iter().map(|e| e.sequence).collect();
        sequences.sort_unstable();
        let deduped = {
            let mut s = sequences.clone();
            s.dedup();
            s
        };
        assert_eq!(
            sequences.len(),
            deduped.len(),
            "no two concurrent appends may receive the same sequence number"
        );
        assert!(pool.verify_chain_for_session(session.id).await.unwrap());
    }
}

mod large_chain {
    use super::*;

    #[tokio::test]
    async fn verify_chain_holds_over_a_few_thousand_events() {
        let pool = memory_pool().await;
        let (session, key) = pool
            .create_session("qa large chain", "mock", "mock-v1", None)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        for i in 0..3000 {
            pool.append_event(
                thought(&format!("event-{i}")),
                Some(session.id),
                Some("qa large chain"),
                Some(&key),
            )
            .await
            .unwrap();
        }
        assert!(pool.verify_chain_for_session(session.id).await.unwrap());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "3000 sequential appends plus verification took too long: {:?}",
            started.elapsed()
        );
    }
}

mod zombie_reaping {
    use super::*;

    #[tokio::test]
    async fn a_session_older_than_the_cutoff_is_reaped_to_failed() {
        let pool = memory_pool().await;
        let (session, _) = pool
            .create_session("qa zombie", "mock", "mock-v1", None)
            .await
            .unwrap();
        // The cutoff compares julianday() values, which resolve milliseconds.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let reaped = pool.reap_zombie_sessions(0).await.unwrap();
        assert!(reaped >= 1);
        let status = pool
            .list_sessions()
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.id == session.id)
            .unwrap()
            .status;
        assert_eq!(status, "failed");
    }

    #[tokio::test]
    async fn a_freshly_created_session_is_not_reaped_by_a_generous_cutoff() {
        let pool = memory_pool().await;
        let (session, _) = pool
            .create_session("qa not zombie", "mock", "mock-v1", None)
            .await
            .unwrap();
        pool.reap_zombie_sessions(600).await.unwrap();
        let status = pool
            .list_sessions()
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.id == session.id)
            .unwrap()
            .status;
        assert_eq!(status, "running");
    }
}

mod consumed_requests {
    use super::*;

    #[tokio::test]
    async fn the_same_request_id_cannot_be_consumed_twice() {
        let pool = memory_pool().await;
        let first = pool
            .consume_request("scope-a", "req-1", "caller-a")
            .await
            .unwrap();
        let second = pool
            .consume_request("scope-a", "req-1", "caller-a")
            .await
            .unwrap();
        assert!(first);
        assert!(!second);
    }

    #[tokio::test]
    async fn the_same_request_id_in_a_different_scope_is_independent() {
        let pool = memory_pool().await;
        let a = pool
            .consume_request("scope-a", "req-shared", "caller")
            .await
            .unwrap();
        let b = pool
            .consume_request("scope-b", "req-shared", "caller")
            .await
            .unwrap();
        assert!(a);
        assert!(b);
    }
}

mod tokens {
    use super::*;

    #[tokio::test]
    async fn an_inserted_token_is_found_listed_and_deletable() {
        let pool = memory_pool().await;
        pool.insert_token("hash-1", "admin", Some("ci"), None)
            .await
            .unwrap();
        assert_eq!(
            pool.find_token_role("hash-1").await.unwrap(),
            Some("admin".to_string())
        );
        assert_eq!(pool.list_tokens().await.unwrap().len(), 1);
        assert!(pool.delete_token("hash-1").await.unwrap());
        assert!(pool.find_token_role("hash-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_expired_token_does_not_resolve_a_role() {
        let pool = memory_pool().await;
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        pool.insert_token("hash-expired", "viewer", None, Some(past))
            .await
            .unwrap();
        assert!(
            pool.find_token_role("hash-expired")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn replacing_a_labelled_token_removes_the_old_one() {
        let pool = memory_pool().await;
        pool.insert_token("hash-old", "admin", Some("ci"), None)
            .await
            .unwrap();
        pool.replace_labelled_token("ci", "hash-new", "admin")
            .await
            .unwrap();
        assert!(pool.find_token_role("hash-old").await.unwrap().is_none());
        assert_eq!(
            pool.find_token_role("hash-new").await.unwrap(),
            Some("admin".to_string())
        );
    }

    #[tokio::test]
    async fn deleting_an_unknown_token_returns_false() {
        let pool = memory_pool().await;
        assert!(!pool.delete_token("never-existed").await.unwrap());
    }
}

mod webhooks {
    use super::*;

    #[tokio::test]
    async fn an_inserted_webhook_is_listed_toggled_and_deletable() {
        let pool = memory_pool().await;
        let id = pool
            .insert_webhook(
                "qa hook",
                "https://example.com/hook",
                None,
                "json",
                &["action".to_string()],
                true,
            )
            .await
            .unwrap();
        let listed = pool.list_webhooks().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert!(listed[0].enabled);

        assert!(pool.toggle_webhook(&id, false).await.unwrap());
        let listed = pool.list_webhooks().await.unwrap();
        assert!(!listed[0].enabled);

        assert!(pool.delete_webhook(&id).await.unwrap());
        assert!(pool.list_webhooks().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn toggling_an_unknown_webhook_returns_false() {
        let pool = memory_pool().await;
        assert!(!pool.toggle_webhook("not-a-real-id", true).await.unwrap());
    }
}
