use super::*;
use serde_json::json;
use std::path::Path;

#[tokio::test]
async fn a_file_matches_the_receipt_of_its_read_and_nothing_else() {
    let sq = crate::pool::open_sqlite_ledger(Path::new(":memory:"))
        .await
        .unwrap();
    let pool = DatabasePool::Sqlite(sq.clone());
    let (session, key) = pool
        .create_session("receipts", "test", "n/a", None)
        .await
        .unwrap();
    let content = "db_password=example\n";
    let receipt = crate::receipts::receipt(
        "Read",
        &json!({ "file_path": "/p/config.ini" }),
        &json!({ "file": { "content": content } }),
        Some("toolu_1"),
    );
    pool.append_event(receipt, Some(session.id), None, Some(&key))
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let same = dir.path().join("config.ini");
    let changed = dir.path().join("config-now.ini");
    std::fs::write(&same, content).unwrap();
    std::fs::write(&changed, "db_password=rotated\n").unwrap();

    let listed = receipts(&pool, session.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].source.as_deref(), Some("/p/config.ini"));
    let matched = match_files(&listed, &[same, changed]).unwrap();
    assert_eq!(matched[0].sequences, vec![listed[0].sequence]);
    assert!(matched[1].sequences.is_empty(), "{matched:?}");
}

#[test]
fn the_listing_names_each_receipt_and_each_file_verdict() {
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    let receipts = [Receipt {
        sequence: 12,
        tool: "Read".into(),
        source: Some("/p/config.ini".into()),
        text_sha256: vec![a.clone(), b.clone()],
        text_bytes: 42,
    }];
    let matches = [
        FileMatch {
            file: PathBuf::from("config.ini"),
            sha256: a.clone(),
            sequences: vec![12, 15],
        },
        FileMatch {
            file: PathBuf::from("other.ini"),
            sha256: "c".repeat(64),
            sequences: vec![],
        },
    ];
    let session = Uuid::nil();
    let (text, unmatched) = render(session, &receipts, &matches);
    assert_eq!(unmatched, 1);
    assert_eq!(
        text,
        format!(
            "Session {session} verifies. 1 data receipt(s):\n\
                 \x20 #12    Read                         /p/config.ini  2 text(s), 42 bytes  [{}, {}]\n\
                 \x20 ✓ config.ini: exactly what the tool returned at #12, #15\n\
                 \x20 ✗ other.ini ({}…): no tool in this session returned these bytes\n",
            &a[..16],
            &b[..16],
            "c".repeat(16),
        )
    );
    let (_, none) = render(session, &receipts, &matches[..1]);
    assert_eq!(none, 0);
}

/// The command fails when a file matches nothing, and only then.
#[tokio::test]
async fn the_command_fails_for_a_file_no_tool_returned() {
    let sq = crate::pool::open_sqlite_ledger(Path::new(":memory:"))
        .await
        .unwrap();
    let pool = DatabasePool::Sqlite(sq);
    let (session, key) = pool
        .create_session("receipts", "test", "n/a", None)
        .await
        .unwrap();
    let receipt = crate::receipts::receipt("Read", &json!({}), &json!("same"), None);
    pool.append_event(receipt, Some(session.id), None, Some(&key))
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (same, other) = (dir.path().join("same"), dir.path().join("other"));
    std::fs::write(&same, "same").unwrap();
    std::fs::write(&other, "other").unwrap();
    assert!(run(pool.clone(), session.id, &[]).await.is_ok());
    assert!(
        run(pool.clone(), session.id, std::slice::from_ref(&same))
            .await
            .is_ok()
    );
    let err = run(pool, session.id, &[same, other])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("1 file(s) match no receipt"), "{err}");
}

#[tokio::test]
async fn receipts_in_a_session_that_does_not_verify_prove_nothing() {
    let sq = crate::pool::open_sqlite_ledger(Path::new(":memory:"))
        .await
        .unwrap();
    let pool = DatabasePool::Sqlite(sq.clone());
    let (session, key) = pool
        .create_session("receipts", "test", "n/a", None)
        .await
        .unwrap();
    let receipt = crate::receipts::receipt("Read", &json!({}), &json!("text"), None);
    pool.append_event(receipt, Some(session.id), None, Some(&key))
        .await
        .unwrap();
    // Someone with the database file: the append-only trigger goes first.
    sqlx::query("DROP TRIGGER agent_event_signatures_no_delete")
        .execute(&sq)
        .await
        .unwrap();
    sqlx::query("DELETE FROM agent_event_signatures")
        .execute(&sq)
        .await
        .unwrap();
    let err = receipts(&pool, session.id).await.unwrap_err();
    assert!(err.contains("prove nothing"), "{err}");
}
