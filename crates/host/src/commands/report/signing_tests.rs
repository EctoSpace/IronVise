use super::*;
use crate::schema::EventPayload;
use ectoledger_elc::verify::{Requirements, Verdict, verify};

const PASSWORD: &str = "correct horse battery";

/// `audit` saves the key; a certificate made later from the same password
/// verifies against the session's key given out of band.
#[tokio::test]
async fn a_certificate_is_signed_with_the_sessions_saved_key() {
    let pool = crate::pool::open_sqlite_ledger(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let (session, key) =
        crate::ledger::sqlite::create_session_sqlite(&pool, "sign me", "test", "n/a", None, None)
            .await
            .unwrap();
    crate::ledger::sqlite::append_event_sqlite(
        &pool,
        &EventPayload::Thought {
            content: "hello".into(),
        },
        Some(session.id),
        Some("sign me"),
        Some(&key),
    )
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();

    assert!(
        saved_session_key(dir.path(), session.id, || Some(PASSWORD.into()))
            .unwrap()
            .is_none(),
        "no key file: unsigned, not an error"
    );
    crate::signing::save_session_key(dir.path(), session.id, &key, PASSWORD).unwrap();
    assert!(
        saved_session_key(dir.path(), session.id, || None)
            .unwrap()
            .is_none(),
        "a blank password writes it unsigned"
    );
    assert!(
        saved_session_key(dir.path(), session.id, || Some("wrong password!".into())).is_err(),
        "a wrong password is an error, never a quiet unsigned certificate"
    );

    let loaded = saved_session_key(dir.path(), session.id, || Some(PASSWORD.into()))
        .unwrap()
        .expect("key");
    let cert =
        crate::certificate::build_certificate_sqlite(&pool, session.id, Some(&loaded), false, None)
            .await
            .unwrap();
    let expected = crate::signing::public_key_hex(&key.verifying_key());
    let report = verify(
        &cert,
        &Requirements {
            expected_key: Some(expected),
            ..Default::default()
        },
    );
    assert!(
        matches!(report.verdict, Verdict::Valid { expected: true, .. }),
        "{:?}",
        report.verdict
    );
}

/// A key file saved the way official v0.6.3 did (session id authenticated,
/// no commitment) still signs its own session's certificate. Holding another
/// session's key it is refused, because the certificate names the session's key.
#[tokio::test]
async fn a_legacy_key_file_signs_only_its_own_sessions_certificate() {
    let pool = crate::pool::open_sqlite_ledger(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let (session, key) =
        crate::ledger::sqlite::create_session_sqlite(&pool, "legacy", "test", "n/a", None, None)
            .await
            .unwrap();
    crate::ledger::sqlite::append_event_sqlite(
        &pool,
        &EventPayload::Thought {
            content: "hello".into(),
        },
        Some(session.id),
        Some("legacy"),
        Some(&key),
    )
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let build = |k: ed25519_dalek::SigningKey| {
        let pool = pool.clone();
        async move {
            crate::certificate::build_certificate_sqlite(&pool, session.id, Some(&k), false, None)
                .await
        }
    };

    crate::signing::save_legacy_key_file(dir.path(), session.id, &key, PASSWORD);
    let loaded = saved_session_key(dir.path(), session.id, || Some(PASSWORD.into()))
        .unwrap()
        .expect("legacy key");
    assert!(build(loaded).await.unwrap().signature.is_some());

    let (other, _) = crate::signing::generate_keypair();
    crate::signing::save_legacy_key_file(dir.path(), session.id, &other, PASSWORD);
    let swapped = saved_session_key(dir.path(), session.id, || Some(PASSWORD.into()))
        .unwrap()
        .expect("it decrypts: nothing in a legacy file binds it");
    assert!(matches!(
        build(swapped).await,
        Err(crate::certificate::CertificateError::KeyMismatch)
    ));
}

/// The committed file is the official v0.6.3 encryption (fixed salt and nonce).
/// Exporting a certificate decrypts it, signs with that key, and keeps the
/// original bytes in `session-<id>.key.v063.bak`.
#[tokio::test]
async fn a_committed_v063_key_file_signs_its_certificate() {
    use crate::signing::{V063_KEY_FILE, V063_PASSWORD, V063_SECRET, V063_SESSION};

    let session = uuid::Uuid::parse_str(V063_SESSION).unwrap();
    let secret: [u8; 32] = hex::decode(V063_SECRET).unwrap().try_into().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("session-{session}.key"));
    std::fs::write(&path, V063_KEY_FILE).unwrap();
    let original = std::fs::read(&path).unwrap();

    let loaded = saved_session_key(dir.path(), session, || Some(V063_PASSWORD.into()))
        .unwrap()
        .expect("v0.6.3 key");
    assert_eq!(loaded.to_bytes(), secret);

    let backup = std::fs::read(dir.path().join(format!("session-{session}.key.v063.bak"))).unwrap();
    assert_eq!(backup, original, "the v0.6.3 file is kept byte for byte");
    let rewritten: crate::signing::EncryptedKeyFile =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(
        !rewritten.commitment_hex.is_empty(),
        "the key file is rewritten in the 0.8 format after it opens"
    );
    assert_eq!(
        crate::signing::decrypt_signing_key(&rewritten, session, V063_PASSWORD)
            .unwrap()
            .to_bytes(),
        secret
    );

    let pool = crate::pool::open_sqlite_ledger(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let goal = "check the sample";
    let public = crate::signing::public_key_hex(&loaded.verifying_key());
    sqlx::query(
        "INSERT INTO agent_sessions
         (id, goal, goal_hash, status, llm_backend, llm_model, created_at, session_public_key)
         VALUES (?1, ?2, ?3, 'running', 'test', 'n/a', datetime('now'), ?4)",
    )
    .bind(session.to_string())
    .bind(goal)
    .bind(crate::hash::goal_hash(goal))
    .bind(&public)
    .execute(&pool)
    .await
    .unwrap();
    crate::ledger::sqlite::append_event_sqlite(
        &pool,
        &EventPayload::Thought {
            content: "hello from 0.6.3".into(),
        },
        Some(session),
        Some(goal),
        Some(&loaded),
    )
    .await
    .unwrap();
    let cert =
        crate::certificate::build_certificate_sqlite(&pool, session, Some(&loaded), false, None)
            .await
            .unwrap();
    let report = verify(
        &cert,
        &Requirements {
            expected_key: Some(public),
            ..Default::default()
        },
    );
    assert!(
        matches!(report.verdict, Verdict::Valid { expected: true, .. }),
        "{:?}",
        report.verdict
    );
}
