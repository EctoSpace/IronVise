//! `import-openshell` against a fixture of OpenShell OCSF records
//! (tests/fixtures/openshell/README.md says which lines are verbatim docs).

use std::path::{Path, PathBuf};

use ectoledger::commands::openshell::import;
use ectoledger::pool::{DatabasePool, create_sqlite_pool};
use sha2::{Digest, Sha256};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/openshell/ocsf-sample.jsonl")
}

async fn pool() -> DatabasePool {
    create_sqlite_pool(Path::new(":memory:")).await.unwrap()
}

#[tokio::test]
async fn every_record_is_imported_as_what_openshell_decided() {
    let pool = pool().await;
    let out = tempfile::tempdir().unwrap();
    let r = import(&pool, &[fixture()], out.path()).await.unwrap();

    assert_eq!(r.imported, 6);
    assert_eq!(r.duplicates, 0);
    let file = fixture().display().to_string();
    assert_eq!(r.malformed, [format!("{file}:7"), format!("{file}:8")]);
    let counts: Vec<_> = r.by_decision.iter().map(|(d, n)| (*d, *n)).collect();
    assert_eq!(
        counts,
        [("allowed", 2), ("audit", 1), ("denied", 2), ("other", 1)]
    );
    assert_eq!(
        r.sessions.keys().collect::<Vec<_>>(),
        ["sbx-1", "unknown-sandbox"],
        "one session per sandbox"
    );
}

/// Each sandbox's session is sealed and verifies, and its receipt is a signed
/// certificate the standalone verifier accepts.
#[tokio::test]
async fn each_sandbox_gets_a_sealed_session_and_a_signed_receipt() {
    let pool = pool().await;
    let out = tempfile::tempdir().unwrap();
    let r = import(&pool, &[fixture()], out.path()).await.unwrap();
    for id in r.sessions.values() {
        let verdict = pool.verify_session_detailed(*id).await.unwrap();
        assert!(verdict.is_verified(), "{id}: {verdict}");
    }
    assert_eq!(r.receipts.len(), 2);
    for path in &r.receipts {
        let bytes = std::fs::read(path).unwrap();
        let cert = ectoledger_elc::parse_certificate(&bytes).unwrap();
        let report = ectoledger_elc::verify::verify(
            &cert,
            &ectoledger_elc::verify::Requirements {
                signature: true,
                ..Default::default()
            },
        );
        assert!(
            report.is_valid(),
            "{}: {}",
            path.display(),
            report.verdict_line()
        );
    }
}

/// Audit mode logs a violating request as Allowed. The import must not.
#[tokio::test]
async fn an_audit_mode_allow_is_recorded_as_audit_not_allowed() {
    let pool = pool().await;
    let out = tempfile::tempdir().unwrap();
    let r = import(&pool, &[fixture()], out.path()).await.unwrap();
    let events = pool
        .get_events_by_session(r.sessions["sbx-1"])
        .await
        .unwrap();
    let audit = events
        .iter()
        .map(|e| serde_json::to_value(&e.payload).unwrap())
        .find(|p| p["params"]["target"] == "https://api.example.com/v1/repos/delete")
        .expect("audit record imported");
    assert_eq!(audit["params"]["decision"], "audit", "{audit}");
}

/// The recorded hash is of the line as OpenShell wrote it, so the source log
/// can be checked against the ledger byte for byte.
#[tokio::test]
async fn each_event_carries_the_hash_of_its_original_line() {
    let pool = pool().await;
    let out = tempfile::tempdir().unwrap();
    let r = import(&pool, &[fixture()], out.path()).await.unwrap();
    let text = std::fs::read_to_string(fixture()).unwrap();
    let line3 = text.lines().nth(2).unwrap();
    let want = hex::encode(Sha256::digest(line3.as_bytes()));
    let events = pool
        .get_events_by_session(r.sessions["sbx-1"])
        .await
        .unwrap();
    let found = events
        .iter()
        .map(|e| serde_json::to_value(&e.payload).unwrap())
        .any(|p| p["params"]["line"] == 3 && p["params"]["line_sha256"] == want);
    assert!(found, "no event for line 3 with sha256 {want}");
}

#[tokio::test]
async fn importing_the_same_log_again_adds_nothing() {
    let pool = pool().await;
    let out = tempfile::tempdir().unwrap();
    import(&pool, &[fixture()], out.path()).await.unwrap();
    let again = import(&pool, &[fixture()], out.path()).await.unwrap();
    assert_eq!(again.imported, 0);
    assert_eq!(again.duplicates, 6);
    assert!(again.sessions.is_empty() && again.receipts.is_empty());
}

/// A denial is a signed refusal with OpenShell's engine as its stage.
#[tokio::test]
async fn a_denial_names_openshells_rule_engine_and_reason() {
    let pool = pool().await;
    let out = tempfile::tempdir().unwrap();
    let r = import(&pool, &[fixture()], out.path()).await.unwrap();
    let events = pool
        .get_events_by_session(r.sessions["sbx-1"])
        .await
        .unwrap();
    let denial = events
        .iter()
        .map(|e| serde_json::to_value(&e.payload).unwrap())
        .find(|p| p["type"] == "tripwire_rejection")
        .expect("denial imported");
    assert_eq!(denial["stage"], "openshell:opa");
    assert!(
        denial["reason"]
            .as_str()
            .unwrap()
            .contains("pastebin.com:443"),
        "{denial}"
    );
    assert!(
        denial["reason"]
            .as_str()
            .unwrap()
            .contains("no matching policy"),
        "{denial}"
    );
}
