//! The break-the-ledger challenge must stay solvable.
//!
//! `examples/challenge/` invites people to find the one genuine ledger among
//! five and name what was done to the other four. That invitation is only
//! honest if the fixtures still behave as advertised: exactly one ledger
//! verifies, each tampered one fails for its own distinct reason, and the
//! shipped certificate is still rejected.
//!
//! This test deliberately does **not** name which file is which. It runs the
//! verifier over all five, builds the canonical answer string from what it
//! *observes*, hashes that, and compares it against the sealed hash committed
//! in `ANSWER.sha256`. So it proves the challenge is intact without the test
//! source being a spoiler - and it fails if a fixture rots, if a verification
//! path regresses, or if someone regenerates the ledgers without re-sealing
//! the answer.

use std::path::{Path, PathBuf};

use ectoledger::ledger::SessionVerdict;
use sqlx::sqlite::SqlitePoolOptions;

fn challenge_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/challenge")
}

/// The verdict kinds, as stable strings. Deliberately not the `Display` text -
/// that is prose meant for humans and should be free to improve without
/// invalidating a committed hash.
fn kind(v: &SessionVerdict) -> &'static str {
    v.kind()
}

async fn verdict_for(db: &Path) -> SessionVerdict {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=ro", db.display()))
        .await
        .unwrap_or_else(|e| panic!("opening {}: {e}", db.display()));

    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM agent_sessions")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(
        ids.len(),
        1,
        "{} should contain exactly one session",
        db.display()
    );
    let session = uuid::Uuid::parse_str(&ids[0]).unwrap();
    ectoledger::ledger::sqlite::verify_session_detailed_sqlite(&pool, session)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_challenge_still_has_exactly_one_clean_ledger() {
    let dir = challenge_dir();
    let mut ledgers: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sqlite"))
        .collect();
    ledgers.sort();
    assert_eq!(ledgers.len(), 5, "the challenge ships five ledgers");

    let mut observed = Vec::new();
    for path in &ledgers {
        let v = verdict_for(path).await;
        observed.push((
            path.file_name().unwrap().to_string_lossy().to_string(),
            kind(&v).to_string(),
        ));
    }

    let clean: Vec<&String> = observed
        .iter()
        .filter(|(_, k)| k == "verified")
        .map(|(n, _)| n)
        .collect();
    // Two ledgers verify as ledgers: the genuine one, and the one whose *file*
    // is untouched but whose certificate is forged. Finding that distinction is
    // part of the challenge, so it is asserted rather than explained away.
    assert_eq!(
        clean.len(),
        2,
        "expected two ledgers to verify (the genuine one and the forged-certificate one), \
         got {clean:?} from {observed:?}"
    );

    let distinct: std::collections::HashSet<&String> = observed.iter().map(|(_, k)| k).collect();
    assert!(
        distinct.len() >= 4,
        "the tampers should fail in distinct ways, so the challenge can be solved \
         by reading verdicts rather than guessing; saw {distinct:?}"
    );
}

/// Surveying a ledger must not change it.
///
/// `verify-ledger` documents itself as read-only, and the challenge README
/// tells people to point it at these committed fixtures. It used to open them
/// through the ordinary startup path, which runs `PRAGMA journal_mode=WAL`,
/// applies pending migrations and seeds an `api_tokens` row - so following the
/// documented instructions modified all five tracked files. Evidence you are
/// asked to inspect is exactly what must not be written to.
#[tokio::test]
async fn opening_a_ledger_read_only_does_not_modify_it() {
    use sha2::{Digest, Sha256};

    let dir = challenge_dir();
    let mut ledgers: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sqlite"))
        .collect();
    ledgers.sort();
    assert_eq!(ledgers.len(), 5);

    for path in &ledgers {
        let before = Sha256::digest(std::fs::read(path).unwrap());

        let backend = ectoledger::pool::open_sqlite_pool_read_only(path)
            .await
            .unwrap_or_else(|e| panic!("opening {} read-only: {e}", path.display()));
        let ectoledger::pool::DatabasePool::Sqlite(pool) = &backend else {
            panic!("expected a SQLite pool");
        };

        // Reads work.
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_events")
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(n > 0, "{} should have events", path.display());

        // Writes are refused by the driver, not merely avoided by convention.
        let write = sqlx::query("INSERT INTO api_tokens (token_hash, role) VALUES ('x','admin')")
            .execute(pool)
            .await;
        assert!(
            write.is_err(),
            "a read-only pool must refuse writes to {}",
            path.display()
        );

        drop(backend);
        let after = Sha256::digest(std::fs::read(path).unwrap());
        assert_eq!(
            before,
            after,
            "{} changed on disk after being surveyed",
            path.display()
        );
    }
}

#[tokio::test]
async fn the_sealed_answer_matches_what_the_verifier_actually_finds() {
    let dir = challenge_dir();
    let sealed = std::fs::read_to_string(dir.join("ANSWER.sha256"))
        .expect("ANSWER.sha256 missing - regenerate with examples/challenge/generate.py")
        .trim()
        .to_string();

    let mut ledgers: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sqlite"))
        .collect();
    ledgers.sort();

    let mut lines = Vec::new();
    for path in &ledgers {
        let v = verdict_for(path).await;
        lines.push(format!(
            "{}:{}",
            path.file_name().unwrap().to_string_lossy(),
            kind(&v)
        ));
    }
    lines.push("ledger-5-certificate.elc:merkle-root-mismatch".to_string());

    let canonical = lines.join("\n");
    let digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        hex::encode(h.finalize())
    };

    assert_eq!(
        digest, sealed,
        "\nThe challenge's sealed answer no longer matches what the verifier finds.\n\
         Observed:\n{canonical}\n\n\
         Either a fixture changed, a verification path regressed, or the ledgers were \
         regenerated without updating ANSWER.sha256. Do not simply paste the new hash in \
         - work out which of those three it is first.\n"
    );
}

/// The forged certificate must keep failing, or the fifth puzzle piece is a
/// ledger that is simply clean and the challenge has two answers.
#[test]
fn the_forged_certificate_is_still_rejected() {
    use ectoledger::certificate::EctoLedgerCertificate;
    use ectoledger::merkle;

    let raw = std::fs::read_to_string(challenge_dir().join("ledger-5-certificate.elc")).unwrap();
    let cert: EctoLedgerCertificate = serde_json::from_str(&raw).unwrap();
    let hashes: Vec<&str> = cert
        .events
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();
    let root = merkle::build_merkle_tree(&hashes)
        .ok()
        .and_then(|t| merkle::root(&t).ok());
    assert_ne!(
        root.as_deref(),
        Some(cert.merkle_root.as_str()),
        "the forged certificate now passes its Merkle check"
    );
}
