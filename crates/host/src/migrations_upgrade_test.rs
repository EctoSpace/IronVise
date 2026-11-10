//! A database built by the migrations that shipped in public v0.6.3 must open
//! under this binary.
//!
//! sqlx refuses to start when a previously applied file's SHA-384 no longer
//! matches the text embedded in the binary, including a comment-only edit.
//! `V063_CHECKSUMS.json` is that SHA-384 for every migration in the public
//! tag (commit cf7d29df91738d983fcef0635539b02aac6a847d). The SQLite cases
//! apply those files, record the checksums 0.6.3 would have stored (LF, and
//! the CRLF a Windows checkout of that tag could have stored), insert a
//! session, six events, and one signing key, then run the real migrator.
//! The PostgreSQL case checks the same checksums against the embedded
//! migrator, including the line-ending repair `migrate_postgres` runs before
//! `Migrator::run`. A live Postgres server is not required for that.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha384};
use sqlx::migrate::Migrator;

const V063: &str = include_str!("../migrations/V063_CHECKSUMS.json");

fn manifest() -> BTreeMap<String, String> {
    serde_json::from_str(V063).expect("V063_CHECKSUMS.json parses")
}

fn migrations_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

fn version_of(rel: &str) -> i64 {
    let name = rel.rsplit('/').next().expect("file name");
    name.split('_')
        .next()
        .expect("version prefix")
        .parse()
        .unwrap_or_else(|_| panic!("version prefix of {rel}"))
}

fn read_sql(rel: &str) -> String {
    let text = std::fs::read_to_string(migrations_root().join(rel))
        .unwrap_or_else(|e| panic!("reading {rel}: {e}"));
    assert!(
        !text.contains('\r'),
        "{rel} contains CR; migrations stay LF (.gitattributes: *.sql eol=lf)"
    );
    text
}

fn sha384(bytes: &[u8]) -> Vec<u8> {
    Sha384::digest(bytes).to_vec()
}

fn up(migrator: &Migrator, version: i64) -> &sqlx::migrate::Migration {
    migrator
        .migrations
        .iter()
        .find(|m| m.version == version && !m.migration_type.is_down_migration())
        .unwrap_or_else(|| panic!("no up migration {version}"))
}

#[test]
fn v063_files_still_have_the_checksums_that_release_recorded() {
    let pinned = manifest();
    assert!(
        pinned.len() >= 23,
        "v0.6.3 shipped 13 Postgres migrations and 10 SQLite migrations"
    );

    for (rel, want) in &pinned {
        let got = hex::encode(sha384(read_sql(rel).as_bytes()));
        assert_eq!(
            got, *want,
            "{rel} no longer matches the bytes that shipped in v0.6.3.\n\
             sqlx will refuse every database that already applied it.\n\
             Restore the file. Put the change in a new migration.\n\
             Do not update V063_CHECKSUMS.json to match the edit."
        );
    }
}

#[test]
fn postgres_v063_checksums_match_the_embedded_migrator_and_crlf_repairs() {
    let migrator = sqlx::migrate!("./migrations");
    let pinned = manifest();
    let mut shipped = 0usize;

    for (rel, want) in &pinned {
        if rel.starts_with("sqlite/") {
            continue;
        }
        shipped += 1;
        let version = version_of(rel);
        let migration = up(&migrator, version);
        let embedded = migration.checksum.as_ref();
        assert_eq!(
            hex::encode(embedded),
            *want,
            "{rel}: the binary embeds a different SHA-384 than v0.6.3 recorded"
        );

        let lf = migration.sql.as_str().replace("\r\n", "\n");
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(
            sha384(lf.as_bytes()).as_slice(),
            embedded,
            "{rel}: embedded checksum is not the LF text"
        );
        let fixes = super::repairs(&migrator, &[(version, sha384(crlf.as_bytes()))]);
        assert_eq!(
            fixes,
            vec![(version, embedded.to_vec())],
            "{rel}: a Windows CRLF checksum of the v0.6.3 text must repair to the embedded LF checksum"
        );

        let mut edited = lf;
        edited.push_str("-- edited after it shipped\n");
        assert!(
            super::repairs(&migrator, &[(version, sha384(edited.as_bytes()))]).is_empty(),
            "{rel}: a real text change must stay a VersionMismatch"
        );
    }

    assert_eq!(shipped, 13, "v0.6.3 Postgres migrations");
    assert!(
        migrator
            .migrations
            .iter()
            .any(|m| m.version == 20_260_812_000_014),
        "seal-records migration must stay a new file, not an edit of a v0.6.3 file"
    );
    assert!(
        migrator
            .migrations
            .iter()
            .any(|m| m.version == 20_260_929_000_015),
        "consumed-requests migration must stay a new file"
    );
    assert!(!pinned.contains_key("20260812000014_seal_records_tip.sql"));
    assert!(!pinned.contains_key("20260929000015_consumed_requests.sql"));
}

async fn upgrade_sqlite(crlf_checksums: bool) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("ledger.db");
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=rwc", path.display()))
        .await
        .expect("open sqlite");

    let mut shipped: Vec<(i64, String)> = manifest()
        .into_keys()
        .filter(|rel| rel.starts_with("sqlite/"))
        .map(|rel| (version_of(&rel), rel))
        .collect();
    shipped.sort_by_key(|(version, _)| *version);
    assert_eq!(shipped.len(), 10, "v0.6.3 SQLite migrations");

    // The same table sqlx creates. Rows have to exist before migrate_sqlite so
    // it can repair checksums and skip the migrations 0.6.3 already applied.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _sqlx_migrations (
            version BIGINT PRIMARY KEY,
            description TEXT NOT NULL,
            installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN NOT NULL,
            checksum BLOB NOT NULL,
            execution_time BIGINT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("create _sqlx_migrations");

    for (version, rel) in &shipped {
        let sql = read_sql(rel);
        // Repository migration files, not user input. sqlx 0.9 refuses a
        // non-static string until that is stated.
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql.as_str()))
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("applying {rel}: {e}"));
        let stored = if crlf_checksums {
            sha384(sql.replace('\n', "\r\n").as_bytes())
        } else {
            sha384(sql.as_bytes())
        };
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
             VALUES (?1, ?2, 1, ?3, 0)",
        )
        .bind(version)
        .bind(rel.as_str())
        .bind(stored.as_slice())
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("recording {rel}: {e}"));
    }

    let session = "11111111-1111-1111-1111-111111111111";
    sqlx::query("INSERT INTO agent_sessions (id, goal, session_public_key) VALUES (?1, ?2, ?3)")
        .bind(session)
        .bind("check the sample service")
        .bind("signing-key-1")
        .execute(&pool)
        .await
        .expect("insert session");
    for sequence in 1..=6 {
        sqlx::query(
            "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, session_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(sequence)
        .bind(format!("prev-{sequence}"))
        .bind(format!("hash-{sequence}"))
        .bind("{\"kind\":\"note\"}")
        .bind(session)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("insert event {sequence}: {e}"));
    }
    sqlx::query(
        "INSERT INTO agent_event_signatures (event_id, content_hash, signature, public_key)
         VALUES (1, 'hash-1', 'sig', 'signing-key-1')",
    )
    .execute(&pool)
    .await
    .expect("insert signing key");

    super::migrate_sqlite(&pool)
        .await
        .expect("v0.6.3 SQLite ledger upgrades");

    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_events")
        .fetch_one(&pool)
        .await
        .expect("count events");
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_sessions")
        .fetch_one(&pool)
        .await
        .expect("count sessions");
    let keys: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_event_signatures WHERE public_key = 'signing-key-1'",
    )
    .fetch_one(&pool)
    .await
    .expect("count signing keys");
    let kept: String = sqlx::query_scalar("SELECT session_public_key FROM agent_sessions")
        .fetch_one(&pool)
        .await
        .expect("read signing key");
    let applied: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = 1")
            .fetch_one(&pool)
            .await
            .expect("count migrations");
    let on_disk = std::fs::read_dir(migrations_root().join("sqlite"))
        .expect("sqlite dir")
        .filter(|entry| {
            entry
                .as_ref()
                .ok()
                .and_then(|e| e.path().extension().map(|ext| ext == "sql"))
                .unwrap_or(false)
        })
        .count();

    assert_eq!(events, 6);
    assert_eq!(sessions, 1);
    assert_eq!(keys, 1);
    assert_eq!(kept, "signing-key-1");
    assert_eq!(applied as usize, on_disk);
    assert!(
        on_disk > shipped.len(),
        "newer SQLite migrations must apply"
    );

    pool.close().await;
}

#[tokio::test]
async fn sqlite_v063_ledger_with_lf_checksums_upgrades() {
    upgrade_sqlite(false).await;
}

#[tokio::test]
async fn sqlite_v063_ledger_with_windows_crlf_checksums_upgrades() {
    upgrade_sqlite(true).await;
}
