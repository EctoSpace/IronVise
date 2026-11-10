//! `verify-ledger` against PostgreSQL: a database that is not there is
//! "could not survey" (exit 2), and the survey creates nothing.
//!
//!   DATABASE_URL=postgres://… cargo test --features integration

#![cfg(feature = "integration")]

use std::process::Command;

fn base_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL for the integration database")
}

/// The integration server's URL, naming another database.
fn with_database(url: &str, name: &str) -> String {
    let (server, _) = url.rsplit_once('/').expect("a URL ending in /<database>");
    format!("{server}/{name}")
}

#[tokio::test]
async fn a_missing_database_is_exit_two_and_is_not_created() {
    let name = format!("ectoledger_missing_{}", std::process::id());
    let out = Command::new(env!("CARGO_BIN_EXE_ironvise"))
        .args(["verify-ledger", "--strict"])
        .env("DATABASE_URL", with_database(&base_url(), &name))
        .env("OBSERVER_TOKEN", "verify-ledger-postgres")
        .output()
        .expect("run verify-ledger");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stderr.contains("does not exist"), "stderr:\n{stderr}");

    let pool = sqlx::PgPool::connect(&base_url()).await.unwrap();
    let created: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_database WHERE datname = $1")
        .bind(&name)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        created, 0,
        "a survey must not create the database it was pointed at"
    );
}
