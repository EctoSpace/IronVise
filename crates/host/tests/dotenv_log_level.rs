//! `RUST_LOG` in `.env` sets the log level. `.env.example` ships
//! `RUST_LOG=info`, so the log filter must be built after `.env` is read, or
//! a user following the quickstart sees only errors.

#[test]
fn rust_log_from_dot_env_applies() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    std::fs::File::create(&db).unwrap();
    std::fs::write(
        dir.path().join(".env"),
        format!("RUST_LOG=info\nDATABASE_URL=sqlite:{}\n", db.display()),
    )
    .unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ironvise"))
        .arg("verify-ledger")
        .current_dir(dir.path())
        .env_remove("RUST_LOG")
        .env_remove("DATABASE_URL")
        .env("ECTO_DATA_DIR", dir.path().join("data"))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run ectoledger verify-ledger");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        all.contains("INFO"),
        "RUST_LOG=info from .env had no effect:\n{all}"
    );
}
