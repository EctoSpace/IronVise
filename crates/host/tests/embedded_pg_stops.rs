//! A command that started the embedded PostgreSQL stops it on the way out,
//! also when it exits with a non-zero code. `std::process::exit` skips
//! destructors, so an exit after "no ledger in this database" (exit 2) or a
//! `--strict` finding (exit 1) must stop the server first.
//!
//! Downloads PostgreSQL on first use and needs port 5432 free, so it is
//! ignored by default: `cargo test -p ectoledger --test embedded_pg_stops -- --ignored`.

#[test]
#[ignore = "downloads PostgreSQL and needs port 5432"]
fn verify_ledger_stops_the_embedded_postgres_it_started() {
    let home = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ironvise"))
        .arg("verify-ledger")
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("ECTO_DEV_MODE", "true")
        .env_remove("DATABASE_URL")
        .env_remove("ECTO_DATA_DIR")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run ectoledger verify-ledger");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // An empty embedded database has no ledger: the survey cannot run.
    assert_eq!(out.status.code(), Some(2), "{stderr}");

    // The stop is asked for on the way out; under the binary's sandbox
    // pg_ctl cannot wait for it ("server does not shut down"), so the server
    // finishes stopping a moment after the command has exited.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let running = || {
        walk(home.path())
            .into_iter()
            .filter(|p| p.file_name().is_some_and(|n| n == "postmaster.pid"))
            .collect::<Vec<_>>()
    };
    while !running().is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let left = running();
    assert!(left.is_empty(), "PostgreSQL is still running: {left:?}");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walk(&path));
            } else {
                found.push(path);
            }
        }
    }
    found
}
