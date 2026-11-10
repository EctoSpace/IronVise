//! A guard that cannot run stops `ironvise audit` before anything is
//! recorded: with no guard model named, or no `guard-worker` binary built,
//! the audit must fail before it creates a session, not leave one `running`
//! with only its genesis event.

use std::path::Path;

/// Runs `audit` with a required guard and an unreachable model; `guard` sets
/// the guard's own environment. Returns stderr after checking the run failed.
async fn refused_audit(dir: &Path, guard: &[(&str, &str)]) -> String {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_ironvise"));
    cmd.args(["audit", "List the project files"])
        .current_dir(dir)
        .env(
            "DATABASE_URL",
            format!("sqlite:{}", dir.join("ledger.db").display()),
        )
        .env("ECTO_DATA_DIR", dir.join("data"))
        .env("LLM_BACKEND", "ollama")
        // Nothing listens here: the run must not get as far as the model.
        .env("OLLAMA_BASE_URL", "http://127.0.0.1:9")
        .env("OLLAMA_MODEL", "mock")
        .env("GUARD_REQUIRED", "true")
        .env_remove("GUARD_LLM_BACKEND")
        .env_remove("GUARD_LLM_MODEL")
        .env_remove("ECTO_GUARD_WORKER")
        .env("ECTO_KEY_PASSWORD", "")
        .env("ECTO_BIND_PORT", "0")
        .stdin(std::process::Stdio::null());
    for (key, value) in guard {
        cmd.env(key, value);
    }
    let out = cmd.output().await.expect("run ectoledger audit");
    assert!(!out.status.success(), "the audit should refuse to start");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

async fn assert_no_session(dir: &Path) {
    let db = dir.join("ledger.db");
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=ro", db.display()))
        .await
        .unwrap();
    let sessions: Result<i64, _> = sqlx::query_scalar("SELECT COUNT(*) FROM agent_sessions")
        .fetch_one(&pool)
        .await;
    // No table at all is fine too: nothing was written.
    if let Ok(count) = sessions {
        assert_eq!(count, 0, "no session may be left behind");
    }
}

#[tokio::test]
async fn a_missing_guard_model_fails_before_a_session_is_created() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::File::create(dir.path().join("ledger.db")).unwrap();
    let stderr = refused_audit(dir.path(), &[]).await;
    assert!(
        stderr.contains("GUARD_LLM_BACKEND and GUARD_LLM_MODEL are unset"),
        "the error should name the missing settings: {stderr}"
    );
    assert_no_session(dir.path()).await;
}

#[tokio::test]
async fn a_missing_guard_worker_fails_before_a_session_is_created() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::File::create(dir.path().join("ledger.db")).unwrap();
    let missing = dir.path().join("no-such-guard-worker");
    let stderr = refused_audit(
        dir.path(),
        &[
            ("GUARD_LLM_BACKEND", "ollama"),
            ("GUARD_LLM_MODEL", "mock"),
            ("ECTO_GUARD_WORKER", missing.to_str().unwrap()),
        ],
    )
    .await;
    assert!(
        stderr.contains("Guard process failed to start"),
        "the error should say the guard did not start: {stderr}"
    );
    assert_no_session(dir.path()).await;
}
