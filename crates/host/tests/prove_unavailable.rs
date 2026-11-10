//! The withdrawn prover must refuse before touching a ledger or signing key.

use std::process::Command;

#[test]
fn unavailable_prover_refuses_without_creating_a_database_or_certificate() {
    let work = tempfile::tempdir().unwrap();
    let db = work.path().join("must-not-create.db");
    let output = work.path().join("proof.elc");
    let result = Command::new(env!("CARGO_BIN_EXE_ironvise"))
        .args(["prove-audit", "00000000-0000-0000-0000-000000000001"])
        .arg("--output")
        .arg(&output)
        .args([
            "--policy",
            "missing-policy.toml",
            "--no-ots",
            "--key-password-fd",
            "99",
        ])
        .env("DATABASE_URL", format!("sqlite://{}", db.display()))
        .env("ECTO_DATA_DIR", work.path().join("data"))
        .current_dir(work.path())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("RUSTSEC-2026-0387"), "{error}");
    assert!(error.contains("report --format certificate"), "{error}");
    assert!(!output.exists());
    assert!(!db.exists());
}
