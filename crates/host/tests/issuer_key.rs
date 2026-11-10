//! The installation issuer key, through the real binaries: `issuer-key init`
//! makes it, a certificate exported after the session key is gone is still
//! signed (by the issuer), and `verify-cert --issuer` accepts exactly that key.

use std::path::Path;
use std::process::{Command, Output};

fn run(bin: &str, args: &[&str], data: &Path, db: &Path) -> Output {
    Command::new(bin)
        .args(args)
        .env("ECTO_DATA_DIR", data)
        .env("DATABASE_URL", format!("sqlite:{}", db.display()))
        .env_remove("ECTO_KEY_PASSWORD")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[tokio::test]
async fn an_export_without_the_session_key_is_signed_by_the_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let (data, db) = (dir.path().join("data"), dir.path().join("ledger.db"));
    let ecto = env!("CARGO_BIN_EXE_ironvise");
    let verify = env!("CARGO_BIN_EXE_verify-cert");

    let init = run(ecto, &["issuer-key", "init"], &data, &db);
    assert!(init.status.success(), "{init:?}");
    let issuer = stdout(&init).lines().last().unwrap().trim().to_string();
    assert_eq!(issuer.len(), 64, "{issuer}");
    // Owner-only. Windows has no mode bits: there `icacls` restricts the ACL,
    // which this test does not read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(data.join("issuer.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(
        !run(ecto, &["issuer-key", "init"], &data, &db)
            .status
            .success()
    );
    assert_eq!(
        stdout(&run(ecto, &["issuer-key", "show"], &data, &db)).trim(),
        issuer
    );

    // A session whose key this process drops: no key file is saved.
    let session = {
        let pool = ectoledger::pool::create_sqlite_pool(&db).await.unwrap();
        let (session, key) = pool
            .create_session("issuer test", "test", "n/a", None)
            .await
            .unwrap();
        pool.append_event(
            ectoledger::schema::EventPayload::Thought {
                content: "hello".into(),
            },
            Some(session.id),
            Some("issuer test"),
            Some(&key),
        )
        .await
        .unwrap();
        session.id.to_string()
    };

    let cert = dir.path().join("audit.elc");
    let cert_arg = cert.to_str().unwrap();
    let export = run(
        ecto,
        &[
            "report",
            &session,
            "--format",
            "certificate",
            "--no-ots",
            "--output",
            cert_arg,
        ],
        &data,
        &db,
    );
    assert!(export.status.success(), "{export:?}");

    let pinned = run(verify, &["--issuer", &issuer, cert_arg], &data, &db);
    assert!(pinned.status.success(), "{}", stdout(&pinned));
    assert!(
        stdout(&pinned).contains("signed by the expected issuer"),
        "{}",
        stdout(&pinned)
    );
    assert!(
        run(verify, &["--strict", cert_arg], &data, &db)
            .status
            .success()
    );
    let other = "ab".repeat(32);
    assert!(
        !run(verify, &["--issuer", &other, cert_arg], &data, &db)
            .status
            .success()
    );
    assert!(
        !run(verify, &["--expected-key", &issuer, cert_arg], &data, &db)
            .status
            .success()
    );
    assert!(
        run(
            ecto,
            &["verify-certificate", "--issuer", &issuer, cert_arg],
            &data,
            &db
        )
        .status
        .success()
    );
}
