//! `verify-vc`, `webhook-key` and `health` through the real `ironvise` binary.
//! None of them needs a database; each is a public entry point that scripts
//! and the container health check depend on.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use ectoledger::verifiable_credential::build_vc_jwt;
use ed25519_dalek::SigningKey;
use uuid::Uuid;

fn ironvise(args: &[&str], dir: &Path, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ironvise"));
    cmd.args(args)
        .current_dir(dir)
        .env("ECTO_DATA_DIR", dir.join("data"))
        .env(
            "DATABASE_URL",
            format!("sqlite:{}", dir.join("ledger.db").display()),
        )
        .env_remove("WEBHOOK_HMAC_SECRET")
        .env_remove("ECTO_BIND_PORT")
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run ironvise")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn issuer_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

#[test]
fn verify_vc_accepts_a_credential_signed_by_the_pinned_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let key = issuer();
    let jwt = build_vc_jwt(Uuid::new_v4(), "audit goal", Some("abc"), Some(&key), None);

    let out = ironvise(
        &["verify-vc", &jwt, "--issuer-hex", &issuer_hex(&key)],
        dir.path(),
        &[],
    );

    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("signature valid"), "{}", text(&out));
    assert!(text(&out).contains("audit goal"), "{}", text(&out));
}

#[test]
fn verify_vc_refuses_a_credential_from_another_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let jwt = build_vc_jwt(Uuid::new_v4(), "goal", None, Some(&issuer()), None);
    let stranger = SigningKey::from_bytes(&[9u8; 32]);

    let out = ironvise(
        &["verify-vc", &jwt, "--issuer-hex", &issuer_hex(&stranger)],
        dir.path(),
        &[],
    );

    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("INVALID"), "{}", text(&out));
}

#[test]
fn verify_vc_refuses_an_edited_payload() {
    let dir = tempfile::tempdir().unwrap();
    let key = issuer();
    let jwt = build_vc_jwt(Uuid::new_v4(), "goal", None, Some(&key), None);
    let mut parts: Vec<String> = jwt.split('.').map(str::to_string).collect();
    let other = build_vc_jwt(Uuid::new_v4(), "another goal", None, Some(&key), None);
    parts[1] = other.split('.').nth(1).unwrap().to_string();

    let out = ironvise(
        &[
            "verify-vc",
            &parts.join("."),
            "--issuer-hex",
            &issuer_hex(&key),
        ],
        dir.path(),
        &[],
    );

    assert!(!out.status.success(), "{}", text(&out));
}

#[test]
fn verify_vc_requires_the_named_audience() {
    let dir = tempfile::tempdir().unwrap();
    let key = issuer();
    let jwt = build_vc_jwt(
        Uuid::new_v4(),
        "goal",
        None,
        Some(&key),
        Some("did:web:auditor"),
    );
    let pinned = issuer_hex(&key);

    let without = ironvise(
        &["verify-vc", &jwt, "--issuer-hex", &pinned],
        dir.path(),
        &[],
    );
    let wrong = ironvise(
        &[
            "verify-vc",
            &jwt,
            "--issuer-hex",
            &pinned,
            "--audience",
            "did:web:other",
        ],
        dir.path(),
        &[],
    );
    let right = ironvise(
        &[
            "verify-vc",
            &jwt,
            "--issuer-hex",
            &pinned,
            "--audience",
            "did:web:auditor",
        ],
        dir.path(),
        &[],
    );

    assert!(!without.status.success(), "{}", text(&without));
    assert!(!wrong.status.success(), "{}", text(&wrong));
    assert!(right.status.success(), "{}", text(&right));
}

#[test]
fn verify_vc_rejects_a_malformed_issuer_key() {
    let dir = tempfile::tempdir().unwrap();
    let jwt = build_vc_jwt(Uuid::new_v4(), "goal", None, Some(&issuer()), None);

    let out = ironvise(
        &["verify-vc", &jwt, "--issuer-hex", "abcd"],
        dir.path(),
        &[],
    );

    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("32 bytes"), "{}", text(&out));
}

#[test]
fn webhook_key_prints_the_receiver_key_the_server_signs_with() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "test-webhook-secret";
    let url = "https://siem.example/hook";

    let out = ironvise(
        &["webhook-key", "--url", url],
        dir.path(),
        &[("WEBHOOK_HMAC_SECRET", secret)],
    );

    assert!(out.status.success(), "{}", text(&out));
    let printed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        printed,
        hex::encode(ectoledger::webhook::receiver_key(secret, url))
    );
}

#[test]
fn webhook_key_differs_per_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let env = [("WEBHOOK_HMAC_SECRET", "test-webhook-secret")];

    let a = ironvise(
        &["webhook-key", "--url", "https://a.example/"],
        dir.path(),
        &env,
    );
    let b = ironvise(
        &["webhook-key", "--url", "https://b.example/"],
        dir.path(),
        &env,
    );

    assert!(a.status.success() && b.status.success());
    assert_ne!(a.stdout, b.stdout);
}

#[test]
fn webhook_key_fails_without_a_secret() {
    let dir = tempfile::tempdir().unwrap();

    let out = ironvise(
        &["webhook-key", "--url", "https://a.example/"],
        dir.path(),
        &[],
    );

    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("WEBHOOK_HMAC_SECRET"), "{}", text(&out));
}

/// Answers one HTTP request with `status_line`, on a free loopback port.
fn one_shot_server(status_line: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let _ = write!(stream, "{status_line}\r\nContent-Length: 0\r\n\r\n");
        }
    });
    (port, handle)
}

#[test]
fn health_succeeds_when_the_observer_answers_200() {
    let dir = tempfile::tempdir().unwrap();
    let (port, server) = one_shot_server("HTTP/1.1 200 OK");

    let out = ironvise(
        &["health"],
        dir.path(),
        &[("ECTO_BIND_PORT", &port.to_string())],
    );

    server.join().unwrap();
    assert!(out.status.success(), "{}", text(&out));
}

#[test]
fn health_fails_when_the_observer_is_unhealthy() {
    let dir = tempfile::tempdir().unwrap();
    let (port, server) = one_shot_server("HTTP/1.1 503 Service Unavailable");

    let out = ironvise(
        &["health"],
        dir.path(),
        &[("ECTO_BIND_PORT", &port.to_string())],
    );

    server.join().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
}

#[test]
fn health_fails_when_nothing_listens() {
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let out = ironvise(
        &["health"],
        dir.path(),
        &[("ECTO_BIND_PORT", &port.to_string())],
    );

    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
}
