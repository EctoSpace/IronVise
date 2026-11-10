//! The real `guard-worker` binary, driven over its stdin/stdout protocol: a
//! correctly signed request line sent twice is evaluated once, and a request
//! without a timestamp is refused.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const KEY: [u8; 32] = [7; 32];

fn signed_line(nonce: u64, timestamp_ms: u64) -> String {
    let json = serde_json::json!({
        "goal": "check the worker",
        "intent": { "action": "read_file", "params": { "path": "README.md" } },
        "nonce": nonce,
        "timestamp_ms": timestamp_ms,
    })
    .to_string();
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&KEY).expect("key");
    mac.update(format!("{nonce}:{json}").as_bytes());
    format!("{json}\t{}\n", hex::encode(mac.finalize().into_bytes()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

#[test]
fn a_replayed_or_undated_request_is_refused() {
    let data = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_guard-worker"))
        .env("GUARD_HMAC_KEY", hex::encode(KEY))
        .env("GUARD_LLM_BACKEND", "mock")
        .env("ECTO_DATA_DIR", data.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn guard-worker");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut ask = |line: &str| {
        stdin.write_all(line.as_bytes()).expect("write");
        let mut verdict = String::new();
        stdout.read_line(&mut verdict).expect("read");
        verdict
            .rsplit_once('\t')
            .expect("signed verdict")
            .0
            .to_string()
    };

    let first = signed_line(0, now_ms());
    let evaluated = ask(&first);
    // The mock backend's answer is not ALLOW/DENY, so the guard fails closed;
    // what matters is that the guard ran, which the replay below must not.
    assert!(evaluated.contains("fail-closed"), "{evaluated}");
    let replayed = ask(&first);
    assert_eq!(replayed, "DENY: replayed nonce 0");
    let undated = ask(&signed_line(1, 0));
    assert_eq!(undated, "DENY: request has no timestamp");
    let next = ask(&signed_line(1, now_ms()));
    assert!(next.contains("fail-closed"), "{next}");

    drop(stdin);
    child.wait().expect("wait");
}
