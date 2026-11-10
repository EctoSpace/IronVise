use super::*;
use serde_json::{Value, json};

const SECRET: &str = "fixture-secret-not-for-production";
const RECEIVER: &str = "https://siem.example/ectoledger";
const OTHER: &str = "https://other.example/ectoledger";
const ID: &str = "3f2b8c1e-5d4a-4c3b-9e8f-7a6b5c4d3e2f";
const TS: i64 = 1_790_700_000;
const BODY: &str = r#"{"event_kind":"tripwire_rejection","session_id":"s1"}"#;

/// The reference verifier the SDKs implement. Order matters: a forged
/// delivery must not be able to fill the replay cache.
fn verify(
    key: &[u8; 32],
    receiver_url: &str,
    headers: &Value,
    body: &str,
    now: i64,
    seen: &mut std::collections::HashSet<String>,
) -> &'static str {
    let h = |n: &str| headers.get(n).and_then(Value::as_str);
    let (Some(id), Some(ts), Some(sig)) = (
        h("X-EctoLedger-Delivery"),
        h("X-EctoLedger-Timestamp").and_then(|t| t.parse::<i64>().ok()),
        h("X-EctoLedger-Signature-V1"),
    ) else {
        return "missing_headers";
    };
    if (now - ts).abs() > WEBHOOK_TOLERANCE_SECS {
        return "stale";
    }
    if signature_v1(key, id, ts, receiver_url, body) != sig {
        return "bad_signature";
    }
    if !seen.insert(id.to_string()) {
        return "replayed";
    }
    "ok"
}

/// A delivery to a real HTTP receiver: refused once, retried with the
/// same signed headers, accepted, and verified the way the SDKs verify.
/// Webhooks saved in the app must point at public endpoints, so the
/// delivery itself is tested here against a local server.
#[tokio::test]
async fn a_delivery_is_retried_with_the_same_headers_and_verifies_at_its_receiver() {
    use std::sync::{Arc, Mutex};
    type Seen = Arc<Mutex<Vec<(axum::http::HeaderMap, String)>>>;
    let seen: Seen = Arc::default();
    let app = axum::Router::new()
        .route(
            "/hook",
            axum::routing::post(
                |axum::extract::State(seen): axum::extract::State<Seen>,
                 headers: axum::http::HeaderMap,
                 body: String| async move {
                    let mut all = seen.lock().unwrap();
                    all.push((headers, body));
                    if all.len() == 1 {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        axum::http::StatusCode::OK
                    }
                },
            ),
        )
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });

    let body = BODY;
    let signing = signed_headers(Some(SECRET), false, &url, body);
    deliver(
        &reqwest::Client::new(),
        &url,
        "json",
        body,
        Some("receiver-token"),
        &signing,
    )
    .await
    .expect("delivered on the retry");

    let all = seen.lock().unwrap();
    assert_eq!(all.len(), 2, "one refusal, one retry");
    let (first, second) = (&all[0].0, &all[1].0);
    for name in ["X-EctoLedger-Delivery", "X-EctoLedger-Signature-V1"] {
        assert_eq!(first.get(name), second.get(name), "{name} changed on retry");
    }
    let (h, got_body) = &all[1];
    assert_eq!(got_body, body);
    assert_eq!(h.get("authorization").unwrap(), "Bearer receiver-token");
    assert_eq!(h.get("content-type").unwrap(), "application/json");
    let as_json: Value = h
        .iter()
        .filter(|(n, _)| n.as_str().starts_with("x-ectoledger"))
        .map(|(n, v)| {
            let name = match n.as_str() {
                "x-ectoledger-delivery" => "X-EctoLedger-Delivery",
                "x-ectoledger-timestamp" => "X-EctoLedger-Timestamp",
                "x-ectoledger-signature-v1" => "X-EctoLedger-Signature-V1",
                other => other,
            };
            (name.to_string(), Value::from(v.to_str().unwrap()))
        })
        .collect::<serde_json::Map<_, _>>()
        .into();
    let now = chrono::Utc::now().timestamp();
    let mut replay = std::collections::HashSet::new();
    assert_eq!(
        verify(
            &receiver_key(SECRET, &url),
            &url,
            &as_json,
            got_body,
            now,
            &mut replay
        ),
        "ok"
    );
    assert_eq!(
        verify(
            &receiver_key(SECRET, OTHER),
            OTHER,
            &as_json,
            got_body,
            now,
            &mut replay
        ),
        "bad_signature",
        "another receiver cannot accept it"
    );
}

fn headers() -> Value {
    let key = receiver_key(SECRET, RECEIVER);
    json!({
        "X-EctoLedger-Delivery": ID,
        "X-EctoLedger-Timestamp": TS.to_string(),
        "X-EctoLedger-Signature-V1": signature_v1(&key, ID, TS, RECEIVER, BODY),
    })
}

fn fixture() -> Value {
    let key = |url: &str| hex::encode(receiver_key(SECRET, url));
    let case = |name: &str, url: &str, headers: Value, body: &str, now: i64| {
        json!({ "name": name, "receiver_url": url, "receiver_key": key(url),
                    "headers": headers, "body": body, "now": now })
    };
    let mut cases = vec![
        case("valid", RECEIVER, headers(), BODY, TS + 10),
        case(
            "presented to another receiver",
            OTHER,
            headers(),
            BODY,
            TS + 10,
        ),
        case(
            "body altered",
            RECEIVER,
            headers(),
            &BODY.replace("s1", "s2"),
            TS + 10,
        ),
        case(
            "older than the tolerance",
            RECEIVER,
            headers(),
            BODY,
            TS + 301,
        ),
        case(
            "newer than the tolerance",
            RECEIVER,
            headers(),
            BODY,
            TS - 301,
        ),
        case(
            "legacy body-only signature",
            RECEIVER,
            json!({ "X-EctoLedger-Signature": hmac_signature(BODY, SECRET).unwrap() }),
            BODY,
            TS,
        ),
    ];
    for c in &mut cases {
        let key: [u8; 32] = hex::decode(c["receiver_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let got = verify(
            &key,
            c["receiver_url"].as_str().unwrap(),
            &c["headers"],
            c["body"].as_str().unwrap(),
            c["now"].as_i64().unwrap(),
            &mut Default::default(),
        );
        c["expect"] = got.into();
    }
    json!({
        "scheme": "ectoledger-webhook-v1",
        "secret": SECRET,
        "tolerance_secs": WEBHOOK_TOLERANCE_SECS,
        "cases": cases,
        "replay": { "presentations": 2, "expect": ["ok", "replayed"], "case": "valid" },
    })
}

#[test]
fn the_sdk_fixture_matches_what_the_server_signs() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/fixtures/webhook-v1.json");
    let want = serde_json::to_string_pretty(&fixture()).unwrap() + "\n";
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        have, want,
        "sdk/fixtures/webhook-v1.json is out of date: rerun with UPDATE_FIXTURES=1 \
             and make the SDK verifiers pass against it"
    );
}

#[test]
fn each_case_gets_the_verdict_it_should() {
    let f = fixture();
    let expect: Vec<&str> = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["expect"].as_str().unwrap())
        .collect();
    assert_eq!(
        expect,
        [
            "ok",
            "bad_signature",
            "bad_signature",
            "stale",
            "stale",
            "missing_headers"
        ]
    );
}

#[test]
fn a_second_presentation_is_refused() {
    let key = receiver_key(SECRET, RECEIVER);
    let mut seen = Default::default();
    let run = |seen: &mut _| verify(&key, RECEIVER, &headers(), BODY, TS, seen);
    assert_eq!(run(&mut seen), "ok");
    assert_eq!(run(&mut seen), "replayed");
}

#[test]
fn a_forged_delivery_does_not_poison_the_replay_cache() {
    let key = receiver_key(SECRET, RECEIVER);
    let mut forged = headers();
    forged["X-EctoLedger-Signature-V1"] = "00".repeat(32).into();
    let mut seen = Default::default();
    assert_eq!(
        verify(&key, RECEIVER, &forged, BODY, TS, &mut seen),
        "bad_signature"
    );
    assert_eq!(
        verify(&key, RECEIVER, &headers(), BODY, TS, &mut seen),
        "ok"
    );
}

/// What both delivery paths attach, checked by the reference verifier.
#[test]
fn the_headers_a_delivery_carries_verify_at_their_receiver_only() {
    let as_json = |h: Vec<(&str, String)>| -> Value {
        h.into_iter()
            .map(|(k, v)| (k.to_string(), Value::from(v)))
            .collect()
    };
    let h = as_json(signed_headers(Some(SECRET), false, RECEIVER, BODY));
    assert!(
        h.get("X-EctoLedger-Signature").is_none(),
        "legacy header is off by default"
    );
    let ts: i64 = h["X-EctoLedger-Timestamp"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let at = |url| {
        verify(
            &receiver_key(SECRET, url),
            url,
            &h,
            BODY,
            ts,
            &mut Default::default(),
        )
    };
    assert_eq!(at(RECEIVER), "ok");
    assert_eq!(at(OTHER), "bad_signature");

    let legacy = as_json(signed_headers(Some(SECRET), true, RECEIVER, BODY));
    assert!(
        legacy["X-EctoLedger-Signature"]
            .as_str()
            .unwrap()
            .starts_with("sha256=")
    );
    assert!(
        signed_headers(None, true, RECEIVER, BODY).is_empty(),
        "no secret, no headers"
    );

    let again = as_json(signed_headers(Some(SECRET), false, RECEIVER, BODY));
    assert_ne!(
        again["X-EctoLedger-Delivery"], h["X-EctoLedger-Delivery"],
        "ids are unique"
    );
}

#[test]
fn receivers_hold_different_keys() {
    assert_ne!(receiver_key(SECRET, RECEIVER), receiver_key(SECRET, OTHER));
    assert_ne!(
        receiver_key(SECRET, RECEIVER),
        receiver_key("other-secret", RECEIVER)
    );
}

/// RFC 4231 test case 2 through both signers' HMAC: key "Jefe", data
/// "what do ya want for nothing?".
#[test]
fn hmac_sha256_gives_the_rfc_4231_answer() {
    const ANSWER: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    assert_eq!(
        hex::encode(hmac_sha256(b"Jefe", &["what do ya want for nothing?"])),
        ANSWER
    );
    assert_eq!(
        hmac_signature("what do ya want for nothing?", "Jefe").as_deref(),
        Some(format!("sha256={ANSWER}").as_str())
    );
}
