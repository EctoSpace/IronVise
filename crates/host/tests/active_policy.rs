//! The policy chosen in Settings for Home → Run (`active_policy`).
//!
//! A run is checked against the chosen policy, read at session start, and
//! records that policy's hash, or none when no policy ran; a recorded hash
//! must never name a policy that was not checked.
//!
//! One test, in its own binary: it sets process-wide environment variables.

use sha2::{Digest, Sha256};
use std::sync::Arc;

const TOKEN: &str = "active-policy-test-token";

/// Proposes an `http_get`, then completes.
struct HttpThenComplete(std::sync::Mutex<u32>);

#[async_trait::async_trait]
impl ectoledger::llm::LlmBackend for HttpThenComplete {
    async fn propose(
        &self,
        _s: &str,
        _u: &str,
    ) -> Result<ectoledger_core::intent::ProposedIntent, ectoledger::llm::LlmError> {
        let mut n = self.0.lock().unwrap();
        *n += 1;
        Ok(if *n == 1 {
            ectoledger_core::intent::ProposedIntent {
                action: "http_get".into(),
                params: serde_json::json!({ "url": "https://example.org/" }),
                justification: "Fetch the page to check its headers.".into(),
                reasoning: "test".into(),
            }
        } else {
            ectoledger_core::intent::ProposedIntent {
                action: "complete".into(),
                params: serde_json::json!({ "findings": [] }),
                justification: "Done with this test.".into(),
                reasoning: "test".into(),
            }
        })
    }
    async fn raw_call(&self, _s: &str, _u: &str) -> Result<String, ectoledger::llm::LlmError> {
        Ok(String::new())
    }
    fn backend_name(&self) -> &str {
        "test"
    }
    fn model_name(&self) -> &str {
        "test"
    }
}

async fn wait_for_server(addr: std::net::SocketAddr) {
    for _ in 0..500 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server at {addr} did not become ready");
}

async fn run_session(c: &reqwest::Client, base: &str) -> serde_json::Value {
    let resp = c
        .post(format!("{base}/sessions"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({ "goal": "check the site" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    for _ in 0..100 {
        let s: serde_json::Value = c
            .get(format!("{base}/sessions/{id}"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if s["status"] != "running" && s["status"] != "pending" {
            let events: serde_json::Value = c
                .get(format!("{base}/events?session_id={id}"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            return serde_json::json!({ "session": s, "events": events });
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("session {id} did not finish");
}

#[tokio::test]
async fn runs_use_the_policy_chosen_in_settings_and_record_its_hash() {
    let data = tempfile::tempdir().unwrap();
    // SAFETY: this binary's only test; set before the server starts.
    unsafe {
        std::env::set_var("ECTO_DATA_DIR", data.path());
        std::env::set_var("GUARD_REQUIRED", "false");
        std::env::remove_var("ECTO_POLICY_PATH");
    }
    let policies = data.path().join("policies");
    std::fs::create_dir_all(&policies).unwrap();
    let text = "name = \"no-http\"\n\n[[forbidden_actions]]\naction = \"http_get\"\n";
    std::fs::write(policies.join("no-http.toml"), text).unwrap();

    let pool = ectoledger::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    pool.insert_token(
        &hex::encode(Sha256::digest(TOKEN.as_bytes())),
        "admin",
        Some("test"),
        None,
    )
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/api");
    tokio::spawn(ectoledger::start_server_with_llm(
        pool,
        Arc::new(ectoledger::metrics::Metrics::default()),
        listener,
        Arc::new(|| Box::new(HttpThenComplete(std::sync::Mutex::new(0)))),
    ));
    wait_for_server(addr).await;
    let c = reqwest::Client::new();

    // No policy chosen: the session records none (it used to claim ISO 42001).
    let run = run_session(&c, &base).await;
    assert!(
        run["session"]["policy_hash"].is_null(),
        "{}",
        run["session"]
    );

    // A policy that does not exist cannot be chosen.
    let r = c
        .put(format!("{base}/config"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({ "active_policy": "missing" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422, "{}", r.text().await.unwrap());

    // Choose it: the run is checked against it and records its hash.
    let r = c
        .put(format!("{base}/config"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({ "active_policy": "no-http" }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    let cfg: serde_json::Value = c
        .get(format!("{base}/config"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["active_policy"], "no-http");

    let run = run_session(&c, &base).await;
    let expected = hex::encode(Sha256::digest(text.as_bytes()));
    assert_eq!(run["session"]["policy_hash"], expected.as_str());
    let refused = run["events"].as_array().unwrap().iter().any(|e| {
        e["payload"]["type"] == "tripwire_rejection"
            && e["payload"]["stage"] == "policy"
            && e["payload"]["action"] == "http_get"
    });
    assert!(
        refused,
        "the policy did not refuse http_get: {}",
        run["events"]
    );

    // An edit applies to the next run: the file is read at session start.
    let edited = format!("{text}# edited\n");
    std::fs::write(policies.join("no-http.toml"), &edited).unwrap();
    let run = run_session(&c, &base).await;
    assert_eq!(
        run["session"]["policy_hash"],
        hex::encode(Sha256::digest(edited.as_bytes())).as_str()
    );

    // Saving checks that the text is a policy, not just TOML. The packs'
    // old command-rule format parses as TOML and is not a policy.
    let not_a_policy = "[[command_rules]]\npattern = \"nmap\"\naction = \"deny\"\n";
    let r = c
        .put(format!("{base}/policies/not-a-policy"))
        .bearer_auth(TOKEN)
        .body(not_a_policy)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    assert!(r.text().await.unwrap().contains("Not a valid policy"));
    // The GUI's old template (bare action names) is accepted now.
    let old_template = "name = \"x\"\nforbidden_actions = [\"write_file\"]\n";
    let r = c
        .put(format!("{base}/policies/from-old-template"))
        .bearer_auth(TOKEN)
        .body(old_template)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    let new_template = "name = \"y\"\ngoal = \"g\"\nmax_steps = 20\n\n[[forbidden_actions]]\naction = \"write_file\"\n\n[[forbidden_actions]]\naction = \"delete_file\"\n";
    let r = c
        .put(format!("{base}/policies/from-new-template"))
        .bearer_auth(TOKEN)
        .body(new_template)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    let r = c
        .put(format!("{base}/policies/iso42001"))
        .bearer_auth(TOKEN)
        .body(new_template)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("read only"));
    // A built-in rule pack can be the active policy; the ISO 42001 controls
    // mapping, which has no rules, cannot.
    let r = c
        .put(format!("{base}/config"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({ "active_policy": "iso42001" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    assert!(r.text().await.unwrap().contains("no rules"));
    let r = c
        .put(format!("{base}/config"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({ "active_policy": "soc2-audit" }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    assert!(run_session(&c, &base).await["session"]["policy_hash"].is_string());

    // Cleared: back to no policy.
    c.put(format!("{base}/config"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({ "active_policy": "" }))
        .send()
        .await
        .unwrap();
    let run = run_session(&c, &base).await;
    assert!(run["session"]["policy_hash"].is_null());
}
