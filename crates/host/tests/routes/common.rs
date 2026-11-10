//! Helpers every route test uses: a server on in-memory SQLite, tokens,
//! sessions and the hook call.

use super::*;

pub(crate) const TEST_TOKEN: &str = "test-token";

/// A zero-dependency LLM backend that always returns `complete`.
/// Lives in the test file so production code never ships a mock.
pub(crate) struct TestStubBackend;

#[async_trait]
impl ectoledger::llm::LlmBackend for TestStubBackend {
    async fn propose(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<ectoledger_core::intent::ProposedIntent, ectoledger::llm::LlmError> {
        Ok(ectoledger_core::intent::ProposedIntent {
            action: "complete".into(),
            params: serde_json::json!({ "findings": [] }),
            justification: "Test stub - completing immediately.".into(),
            reasoning: "Integration test stub.".into(),
        })
    }

    async fn raw_call(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<String, ectoledger::llm::LlmError> {
        Ok("test-stub response".into())
    }

    fn backend_name(&self) -> &str {
        "test-stub"
    }

    fn model_name(&self) -> &str {
        "test-stub-v1"
    }
}

/// A backend that fails, slowly, so the cognitive loop ends *after* the test
/// has sealed the session and ends in a status the seal did not write.
///
/// `TestStubBackend` cannot show the un-sealing race: it completes at once and
/// the loop then writes `completed`, which is what the seal wrote too, so the
/// assertion holds either way. Wrong terminal status and wrong order are both
/// needed for the race to be visible at all.
pub(crate) struct SlowFailingBackend;

#[async_trait]
impl ectoledger::llm::LlmBackend for SlowFailingBackend {
    async fn propose(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<ectoledger_core::intent::ProposedIntent, ectoledger::llm::LlmError> {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        Err(ectoledger::llm::LlmError::EmptyResponse)
    }

    async fn raw_call(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<String, ectoledger::llm::LlmError> {
        Err(ectoledger::llm::LlmError::EmptyResponse)
    }

    fn backend_name(&self) -> &str {
        "slow-failing-stub"
    }

    fn model_name(&self) -> &str {
        "slow-failing-stub-v1"
    }
}

/// Set GUARD_REQUIRED=false exactly once before any async runtime is spawned.
pub(crate) fn ensure_guard_disabled() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: called exactly once, before any multi-threaded Tokio
        // runtime is active, so there is no concurrent env reader.
        unsafe {
            std::env::set_var("GUARD_REQUIRED", "false");
        }
    });
}

/// Spawn the IronVise server on a random port, return the base URL.
pub(crate) async fn spawn_server() -> String {
    spawn_server_with(Arc::new(|| Box::new(TestStubBackend))).await
}

/// As [`spawn_server`], but with a caller-chosen LLM backend, so a test can
/// decide how and when the spawned cognitive loop ends.
pub(crate) async fn spawn_server_with(
    llm_factory: Arc<dyn Fn() -> Box<dyn ectoledger::llm::LlmBackend> + Send + Sync>,
) -> String {
    ensure_guard_disabled();

    let pool = ectoledger::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .expect("create in-memory SQLite pool");

    spawn_server_with_pool(pool, llm_factory).await
}

pub(crate) async fn spawn_server_with_pool(
    pool: ectoledger::pool::DatabasePool,
    llm_factory: Arc<dyn Fn() -> Box<dyn ectoledger::llm::LlmBackend> + Send + Sync>,
) -> String {
    ensure_guard_disabled();

    // Seed the test bearer token into api_tokens so the auth middleware accepts it.
    let token_hash = hex::encode(Sha256::digest(TEST_TOKEN.as_bytes()));
    pool.insert_token(&token_hash, "admin", Some("test"), None)
        .await
        .expect("seed test token");

    let metrics = Arc::new(ectoledger::metrics::Metrics::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let base = format!("http://{addr}/api");

    tokio::spawn(async move {
        ectoledger::start_server_with_llm(pool, metrics, listener, llm_factory)
            .await
            .expect("server exited with error");
    });

    wait_until_ready(&base).await;
    base
}

/// Returns once the server answers the public `GET /api/status`.
pub(crate) async fn wait_until_ready(base: &str) {
    let client = reqwest::Client::new();
    for _ in 0..500 {
        let answered = client.get(format!("{base}/status")).send().await;
        if answered.is_ok_and(|r| r.status().is_success()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server at {base} did not answer /status within 5 s");
}

pub(crate) fn auth() -> (&'static str, &'static str) {
    ("Authorization", "Bearer test-token")
}

/// Create a recorder session (no audit loop, open until sealed) and return
/// its id: what a test that appends needs.
pub(crate) async fn create_recorder_session(base: &str) -> String {
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/sessions"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({ "goal": "integration-test", "record": true }))
        .send()
        .await
        .expect("POST /sessions")
        .json()
        .await
        .expect("json");
    body["id"].as_str().expect("id field").to_string()
}

/// Create a session and return its id.
pub(crate) async fn create_session(base: &str) -> String {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/sessions"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({ "goal": "integration-test" }))
        .send()
        .await
        .expect("POST /sessions");
    assert!(
        resp.status().is_success(),
        "create session: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    body["id"].as_str().expect("id field").to_string()
}

pub(crate) async fn status_of(base: &str, id: &str) -> String {
    reqwest::Client::new()
        .get(format!("{base}/sessions/{id}"))
        .header(auth().0, auth().1)
        .send()
        .await
        .expect("GET session")
        .json::<serde_json::Value>()
        .await
        .expect("json")["status"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

pub(crate) async fn hook_call(
    base: &str,
    tool: &str,
    input: serde_json::Value,
) -> serde_json::Value {
    reqwest::Client::new()
        .post(format!("{base}/hook/tool-call"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({
            "session_id": "write-test",
            "tool_name": tool,
            "tool_input": input,
        }))
        .send()
        .await
        .expect("POST /hook/tool-call")
        .json()
        .await
        .expect("json")
}

pub(crate) async fn agent_token(base: &str) -> String {
    token_with_role(base, "agent").await
}

pub(crate) async fn token_with_role(base: &str, role: &str) -> String {
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/tokens"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({ "role": role, "label": "second client" }))
        .send()
        .await
        .expect("POST /tokens")
        .json()
        .await
        .expect("json");
    body["token"].as_str().expect("token").to_string()
}

pub(crate) async fn hook_as(
    base: &str,
    token: &str,
    session: &str,
    tool_use_id: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    let r = reqwest::Client::new()
        .post(format!("{base}/hook/tool-call"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "session_id": session,
            "tool_name": "Bash",
            "tool_input": { "command": "ls" },
            "tool_use_id": tool_use_id,
        }))
        .send()
        .await
        .expect("POST /hook/tool-call");
    let status = r.status();
    (status, r.json().await.unwrap_or_default())
}

/// `total_events` from `/metrics/security`, used to pin that the check writes
/// nothing to the ledger.
pub(crate) async fn total_events(base: &str) -> u64 {
    reqwest::Client::new()
        .get(format!("{base}/metrics/security"))
        .header(auth().0, auth().1)
        .send()
        .await
        .expect("GET /metrics/security")
        .json::<serde_json::Value>()
        .await
        .expect("json")["total_events"]
        .as_u64()
        .expect("total_events is a count")
}

pub(crate) async fn check_tripwire(
    base: &str,
    action: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    reqwest::Client::new()
        .post(format!("{base}/tripwire/check"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({ "action": action, "params": params }))
        .send()
        .await
        .expect("POST /tripwire/check")
        .json()
        .await
        .expect("json")
}
