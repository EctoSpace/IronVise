#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::Digest;

pub const ADMIN_TOKEN: &str = "qa-admin-token";

/// Returns once the server at `base` answers the public `GET /api/status`.
pub async fn wait_until_ready(base: &str) {
    let client = reqwest::Client::new();
    for _ in 0..500 {
        let answered = client.get(format!("{base}/api/status")).send().await;
        if answered.is_ok_and(|r| r.status().is_success()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server at {base} did not answer /api/status within 5 s");
}

pub struct StubBackend;

#[async_trait]
impl ectoledger::llm::LlmBackend for StubBackend {
    async fn propose(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<ectoledger_core::intent::ProposedIntent, ectoledger::llm::LlmError> {
        Ok(ectoledger_core::intent::ProposedIntent {
            action: "complete".into(),
            params: serde_json::json!({ "findings": [] }),
            justification: "qa stub completes immediately".into(),
            reasoning: "qa stub".into(),
        })
    }

    async fn raw_call(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<String, ectoledger::llm::LlmError> {
        Ok("qa-stub-response".into())
    }

    fn backend_name(&self) -> &str {
        "qa-stub"
    }

    fn model_name(&self) -> &str {
        "qa-stub-v1"
    }
}

pub fn ensure_guard_disabled() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe {
        std::env::set_var("GUARD_REQUIRED", "false");
    });
}

pub async fn fresh_pool() -> ectoledger::pool::DatabasePool {
    ectoledger::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .expect("create in-memory sqlite pool")
}

pub async fn seed_token(pool: &ectoledger::pool::DatabasePool, token: &str, role: &str) -> String {
    let hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));
    pool.insert_token(&hash, role, Some("qa"), None)
        .await
        .expect("seed token");
    hash
}

pub async fn spawn_server() -> String {
    spawn_server_with(Arc::new(|| Box::new(StubBackend))).await
}

pub async fn spawn_server_with(
    llm_factory: Arc<dyn Fn() -> Box<dyn ectoledger::llm::LlmBackend> + Send + Sync>,
) -> String {
    ensure_guard_disabled();
    let pool = fresh_pool().await;
    seed_token(&pool, ADMIN_TOKEN, "admin").await;
    let metrics = Arc::new(ectoledger::metrics::Metrics::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let base = format!("http://{addr}");
    tokio::spawn(async move {
        ectoledger::start_server_with_llm(pool, metrics, listener, llm_factory)
            .await
            .expect("server exited with error");
    });
    wait_until_ready(&base).await;
    base
}

/// Like [`spawn_server`], but passes the trusted-proxy list directly to the
/// router instead of through `ECTO_TRUSTED_PROXIES`, which is process-global
/// and would race against other rate-limit tests running on other threads
/// of this same binary. `bind_host` is the loopback address to listen on
/// (`"127.0.0.1"` or `"::1"`) - the test's own client connects from that
/// family, so listing it as trusted is what makes the harness itself the
/// trusted proxy for a test.
pub async fn spawn_server_with_trusted_proxies(bind_host: &str, trusted: &[&str]) -> String {
    ensure_guard_disabled();
    let pool = fresh_pool().await;
    seed_token(&pool, ADMIN_TOKEN, "admin").await;
    let metrics = Arc::new(ectoledger::metrics::Metrics::default());
    let cancel = tokio_util::sync::CancellationToken::new();
    let (router, _tracker) = ectoledger::server::router_with_approval_state_and_trusted_proxies(
        pool,
        metrics,
        Arc::new(ectoledger::approvals::ApprovalState::new()),
        cancel,
        Some(Arc::new(|| {
            Box::new(StubBackend) as Box<dyn ectoledger::llm::LlmBackend>
        })),
        trusted.iter().map(|s| s.to_string()).collect(),
    );
    let listener = tokio::net::TcpListener::bind(format!("{bind_host}:0"))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let base = if addr.is_ipv6() {
        format!("http://[{}]:{}", addr.ip(), addr.port())
    } else {
        format!("http://{addr}")
    };
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("trusted-proxy test server exited with error");
    });
    wait_until_ready(&base).await;
    base
}

pub struct ApprovalHarness {
    pub base: String,
    pub approval_state: Arc<ectoledger::approvals::ApprovalState>,
    pub admin_hash: String,
    pub agent_hash: String,
}

pub async fn spawn_server_with_approvals() -> ApprovalHarness {
    ensure_guard_disabled();
    let pool = fresh_pool().await;
    let admin_hash = seed_token(&pool, ADMIN_TOKEN, "admin").await;
    let agent_hash = seed_token(&pool, "qa-agent-token", "agent").await;
    let metrics = Arc::new(ectoledger::metrics::Metrics::default());
    let approval_state = Arc::new(ectoledger::approvals::ApprovalState::new());
    let cancel = tokio_util::sync::CancellationToken::new();
    let (router, _tracker) = ectoledger::server::router_with_approval_state(
        pool,
        metrics,
        approval_state.clone(),
        cancel,
        Some(Arc::new(|| {
            Box::new(StubBackend) as Box<dyn ectoledger::llm::LlmBackend>
        })),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let base = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("approval test server exited with error");
    });
    wait_until_ready(&base).await;
    ApprovalHarness {
        base,
        approval_state,
        admin_hash,
        agent_hash,
    }
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

pub async fn create_recorder_session(client: &reqwest::Client, base: &str, token: &str) -> String {
    let resp = client
        .post(format!("{base}/api/sessions"))
        .header("Authorization", bearer(token))
        .json(&serde_json::json!({ "goal": "qa recorder session", "record": true }))
        .send()
        .await
        .expect("create recorder session");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "create recorder session"
    );
    let body: serde_json::Value = resp.json().await.expect("recorder session body");
    body["id"]
        .as_str()
        .expect("session id in response")
        .to_string()
}

pub async fn token_with_role(
    client: &reqwest::Client,
    base: &str,
    admin_token: &str,
    role: &str,
) -> String {
    let resp = client
        .post(format!("{base}/api/tokens"))
        .header("Authorization", bearer(admin_token))
        .json(&serde_json::json!({ "role": role, "label": "qa" }))
        .send()
        .await
        .expect("create token");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "create {role} token"
    );
    let body: serde_json::Value = resp.json().await.expect("token body");
    body["token"]
        .as_str()
        .expect("raw token in response")
        .to_string()
}
