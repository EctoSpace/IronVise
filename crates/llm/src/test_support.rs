#![cfg(test)]

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct ScriptedResponse {
    pub status: u16,
    pub body: String,
    pub delay: Option<Duration>,
}

impl ScriptedResponse {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            delay: None,
        }
    }

    pub fn status(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            delay: None,
        }
    }

    pub fn delayed(status: u16, body: impl Into<String>, delay: Duration) -> Self {
        Self {
            status,
            body: body.into(),
            delay: Some(delay),
        }
    }
}

#[derive(Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("recorded request body is valid JSON")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

struct ServerState {
    responses: Vec<ScriptedResponse>,
    counter: AtomicUsize,
    requests: Mutex<Vec<RecordedRequest>>,
}

pub struct MockServer {
    pub url: String,
    state: Arc<ServerState>,
}

impl MockServer {
    pub async fn start(responses: Vec<ScriptedResponse>) -> Self {
        assert!(
            !responses.is_empty(),
            "a mock server needs at least one scripted response"
        );
        let state = Arc::new(ServerState {
            responses,
            counter: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        });
        let app = Router::new().fallback(handler).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral mock-server port");
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        MockServer { url, state }
    }

    pub async fn single(response: ScriptedResponse) -> Self {
        Self::start(vec![response]).await
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests.lock().unwrap().clone()
    }

    pub fn request(&self, n: usize) -> RecordedRequest {
        self.requests()
            .into_iter()
            .nth(n)
            .unwrap_or_else(|| panic!("mock server received fewer than {} requests", n + 1))
    }

    pub fn request_count(&self) -> usize {
        self.state.requests.lock().unwrap().len()
    }
}

async fn handler(
    State(state): State<Arc<ServerState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, String) {
    let idx = state.counter.fetch_add(1, Ordering::SeqCst);
    let scripted = state
        .responses
        .get(idx)
        .or_else(|| state.responses.last())
        .cloned()
        .expect("at least one scripted response");
    if let Some(delay) = scripted.delay {
        tokio::time::sleep(delay).await;
    }
    state.requests.lock().unwrap().push(RecordedRequest {
        method: method.to_string(),
        path: uri.path().to_string(),
        headers,
        body: body.to_vec(),
    });
    (
        StatusCode::from_u16(scripted.status).expect("valid HTTP status code"),
        scripted.body,
    )
}

pub fn closed_port_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

pub fn truncated_body_server(status: u16, declared_len: usize, actual_body: &str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let addr = listener.local_addr().unwrap();
    let body = actual_body.to_string();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.1 {status} MOCK\r\nContent-Type: application/json\r\nContent-Length: {declared_len}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
    });
    format!("http://{addr}")
}

pub fn client_with_timeout(ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(ms))
        .build()
        .expect("build a reqwest client")
}

pub fn generous_client() -> reqwest::Client {
    client_with_timeout(5_000)
}
