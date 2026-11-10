//! Mock-HTTP-server tests for the Tauri commands that talk to the embedded
//! Observer backend over `reqwest`: an unauthorized status, a server error,
//! a success response with a non-JSON body, a dropped connection, and a
//! server that never answers. These are the failure shapes a real backend
//! (wrong port, crashed server, reverse-proxy error page, a stalled request)
//! can hand back, and the point of the test is the message the webview ends
//! up showing, not just that the call failed.
//!
//! `#[serial]`: every case points the shared command code at a different
//! mock server through the process-wide `ECTO_HOST` env var (and the HTTP
//! client's timeouts, also env vars - see `point_at`), so these tests must
//! not run concurrently with each other.

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use serial_test::serial;
use tokio::net::TcpListener;

/// Points every `ECTO_HOST`-aware command at `url`, and gives the shared HTTP
/// client a short, fixed timeout so the "server never answers" case below
/// does not wait the real app's 30s.
///
/// SAFETY: every test that reads these variables is `#[serial]`. The HTTP
/// client itself is a `OnceLock` built once from them (see `commands::mod`),
/// so whichever of these tests happens to run first "wins" the race to
/// initialize it - harmless here because every case sets the identical
/// values.
fn point_at(url: &str) {
    unsafe {
        std::env::set_var("ECTO_HOST", url);
        std::env::set_var("ECTO_HTTP_CONNECT_TIMEOUT_MS", "300");
        std::env::set_var("ECTO_HTTP_TIMEOUT_MS", "300");
    }
}

/// Starts `app` on an ephemeral loopback port and returns its base URL.
async fn spawn(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

/// A loopback address nothing listens on: bind to get a free ephemeral port,
/// then drop the listener so the OS frees it again immediately, before
/// anything connects to it.
async fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}

/// Accepts a connection and never writes a response - the request hangs
/// until the client's own timeout fires.
async fn spawn_silent() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            // Keep the accepted stream alive for the test's duration instead
            // of dropping it (a dropped stream can itself look like a closed
            // connection to the client).
            if let Ok((stream, _)) = listener.accept().await {
                std::mem::forget(stream);
            }
        }
    });
    url
}

#[tokio::test]
#[serial]
async fn unauthorized_status_names_the_fix() {
    let app = Router::new().route(
        "/api/metrics/security",
        get(|| async { (StatusCode::UNAUTHORIZED, "no token") }),
    );
    point_at(&spawn(app).await);
    let err = crate::commands::sessions::get_metrics().await.unwrap_err();
    assert!(err.contains("401"), "{err}");
    assert!(err.contains("Authentication failed"), "{err}");
    assert!(err.contains("Restart the application"), "{err}");
}

#[tokio::test]
#[serial]
async fn server_error_status_is_reported_with_the_status_code() {
    let app = Router::new().route(
        "/api/metrics/security",
        get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "db unavailable") }),
    );
    point_at(&spawn(app).await);
    let err = crate::commands::sessions::get_metrics().await.unwrap_err();
    assert!(err.contains("500"), "{err}");
    assert!(err.contains("db unavailable"), "{err}");
}

/// A dead or misrouted backend answering with an HTML error page used to
/// reach the user as raw markup from `run_prompt` and `chat` - every other
/// command already stripped it via `sanitize_error_body`. Fixed by routing
/// `run_prompt`'s error body through the same sanitizer.
#[tokio::test]
#[serial]
async fn html_error_body_is_stripped_of_tags() {
    let app = Router::new().route(
        "/api/sessions",
        axum::routing::post(|| async {
            (
                StatusCode::BAD_GATEWAY,
                "<html><body>502 Bad Gateway</body></html>",
            )
        }),
    );
    point_at(&spawn(app).await);
    let err = crate::commands::sessions::run_prompt(crate::commands::sessions::RunPromptArgs {
        goal: "audit".to_string(),
    })
    .await
    .unwrap_err();
    assert!(!err.contains('<'), "{err}");
    assert!(err.contains("502 Bad Gateway"), "{err}");
}

/// A success response whose body is not JSON (e.g. a misconfigured reverse
/// proxy returning plain text with a 200) must not panic, and must say what
/// went wrong rather than leaving the webview with nothing.
#[tokio::test]
#[serial]
async fn success_with_a_non_json_body_is_reported() {
    let app = Router::new().route("/api/config", get(|| async { "not json" }));
    point_at(&spawn(app).await);
    let err = crate::commands::settings::get_config().await.unwrap_err();
    assert!(!err.is_empty());
}

/// `get_policy_content` used to say "Policy not found" for every non-2xx
/// status, including a server error that has nothing to do with the policy
/// existing. Fixed to say "not found" only for a real 404.
#[tokio::test]
#[serial]
async fn policy_content_distinguishes_404_from_server_error() {
    let app = Router::new().route(
        "/api/policies/{name}",
        get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "disk full") }),
    );
    point_at(&spawn(app).await);
    let err = crate::commands::policy::get_policy_content("soc2".to_string())
        .await
        .unwrap_err();
    assert!(!err.contains("not found"), "{err}");
    assert!(err.contains("500"), "{err}");
    assert!(err.contains("disk full"), "{err}");
}

#[tokio::test]
#[serial]
async fn connection_refused_is_reported() {
    point_at(&closed_port().await);
    let err = crate::commands::settings::get_config().await.unwrap_err();
    assert!(!err.is_empty());
    assert!(
        !err.to_lowercase().contains("panic"),
        "command panicked instead of returning an error: {err}"
    );
}

/// The server accepts the connection but never answers; the client's own
/// (short, test-only - see `point_at`) timeout must fire well under the
/// real app's 30s default.
#[tokio::test]
#[serial]
async fn an_unresponsive_server_times_out_quickly() {
    point_at(&spawn_silent().await);
    let start = std::time::Instant::now();
    let err = crate::commands::settings::get_config().await.unwrap_err();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "took {:?} - the test timeout override did not take effect",
        start.elapsed()
    );
    assert!(!err.is_empty());
}
