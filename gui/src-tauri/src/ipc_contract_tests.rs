//! IPC contract: every command the webview calls accepts the arguments the
//! webview sends.
//!
//! The Playwright suite mocks `invoke`, so it never deserializes a Rust
//! argument struct: a struct reading `base_url` while the webview sends
//! `baseUrl` loses the field silently, and every GUI test still passes. Tauri
//! renames top-level arguments from camelCase but not the fields of a struct
//! argument.
//!
//! Each case below is the exact JSON a call site in `gui/src` sends. It goes
//! through the real IPC path (`tauri::test`) against the app's own handler.
//! A wrong argument fails with "invalid args"; anything else (here, mostly
//! "connection refused", because the backend is pointed at a closed port) means
//! the arguments were accepted. `every_invoked_command_has_a_case` scans the
//! Svelte sources, so a new call site cannot skip this table.

use serde_json::{Value, json};
use serial_test::serial;
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{INVOKE_KEY, get_ipc_response, mock_builder};
use tauri::webview::InvokeRequest;

/// The origin the app's own pages have, which the capabilities (ACL) allow:
/// `tauri://localhost` on macOS and Linux, `http://tauri.localhost` on
/// Windows (WebView2). Any other origin is refused as "not allowed".
const APP_ORIGIN: &str = if cfg!(windows) {
    "http://tauri.localhost"
} else {
    "tauri://localhost"
};

/// A port nothing listens on, so no case reaches a real backend or provider.
const CLOSED: &str = "http://127.0.0.1:1";

/// (command, arguments exactly as the webview sends them).
fn cases() -> Vec<(&'static str, Value)> {
    vec![
        // Sessions, Dashboard, ObserverPanel, TestingView, backend.ts
        (
            "get_sessions",
            json!({ "status": null, "limit": 100, "offset": 0 }),
        ),
        ("get_session", json!({ "sessionId": "s" })),
        ("get_events", json!({ "sessionId": "s" })),
        ("run_prompt", json!({ "args": { "goal": "g" } })),
        ("get_metrics", json!({})),
        ("get_prometheus_metrics", json!({})),
        ("export_certificate", json!({ "sessionId": "s" })),
        ("download_report", json!({ "sessionId": "s" })),
        ("verify_session_chain", json!({ "sessionId": "s" })),
        ("get_session_vc", json!({ "sessionId": "s" })),
        ("verify_session_vc", json!({ "sessionId": "s" })),
        (
            "post_approval_decision",
            json!({ "sessionId": "s", "gateId": "g", "approved": true, "reason": null }),
        ),
        // Settings, SetupWizard
        ("get_config", json!({})),
        (
            "save_config",
            json!({ "payload": {
                "database_url": "", "llm_backend": "ollama", "ollama_base_url": "",
                "openai_base_url": "", "ollama_model": "m", "guard_required": true,
                "guard_llm_backend": "", "guard_llm_model": "", "max_steps": 20,
                "show_developer_tools": false
            } }),
        ),
        (
            "get_ollama_models",
            json!({ "args": { "baseUrlOverride": CLOSED } }),
        ),
        ("set_window_theme", json!({ "theme": "dark" })),
        ("get_provider_presets", json!({})),
        (
            "get_provider_models",
            json!({ "args": { "provider": "ollama", "baseUrl": CLOSED, "apiKey": null } }),
        ),
        (
            "test_provider_connection",
            json!({ "args": { "provider": "ollama", "baseUrl": CLOSED, "apiKey": null } }),
        ),
        ("api_key_status", json!({ "name": "ANTHROPIC_API_KEY" })),
        // Tripwire, Policy
        ("get_tripwire_config", json!({})),
        (
            "save_tripwire_config",
            json!({ "payload": {
                "allowed_paths": [], "allowed_domains": [], "banned_command_patterns": [],
                "min_justification_length": 5, "require_https": true
            } }),
        ),
        (
            "check_tripwire",
            json!({ "intent": { "action": "run_command", "params": { "command": "ls" } } }),
        ),
        ("get_policies", json!({})),
        ("get_policy_content", json!({ "name": "p" })),
        ("save_policy", json!({ "name": "p", "content": "c" })),
        ("delete_policy", json!({ "name": "p" })),
        // Access
        ("get_tokens", json!({})),
        (
            "create_token",
            json!({ "label": "l", "role": "agent", "expiryDays": 30 }),
        ),
        ("delete_token", json!({ "tokenHash": "h" })),
        ("get_webhooks", json!({})),
        (
            "create_webhook",
            json!({ "label": "l", "url": "https://example.org/h", "bearerToken": null,
                    "siemFormat": "json", "filterKinds": [], "enabled": true }),
        ),
        ("delete_webhook", json!({ "webhookId": "w" })),
        (
            "toggle_webhook",
            json!({ "webhookId": "w", "enabled": false }),
        ),
        // App plumbing
        ("server_url", json!({})),
        ("dashboard_url", json!({})),
        ("observer_token", json!({})),
        ("is_demo_mode", json!({})),
        ("reset_demo_data", json!({})),
    ]
}

/// Commands the webview calls that this test does not invoke, and why. Their
/// arguments are plain top-level values, which Tauri renames itself.
const NOT_INVOKED: &[(&str, &str)] = &[
    ("install_ollama", "downloads and runs the Ollama installer"),
    ("pull_model", "pulls a model into the local Ollama"),
    (
        "mark_setup_complete",
        "writes the setup marker into the app data folder",
    ),
    // Neither takes webview arguments; both reach the real app data folder
    // (check_setup_complete writes the setup marker when Ollama answers).
    (
        "check_setup_complete",
        "may write the setup marker into the app data folder",
    ),
    (
        "detect_system_state",
        "reads the real app data folder and probes Ollama",
    ),
    ("open_devtools", "needs a real webview"),
    ("run_shell_command_streaming", "runs a command"),
    ("set_api_key", "writes to the OS credential store"),
    ("delete_api_key", "deletes from the OS credential store"),
];

#[test]
#[serial]
fn the_webview_s_arguments_are_accepted() {
    // SAFETY: set before the app starts and read only by the commands below.
    // #[serial] (shared with `http_error_tests`, the other suite that points
    // commands at ECTO_HOST) keeps this from racing a case there that expects
    // a different mock server.
    unsafe { std::env::set_var("ECTO_HOST", CLOSED) };
    // The mock app resolves the real app data folder from HOME (macOS) or
    // XDG_DATA_HOME (Linux) and would create it on the developer's machine.
    // Point both at a scratch folder first.
    let scratch = std::env::temp_dir().join(format!("ecto-ipc-test-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch home");
    // SAFETY: as above, before the app starts.
    unsafe {
        std::env::set_var("HOME", &scratch);
        std::env::set_var("XDG_DATA_HOME", scratch.join("data"));
        std::env::set_var("XDG_CONFIG_HOME", scratch.join("config"));
    }
    let app = mock_builder()
        .invoke_handler(crate::invoke_handler())
        // The app's own context, so its capabilities (ACL) apply as they do
        // in the shipped app.
        .build(crate::context())
        .expect("mock app");
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("mock webview");

    let mut refused = Vec::new();
    for (cmd, args) in cases() {
        let res = get_ipc_response(
            &webview,
            InvokeRequest {
                cmd: cmd.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: APP_ORIGIN.parse().unwrap(),
                body: InvokeBody::Json(args),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.to_string(),
            },
        );
        if let Err(e) = res {
            let msg = e.to_string();
            if msg.contains("invalid args") || msg.contains("missing required key") {
                refused.push(format!("{cmd}: {msg}"));
            }
            assert!(
                !msg.contains("not found"),
                "{cmd} is not registered in invoke_handler: {msg}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(
        refused.is_empty(),
        "commands refused the webview's arguments:\n{}",
        refused.join("\n")
    );
}

/// Every `invoke("name"` in `gui/src` has a case above or a reason not to.
#[test]
fn every_invoked_command_has_a_case() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../src");
    let mut invoked = std::collections::BTreeSet::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("svelte" | "ts")
            ) {
                let text = std::fs::read_to_string(&path).unwrap();
                let mut rest = text.as_str();
                while let Some(at) = rest.find("invoke") {
                    rest = &rest[at + "invoke".len()..];
                    // invoke("x" or invoke<T>("x"; skip the type argument.
                    let after = rest.trim_start_matches(|c: char| c != '(' && c != '\n');
                    if let Some(call) = after.strip_prefix("(\"") {
                        let name: String = call
                            .chars()
                            .take_while(|c| c.is_ascii_lowercase() || *c == '_')
                            .collect();
                        if !name.is_empty() && call[name.len()..].starts_with('"') {
                            invoked.insert(name);
                        }
                    }
                }
            }
        }
    }
    let known: std::collections::BTreeSet<&str> = cases()
        .iter()
        .map(|(c, _)| *c)
        .chain(NOT_INVOKED.iter().map(|(c, _)| *c))
        .collect();
    let missing: Vec<_> = invoked
        .iter()
        .filter(|c| !known.contains(c.as_str()))
        .collect();
    assert!(
        invoked.len() > 30,
        "found only {} invoke calls",
        invoked.len()
    );
    assert!(
        missing.is_empty(),
        "invoked from gui/src but not covered by ipc_contract_tests: {missing:?}"
    );
}

/// The visual suite's mock answers `get_provider_presets` from its own table,
/// so a preset added or changed on the Rust side would leave every GUI test
/// passing against stale data. The table must equal what the app returns.
#[test]
fn the_visual_mock_returns_the_real_provider_presets() {
    let mock = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/visual/tauri-mock.ts"),
    )
    .expect("tauri-mock.ts is readable");
    let table = mock
        .split_once("get_provider_presets: [")
        .and_then(|(_, rest)| rest.split_once("\n  ],"))
        .map(|(rows, _)| rows)
        .expect("tauri-mock.ts has a get_provider_presets table");
    const KEYS: [&str; 7] = [
        "id",
        "label",
        "transport",
        "default_base_url",
        "default_model",
        "api_key_env",
        "api_key_required",
    ];
    let mocked: Vec<Value> = table
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('{'))
        .map(|line| {
            let mut json_line = line.trim_end_matches(',').to_string();
            for key in KEYS {
                json_line = json_line.replace(&format!("{key}:"), &format!("\"{key}\":"));
            }
            serde_json::from_str(&json_line)
                .unwrap_or_else(|e| panic!("mock preset row is not plain data ({e}): {line}"))
        })
        .collect();
    let real = serde_json::to_value(crate::commands::settings::get_provider_presets())
        .expect("presets serialize");
    assert_eq!(Value::Array(mocked), real);
}
