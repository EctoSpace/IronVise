// IronVise GUI - Tauri 2 Rust entry point.
//
// Self-contained desktop application: an embedded Axum server backed by
// SQLite starts automatically during the Tauri `setup` hook.  The Svelte
// front-end communicates via Tauri IPC commands that proxy to the local
// server (see `commands/`).
//
// The tauri.conf.json defines a placeholder window labelled
// "_bundler_placeholder" (visible: false, required for Windows WiX/NSIS
// bundling).  During setup we close it and create the real "main" window
// programmatically so we can inject a CSP with the ephemeral server port.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

mod commands;
mod embedded;
#[cfg(test)]
mod http_error_tests;
#[cfg(test)]
mod ipc_contract_tests;
mod setup;

/// True if the error indicates the SQLite DB is invalid due to a migration mismatch.
fn is_migration_mismatch(err: &(dyn std::error::Error + 'static)) -> bool {
    let msg = err.to_string();
    msg.contains("migration") && (msg.contains("modified") || msg.contains("previously applied"))
}

/// Every command the webview can call. A function so the IPC contract test
/// (`ipc_contract_tests`) registers exactly what the app does.
fn invoke_handler<R: tauri::Runtime>()
-> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        commands::app::set_window_theme,
        commands::sessions::get_sessions,
        commands::sessions::get_session,
        commands::sessions::get_events,
        commands::sessions::run_prompt,
        commands::sessions::get_metrics,
        commands::sessions::get_prometheus_metrics,
        commands::sessions::export_certificate,
        commands::settings::get_config,
        commands::settings::save_config,
        commands::settings::get_ollama_models,
        commands::settings::get_provider_presets,
        commands::settings::get_provider_models,
        commands::settings::test_provider_connection,
        commands::keys::api_key_status,
        commands::keys::set_api_key,
        commands::keys::delete_api_key,
        commands::policy::get_tripwire_config,
        commands::policy::save_tripwire_config,
        commands::policy::check_tripwire,
        commands::policy::get_policies,
        commands::policy::get_policy_content,
        commands::policy::save_policy,
        commands::policy::delete_policy,
        commands::sessions::download_report,
        commands::app::server_url,
        commands::app::is_demo_mode,
        commands::app::reset_demo_data,
        commands::app::dashboard_url,
        commands::app::observer_token,
        commands::app::open_devtools,
        commands::sessions::verify_session_chain,
        // Session VC
        commands::sessions::get_session_vc,
        commands::sessions::verify_session_vc,
        commands::sessions::get_pending_approval,
        commands::sessions::post_approval_decision,
        // Token management
        commands::access::get_tokens,
        commands::access::create_token,
        commands::access::delete_token,
        // Webhook management
        commands::access::get_webhooks,
        commands::access::create_webhook,
        commands::access::delete_webhook,
        commands::access::toggle_webhook,
        // First-launch wizard
        setup::detect_system_state,
        setup::check_setup_complete,
        setup::mark_setup_complete,
        setup::ollama::install_ollama,
        setup::ollama::pull_model,
        // Developer Hub (server-side allowlisted shell commands)
        commands::app::run_shell_command_streaming,
    ]
}

/// The app's context (config, assets, capabilities). Generated once, shared
/// with the IPC contract test: macOS embeds Info.plist per expansion.
fn context<R: tauri::Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

/// The argument the embedded server passes when it starts this executable as
/// its semantic-guard worker (see `ectoledger::guard_process`).
const GUARD_WORKER_ARG: &str = "--guard-worker";

fn main() {
    // Started as the guard worker: run the worker loop on stdin/stdout and
    // exit, before anything of the app starts. The parent passes the HMAC key,
    // settings folder and API keys in this process's environment.
    if std::env::args().nth(1).as_deref() == Some(GUARD_WORKER_ARG) {
        let code = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
            .and_then(|rt| {
                rt.block_on(ectoledger::guard_worker::run())
                    .map_err(|e| e.to_string())
            }) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("guard worker: {e}");
                1
            }
        };
        std::process::exit(code);
    }
    // The desktop bundle has no separate guard-worker executable; the
    // embedded server starts this one with GUARD_WORKER_ARG instead.
    if let Ok(exe) = std::env::current_exe() {
        ectoledger::guard_process::set_worker_command(exe, vec![GUARD_WORKER_ARG.to_string()]);
    }

    // Initialise tracing. The filter names stay crate names (`ectoledger`,
    // `ectoledger_gui`) so RUST_LOG keeps working. The printed target says ironvise.
    ectoledger::logfmt::init_or_default("info,ectoledger=debug,ectoledger_gui=debug");

    // Keys saved in Settings live in the OS credential store; the model
    // backends look there before the environment.
    commands::keys::register();

    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let handle = app.handle().clone();

            // Start the embedded Axum server asynchronously.
            // Tauri 2 runs setup on the async runtime, so we can block on
            // the future directly via `tauri::async_runtime::block_on`.
            let server = match tauri::async_runtime::block_on(embedded::start(&handle)) {
                Ok(s) => s,
                Err(e) => {
                    if is_migration_mismatch(e.as_ref()) {
                        let path = embedded::db_path(&handle);
                        let message = format!(
                            "IronVise could not open its ledger: a migration recorded in it differs from this version's.\n\n\
                            Your data has not been changed. Do not delete the file: it holds every recorded session. \
                            Keep it, and report this with the version you upgraded from:\n\n{}",
                            path.display()
                        );
                        app.dialog()
                            .message(message)
                            .title("IronVise - Invalid database")
                            .kind(MessageDialogKind::Error)
                            .blocking_show();
                        std::process::exit(1);
                    }
                    return Err(format!("Failed to start embedded server: {e}").into());
                }
            };

            tracing::info!(
                port = server.port,
                "Embedded server ready - GUI will connect to http://127.0.0.1:{}",
                server.port
            );

            let port = server.port;

            // Store the server handle in Tauri managed state so commands can
            // read the port / token if needed in the future.
            app.manage(server);

            // The tauri.conf.json defines a placeholder window with label
            // "_bundler_placeholder" (visible: false) to satisfy the Windows
            // WiX/NSIS bundler.  Close it now - it is not needed at runtime.
            if let Some(placeholder) = app.get_webview_window("_bundler_placeholder") {
                let _ = placeholder.destroy();
            }

            let main_window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("IronVise")
                .inner_size(1400.0, 900.0)
                .min_inner_size(1024.0, 640.0)
                // NOTE: `transparent` is NOT set - windows are opaque by default in Tauri 2.
                // The tauri.conf.json "transparent": false ensures the bundler never
                // enables compositor transparency, preventing Linux/Windows DWM glitches.
                .center()
                // Shown once the page has painted, so the native background
                // (white or black, whatever the OS picks) never flashes
                // before the theme. A page that never finishes loading still
                // gets a window, after a few seconds.
                .visible(false)
                .on_page_load(|window, payload| {
                    if payload.event() == tauri::webview::PageLoadEvent::Finished {
                        let _ = window.show();
                    }
                })
                .on_web_resource_request(move |_request: tauri::http::Request<Vec<u8>>, response: &mut tauri::http::Response<std::borrow::Cow<'static, [u8]>>| {
                    // Inject CSP on text/html responses (the Tauri entry
                    // document).  The browser then enforces this policy for
                    // all resources loaded by that document.
                    let is_html = response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.contains("text/html"))
                        .unwrap_or(false);

                    if is_html {
                        let csp = format!(
                            "default-src 'self'; \
                             connect-src 'self' http://127.0.0.1:{port}; \
                             script-src 'self'; \
                             style-src 'self' 'unsafe-inline'; \
                             font-src 'self'; \
                             frame-src 'self' http://127.0.0.1:{port}; \
                             img-src 'self' data:",
                        );
                        if let Ok(val) = csp.parse() {
                            response
                                .headers_mut()
                                .insert("content-security-policy", val);
                        }
                    }
                })
                .build()
                .map_err(|e| format!("Failed to create main window: {e}"))?;
            let window = main_window.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                if !window.is_visible().unwrap_or(true) {
                    let _ = window.show();
                }
            });

            Ok(())
        })
        .invoke_handler(invoke_handler())
        .run(context())
        .unwrap_or_else(|e| {
            eprintln!("Fatal: IronVise GUI failed to start: {e}");
            std::process::exit(1);
        });
}
