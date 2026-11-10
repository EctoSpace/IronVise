//! App plumbing: the embedded server's address and token, demo mode,
//! developer tools and the allowlisted Developer Hub commands.

#[allow(unused_imports)]
use super::*;

/// Expose a **read-only (auditor-role)** token to the Svelte frontend so it
/// can construct authenticated EventSource URLs for the SSE stream
/// (EventSource does not support custom headers, so the token must be passed
/// as ?token=). The admin bootstrap token is never handed to the frontend -
/// admin operations go through the Rust IPC proxy commands, which attach it
/// server-side via `auth_headers()`.
#[tauri::command]
pub async fn observer_token() -> String {
    if let Some(s) = embedded::instance() {
        return s.stream_token.clone();
    }
    // External-host mode (ECTO_HOST): no embedded server, fall back to the
    // operator-provided token.
    std::env::var("OBSERVER_TOKEN").unwrap_or_default()
}

#[tauri::command]
pub async fn server_url() -> String {
    base_url()
}

#[tauri::command]
pub async fn is_demo_mode() -> bool {
    ectoledger::config::is_demo_mode()
}

#[tauri::command]
pub async fn reset_demo_data() -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .post(format!("{}/api/admin/reset-demo", base_url()))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| format!("Cannot reach backend: {e}"))?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!("Reset failed: {}", sanitize_error_body(&msg)));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn open_devtools<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<(), String> {
    #[cfg(debug_assertions)]
    {
        let window = app
            .get_webview_window("main")
            .ok_or("Main window not found")?;
        window.open_devtools();
        Ok(())
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = app;
        Err("DevTools are disabled in release builds".to_string())
    }
}

/// Returns the full dashboard URL (without auth token) for "Open full dashboard" link.
/// The auth token must not be appended as a query parameter, to avoid leaking
/// it in Referrer headers, server logs, and the DOM. The iframe uses the
/// Tauri proxy commands instead.
#[tauri::command]
pub async fn dashboard_url() -> String {
    base_url()
}

// Security: only allowlisted commands are permitted to prevent RCE via compromised frontend.

const ALLOWED_DEV_COMMANDS: &[(&str, Option<&str>)] = &[
    (
        "python -m pip install -e \".[langchain,autogen]\" && python -m pytest tests/",
        Some("sdk/python"),
    ),
    ("npm ci && npm run build", Some("sdk/typescript")),
    ("cargo test -p ectoledger", None),
];

#[derive(serde::Deserialize)]
// A misnamed field must fail, not vanish (see ipc_contract_tests).
#[serde(deny_unknown_fields)]
pub struct RunShellCommandArgs {
    pub cmd: String,
    pub cwd: Option<String>,
}

#[derive(serde::Serialize)]
pub struct RunShellCommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

#[derive(Clone, serde::Serialize)]
pub struct ShellCommandStreamPayload {
    pub line: String,
    pub stream: String,
}

/// The (program, argv) pair that runs `cmd` through the platform shell: `sh
/// -c` everywhere `executor.rs`'s own allowlisted-command spawner runs
/// `cmd.exe /C` for CMD builtins - `sh` does not exist on Windows, and `cmd
/// /C` (unlike PowerShell 5.1, the Windows default) understands the `&&`
/// chaining every entry in `ALLOWED_DEV_COMMANDS` uses. Kept pure (no
/// spawning) so the choice can be unit-tested on every OS.
fn shell_invocation(cmd: &str) -> (&'static str, Vec<String>) {
    if cfg!(windows) {
        ("cmd", vec!["/C".to_string(), cmd.to_string()])
    } else {
        ("sh", vec!["-c".to_string(), cmd.to_string()])
    }
}

/// Builds the spawnable shell command for `cmd`. On Windows the command line is
/// handed to `cmd /S /C "…"` verbatim via `raw_arg`: std's argument escaping
/// would turn every embedded `"` into `\"`, which `cmd.exe` does not unescape.
fn shell_command(cmd: &str) -> tokio::process::Command {
    let (program, args) = shell_invocation(cmd);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut builder = std::process::Command::new(program);
        builder.raw_arg(format!("/S {} \"{cmd}\"", args[0]));
        tokio::process::Command::from(builder)
    }
    #[cfg(not(windows))]
    {
        let mut builder = tokio::process::Command::new(program);
        builder.args(&args);
        builder
    }
}

/// Runs an allowlisted shell command and streams stdout/stderr to the frontend via "shell-command-output" events.
#[tauri::command]
pub async fn run_shell_command_streaming<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    args: RunShellCommandArgs,
) -> Result<RunShellCommandResult, String> {
    let allowed = ALLOWED_DEV_COMMANDS
        .iter()
        .find(|(cmd, cwd)| *cmd == args.cmd && *cwd == args.cwd.as_deref());
    if allowed.is_none() {
        return Err("Command not in allowlist".to_string());
    }

    use std::process::Stdio;
    use tokio::io::AsyncBufReadExt;

    let mut builder = shell_command(&args.cmd);
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(ref dir) = args.cwd {
        builder.current_dir(dir);
    }
    let mut child = builder
        .spawn()
        .map_err(|e| format!("Failed to run command: {e}"))?;

    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;

    let app_out = app.clone();
    let app_err = app.clone();

    let out_task = tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stdout).lines();
        let mut acc = String::new();
        while let Ok(Some(line)) = reader.next_line().await {
            acc.push_str(&line);
            acc.push('\n');
            let _ = app_out.emit(
                "shell-command-output",
                ShellCommandStreamPayload {
                    line,
                    stream: "stdout".to_string(),
                },
            );
        }
        acc
    });

    let err_task = tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stderr).lines();
        let mut acc = String::new();
        while let Ok(Some(line)) = reader.next_line().await {
            acc.push_str(&line);
            acc.push('\n');
            let _ = app_err.emit(
                "shell-command-output",
                ShellCommandStreamPayload {
                    line,
                    stream: "stderr".to_string(),
                },
            );
        }
        acc
    });

    let (out_res, err_res) = tokio::join!(out_task, err_task);
    let stdout_acc = out_res.map_err(|e| format!("stdout task: {e}"))?;
    let stderr_acc = err_res.map_err(|e| format!("stderr task: {e}"))?;

    let status = child
        .wait()
        .await
        .map_err(|e| format!("wait failed: {e}"))?;
    let exit_code = status.code();

    Ok(RunShellCommandResult {
        stdout: stdout_acc,
        stderr: stderr_acc,
        exit_code,
    })
}

#[cfg(test)]
mod shell_invocation_tests {
    use super::{ALLOWED_DEV_COMMANDS, shell_invocation};

    #[test]
    fn picks_the_shell_that_exists_on_this_platform() {
        let (program, args) = shell_invocation("echo hi && echo bye");
        if cfg!(windows) {
            assert_eq!(program, "cmd");
            assert_eq!(args, vec!["/C", "echo hi && echo bye"]);
        } else {
            assert_eq!(program, "sh");
            assert_eq!(args, vec!["-c", "echo hi && echo bye"]);
        }
    }

    /// Every allowlisted command arrives as a single argv element, with its
    /// `&&` and embedded quotes intact - the shell, not argv splitting, is
    /// what has to parse it.
    #[test]
    fn allowlisted_commands_survive_as_one_argument() {
        for (cmd, _) in ALLOWED_DEV_COMMANDS {
            let (_, args) = shell_invocation(cmd);
            assert_eq!(args.len(), 2, "{cmd}");
            assert_eq!(&args[1], cmd);
        }
    }

    #[cfg(windows)]
    #[test]
    fn embedded_double_quotes_reach_cmd_unmangled() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let output = runtime
            .block_on(super::shell_command(r#"echo "[langchain,autogen]" && echo done"#).output())
            .expect("spawn shell");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(r#""[langchain,autogen]""#), "{stdout:?}");
        assert!(stdout.contains("done"), "{stdout:?}");
    }
}

/// Matches the native title bar and window chrome to the theme the app
/// shows: `"dark"`, `"light"`, or `"system"` to follow the OS.
#[tauri::command]
pub async fn set_window_theme<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    theme: String,
) -> Result<(), String> {
    let theme = match theme.as_str() {
        "dark" => Some(tauri::Theme::Dark),
        "light" => Some(tauri::Theme::Light),
        "system" => None,
        other => return Err(format!("unknown theme {other:?}")),
    };
    let window = app
        .get_webview_window("main")
        .ok_or("Main window not found")?;
    window.set_theme(theme).map_err(|e| e.to_string())
}
