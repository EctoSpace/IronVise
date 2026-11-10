//! Installing Ollama and pulling a model, for the wizard's provisioning step.

#[allow(unused_imports)]
use super::*;

/// URL of the official Ollama install script.
///
/// Every use sits in a `#[cfg(not(target_os = "windows"))]` block - Windows
/// installs through winget instead - so the constant carries the same gate.
/// Without it the constant is dead code on Windows, which CI compiles with
/// `-D warnings` and therefore fails.
#[cfg(not(target_os = "windows"))]
const OLLAMA_INSTALL_URL: &str = "https://ollama.com/install.sh";

/// A directory only the current user can enter, created under a random name
/// and removed on drop.
#[cfg(not(target_os = "windows"))]
struct PrivateDir(PathBuf);

#[cfg(not(target_os = "windows"))]
impl PrivateDir {
    /// Fails if the path already exists, so a pre-planted directory or symlink
    /// is never adopted.
    fn create_in(base: &std::path::Path) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let path = base.join(format!(
            "ectoledger-ollama-{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    /// Write an owner-only executable script; refuses to overwrite.
    fn write_script(&self, contents: &str) -> std::io::Result<PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.0.join("install.sh");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)?
            .write_all(contents.as_bytes())?;
        Ok(path)
    }
}

#[cfg(not(target_os = "windows"))]
impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Install Ollama using the platform-appropriate method.
/// Emits "install_ollama_progress" events with { line: String }.
///
/// The user must explicitly confirm a dialog that names the exact source
/// before anything is downloaded or executed. On non-Windows platforms the
/// install script is downloaded over TLS into a private, single-use directory
/// and executed from there, so no other local user can swap it between the
/// download and the run.
///
/// The script is not checked against a checksum or signature: none is pinned
/// here, so trust in its contents rests on the TLS connection to ollama.com
/// and on the user's confirmation above.
#[tauri::command]
pub async fn install_ollama<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let source_desc = "the 'Ollama.Ollama' package via winget (Microsoft's package manager)";
    #[cfg(not(target_os = "windows"))]
    let source_desc = OLLAMA_INSTALL_URL;

    // Explicit consent, showing exactly what will be downloaded and executed.
    let confirmed = {
        let app2 = app.clone();
        let message = format!(
            "IronVise will download and run the Ollama installer from:\n\n{source_desc}\n\nContinue?"
        );
        tokio::task::spawn_blocking(move || {
            use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
            app2.dialog()
                .message(message)
                .title("Install Ollama")
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom(
                    "Install".to_string(),
                    "Cancel".to_string(),
                ))
                .blocking_show()
        })
        .await
        .map_err(|e| format!("Ollama install confirmation dialog failed: {e}"))?
    };
    if !confirmed {
        return Err("Ollama installation cancelled by user.".to_string());
    }

    #[cfg(target_os = "windows")]
    let mut child = std::process::Command::new("winget")
        .args(["install", "Ollama.Ollama"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to launch Ollama installer: {e}"))?;

    #[cfg(not(target_os = "windows"))]
    let script_dir = PrivateDir::create_in(&std::env::temp_dir())
        .map_err(|e| format!("Failed to create private install directory: {e}"))?;

    #[cfg(not(target_os = "windows"))]
    let mut child = {
        let script = reqwest::get(OLLAMA_INSTALL_URL)
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("Failed to download {OLLAMA_INSTALL_URL}: {e}"))?
            .text()
            .await
            .map_err(|e| format!("Failed to read Ollama install script: {e}"))?;
        let script_path = script_dir
            .write_script(&script)
            .map_err(|e| format!("Failed to write install script: {e}"))?;
        tracing::info!(
            "install_ollama: downloaded {} ({} bytes) to {}",
            OLLAMA_INSTALL_URL,
            script.len(),
            script_path.display()
        );
        std::process::Command::new("sh")
            .arg(&script_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to launch Ollama installer: {e}"))?
    };

    use std::io::{BufRead, BufReader};
    if let Some(stdout) = child.stdout.take() {
        let app2 = app.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = app2.emit(
                    "install_ollama_progress",
                    serde_json::json!({ "line": line }),
                );
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let app3 = app.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = app3.emit(
                    "install_ollama_progress",
                    serde_json::json!({ "line": line, "stderr": true }),
                );
            }
        });
    }

    let status = child
        .wait()
        .map_err(|e| format!("Ollama installer wait failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Ollama installer exited with status: {status}"))
    }
}

const MAX_MODEL_NAME_LEN: usize = 128;

/// Accept `[host/][namespace/]name[:tag]`, e.g. `llama3.2:3b` or
/// `hf.co/Org/Repo-GGUF:Q4_K_M`. The name comes from the webview and is passed
/// to `ollama pull` as an argument, so anything that could read as an option
/// (leading `-`) or carry shell syntax is refused.
fn validate_model_name(name: &str) -> Result<(), String> {
    let invalid = |why: &str| Err(format!("Invalid model name '{name}': {why}"));
    if name.is_empty() || name.len() > MAX_MODEL_NAME_LEN {
        return invalid(&format!("must be 1-{MAX_MODEL_NAME_LEN} characters"));
    }
    if name.starts_with('-') {
        return invalid("must not start with '-'");
    }
    let (repo, tag) = match name.split_once(':') {
        Some((repo, tag)) => (repo, Some(tag)),
        None => (name, None),
    };
    let repo_ok = repo.split('/').count() <= 3
        && repo.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    if !repo_ok {
        return invalid("expected [host/][namespace/]name in letters, digits, '.', '_' and '-'");
    }
    let tag_ok = tag.is_none_or(|t| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    });
    if !tag_ok {
        return invalid("tag may only contain letters, digits, '.', '_' and '-'");
    }
    Ok(())
}

/// Pull an Ollama model, streaming progress via "pull_model_progress" events.
#[tauri::command]
pub async fn pull_model<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    model_name: String,
) -> Result<(), String> {
    validate_model_name(&model_name)?;
    let mut child = std::process::Command::new("ollama")
        .args(["pull", &model_name])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run 'ollama pull {model_name}': {e}"))?;

    use std::io::{BufRead, BufReader};
    if let Some(stdout) = child.stdout.take() {
        let app2 = app.clone();
        let model = model_name.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = app2.emit(
                    "pull_model_progress",
                    serde_json::json!({ "model": model, "line": line }),
                );
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let app3 = app.clone();
        let model2 = model_name.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = app3.emit(
                    "pull_model_progress",
                    serde_json::json!({ "model": model2, "line": line, "stderr": true }),
                );
            }
        });
    }

    let status = child
        .wait()
        .map_err(|e| format!("ollama pull wait failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ollama pull '{model_name}' exited with status: {status}"
        ))
    }
}

#[cfg(test)]
mod tests;
