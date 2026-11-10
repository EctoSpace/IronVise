// setup - Tauri commands for the first-launch wizard.
//
// Exposes: detect_system_state, check_setup_complete, mark_setup_complete;
//          installing Ollama and pulling a model are in `ollama`. (The embedded server migrates the ledger
//          when it starts; there is no separate database command.)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::{Emitter, Manager};

pub mod ollama;

/// System state returned to the frontend for the wizard's detection step.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemState {
    pub os: String,
    pub arch: String,
    pub ram_gb: Option<f64>,
    pub ollama_running: bool,
    pub ollama_installed: bool,
    pub existing_db_path: Option<String>,
    pub recommended_model: String,
}

fn setup_complete_path<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> PathBuf {
    let base = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("setup_complete.json")
}

/// Try to read total RAM via /proc/meminfo (Linux) or sysctl (macOS/BSD).
/// Returns None if detection fails (non-fatal).
fn detect_ram_gb() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                return Some(kb as f64 / 1_048_576.0);
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("hw.memsize")
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let bytes: u64 = s.trim().parse().ok()?;
        Some(bytes as f64 / 1_073_741_824.0)
    }
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell Get-CimInstance (wmic is deprecated on Windows 11+)
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let bytes: u64 = s.trim().parse().ok()?;
        Some(bytes as f64 / 1_073_741_824.0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Detect if Ollama HTTP API is running on the default port.
async fn probe_ollama_http() -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    client
        .get("http://127.0.0.1:11434/api/tags")
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Check if `ollama` is on PATH.
fn ollama_installed() -> bool {
    #[cfg(target_os = "windows")]
    let cmd = "where";
    #[cfg(not(target_os = "windows"))]
    let cmd = "which";
    std::process::Command::new(cmd)
        .arg("ollama")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pick a sensible default model based on available RAM.
fn recommended_model(ram_gb: Option<f64>) -> &'static str {
    match ram_gb {
        Some(r) if r >= 32.0 => "llama3.3:70b-instruct-q4_K_M",
        Some(r) if r >= 8.0 => "llama3.1:8b",
        _ => "llama3.2:3b",
    }
}

/// Detect system capabilities and return them to the wizard.
#[tauri::command]
pub async fn detect_system_state<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<SystemState, String> {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let ram_gb = detect_ram_gb();

    let ollama_running = probe_ollama_http().await;
    let installed = ollama_installed();

    let existing_db = {
        let base = app
            .path()
            .app_data_dir()
            .unwrap_or_else(|_| PathBuf::from("."));
        let db = base.join("ectoledger.db");
        if db.exists() {
            Some(db.to_string_lossy().into_owned())
        } else {
            None
        }
    };

    let model = recommended_model(ram_gb).to_string();

    Ok(SystemState {
        os,
        arch,
        ram_gb,
        ollama_running,
        ollama_installed: installed,
        existing_db_path: existing_db,
        recommended_model: model,
    })
}

/// Return true if the first-launch wizard has already been completed.
///
/// Also returns true (and auto-writes the marker) when Ollama is already
/// running on the default port - meaning the system is fully configured and
/// the wizard would be a no-op.  This prevents the wizard from appearing on
/// every launch for users who set up manually or via `ectoledger-mac`.
///
/// The env var `ECTO_FORCE_SETUP=1` suppresses the auto-detect so that
/// `./ectoledger-mac --setup` can force the wizard to appear even when Ollama
/// is running.
#[tauri::command]
pub async fn check_setup_complete<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> bool {
    // --setup path: the launcher sets this env var to prevent us from
    // auto-detecting a configured system and re-skipping the wizard.
    if std::env::var("ECTO_FORCE_SETUP")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return false;
    }

    // Fast path: marker file already written.
    if setup_complete_path(&app).exists() {
        return true;
    }

    // Auto-detect: if Ollama is reachable the system is effectively configured.
    // Write the marker so the wizard never appears again.
    let ollama_ok = probe_ollama_http().await;

    // Also accept OpenAI-style setups: if OPENAI_API_KEY or LLM_BACKEND=openai
    // is set in the environment the user consciously chose a cloud backend.
    let openai_ok = ectoledger::llm::api_key::resolve("OPENAI_API_KEY").is_some()
        || std::env::var("LLM_BACKEND")
            .map(|v| v.trim().eq_ignore_ascii_case("openai"))
            .unwrap_or(false);

    if ollama_ok || openai_ok {
        // Best-effort: write marker so future launches skip the wizard.
        if let Err(e) = mark_setup_complete(app).await {
            tracing::warn!(
                "Failed to write setup-complete marker: {e}. The setup wizard will re-appear on next launch."
            );
        }
        return true;
    }

    false
}

/// Persist a marker that tells the wizard to skip on next launch.
#[tauri::command]
pub async fn mark_setup_complete<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<(), String> {
    let path = setup_complete_path(&app);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create app data dir: {e}"))?;
    }
    let content = serde_json::json!({
        "completed_at": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION")
    });
    std::fs::write(&path, serde_json::to_string_pretty(&content).unwrap())
        .map_err(|e| format!("Failed to write setup_complete.json: {e}"))
}
