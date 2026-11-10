//! Running a command in a network-isolated Docker or Podman container.

use super::*;

/// Which container CLI to use.
#[derive(Clone, Debug)]
pub enum DockerRuntime {
    /// Use `docker` (Docker Engine / Docker Desktop).
    Docker,
    /// Use `podman` (rootless-capable OCI runtime).
    Podman,
    /// Detect at runtime: prefer `podman` when available, fall back to `docker`.
    Auto,
}

impl DockerRuntime {
    /// Resolve to the concrete binary name to invoke.
    pub fn binary(&self) -> &'static str {
        match self {
            DockerRuntime::Docker => "docker",
            DockerRuntime::Podman => "podman",
            DockerRuntime::Auto => {
                if std::process::Command::new("podman")
                    .arg("--version")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
                {
                    "podman"
                } else {
                    "docker"
                }
            }
        }
    }
}

/// Configuration for the Docker/Podman container sandbox.
///
/// When configured, `run_command` intents are executed inside an ephemeral, unprivileged
/// container with no network access, strict memory and CPU limits, and a read-only
/// root filesystem.  This provides cross-platform isolation (Linux, macOS, Windows)
/// wherever Docker Desktop or a podman socket is available.
///
/// # Configuration via environment variables
///
/// | Variable                   | Default          | Description                           |
/// |----------------------------|------------------|---------------------------------------|
/// | `ECTO_DOCKER_IMAGE`    | `alpine:3.19`    | Container image to use                |
/// | `ECTO_DOCKER_MEMORY`   | `256m`           | Memory limit (`--memory`)             |
/// | `ECTO_DOCKER_CPUS`     | `1`              | CPU quota (`--cpus`)                  |
/// | `ECTO_DOCKER_TIMEOUT`  | `30`             | Execution timeout in seconds          |
/// | `ECTO_DOCKER_RUNTIME`  | `auto`           | `auto`, `docker`, or `podman`         |
#[derive(Clone, Debug)]
pub struct DockerConfig {
    /// Container image (must be pre-pulled on the host).
    pub image: String,
    /// Memory limit string passed to `--memory` (e.g. `"256m"`, `"1g"`).
    pub memory: String,
    /// CPU quota passed to `--cpus` (e.g. `"1"`, `"0.5"`).
    pub cpus: String,
    /// Hard execution timeout in seconds.
    pub timeout_secs: u64,
    /// Which container CLI to use.
    pub runtime: DockerRuntime,
}

impl Default for DockerConfig {
    fn default() -> Self {
        DockerConfig {
            image: "alpine:3.19".to_string(),
            memory: "256m".to_string(),
            cpus: "1".to_string(),
            timeout_secs: 30,
            runtime: DockerRuntime::Auto,
        }
    }
}

impl DockerConfig {
    /// Build from environment variables, falling back to `Self::default()`.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("ECTO_DOCKER_IMAGE") {
            cfg.image = v;
        }
        if let Ok(v) = std::env::var("ECTO_DOCKER_MEMORY") {
            cfg.memory = v;
        }
        if let Ok(v) = std::env::var("ECTO_DOCKER_CPUS") {
            cfg.cpus = v;
        }
        if let Ok(v) = std::env::var("ECTO_DOCKER_TIMEOUT")
            && let Ok(n) = v.parse::<u64>()
        {
            cfg.timeout_secs = n;
        }
        if let Ok(v) = std::env::var("ECTO_DOCKER_RUNTIME") {
            cfg.runtime = match v.to_lowercase().as_str() {
                "docker" => DockerRuntime::Docker,
                "podman" => DockerRuntime::Podman,
                _ => DockerRuntime::Auto,
            };
        }
        cfg
    }

    /// Return `Some(Self::from_env())` when `ECTO_DOCKER_IMAGE` is set (opt-in),
    /// `None` otherwise (Docker sandbox disabled by default).
    pub fn from_env_opt() -> Option<Self> {
        if std::env::var("ECTO_DOCKER_IMAGE").is_ok() {
            Some(Self::from_env())
        } else {
            None
        }
    }
}

/// A shell metacharacter in `cmd`, if `sh -c` would act on it.
///
/// Longer operators are listed first so `&&` is reported as `&&` rather than
/// `&`. Bare `&` is included: under `sh -c` it backgrounds a second command,
/// and the tripwire allows it inside a token because the host executor does
/// not use a shell. This path does.
pub(crate) fn shell_metacharacter(cmd: &str) -> Option<&'static str> {
    const DANGEROUS_PATTERNS: &[&str] = &[
        ";", "&&", "||", "&", "|", "`", "$(", "${", ">>", ">", "<", "\n", "\r",
    ];
    DANGEROUS_PATTERNS
        .iter()
        .copied()
        .find(|pat| cmd.contains(pat))
}

/// Execute a validated `run_command` intent inside an ephemeral container.
///
/// The container is started with:
/// - `--rm`            - auto-removed on exit
/// - `--network=none`  - no network access
/// - `--memory`        - capped per `config.memory`
/// - `--cpus`          - capped per `config.cpus`
/// - `--read-only`     - immutable root filesystem
/// - `--security-opt no-new-privileges` - prevents privilege escalation
/// - `--user nobody`   - drop to unprivileged user
///
/// The command string from `intent_json["params"]["command"]` is passed directly to
/// `sh -c` inside the container.  Only `run_command` intents are handled; any other
/// action returns `SandboxError::Io` so the caller can fall back to the host executor.
pub async fn run_in_docker(
    config: &DockerConfig,
    intent_json: &str,
) -> Result<String, SandboxError> {
    use std::time::Duration;
    use tokio::process::Command;

    // Extract the command from the intent JSON.
    let intent: serde_json::Value = serde_json::from_str(intent_json).map_err(|e| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("intent JSON parse error: {e}"),
        ))
    })?;

    let action = intent.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action != "run_command" {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "Docker sandbox only handles run_command, got '{action}': falling back to host executor"
            ),
        )));
    }

    let cmd_str = intent["params"]["command"].as_str().ok_or_else(|| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "run_command intent missing params.command",
        ))
    })?;

    // Defence-in-depth: reject shell metacharacters at the sandbox boundary
    // regardless of whether the tripwire already checked them.  This prevents
    // any future code path from calling `run_in_docker` without upstream
    // sanitisation. The check is not quote-aware, matching the other patterns.
    if let Some(pat) = shell_metacharacter(cmd_str) {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Docker sandbox: shell metacharacter '{}' blocked in command (defence-in-depth)",
                pat.escape_default()
            ),
        )));
    }

    let binary = config.runtime.binary();

    // Verify the container CLI is reachable before attempting to run.
    let version_check = std::process::Command::new(binary)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if version_check.map(|s| !s.success()).unwrap_or(true) {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Container runtime '{binary}' not found or not responding. \
                 Install Docker Desktop or Podman and ensure the daemon is running."
            ),
        )));
    }

    let output = tokio::time::timeout(
        Duration::from_secs(config.timeout_secs),
        Command::new(binary)
            .args([
                "run",
                "--rm",
                "--network=none",
                &format!("--memory={}", config.memory),
                &format!("--cpus={}", config.cpus),
                "--read-only",
                "--security-opt",
                "no-new-privileges",
                "--user",
                "nobody",
                &config.image,
                "sh",
                "-c",
                cmd_str,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "Docker container timed out after {} seconds",
                config.timeout_secs
            ),
        ))
    })?
    .map_err(SandboxError::Io)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format_sandbox_output(
        output.status.code(),
        stdout.trim_end(),
        stderr.trim_end(),
    ))
}
