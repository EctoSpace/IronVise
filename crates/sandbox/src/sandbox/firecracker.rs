//! Running a command in an ephemeral Firecracker microVM (Linux, KVM).

use super::*;

/// Configuration for the Firecracker microVM execution sandbox.
///
/// Firecracker provides hardware-level isolation via KVM: each `run_command` intent
/// is executed inside an ephemeral microVM that is destroyed after the command
/// completes.  This prevents host breakouts caused by prompt-injection attacks that
/// exploit the child-process execution surface.
///
/// # Prerequisites (Linux + KVM only)
/// - The `sandbox-firecracker` Cargo feature must be enabled.
/// - A Firecracker binary (≥ 1.5) must be available at `firecracker_binary_path`.
/// - A minimal Linux kernel image (`vmlinux`) at `kernel_image_path`.
/// - A root filesystem image (`rootfs.ext4`) at `rootfs_path`.  The guest init must
///   read `/dev/vdb` (the intent block device), execute the requested command, and
///   write its output back to the serial console (ttyS0), which Firecracker exposes
///   as the process's stdout.
///
/// # Graceful degradation
/// When the `sandbox-firecracker` feature is absent, or on non-Linux platforms,
/// `run_in_firecracker()` returns `SandboxError::Io` with an explanatory message
/// so callers can fall back to the standard executor.
#[derive(Clone, Debug)]
pub struct FirecrackerConfig {
    /// Path to the `firecracker` binary.
    pub firecracker_binary_path: std::path::PathBuf,
    /// Path to the Linux kernel image (`vmlinux` ELF or `Image` format).
    pub kernel_image_path: std::path::PathBuf,
    /// Path to the root filesystem ext4 image.
    pub rootfs_path: std::path::PathBuf,
    /// Number of vCPUs to give the microVM (default: 1).
    pub vcpu_count: u8,
    /// Memory in MiB to give the microVM (default: 128).
    pub mem_mib: u32,
    /// Hard timeout for the microVM execution in seconds (default: 30).
    pub timeout_secs: u64,
    /// Outer timeout wrapping the *entire* Firecracker attempt - including
    /// pre-launch IO (tmpdir creation, config serialization, intent file
    /// writes) - not just the `Command::new().output()` call.  If the pre-
    /// launch phase or a kernel-panic-induced hang stalls beyond this
    /// duration at the agent level, the attempt returns a `TimedOut` error
    /// and the Docker/host fallback cascade fires normally.
    /// Default: 60 seconds.  Configure via `FC_OUTER_TIMEOUT_SECS`.
    pub outer_timeout_secs: u64,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        FirecrackerConfig {
            firecracker_binary_path: std::path::PathBuf::from("/usr/local/bin/firecracker"),
            kernel_image_path: std::path::PathBuf::from("/opt/ectoledger/vmlinux"),
            rootfs_path: std::path::PathBuf::from("/opt/ectoledger/rootfs.ext4"),
            vcpu_count: 1,
            mem_mib: 128,
            timeout_secs: 30,
            outer_timeout_secs: 60,
        }
    }
}

impl FirecrackerConfig {
    /// Build from environment variables, falling back to `Self::default()`.
    ///
    /// | Env var                          | Field                       |
    /// |----------------------------------|-----------------------------|
    /// | `ECTO_FC_BINARY`             | `firecracker_binary_path`   |
    /// | `ECTO_FC_KERNEL`             | `kernel_image_path`         |
    /// | `ECTO_FC_ROOTFS`             | `rootfs_path`               |
    /// | `ECTO_FC_VCPUS`              | `vcpu_count`                |
    /// | `ECTO_FC_MEM_MIB`            | `mem_mib`                   |
    /// | `ECTO_FC_TIMEOUT_SECS`       | `timeout_secs`              |
    /// | `FC_OUTER_TIMEOUT_SECS`      | `outer_timeout_secs`        |
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("ECTO_FC_BINARY") {
            cfg.firecracker_binary_path = std::path::PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ECTO_FC_KERNEL") {
            cfg.kernel_image_path = std::path::PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ECTO_FC_ROOTFS") {
            cfg.rootfs_path = std::path::PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ECTO_FC_VCPUS")
            && let Ok(n) = v.parse::<u8>()
        {
            cfg.vcpu_count = n;
        }
        if let Ok(v) = std::env::var("ECTO_FC_MEM_MIB")
            && let Ok(n) = v.parse::<u32>()
        {
            cfg.mem_mib = n;
        }
        if let Ok(v) = std::env::var("ECTO_FC_TIMEOUT_SECS")
            && let Ok(n) = v.parse::<u64>()
        {
            cfg.timeout_secs = n;
        }
        if let Ok(v) = std::env::var("FC_OUTER_TIMEOUT_SECS")
            && let Ok(n) = v.parse::<u64>()
        {
            cfg.outer_timeout_secs = n;
        }
        cfg
    }

    /// Returns `true` when all required files are present on disk.
    /// Returns `Some(config)` when the Firecracker binary path is explicitly set via
    /// `ECTO_FC_BINARY`, otherwise returns `None` (sandbox disabled by default).
    /// This allows opt-in activation without requiring all three file paths to exist at
    /// startup - existence is checked lazily when the first microVM is launched.
    pub fn from_env_opt() -> Option<Self> {
        if std::env::var("ECTO_FC_BINARY").is_ok() {
            Some(Self::from_env())
        } else {
            None
        }
    }

    /// Returns `true` when all required files are present on disk.
    pub fn is_available(&self) -> bool {
        self.firecracker_binary_path.exists()
            && self.kernel_image_path.exists()
            && self.rootfs_path.exists()
    }
}

/// Execute a validated intent inside an ephemeral Firecracker microVM.
///
/// Returns the serial-console output of the VM as the observation string, or a
/// `SandboxError` if the VM cannot be started or times out.
///
/// This function is only compiled and available on Linux with the
/// `sandbox-firecracker` feature enabled.  On all other platforms it returns
/// `SandboxError::Io` immediately so callers can fall back gracefully.
#[cfg(all(target_os = "linux", feature = "sandbox-firecracker"))]
pub async fn run_in_firecracker(
    config: &FirecrackerConfig,
    intent_json: &str,
) -> Result<String, SandboxError> {
    use std::time::Duration;

    // Enforce an outer timeout that covers the entire function - VM setup,
    // temp file creation, process spawn, and execution.  The inner
    // `tokio::time::timeout` on the process output only covers the child
    // process itself; this outer layer catches setup hangs too.
    tokio::time::timeout(
        Duration::from_secs(config.outer_timeout_secs),
        run_in_firecracker_inner(config, intent_json),
    )
    .await
    .map_err(|_| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "Firecracker sandbox outer timeout ({} seconds) exceeded",
                config.outer_timeout_secs
            ),
        ))
    })?
}

#[cfg(all(target_os = "linux", feature = "sandbox-firecracker"))]
pub(super) async fn run_in_firecracker_inner(
    config: &FirecrackerConfig,
    intent_json: &str,
) -> Result<String, SandboxError> {
    use std::time::Duration;
    use tokio::process::Command;

    if !config.is_available() {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Firecracker sandbox not available: check firecracker binary ({}), \
                 kernel image ({}), and rootfs ({}) exist. \
                 See https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md",
                config.firecracker_binary_path.display(),
                config.kernel_image_path.display(),
                config.rootfs_path.display(),
            ),
        )));
    }

    // Create an ephemeral temp directory for this VM's API socket and intent file.
    let tmp = tempfile::TempDir::new().map_err(SandboxError::Io)?;
    let intent_file = tmp.path().join("intent.json");
    let vm_config_file = tmp.path().join("vm_config.json");

    // Write the intent JSON to a file that the VM will read from /dev/vdb.
    std::fs::write(&intent_file, intent_json).map_err(SandboxError::Io)?;

    // Build the Firecracker machine configuration JSON.
    // The guest rootfs is expected to:
    //   1. Mount /dev/vdb (or read it raw) to obtain the intent JSON.
    //   2. Execute the requested action.
    //   3. Write the result to ttyS0 (the serial console), which Firecracker
    //      exposes as stdout of the `firecracker` process.
    let vm_config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": config.kernel_image_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=0"
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": config.rootfs_path,
                "is_root_device": true,
                "is_read_only": false
            },
            {
                "drive_id": "intent",
                "path_on_host": intent_file,
                "is_root_device": false,
                "is_read_only": true
            }
        ],
        "machine-config": {
            "vcpu_count": config.vcpu_count,
            "mem_size_mib": config.mem_mib,
            "smt": false
        },
        "logger": {
            "log_path": "/dev/null",
            "level": "Error",
            "show_level": false,
            "show_log_origin": false
        }
    });

    std::fs::write(
        &vm_config_file,
        serde_json::to_string_pretty(&vm_config)
            .map_err(|e| SandboxError::Io(std::io::Error::other(e)))?,
    )
    .map_err(SandboxError::Io)?;

    // Spawn the Firecracker process.  The VM boots, runs the guest init, outputs
    // results to the serial console (our stdout), then shuts down.
    let output = tokio::time::timeout(
        Duration::from_secs(config.timeout_secs),
        Command::new(&config.firecracker_binary_path)
            .arg("--no-api")
            .arg("--config-file")
            .arg(&vm_config_file)
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
                "Firecracker microVM timed out after {} seconds",
                config.timeout_secs
            ),
        ))
    })?
    .map_err(SandboxError::Io)?;

    // Treat non-zero exit with stderr content as execution failure.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Io(std::io::Error::other(format!(
            "Firecracker microVM exited with status {}: {}",
            output.status,
            stderr.trim()
        ))));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format_sandbox_output(
        output.status.code(),
        &stdout,
        &stderr,
    ))
}

/// Stub for platforms or builds where Firecracker is not available.
#[cfg(not(all(target_os = "linux", feature = "sandbox-firecracker")))]
pub async fn run_in_firecracker(
    _config: &FirecrackerConfig,
    _intent_json: &str,
) -> Result<String, SandboxError> {
    Err(SandboxError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Firecracker microVM sandbox is only available on Linux with the \
         `sandbox-firecracker` Cargo feature enabled. \
         Rebuild with: cargo build --features sandbox-firecracker",
    )))
}
