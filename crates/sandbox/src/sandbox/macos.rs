//! Apple Seatbelt: the profile a child process runs under on macOS.

use super::*;

/// Generates a Seatbelt `.sb` profile string restricting the process to:
///   - Read-only access to system libraries, frameworks, and executable paths
///   - Read/write access only to the given workspace directory
///   - No network access, no signal sending, no sysctl writes
///
/// **Design note (pre_exec compatibility):**
/// This profile is applied via `pre_exec` - i.e. after `fork()` but *before*
/// `exec()`. Therefore:
///   1. Executable paths (`/usr/bin`, `/bin`, `/usr/local/bin`, Homebrew) must be
///      readable so the kernel can load the target binary.
///   2. `process-exec` must be allowed so the pending `exec()` syscall succeeds.
///
/// The primary security value of the Seatbelt layer in this context is:
///   - **Network isolation** (`deny network*`) - prevents data exfiltration
///   - **Filesystem write restriction** - only the workspace is writable
///   - **Signal denial** - prevents signal injection into other processes
///
/// For stronger process-exec control, use Docker/Podman or Firecracker tiers.
#[cfg(any(test, target_os = "macos"))]
pub(super) fn seatbelt_profile(workspace: &Path) -> String {
    let ws = sbpl_string_body(&workspace.to_string_lossy());
    format!(
        "{}{}",
        base_profile(&ws),
        ancestor_metadata_clause(workspace)
    )
}

/// Lets a command stat the workspace's parent folders, and only stat them:
/// `ls -la` lists `..`, and path resolution walks up, so without this an
/// agent listing its own folder exits 1. The folders' contents stay
/// unreadable. Nothing is emitted for a workspace with no parent but `/`:
/// a metadata rule with no paths would cover every file.
fn ancestor_metadata_clause(workspace: &Path) -> String {
    let parents: String = workspace
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty() && *p != Path::new("/"))
        .map(|p| {
            format!(
                "\n    (literal \"{}\")",
                sbpl_string_body(&p.to_string_lossy())
            )
        })
        .collect();
    if parents.is_empty() {
        return String::new();
    }
    format!(
        "\n;; The workspace's parent folders, metadata only.\n(allow file-read-metadata{parents})\n"
    )
}

fn base_profile(ws: &str) -> String {
    format!(
        r#"(version 1)
(deny default)

;; Allow read-only access to system libraries, frameworks, and dyld cache.
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/System")
    (subpath "/Library/Frameworks")
    (subpath "/private/var/db/dyld")
    (literal "/dev/null")
    (literal "/dev/urandom")
    (literal "/dev/random"))

;; The root directory itself (not what is under it): dyld and libc read it
;; at process start, and without it every command aborts with SIGABRT (seen
;; on macOS 27; earlier releases did not need it).
(allow file-read* (literal "/"))

;; Allow reading executable directories so the initial exec() can find
;; and load the target binary. Required because this profile is applied
;; in pre_exec (before exec, not after).
(allow file-read*
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/usr/local/bin")
    (subpath "/opt/homebrew/bin")
    (subpath "/usr/sbin")
    (subpath "/sbin"))

;; Allow read/write access to the workspace directory only.
(allow file-read* file-write*
    (subpath "{ws}"))

;; Allow reading tmpdir for scratch files.
(allow file-read* file-write*
    (subpath "/private/tmp")
    (subpath "/tmp"))

;; Allow mach lookups required for basic process operation.
(allow mach-lookup
    (global-name "com.apple.system.logger"))

;; Allow process-exec: this profile is installed in pre_exec, so the
;; pending exec() syscall must be permitted. The tripwire layer and
;; the executable allowlist enforce command restrictions instead.
(allow process-exec)
(allow process-info-pidinfo)
(allow process-info-setcontrol)
(allow sysctl-read)

;; Deny everything else explicitly (network, signal, IPC).
(deny network*)
(deny signal)
"#
    )
}

/// Escapes `text` for use inside a double-quoted SBPL string. The workspace
/// path comes from the caller, and an unescaped `"` or trailing `\` in it
/// would end the string early and let the rest of the path add rules.
#[cfg(any(test, target_os = "macos"))]
pub(super) fn sbpl_string_body(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Applies a Seatbelt sandbox profile to the current process on macOS.
///
/// Uses the `sandbox_init` C API (declared in `<sandbox.h>`). While Apple has
/// deprecated the public header, the underlying system call is still enforced
/// and used by first-party macOS apps.  We call it via `extern "C"` FFI.
#[cfg(target_os = "macos")]
pub(super) fn apply_seatbelt(workspace: &Path) -> Result<(), SandboxError> {
    use std::ffi::CString;

    unsafe extern "C" {
        /// Apply a Seatbelt profile from a string.
        /// Returns 0 on success; on failure, sets `*errorbuf` to a malloc'd
        /// C string describing the error and returns -1.
        fn sandbox_init(
            profile: *const std::ffi::c_char,
            flags: u64,
            errorbuf: *mut *mut std::ffi::c_char,
        ) -> std::ffi::c_int;

        fn sandbox_free_error(errorbuf: *mut std::ffi::c_char);
    }

    // SANDBOX_NAMED = 0x0001 is for named built-in profiles; 0x0000 means
    // the `profile` argument is a raw Scheme string.
    const SANDBOX_NAMED_NONE: u64 = 0;

    let profile_str = seatbelt_profile(workspace);
    let c_profile = CString::new(profile_str)
        .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;

    let mut errorbuf: *mut std::ffi::c_char = std::ptr::null_mut();
    let ret = unsafe { sandbox_init(c_profile.as_ptr(), SANDBOX_NAMED_NONE, &mut errorbuf) };

    if ret != 0 {
        let msg = if !errorbuf.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(errorbuf) }
                .to_string_lossy()
                .to_string();
            unsafe { sandbox_free_error(errorbuf) };
            s
        } else {
            "unknown sandbox_init error".to_string()
        };
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Seatbelt sandbox_init failed: {msg}"),
        )));
    }

    // No log here: this runs in the forked child before exec, where logging
    // is not async-signal-safe, and any such line would land in the command's
    // own stdout and so in the ledger's observation.
    Ok(())
}
