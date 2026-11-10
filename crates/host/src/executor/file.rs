//! `read_file`: a bounded read of a file the tripwire approved, re-checked
//! when it is opened.

use super::*;

pub(super) const FILE_MAX_BYTES: usize = 256 * 1024;

pub(super) async fn read_file(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let path = validated
        .params()
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("path"))?
        .to_string();

    // Re-validate the path at open time, not just at intent-validation time.
    // The tripwire's earlier check canonicalized the path, but a symlink could
    // have been swapped in between check and use (TOCTOU). The blocking helper
    // canonicalizes again, checks the allowlist, and opens with O_NOFOLLOW so
    // a symlink planted at the leaf after canonicalization is rejected by the
    // kernel rather than followed.
    // The same list that approved the intent; an intent built without a
    // tripwire falls back to the configured allowlist.
    let allowed: Vec<std::path::PathBuf> = if validated.allowed_roots().is_empty() {
        crate::config::canonical_allowed_prefixes(
            &crate::config::load_tripwire_config().allowed_paths,
        )
    } else {
        validated.allowed_roots().to_vec()
    };
    tokio::task::spawn_blocking(move || read_file_locked_down(&path, &allowed))
        .await
        .map_err(|e| ExecuteError::Io(std::io::Error::other(e)))?
}

/// Locked-down file read: canonicalize + allowlist check at open time, open
/// without following a leaf symlink, verify the opened handle is a regular
/// file, and cap the bytes read.
pub(super) fn read_file_locked_down(
    path: &str,
    allowed_prefixes: &[std::path::PathBuf],
) -> Result<String, ExecuteError> {
    let canonical = crate::tripwire::validate_path_strict(path, allowed_prefixes)
        .map_err(|e| ExecuteError::InvalidCommand(format!("read_file: {e}")))?;
    // Everything after this point runs against the already-validated path, so
    // it must assume the filesystem may have changed underneath it.
    open_and_read_verified(&canonical)
}

/// Opens an already-validated path and reads it, refusing anything that is no
/// longer a plain regular file.
///
/// This is the second half of the TOCTOU defence and is deliberately a
/// separate function: `validate_path_strict` returns a *canonicalized* path
/// (symlinks already resolved), so the `O_NOFOLLOW` below can only ever fire
/// when the leaf was swapped for a symlink **after** validation - exactly the
/// check/use race being closed. Keeping it separate lets the regression tests
/// reproduce that window deterministically instead of racing threads.
pub(super) fn open_and_read_verified(canonical: &std::path::Path) -> Result<String, ExecuteError> {
    use std::io::Read;

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW: fail if the final component is (now) a symlink.
        // O_NONBLOCK: opening a FIFO must not hang; harmless on regular files.
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(canonical)
            .map_err(ExecuteError::Io)?
    };
    #[cfg(not(unix))]
    let file = {
        // Windows: no O_NOFOLLOW equivalent in std. Reject a symlink/reparse
        // point at the leaf immediately before opening (small residual race;
        // the process-wide Job Object sandbox still applies).
        let leaf = std::fs::symlink_metadata(canonical).map_err(ExecuteError::Io)?;
        if leaf.file_type().is_symlink() {
            return Err(ExecuteError::InvalidCommand(format!(
                "read_file: '{}' is a symlink (rejected)",
                canonical.display()
            )));
        }
        std::fs::File::open(canonical).map_err(ExecuteError::Io)?
    };

    // The opened handle must be a regular file - never a FIFO, device, or
    // directory, which could hang the read or leak kernel state.
    let meta = file.metadata().map_err(ExecuteError::Io)?;
    if !meta.is_file() {
        return Err(ExecuteError::InvalidCommand(format!(
            "read_file: '{}' is not a regular file",
            canonical.display()
        )));
    }

    // Bounded read: never buffer more than the cap + 1 probe byte.
    let mut buf = Vec::with_capacity(FILE_MAX_BYTES.min(meta.len() as usize) + 1);
    file.take(FILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(ExecuteError::Io)?;
    let content = String::from_utf8_lossy(&buf).into_owned();
    if buf.len() > FILE_MAX_BYTES {
        return Ok(format!(
            "file too large ({} bytes); showing first {} bytes: {}",
            meta.len(),
            FILE_MAX_BYTES,
            trim_to_max(&content, FILE_MAX_BYTES)
        ));
    }
    Ok(content)
}
