//! Landlock rules and resource limits for a child process on Linux.

use super::*;

#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub(super) fn apply_landlock(workspace: &Path) -> Result<(), SandboxError> {
    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    };

    let abi = ABI::V3;
    let path_fd = PathFd::new(workspace)
        .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(SandboxError::Landlock)?
        .create()
        .map_err(SandboxError::Landlock)?
        .add_rule(PathBeneath::new(path_fd, AccessFs::from_read(abi)))
        .map_err(SandboxError::Landlock)?;

    // Allow read + execute access to standard system binary directories so
    // that child processes (e.g. `ls`, `git`) can be located and executed by
    // the kernel.  Library / linker-config paths only need read access.
    let exec_paths: &[&str] = &[
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/usr/local/bin",
        "/usr/libexec",
    ];
    for p in exec_paths {
        let path = std::path::Path::new(p);
        if path.exists()
            && let Ok(fd) = PathFd::new(path)
        {
            created = created
                .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
                .map_err(SandboxError::Landlock)?;
        }
    }
    // Libraries and dynamic linker config: read-only (no execute needed for
    // directories themselves - the kernel loads .so files via the binary).
    let read_paths: &[&str] = &[
        "/usr/lib",
        "/lib",
        "/usr/lib64",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
    ];
    for p in read_paths {
        let path = std::path::Path::new(p);
        if path.exists()
            && let Ok(fd) = PathFd::new(path)
        {
            created = created
                .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
                .map_err(SandboxError::Landlock)?;
        }
    }

    let status = created.restrict_self().map_err(SandboxError::Landlock)?;

    // Best-effort mode reports "not enforced" instead of failing, which would
    // run the command with no confinement at all. That is a sandbox failure:
    // the executor aborts unless ECTO_SANDBOX_PERMISSIVE is set.
    if status.ruleset == landlock::RulesetStatus::NotEnforced {
        return Err(SandboxError::Unsupported(
            "Landlock is not enforced: this kernel lacks it, or it is disabled or blocked".into(),
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub(super) fn apply_rlimits() {
    unsafe {
        let cpu_limit = libc::rlimit {
            rlim_cur: 30,
            rlim_max: 30,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
            tracing::warn!("Failed to set RLIMIT_CPU");
        }

        let mem_limit = libc::rlimit {
            rlim_cur: 512 * 1024 * 1024,
            rlim_max: 512 * 1024 * 1024,
        };
        if libc::setrlimit(libc::RLIMIT_AS, &mem_limit) != 0 {
            tracing::warn!("Failed to set RLIMIT_AS");
        }

        // Limit open file descriptors to prevent file descriptor exhaustion attacks.
        let fd_limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit) != 0 {
            tracing::warn!("Failed to set RLIMIT_NOFILE");
        }
    }
}
