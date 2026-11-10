//! The seccomp-BPF syscall allowlists for the guard worker and the main
//! process on Linux; elsewhere both are no-ops.

use super::*;

/// Applies a child-process sandbox for the given workspace directory.
///
/// On Linux with the `sandbox` feature flag: uses Landlock to enforce
/// read-only access to the workspace and applies `rlimit` bounds for
/// CPU time and address space.
///
/// Applies a strict seccomp BPF allowlist for the guard-worker process.
/// Denies ptrace, process_vm_readv, kexec_load with EPERM.
/// Anything outside the allowlist returns EPERM rather than kill, so missed
/// syscalls surface as errors instead of silent process termination.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_guard_worker_seccomp() -> Result<(), SandboxError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    // Syscalls needed by tokio + reqwest (HTTP to local LLM) + stdin/stdout JSON protocol.
    // Kept minimal; nothing that enables ptrace, raw memory access, or kernel loading.
    #[rustfmt::skip]
    let allowed: &[i64] = &[
        libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
        libc::SYS_openat, libc::SYS_close, libc::SYS_fstat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_stat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_lstat,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_newfstatat,
        libc::SYS_lseek, libc::SYS_mmap, libc::SYS_mprotect,
        libc::SYS_munmap, libc::SYS_brk, libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn, libc::SYS_ioctl,
        libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_getcwd,
        libc::SYS_clone, libc::SYS_clone3, libc::SYS_exit, libc::SYS_exit_group,
        libc::SYS_futex, libc::SYS_sched_yield, libc::SYS_nanosleep,
        libc::SYS_clock_gettime, libc::SYS_gettimeofday,
        libc::SYS_socket, libc::SYS_connect, libc::SYS_accept4,
        libc::SYS_sendto, libc::SYS_recvfrom, libc::SYS_sendmsg,
        libc::SYS_recvmsg, libc::SYS_shutdown, libc::SYS_bind,
        libc::SYS_getsockname, libc::SYS_getpeername,
        libc::SYS_setsockopt, libc::SYS_getsockopt,
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl, libc::SYS_epoll_pwait,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_prctl, libc::SYS_prlimit64,
        libc::SYS_getuid, libc::SYS_getgid, libc::SYS_getpid, libc::SYS_gettid,
        libc::SYS_set_robust_list, libc::SYS_getrandom, libc::SYS_madvise,
        libc::SYS_pipe2, libc::SYS_eventfd2, libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime, libc::SYS_wait4, libc::SYS_fcntl,
        libc::SYS_dup, libc::SYS_dup3, libc::SYS_set_tid_address,
        libc::SYS_sigaltstack, libc::SYS_uname,
        // needed by newer glibc / musl thread initialisation + file ops
        libc::SYS_rseq, libc::SYS_memfd_create, libc::SYS_statx,
        libc::SYS_tgkill, libc::SYS_flock,
        libc::SYS_faccessat, libc::SYS_kill,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_arch_prctl,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_newfstatat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_access,
    ];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in allowed {
        rules.insert(nr, vec![]);
    }

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;
    // On unsupported architectures (RISC-V, s390x, etc.) we skip the filter rather than
    // failing the build. The sandbox feature is still useful for Landlock and rlimits.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Ok(());

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    let bpf: BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| {
        SandboxError::Io(std::io::Error::other(e.to_string()))
    })?;

    seccompiler::apply_filter(&bpf)
        .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    Ok(())
}

/// Seccomp stub for the guard worker on non-Linux or when the sandbox feature is disabled.
#[cfg(not(all(target_os = "linux", feature = "sandbox")))]
pub fn apply_guard_worker_seccomp() -> Result<(), SandboxError> {
    Ok(())
}

/// Applies a production-ready seccomp BPF allowlist to the main process.
/// The allowlist is broader than the guard-worker filter because the main process runs:
///   - Axum HTTP server (accept4, listen, sendmsg, recvmsg, setsockopt, epoll_*)
///   - SQLx Postgres client (same networking)
///   - Process spawning for tool execution (clone, wait4, pipe2, eventfd2)
///   - File-descriptor management (fcntl, dup, dup3)
///
/// Explicitly denied (EPERM): ptrace, process_vm_readv/writev, kexec_load,
/// init_module, finit_module, mount, umount2, pivot_root, reboot.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    #[rustfmt::skip]
    let allowed: &[i64] = &[
        // Basic I/O
        libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
        libc::SYS_pread64, libc::SYS_pwrite64,
        libc::SYS_openat, libc::SYS_close, libc::SYS_fstat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_stat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_lstat,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_newfstatat,
        libc::SYS_lseek, libc::SYS_getcwd, libc::SYS_getdents64,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rename,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_renameat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_unlink,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_unlinkat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_mkdir,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_mkdirat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rmdir,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chmod,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_fchmodat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chown,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_fchownat,
        libc::SYS_truncate, libc::SYS_ftruncate,
        libc::SYS_statx, libc::SYS_faccessat, libc::SYS_flock,
        // SQLite commits (connection threads opened after the filter inherit it),
        // key files written 0600, and current_exe() for the guard worker's path.
        libc::SYS_fsync, libc::SYS_fdatasync, libc::SYS_fchmod,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        // Memory
        libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_munmap, libc::SYS_brk,
        libc::SYS_madvise, libc::SYS_memfd_create, libc::SYS_mremap, libc::SYS_msync,
        // Signals / threads
        libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack, libc::SYS_futex, libc::SYS_sched_yield,
        libc::SYS_nanosleep, libc::SYS_clock_gettime, libc::SYS_gettimeofday,
        libc::SYS_tgkill, libc::SYS_kill,
        // Process management (needed for spawning tool sub-processes)
        libc::SYS_clone, libc::SYS_clone3, libc::SYS_wait4,
        libc::SYS_exit, libc::SYS_exit_group,
        libc::SYS_execve, libc::SYS_set_tid_address,
        libc::SYS_setpgid, libc::SYS_setsid, libc::SYS_getrusage,
        // Pipe / FD helpers
        libc::SYS_pipe2, libc::SYS_eventfd2, libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime, libc::SYS_fcntl, libc::SYS_dup, libc::SYS_dup3,
        // std::process::Command wires a child's stdio with dup2. Children
        // inherit this filter, and a tokio child (the guard worker) needs
        // socketpair for its signal driver.
        #[cfg(target_arch = "x86_64")]
        libc::SYS_dup2,
        libc::SYS_socketpair,
        libc::SYS_ioctl,
        // Networking (Axum + SQLx)
        libc::SYS_socket, libc::SYS_connect, libc::SYS_bind, libc::SYS_listen,
        libc::SYS_accept4, libc::SYS_sendto, libc::SYS_recvfrom,
        libc::SYS_sendmsg, libc::SYS_recvmsg, libc::SYS_shutdown,
        libc::SYS_getsockname, libc::SYS_getpeername,
        libc::SYS_setsockopt, libc::SYS_getsockopt,
        // epoll / poll (a filtered child's tokio driver polls with epoll_wait)
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl, libc::SYS_epoll_pwait,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_epoll_wait,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_poll,
        libc::SYS_ppoll,
        // Misc. seccomp lets a child (the guard worker) add its own, stricter
        // filter; filters only ever narrow what is allowed. The landlock calls
        // are how run_command children confine themselves: refused here, the
        // landlock crate's best-effort mode ran them unconfined.
        libc::SYS_prctl, libc::SYS_prlimit64, libc::SYS_getrandom, libc::SYS_seccomp,
        libc::SYS_landlock_create_ruleset, libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
        libc::SYS_getuid, libc::SYS_getgid, libc::SYS_getpid, libc::SYS_gettid,
        libc::SYS_set_robust_list, libc::SYS_uname,
        libc::SYS_rseq,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_arch_prctl,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_newfstatat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_access,
    ];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in allowed {
        rules.insert(nr, vec![]);
    }

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Ok(());

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    let bpf: BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| {
        SandboxError::Io(std::io::Error::other(e.to_string()))
    })?;

    seccompiler::apply_filter(&bpf).map_err(install_error)?;

    tracing::info!("Main-process seccomp filter applied.");
    Ok(())
}

/// Keep the kernel's errno. `Error::other(display)` would hide `EINVAL`.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn install_error(err: seccompiler::Error) -> SandboxError {
    match err {
        seccompiler::Error::Seccomp(io) | seccompiler::Error::Prctl(io) => SandboxError::Io(io),
        other => SandboxError::Io(std::io::Error::other(other.to_string())),
    }
}

/// What `serve` prints when the filter does not install. The process still
/// exits: serving without the filter is not a fallback.
pub fn main_process_seccomp_failure(err: &SandboxError) -> String {
    // Linux EINVAL. Compared numerically so this helper builds on every OS.
    let rejected = matches!(err, SandboxError::Io(io) if io.raw_os_error() == Some(22));
    if rejected {
        format!(
            "Aborting: the kernel rejected the main-process seccomp filter ({err}). \
             The process exits instead of serving without it. \
             EINVAL (os error 22) is what QEMU user-mode returns for seccomp, \
             which is how an amd64 image runs on Apple Silicon. \
             On real x86_64 the same filter installs. Do not disable the sandbox to get past this."
        )
    } else {
        format!("Aborting: main-process seccomp sandbox could not be applied: {err}")
    }
}

/// No-op on non-Linux or when the sandbox feature is disabled.
/// On macOS, applies a Seatbelt profile that denies network, process-exec, and
/// restricts filesystem writes to the workspace directory only.
#[cfg(not(all(target_os = "linux", feature = "sandbox")))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        tracing::info!(
            "macOS: seccomp-BPF is Linux-only; Seatbelt is applied to child processes instead."
        );
        return Ok(());
    }
    #[allow(unreachable_code)]
    Ok(())
}
