use super::*;
use std::path::PathBuf;

/// Runs `body` in a child copy of this test binary and returns the
/// child's exit status to the parent (None inside the child). A sandbox
/// is permanent for the process, or thread, that applies it: applied to
/// the shared test harness, Seatbelt, Landlock, seccomp or a Job Object
/// constrains every test that runs after it (on Linux a filter once broke
/// a later test's thread start and cargo skipped eleven binaries).
fn in_child(test_name: &str, body: impl FnOnce()) -> Option<std::process::ExitStatus> {
    const MARK: &str = "ECTO_SANDBOX_TEST_CHILD";
    if std::env::var(MARK).as_deref() == Ok(test_name) {
        body();
        return None;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test_name, "--exact", "--test-threads=1", "--nocapture"])
        .env(MARK, test_name)
        .output()
        .expect("run the child test binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // `--exact` silently matches zero tests if `test_name` is wrong, and
    // libtest then reports "0 passed" with a zero exit code: a vacuous
    // pass that would hide the child body never having run at all.
    assert!(
        stdout.contains("running 1 test"),
        "child test filter {test_name:?} matched zero tests (vacuous pass);\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    if !output.status.success() {
        eprintln!("child stdout:\n{stdout}");
        eprintln!("child stderr:\n{stderr}");
    }
    Some(output.status)
}

#[test]
#[should_panic(expected = "matched zero tests")]
fn in_child_panics_when_the_filter_matches_no_test() {
    in_child("sandbox::tests::this_test_name_does_not_exist", || {});
}

/// The name libtest gives a test in this module, for `--exact`.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let in_crate = module.split_once("::").map_or(module, |(_, rest)| rest);
    format!("{in_crate}::{name}")
}

#[cfg(not(all(target_os = "linux", feature = "sandbox")))]
#[test]
fn guard_worker_seccomp_is_a_no_op_off_linux() {
    assert!(apply_guard_worker_seccomp().is_ok());
}

#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
fn guard_worker_seccomp_applies() {
    let name = test_path("guard_worker_seccomp_applies");
    if let Some(status) = in_child(&name, || {
        apply_guard_worker_seccomp().expect("the guard worker filter installs");
    }) {
        assert!(status.success(), "child: {status}");
    }
}

/// The guard-worker filter maps every syscall outside its allowlist to
/// EPERM, never kill, and ptrace is explicitly outside it. Not run on
/// this (Windows) machine; verified only by `cargo check`/`clippy` here.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
fn guard_worker_seccomp_denies_ptrace() {
    let name = test_path("guard_worker_seccomp_denies_ptrace");
    if let Some(status) = in_child(&name, || {
        apply_guard_worker_seccomp().expect("the guard worker filter installs");
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        let err = std::io::Error::last_os_error();
        assert_eq!(ret, -1, "ptrace(PTRACE_TRACEME) should be denied: {err}");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EPERM),
            "unexpected errno: {err}"
        );
    }) {
        assert!(status.success(), "child: {status}");
    }
}

/// Pins the documented CPU/address-space/file-descriptor bounds from
/// `apply_rlimits`. Not run on this (Windows) machine; verified only by
/// `cargo check`/`clippy` here.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
#[test]
fn rlimits_apply_the_documented_bounds() {
    let name = test_path("rlimits_apply_the_documented_bounds");
    if let Some(status) = in_child(&name, || {
        apply_rlimits();
        unsafe {
            let mut cpu = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_CPU, &mut cpu), 0);
            assert_eq!(cpu.rlim_cur, 30);

            let mut mem = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_AS, &mut mem), 0);
            assert_eq!(mem.rlim_cur, 512 * 1024 * 1024);

            let mut nofile = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut nofile), 0);
            assert_eq!(nofile.rlim_cur, 64);
        }
    }) {
        assert!(status.success(), "child: {status}");
    }
}

#[test]
fn a_rejected_seccomp_filter_stays_fatal_and_names_qemu() {
    let err = SandboxError::Io(std::io::Error::from_raw_os_error(22));
    let message = main_process_seccomp_failure(&err);
    assert!(
        message.contains("exits instead of serving without it"),
        "{message}"
    );
    assert!(message.contains("QEMU"), "{message}");
    assert!(message.contains("real x86_64"), "{message}");
    let other = SandboxError::Io(std::io::Error::other("bpf compile failed"));
    let other_message = main_process_seccomp_failure(&other);
    assert!(
        other_message.contains("could not be applied"),
        "{other_message}"
    );
    assert!(!other_message.contains("QEMU"), "{other_message}");
}

#[test]
fn main_process_seccomp_applies_or_is_a_no_op() {
    let name = test_path("main_process_seccomp_applies_or_is_a_no_op");
    if let Some(status) = in_child(&name, || {
        apply_main_process_seccomp().expect("Linux installs the filter; elsewhere a no-op");
    }) {
        assert!(status.success(), "child: {status}");
    }
}

/// The child sandbox applies on every platform that has one: Seatbelt on
/// macOS, Landlock (with rlimits) on Linux, a Job Object on Windows.
/// Landlock may be missing from an old kernel, which is reported as
/// Unsupported, never as another error. Where the sandbox confines the
/// file system, the child then proves it: the workspace stays readable
/// and a file outside it does not.
#[test]
fn child_sandbox_applies() {
    let name = test_path("child_sandbox_applies");
    if let Some(status) = in_child(&name, || {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        match apply_child_sandbox(&workspace) {
            Ok(()) => assert_confined(&workspace),
            Err(SandboxError::Unsupported(msg)) if cfg!(target_os = "linux") => {
                eprintln!("Landlock unavailable on this kernel: {msg}");
            }
            Err(e) => panic!("the child sandbox did not apply: {e}"),
        }
    }) {
        assert!(status.success(), "child: {status}");
    }
}

/// Checks, inside a sandboxed child, what the sandbox allows and refuses.
/// Landlock grants the workspace read-only, so a write there is refused
/// too; Seatbelt grants it read-write and also denies the network. A Job
/// Object limits the process tree, not the file system: nothing to probe.
fn assert_confined(workspace: &Path) {
    use std::io::ErrorKind::PermissionDenied;

    if cfg!(target_os = "windows") {
        #[cfg(target_os = "windows")]
        assert_windows_job_object_confined();
        return;
    }
    std::fs::read(workspace.join("Cargo.toml")).expect("the workspace stays readable");
    let outside = std::fs::read("/etc/passwd").expect_err("a file outside the workspace");
    assert_eq!(outside.kind(), PermissionDenied, "/etc/passwd: {outside}");

    if cfg!(target_os = "linux") {
        let probe = workspace.join("landlock-write-probe");
        let written = std::fs::write(&probe, b"");
        let _ = std::fs::remove_file(&probe);
        let refused = written.expect_err("a write in the read-only workspace");
        assert_eq!(
            refused.kind(),
            PermissionDenied,
            "workspace write: {refused}"
        );
    }
    if cfg!(target_os = "macos") {
        // Port 9 (discard) has no listener: without the sandbox this is
        // ConnectionRefused, under it the connect itself is refused.
        let refused =
            std::net::TcpStream::connect(("127.0.0.1", 9)).expect_err("a network connection");
        assert_eq!(refused.kind(), PermissionDenied, "connect: {refused}");

        // The parent folder can be stat'ed, so `ls -la` lists `..`, but not
        // read. (A spawned `ls` cannot be used here: this test sandboxes its
        // own process, and the profile denies fork; production applies it
        // after the fork.)
        let parent = workspace.parent().expect("the workspace has a parent");
        std::fs::metadata(parent).expect("the parent folder's metadata");
        let listing = std::fs::read_dir(parent).expect_err("listing the parent folder");
        assert_eq!(listing.kind(), PermissionDenied, "read_dir(..): {listing}");
        // What `ls -la` does for its `..` row; it failed with EPERM before.
        std::fs::symlink_metadata(workspace.join("..")).expect("lstat of the workspace's ..");
    }
}

/// Confirms the Job Object `apply_windows_job_object` assigned the
/// current process to actually carries `KILL_ON_JOB_CLOSE`, by querying
/// the stored job handle directly rather than the ambient job of the
/// calling process (which can be an unrelated outer job under nested
/// Job Object scenarios on Windows 8+).
#[cfg(target_os = "windows")]
fn assert_windows_job_object_confined() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, QueryInformationJobObject,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::core::BOOL;

    let job: HANDLE = JOB_OBJECT_HANDLE
        .get()
        .expect("apply_child_sandbox stored the job object handle")
        .0;

    let mut in_job = BOOL(0);
    unsafe {
        IsProcessInJob(GetCurrentProcess(), Some(job), &mut in_job)
            .expect("IsProcessInJob should succeed");
    }
    assert!(
        in_job.as_bool(),
        "the current process is not a member of the job object it was assigned to"
    );

    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    unsafe {
        QueryInformationJobObject(
            Some(job),
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            None,
        )
        .expect("QueryInformationJobObject should succeed");
    }
    assert!(
        info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            == JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        "KILL_ON_JOB_CLOSE was not applied to the job object"
    );
}

#[test]
fn sandbox_error_display_formats() {
    let io_err = SandboxError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "test",
    ));
    assert!(io_err.to_string().contains("sandbox io"));

    let unsupported = SandboxError::Unsupported("test platform".into());
    assert!(unsupported.to_string().contains("unsupported"));
}

#[test]
fn docker_config_defaults_are_sane() {
    let cfg = DockerConfig::default();
    assert_eq!(cfg.image, "alpine:3.19");
    assert_eq!(cfg.timeout_secs, 30);
}

#[test]
fn docker_shell_rejects_a_backgrounded_command() {
    assert_eq!(shell_metacharacter("echo hello&whoami"), Some("&"));
    assert_eq!(shell_metacharacter("echo hello && whoami"), Some("&&"));
    assert_eq!(shell_metacharacter("echo hello || whoami"), Some("||"));
    assert_eq!(shell_metacharacter("echo hello > out.txt"), Some(">"));
    assert!(shell_metacharacter("echo hello").is_none());
    assert!(shell_metacharacter("ls -la").is_none());
}

#[test]
fn firecracker_config_defaults_are_sane() {
    let cfg = FirecrackerConfig::default();
    assert_eq!(cfg.vcpu_count, 1);
    assert_eq!(cfg.mem_mib, 128);
    assert_eq!(cfg.timeout_secs, 30);
}

#[test]
fn a_workspace_path_cannot_add_seatbelt_rules() {
    let hostile = r#"/tmp/ws") (allow default) (allow file-read* (subpath "/"#;
    let profile = seatbelt_profile(Path::new(hostile));
    assert!(
        profile
            .contains(r#"(subpath "/tmp/ws\") (allow default) (allow file-read* (subpath \"/")"#)
    );
    assert_eq!(sbpl_string_body(r"C:\ws\"), r"C:\\ws\\");
}

/// A workspace whose name holds a quote still gets a sandbox that
/// parses and confines, rather than one that fails or opens up.
#[cfg(target_os = "macos")]
#[test]
fn a_quoted_workspace_path_still_confines() {
    let root = std::env::temp_dir().join("ectoledger-sandbox-quoted-workspace");
    let workspace = root.join(r#"ws") (allow default) ("#);
    std::fs::create_dir_all(&workspace).expect("create the workspace");
    std::fs::write(workspace.join("Cargo.toml"), b"").expect("seed the workspace");
    // Seatbelt matches resolved paths, and the temp folder is under a symlink.
    let workspace = std::fs::canonicalize(&workspace).expect("resolve the workspace");

    let name = test_path("a_quoted_workspace_path_still_confines");
    if let Some(status) = in_child(&name, || {
        apply_child_sandbox(&workspace).expect("the profile parses");
        assert_confined(&workspace);
    }) {
        let _ = std::fs::remove_dir_all(&root);
        assert!(status.success(), "child: {status}");
    }
}

#[test]
fn seatbelt_profile_generates_the_expected_clauses() {
    let profile = seatbelt_profile(std::path::Path::new("/tmp/test-workspace"));
    assert!(profile.contains("(deny default)"));
    assert!(profile.contains("(deny network*)"));
    assert!(profile.contains("(allow process-exec)"));
    assert!(profile.contains("/tmp/test-workspace"));
    // Must allow executable paths for pre_exec compatibility
    assert!(profile.contains("/usr/bin"));
    assert!(profile.contains("/bin"));
}

#[test]
fn seatbelt_profile_accepts_a_workspace_path_with_spaces() {
    let profile = seatbelt_profile(std::path::Path::new("/Users/dev/My Workspace"));
    assert!(profile.contains("/Users/dev/My Workspace"));
    assert!(profile.contains("(deny default)"));
}

#[test]
fn seatbelt_profile_accepts_a_workspace_path_with_parentheses() {
    // Parentheses inside a Scheme string literal are inert; they only
    // matter as unescaped structural syntax outside a string.
    let profile = seatbelt_profile(std::path::Path::new("/tmp/workspace (copy)"));
    assert!(profile.contains("/tmp/workspace (copy)"));
    assert!(profile.contains("(deny default)"));
}

#[test]
fn seatbelt_profile_accepts_a_workspace_path_with_unicode() {
    let profile = seatbelt_profile(std::path::Path::new("/tmp/wörkspace-日本語"));
    assert!(profile.contains("/tmp/wörkspace-日本語"));
    assert!(profile.contains("(deny default)"));
}

#[test]
fn seatbelt_profile_does_not_let_a_trailing_backslash_escape_the_closing_quote() {
    let workspace = std::path::Path::new("/tmp/workspace\\");
    let profile = seatbelt_profile(workspace);

    let marker = "(subpath \"/tmp/workspace";
    let after_workspace = &profile[profile
        .find(marker)
        .expect("profile contains the workspace subpath clause")
        + marker.len()..];
    let leading_backslashes = after_workspace.chars().take_while(|&c| c == '\\').count();
    assert!(
        leading_backslashes % 2 == 0,
        "an odd run of backslashes precedes the closing quote, so the last one escapes \
             it instead of ending the string:\n{profile}"
    );
}

#[test]
fn the_workspaces_parents_are_open_to_stat_and_nothing_else() {
    let profile = seatbelt_profile(Path::new("/Users/dev/projects/audit"));
    let clause = profile
        .split("(allow file-read-metadata")
        .nth(1)
        .expect("a metadata clause");
    let clause = &clause[..clause.find(')').map(|i| i + 1).unwrap_or(clause.len())];
    assert!(
        profile.contains(r#"(literal "/Users/dev/projects")"#),
        "{profile}"
    );
    assert!(profile.contains(r#"(literal "/Users/dev")"#), "{profile}");
    assert!(profile.contains(r#"(literal "/Users")"#), "{profile}");
    assert!(!clause.contains("subpath"), "{clause}");
}

#[test]
fn a_workspace_directly_under_the_root_adds_no_metadata_rule() {
    let profile = seatbelt_profile(Path::new("/audit"));
    assert!(!profile.contains("file-read-metadata"), "{profile}");
}
