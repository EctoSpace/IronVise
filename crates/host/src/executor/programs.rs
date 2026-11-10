//! Which programs `run_command` may start, and with which arguments, on
//! each OS; plugin binaries and their integrity.

use super::*;

/// Unix-native programs allowed for agent command execution.
#[cfg(not(windows))]
pub(super) const ALLOWED_PROGRAMS: &[&str] = &[
    "ls",
    "cat",
    "find",
    "grep",
    "head",
    "tail",
    "wc",
    "stat",
    "file",
    "diff",
    "md5sum",
    "sha256sum",
    "sha1sum",
    "ps",
    // "env" removed: acts as a command launcher (`env bash -c '...'`), bypassing the allowlist entirely.
    "echo",
    "date",
    "id",
    "hostname",
    "uname",
    "df",
    "du",
    "pwd",
    "which",
    "whoami",
    "netstat",
    "ss",
    "lsof",
    // "nmap" and "openssl" removed: network pivoting risk. Add via AGENT_ALLOWED_PROGRAMS if needed.
    // "wget" removed: curl covers the same use case and is already in the tripwire ban list.
    //   wget supports recursive download (-r) and mirror (-m) which increase exfiltration surface.
    //   To re-enable, add "wget" to the AGENT_ALLOWED_PROGRAMS env var (comma-separated).
    "curl",
];

/// Windows-native programs allowed for agent command execution.
///
/// These are the native equivalents (or close analogues) of the Unix allowlist.
/// CMD builtins (dir, type, echo, date, cd, set, ver) are automatically
/// prefixed with `cmd.exe /C` at spawn time - see [`run_command_with_context`].
#[cfg(windows)]
pub(super) const ALLOWED_PROGRAMS: &[&str] = &[
    // Directory & file inspection (≈ ls, cat, stat, file, find)
    "dir",
    "type",
    "where", // ≈ which
    "more",  // ≈ head/tail (paginated output)
    // Text search & comparison (≈ grep, diff)
    "findstr",
    "fc",
    // Hashing (≈ md5sum / sha256sum / sha1sum)
    "certutil", // `certutil -hashfile <path> SHA256`
    // Process & system info (≈ ps, uname, id, hostname, df, du)
    "tasklist",
    "hostname",
    "systeminfo",
    "wmic",
    // Environment & identity (≈ whoami, pwd, echo, date)
    "whoami",
    "echo",
    "date",
    "cd",
    "set",
    "ver",
    // Networking (≈ netstat, curl)
    "netstat",
    "curl",
    // Filesystem metadata (≈ stat). Mutating forms are rejected in
    // `validate_program_args`: `attrib +H` and `icacls /grant` change the
    // file, and `wmic process call create` starts another program.
    "attrib",
    "icacls",
];

/// CMD builtins that must be spawned via `cmd.exe /C <builtin> <args...>`
/// because they are not standalone executables on Windows.
#[cfg(windows)]
pub(super) const CMD_BUILTINS: &[&str] =
    &["dir", "type", "echo", "date", "cd", "set", "ver", "more"];

/// Returns the effective allowlist of programs, extended by AGENT_ALLOWED_PROGRAMS env var,
/// optional cloud CLI binaries (when creds are present), and optional plugin binaries.
pub(super) fn allowed_programs_with_context(
    creds: Option<&CloudCredentialSet>,
    policy: Option<&PolicyEngine>,
) -> Vec<String> {
    let mut list: Vec<String> = ALLOWED_PROGRAMS.iter().map(|s| (*s).to_string()).collect();

    if let Ok(extra) = std::env::var("AGENT_ALLOWED_PROGRAMS") {
        for s in extra.split(',') {
            let t = s.trim().to_string();
            if !t.is_empty() && !list.contains(&t) {
                list.push(t);
            }
        }
    }

    // Cloud CLI binaries are added only when a credential set is loaded.
    if creds.is_some() {
        for b in crate::cloud_creds::CLOUD_CLI_BINARIES {
            let name = b.to_string();
            if !list.contains(&name) {
                list.push(name);
            }
        }
    }

    // Plugin binaries registered in the policy are added to the allowlist.
    if let Some(pe) = policy {
        for name in pe.effective_allowed_programs() {
            if !list.contains(&name) {
                list.push(name);
            }
        }
    }

    list
}

/// What the agent is told `run_command` can start here: this host's
/// allowlist, narrowed to a policy's `allowed_commands` for run_command when
/// it has one. Naming the programs tells the model which OS it is on; without
/// it, a model proposes `ls` on Windows, is refused, and loops.
pub fn programs_for_prompt(policy: Option<&PolicyEngine>) -> Vec<String> {
    let mut list = allowed_programs_with_context(None, policy);
    if let Some(cmds) = policy
        .and_then(|p| p.policy().allowed_actions.as_ref())
        .and_then(|actions| {
            actions
                .iter()
                .find(|a| a.action == "run_command")
                .and_then(|a| a.allowed_commands.clone())
        })
    {
        list.retain(|p| cmds.contains(p));
    }
    list
}

/// The host OS as the agent's prompt names it.
pub fn host_os_for_prompt() -> &'static str {
    if cfg!(windows) {
        "Windows (commands run without a Unix shell; use dir, type, findstr, not ls, cat, grep)"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Linux"
    }
}

pub(super) fn parse_command(cmd: &str) -> Result<(String, Vec<String>), ExecuteError> {
    // Windows-style paths are protected first so shlex's POSIX backslash-escaping
    // doesn't strip them (see `tripwire::protect_windows_paths`).
    let protected = crate::tripwire::protect_windows_paths(cmd);
    let parts =
        shlex::split(&protected).ok_or_else(|| ExecuteError::InvalidCommand(cmd.to_string()))?;
    if parts.is_empty() {
        return Err(ExecuteError::InvalidCommand("empty command".to_string()));
    }
    Ok((parts[0].clone(), parts[1..].to_vec()))
}

/// Defense-in-depth: block dangerous arguments on programs that can be
/// weaponised for arbitrary execution or file writes even though they are
/// in `ALLOWED_PROGRAMS`.
pub(super) fn validate_program_args(program: &str, args: &[String]) -> Result<(), ExecuteError> {
    const BLOCKED_ARGS: &[(&str, &[&str])] = &[
        ("find", &["-exec", "-execdir", "-ok", "-okdir", "-delete"]),
        (
            "curl",
            &[
                "-o",
                "--output",
                "-O",
                "--remote-name",
                "-T",
                "--upload-file",
                "-F",
                "--form",
                "--data-binary",
                "-d",
                "--data",
                "--data-raw",
                "--data-urlencode",
                // Additional flags that can be used for data exfiltration or SSRF:
                "--json",
                "--connect-to",
                "--resolve",
                "--unix-socket",
                "--abstract-unix-socket",
                "--proxy",
                "--socks4",
                "--socks5",
            ],
        ),
        ("xargs", &["-I", "--replace"]),
        // certutil (Windows) can download files, encode/decode, and modify cert stores.
        // Allow only read-only hash operations (certutil -hashfile).
        (
            "certutil",
            &[
                "-urlcache",
                "-encode",
                "-decode",
                "-addstore",
                "-delstore",
                "-importpfx",
                "-exportpfx",
                "-setreg",
            ],
        ),
        // icacls lists ACLs with no switch. These switches write an ACL file,
        // replace an ACL, or change the owner.
        (
            "icacls",
            &[
                "/grant",
                "/deny",
                "/remove",
                "/setowner",
                "/save",
                "/restore",
                "/reset",
                "/setintegritylevel",
                "/substitute",
            ],
        ),
        // wmic is on the allowlist for read-only queries (`os get`, `process
        // list`). `call create` starts an arbitrary process, `/format` can
        // load an XSL stylesheet, and `/node` talks to another machine.
        (
            "wmic",
            &[
                "call",
                "create",
                "delete",
                "set",
                "/format",
                "/node",
                "/user",
                "/password",
                "/output",
                "/record",
            ],
        ),
    ];
    let prog_lower = program.to_lowercase();
    let prog_base = std::path::Path::new(&prog_lower)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(&prog_lower);
    for (blocked_prog, blocked_flags) in BLOCKED_ARGS {
        if prog_base == *blocked_prog {
            // certutil is a Windows tool whose switches are conventionally case-
            // insensitive ('-URLCache' == '-urlcache'); every other program here
            // (find, curl, xargs) is POSIX, where short flags are case-sensitive
            // and distinct by case (e.g. curl's '-o' vs '-O', '-t' vs '-T').
            // Windows tools compare switches without case, and take a value
            // after `:` (`/grant:r`) as well as `=`. POSIX flags stay
            // case-sensitive and `=`-only: curl's `-o` and `-O` are different.
            let case_insensitive = matches!(*blocked_prog, "certutil" | "icacls" | "wmic");
            for arg in args {
                for flag in *blocked_flags {
                    if arg_matches_blocked_flag(arg, flag, case_insensitive) {
                        return Err(ExecuteError::ProgramNotAllowed(format!(
                            "{program} with '{flag}' argument is not allowed"
                        )));
                    }
                }
            }
        }
    }
    // `attrib +R file` sets an attribute; a bare name only displays one.
    if prog_base == "attrib" {
        for arg in args {
            let bytes = arg.as_bytes();
            if bytes.len() >= 2 && matches!(bytes[0], b'+' | b'-') && bytes[1].is_ascii_alphabetic()
            {
                return Err(ExecuteError::ProgramNotAllowed(format!(
                    "{program} with '{arg}' argument is not allowed"
                )));
            }
        }
    }
    Ok(())
}

/// Compares a single CLI argument against a blocked flag, matching either the
/// bare flag or its `flag=value` form.
pub(super) fn arg_matches_blocked_flag(arg: &str, flag: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        if arg.eq_ignore_ascii_case(flag) {
            return true;
        }
        arg.len() > flag.len()
            && matches!(arg.as_bytes()[flag.len()], b'=' | b':')
            && arg[..flag.len()].eq_ignore_ascii_case(flag)
    } else {
        arg == flag || arg.starts_with(&format!("{flag}="))
    }
}

/// A character `cmd.exe` acts on when it re-parses `cmd /C <builtin> <args>`.
///
/// The tripwire rejects `&` and `|` only when they are their own token, so a
/// query string can contain them. CMD builtins are not programs: they are
/// wrapped in `cmd.exe /C`, which joins the arguments and parses them again.
/// `echo hello&whoami` therefore runs `whoami`, `echo hello|whoami` pipes,
/// `echo hello>file` creates a file, `%PATH%` expands, and a `"` breaks out
/// of quoting (`echo hello"&whoami`). Confirmed with Rust `Command` on
/// Windows 11. Spaces and parentheses are not in this set: `C:\Program Files
/// (x86)` is an ordinary path.
///
/// Only the Windows spawn path calls it; the unit test runs on every OS.
#[cfg(any(windows, test))]
pub(crate) fn cmd_metacharacter(arg: &str) -> Option<char> {
    arg.chars()
        .find(|c| matches!(c, '&' | '|' | '<' | '>' | '%' | '"' | '\n' | '\r'))
}

// Plugin binary integrity & path validation.

/// Directories that must NEVER be the resolved location of a plugin binary.
/// Prevents symlink attacks pointing plugin paths into system directories.
pub(super) const BLOCKED_PLUGIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/sbin",
    "/bin",
    "/usr/local/sbin",
    "/System",
    "/Library",
    "C:\\Windows",
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
];

/// Verify a plugin binary's SHA-256 hash and resolved real path before spawning.
///
/// - If the plugin definition includes a `sha256` field, the binary
///   file is read and its hash is compared to the expected value. A mismatch
///   (indicating binary replacement or supply-chain compromise) is fatal.
///
/// - The binary path is canonicalized (following symlinks). If it
///   resolves to a system directory, execution is denied to prevent symlink-
///   based privilege escalation.
pub(super) fn validate_plugin_binary(
    program: &str,
    policy: Option<&PolicyEngine>,
) -> Result<(), ExecuteError> {
    let plugin = match policy.and_then(|pe| pe.plugin_for(program)) {
        Some(p) => p,
        None => return Ok(()), // not a plugin binary; skip
    };

    // Resolve the binary to an absolute path via which/where equivalent.
    let resolved = match which::which(&plugin.binary) {
        Ok(p) => p,
        Err(_) => {
            // Binary not in PATH; let the later Command::new fail naturally.
            return Ok(());
        }
    };

    // Follow symlinks and reject paths under system directories.
    if let Ok(canonical) = std::fs::canonicalize(&resolved) {
        let canonical_str = canonical.to_string_lossy().to_string();
        for blocked in BLOCKED_PLUGIN_DIRS {
            if canonical_str.starts_with(blocked) {
                return Err(ExecuteError::PluginIntegrityFailed(format!(
                    "plugin '{}' binary resolves to system directory {} ({}); execution denied",
                    plugin.name, blocked, canonical_str,
                )));
            }
        }
    }

    // If a SHA-256 hash is declared, verify the binary.
    if let Some(expected_hash) = &plugin.sha256 {
        let binary_bytes = std::fs::read(&resolved).map_err(|e| {
            ExecuteError::PluginIntegrityFailed(format!(
                "plugin '{}': cannot read binary '{}' for hash verification: {}",
                plugin.name,
                resolved.display(),
                e
            ))
        })?;
        let actual_hash = hex::encode(Sha256::digest(&binary_bytes));
        if !constant_time_eq(expected_hash.as_bytes(), actual_hash.as_bytes()) {
            return Err(ExecuteError::PluginIntegrityFailed(format!(
                "plugin '{}' binary SHA-256 mismatch: expected {}, got {}",
                plugin.name, expected_hash, actual_hash
            )));
        }
    }

    Ok(())
}

/// Constant-time byte comparison (prevents timing side-channels on hash checks).
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
