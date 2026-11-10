//! `run_command`: one allowed program, sandboxed, with a timeout and bounded
//! output.

use super::*;

pub(super) const CMD_TIMEOUT_SECS: u64 = 30;

pub(super) async fn run_command_with_context(
    validated: ValidatedIntent,
    creds: Option<&CloudCredentialSet>,
    policy: Option<&PolicyEngine>,
) -> Result<String, ExecuteError> {
    let cmd = validated
        .params()
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("command"))?;

    let (program, args) = parse_command(cmd)?;

    let allowed = allowed_programs_with_context(creds, policy);
    let program_lower = program.to_lowercase();
    if !allowed.iter().any(|a| a.to_lowercase() == program_lower) {
        return Err(ExecuteError::ProgramNotAllowed(program));
    }

    // Verify plugin binary integrity (SHA-256) and resolved path.
    validate_plugin_binary(&program, policy)?;

    // Defense-in-depth: block dangerous arguments on specific allowed programs
    // that can be weaponised for arbitrary execution or file writes.
    validate_program_args(&program, &args)?;

    // On Windows, CMD builtins (dir, type, echo, …) are not standalone .exe
    // files - they must be run via `cmd.exe /C <builtin> <args>`.
    #[cfg(windows)]
    let (spawn_program, spawn_args) = {
        let prog_lower = program.to_lowercase();
        if CMD_BUILTINS.iter().any(|b| *b == prog_lower) {
            for piece in std::iter::once(&program).chain(args.iter()) {
                if let Some(c) = cmd_metacharacter(piece) {
                    return Err(ExecuteError::InvalidCommand(format!(
                        "{program} is run through cmd.exe, which would interpret '{c}'"
                    )));
                }
            }
            let mut cmd_args = vec!["/C".to_string(), program.clone()];
            cmd_args.extend(args.iter().cloned());
            ("cmd".to_string(), cmd_args)
        } else {
            (program.clone(), args.clone())
        }
    };
    #[cfg(not(windows))]
    let (spawn_program, spawn_args) = (program.clone(), args.clone());

    let mut child_cmd = Command::new(&spawn_program);
    child_cmd.args(&spawn_args);

    // Clear inherited env to prevent secret leakage (DATABASE_URL, API keys, etc.)
    // to child processes. Re-inject only minimal safe variables.
    child_cmd.env_clear();
    #[cfg(windows)]
    const SAFE_ENV_VARS: &[&str] = &[
        "PATH",
        "USERPROFILE",
        "USERNAME",
        "LANG",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "COMSPEC",
    ];
    #[cfg(not(windows))]
    const SAFE_ENV_VARS: &[&str] = &["PATH", "HOME", "USER", "LANG", "TERM", "LC_ALL", "TMPDIR"];
    for var in SAFE_ENV_VARS {
        if let Ok(val) = std::env::var(var) {
            child_cmd.env(var, val);
        }
    }

    // Inject cloud CLI env vars into the child process only (parent env is unchanged).
    if let Some(c) = creds
        && crate::cloud_creds::is_cloud_cli(&program)
    {
        child_cmd.envs(&c.env_vars);
    }

    // Inject plugin env_passthrough vars for the matching plugin binary.
    if let Some(pe) = policy {
        let passthrough = pe.plugin_env_passthrough_for(&program);
        for var_name in passthrough {
            if let Ok(val) = std::env::var(&var_name) {
                child_cmd.env(&var_name, val);
            }
        }
    }

    // Apply the strongest available child-process sandbox on Unix platforms:
    //   - Linux (with `sandbox` feature): Landlock + rlimits + seccomp
    //   - macOS: Seatbelt (sandbox_init) profile
    //   - Other Unix: no-op (advisory tripwires only)
    // On Windows, the Job Object sandbox is applied once at main-process startup
    // (see main.rs) because Windows lacks the Unix pre_exec hook.
    #[cfg(unix)]
    {
        let workspace = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        // Resolve the failure policy before fork: env access inside pre_exec
        // (post-fork, pre-exec) is not async-signal-safe.
        let permissive = crate::config::sandbox_permissive();
        unsafe {
            child_cmd.pre_exec(move || {
                if let Err(e) = apply_child_sandbox_for_exec(&workspace) {
                    if permissive {
                        eprintln!(
                            "sandbox: OS-level isolation unavailable ({e}); \
                             ECTO_SANDBOX_PERMISSIVE=true - continuing with \
                             advisory tripwires only"
                        );
                        return Ok(());
                    }
                    eprintln!(
                        "sandbox: OS-level isolation failed ({e}); aborting command. \
                         Set ECTO_SANDBOX_PERMISSIVE=true to allow unsandboxed fallback."
                    );
                    return Err(std::io::Error::other(format!(
                        "child sandbox setup failed: {e}"
                    )));
                }
                Ok(())
            });
        }
    }

    let output = tokio::time::timeout(Duration::from_secs(CMD_TIMEOUT_SECS), child_cmd.output())
        .await
        .map_err(|_| ExecuteError::Timeout)?
        .map_err(ExecuteError::Io)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status;
    Ok(format_sandbox_output(status.code(), &stdout, &stderr))
}
