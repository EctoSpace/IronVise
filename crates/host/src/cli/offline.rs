//! Commands that need no ledger. They run before any database is opened, so
//! they work without `DATABASE_URL`.

use super::BoxError;
use crate::{Commands, HookAction, IssuerKeyAction};
use ectoledger::{commands, config};

/// Runs `command` if it needs no ledger. True when it ran.
pub async fn run(command: &Commands) -> Result<bool, BoxError> {
    match command {
        Commands::ProveAudit { .. } => return Err(commands::prove::UNAVAILABLE.into()),
        Commands::Hook { action: None } => {
            // Never touches the ledger directly: it is a client of the Observer,
            // so it needs no DATABASE_URL and no migrations.
            commands::hook::run().await;
        }
        Commands::Hook {
            action:
                Some(HookAction::Install {
                    shared,
                    user,
                    codex,
                    antigravity,
                    project,
                    command,
                }),
        } => {
            use commands::hook_install::Scope;
            let scope = match (*codex, *antigravity, *user, *shared) {
                (true, _, true, _) => Scope::CodexUser,
                (true, _, false, _) => Scope::CodexProject,
                (_, true, true, _) => Scope::AntigravityUser,
                (_, true, false, _) => Scope::AntigravityProject,
                (false, false, true, _) => Scope::User,
                (false, false, false, true) => Scope::Shared,
                (false, false, false, false) => Scope::Local,
            };
            install_hook(scope, project.as_deref(), command.as_deref()).await?;
            return Ok(true);
        }
        Commands::VerifyCertificate {
            file,
            strict,
            expected_key,
            require_anchor,
            ots,
            export_ots,
            issuer,
        } => {
            commands::report::run_verify_certificate(
                file,
                *strict || expected_key.is_some(),
                expected_key.as_deref(),
                *require_anchor,
                ots.as_deref(),
                export_ots.as_deref(),
                issuer.as_deref(),
            )?;
            return Ok(true);
        }
        Commands::IssuerKey { action } => {
            let key = match action {
                IssuerKeyAction::Init { replace } => {
                    let key = ectoledger::issuer::init(*replace)?;
                    println!("Created {}", ectoledger::issuer::key_path().display());
                    key
                }
                IssuerKeyAction::Show => ectoledger::issuer::load()?.ok_or_else(|| {
                    format!(
                        "no issuer key at {}; create one with `ironvise issuer-key init`",
                        ectoledger::issuer::key_path().display()
                    )
                })?,
            };
            println!("{}", ectoledger::issuer::public_key_hex(&key));
            return Ok(true);
        }
        Commands::VerifyVc {
            jwt,
            issuer_hex,
            audience,
        } => {
            commands::report::run_verify_vc(jwt, issuer_hex.as_deref(), audience.as_deref())?;
            return Ok(true);
        }
        Commands::McpProxy { name, command } => {
            std::process::exit(commands::mcp_proxy::run(name, command).await?);
        }
        Commands::WebhookKey { url } => {
            let secret = config::webhook_hmac_secret()
                .ok_or("WEBHOOK_HMAC_SECRET is not set: there is no key to derive from")?;
            println!(
                "{}",
                hex::encode(ectoledger::webhook::receiver_key(&secret, url))
            );
            return Ok(true);
        }
        _ => {}
    }
    Ok(false)
}

/// Adds the hook to Claude Code's settings (or updates an older one), then
/// checks the Observer and the token.
async fn install_hook(
    scope: commands::hook_install::Scope,
    project: Option<&std::path::Path>,
    command: Option<&str>,
) -> Result<(), BoxError> {
    use commands::hook_install::{
        Change, Scope, check_observer, default_command, install, install_antigravity,
    };
    let project = match project {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .ok_or("no home directory (HOME / USERPROFILE)")?;
    let path = commands::hook_install::settings_path(scope, &project, &home);
    let command = match command {
        Some(c) => c.to_string(),
        None => default_command()?,
    };
    let antigravity = matches!(scope, Scope::AntigravityProject | Scope::AntigravityUser);
    let (change, matcher) = if antigravity {
        let tools = ectoledger::server::antigravity_hook_tools();
        (
            install_antigravity(&path, &command, tools)?,
            tools.join(", "),
        )
    } else {
        let matcher = ectoledger::server::hook_matcher();
        (install(&path, &command, &matcher)?, matcher)
    };
    let verb = match change {
        Change::Added => "Installed",
        Change::Updated => "Updated",
        Change::Unchanged => "Already installed",
    };
    println!("{verb}: the IronVise hook in {}", path.display());
    println!("  matcher  {matcher}");
    println!("  command  {command}");
    let url =
        std::env::var("ECTOLEDGER_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let token = std::env::var("ECTOLEDGER_TOKEN").ok();
    println!("Observer: {}", check_observer(&url, token.as_deref()).await);
    let agent = match scope {
        Scope::CodexProject | Scope::CodexUser => "Codex",
        Scope::AntigravityProject | Scope::AntigravityUser => "Antigravity CLI",
        _ => "Claude Code",
    };
    println!(
        "{agent} runs the hook with its own environment: set ECTOLEDGER_TOKEN \
         (an agent token) and, if not the default, ECTOLEDGER_URL there."
    );
    if scope == Scope::CodexProject {
        println!("Codex runs a project's hooks once you trust them: review them with /hooks.");
    }
    if antigravity {
        println!("Antigravity CLI lists the hooks it loaded under /hooks.");
    }
    Ok(())
}
