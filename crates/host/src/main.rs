use clap::{Parser, Subcommand};

mod cli;

use uuid::Uuid;

#[derive(Parser)]
#[command(name = "ironvise")]
#[command(version)]
#[command(
    about = "Cryptographically verified, state-driven agent framework for automated security auditing"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Exit 0 when the local Observer answers GET /api/status.
    ///
    /// Uses 127.0.0.1 and `ECTO_BIND_PORT` (default 3000). No database and no
    /// curl: this is the container health check.
    Health,

    /// Run the database, migrations, and Observer dashboard on port 3000 (no agent).
    Serve {
        /// Verify full chain from genesis; otherwise only last 1000 events.
        #[arg(long, default_value_t = false)]
        verify_full: bool,
    },

    /// Run a security audit: start the Observer and execute the cognitive loop with the given prompt.
    Audit {
        /// Audit instruction for the agent (e.g. "Read server_config.txt").
        #[arg(required = true)]
        prompt: String,
        /// Verify full chain from genesis; otherwise only last 1000 events.
        #[arg(long, default_value_t = false)]
        verify_full: bool,
        /// Path to audit_policy.toml (policy hash stored in session and genesis).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// Disable the Guard (not recommended). Requires --no-guard-confirmed to proceed.
        #[arg(long)]
        no_guard: bool,
        /// Explicitly acknowledge running without the Guard. Must be used with --no-guard.
        #[arg(long)]
        no_guard_confirmed: bool,
        /// Prompt for approval gate decisions interactively on stdin instead of the dashboard.
        #[arg(long, default_value_t = false)]
        interactive: bool,
        /// Read the key-encryption password from the given file descriptor
        /// instead of the interactive prompt or ECTO_KEY_PASSWORD env var.
        /// More secure than env vars (not visible via /proc, ps, docker inspect).
        /// Unix only.  Example: `ironvise audit "..." --key-password-fd 3  3< <(pass show ironvise)`
        #[arg(long)]
        key_password_fd: Option<i32>,
    },

    /// Replay events for a session (colored output).
    Replay {
        /// Session UUID to replay.
        session: Uuid,
        /// Stop after this many steps (default: all).
        #[arg(long)]
        to_step: Option<u32>,
        /// Inject adversarial observation at sequence (e.g. "seq=3:EVIL PAYLOAD"). Can be repeated.
        #[arg(long)]
        inject_observation: Vec<String>,
    },

    /// Verify event signatures for a session (ed25519).
    VerifySession {
        /// Session UUID.
        session: Uuid,
        /// Also check the ledger against a certificate exported from this
        /// session earlier and kept elsewhere. Catches what the database alone
        /// cannot: events removed behind a rewritten seal, and a session
        /// re-signed with another key. The certificate must be signed.
        #[arg(long, value_name = "AUDIT.elc")]
        against: Option<std::path::PathBuf>,
        /// With --against: require the certificate to be signed by this
        /// Ed25519 key (hex), obtained out of band.
        #[arg(long, value_name = "HEX", requires = "against")]
        expected_key: Option<String>,
    },

    /// Survey every session's integrity, read-only. Reports rather than fails.
    ///
    /// Written for upgrades: 0.8.0 made `verify-session` bind signatures to
    /// events (the 0.8.0 changelog, F-1), so run this first to see
    /// whether any existing session is affected before the stricter check
    /// starts refusing things.
    VerifyLedger {
        /// Print a line for every session, not only the failing ones.
        #[arg(long)]
        all: bool,

        /// Exit non-zero when any session fails to verify.
        ///
        /// Off by default on purpose: the survey exists to answer "does the
        /// stricter 0.8.0 check affect anything I hold?", and a tool that
        /// fails because the answer is yes is answering a different question.
        /// Turn it on to use the survey as a gate in a script or a CI job,
        /// where "some session does not verify" has to stop the pipeline.
        #[arg(long)]
        strict: bool,
    },

    /// Export audit report for a session.
    Report {
        /// Session UUID.
        session: Uuid,
        /// Output format: sarif, json, html, or certificate (.elc).
        #[arg(long, default_value = "json")]
        format: String,
        /// Write to file (default: stdout). Required for --format certificate.
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Skip OpenTimestamps submission when generating a certificate.
        #[arg(long, default_value_t = false)]
        no_ots: bool,
        /// Read the password for the session's saved signing key from this
        /// file descriptor (Unix). Otherwise ECTO_KEY_PASSWORD or a prompt;
        /// blank writes the certificate unsigned.
        #[arg(long)]
        key_password_fd: Option<i32>,
    },

    /// [preview] Multi-agent orchestration: runs recon / analysis / verify sub-agents with independent ledgers.
    Orchestrate {
        /// Audit goal for the orchestrated run.
        #[arg(required = true)]
        goal: String,
        /// Shared policy file applied to all sub-agents (optional).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// Maximum steps per sub-agent (default: role-specific policy max_steps).
        #[arg(long)]
        max_steps: Option<u32>,
    },

    /// [preview] Compare two audit sessions (baseline vs current). Outputs remediation evidence.
    DiffAudit {
        /// Baseline session UUID.
        #[arg(long)]
        baseline: Uuid,
        /// Current session UUID.
        #[arg(long)]
        current: Uuid,
        /// Output path (default: stdout).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// [preview] Red-team mode: adversarial agent to test defenses.
    RedTeam {
        /// UUID of the completed audit session to attack.
        #[arg(long)]
        target_session: Uuid,
        /// Maximum number of injection candidates to generate.
        #[arg(long, default_value = "50")]
        attack_budget: u32,
        /// Optional path to write the report as JSON.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },

    /// [unavailable in 0.8] SP1 ZK proving withdrawn because of RUSTSEC-2026-0387.
    /// Use `report --format certificate` for verifiable audit provenance.
    ProveAudit {
        /// Session UUID to prove.
        session: Uuid,
        /// Path to the audit policy TOML file (used to extract policy patterns for the proof).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// Output path for the .elc certificate file (default: audit-<session>.elc).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// Skip OpenTimestamps submission in the generated certificate.
        #[arg(long, default_value_t = false)]
        no_ots: bool,
        /// Read the password for the session's saved signing key from this
        /// file descriptor (Unix). Otherwise ECTO_KEY_PASSWORD or a prompt;
        /// blank writes the certificate unsigned.
        #[arg(long)]
        key_password_fd: Option<i32>,
    },

    /// [preview] Timestamp a session's ledger tip with OpenTimestamps.
    AnchorSession {
        /// Session UUID whose ledger tip to anchor.
        session: Uuid,
        /// Timestamp backend. `bitcoin` (OpenTimestamps) is the only one.
        #[arg(long, default_value = "bitcoin", value_parser = ["bitcoin"])]
        chain: String,
    },

    /// Claude Code PreToolUse hook client: reads the hook JSON on stdin,
    /// asks the Observer to verify the tool call, writes the decision on stdout.
    ///
    /// Fail-closed - any error blocks the tool call. Needs ECTOLEDGER_TOKEN,
    /// and ECTOLEDGER_URL if the Observer is not on http://127.0.0.1:3000.
    ///
    /// This ENFORCES: Claude Code honours the deny before the tool runs. Not to
    /// be confused with `proxy`, which only records.
    ///
    /// `ironvise hook install` adds it to Claude Code's settings.
    Hook {
        #[command(subcommand)]
        action: Option<HookAction>,
    },
    /// Run an OpenAI-compatible RECORDING proxy in front of a real upstream.
    ///
    /// Point any agent's base URL at this and every prompt and completion is
    /// written to the hash chain. Covers Codex CLI, Cursor, Aider, Continue and
    /// anything else with a configurable endpoint, with no per-tool work.
    ///
    /// This RECORDS ONLY. It cannot block: it sees text, not actions -- it
    /// never sees a command execute, only a model asking to run one. For
    /// enforcement use `hook`.
    Proxy {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:3100")]
        bind: String,
        /// Upstream OpenAI-compatible server to forward to.
        #[arg(long, default_value = "https://api.openai.com")]
        upstream: String,
        /// Allow a non-loopback --bind. The proxy has no authentication:
        /// anyone who can reach it can write to this ledger.
        #[arg(long, default_value_t = false)]
        allow_remote: bool,
    },
    /// Verify an IronVise Audit Certificate (.elc) file.
    VerifyCertificate {
        /// Path to the .elc certificate file.
        file: std::path::PathBuf,
        /// Require a signature that verifies. Without this an unsigned
        /// certificate is reported as internally consistent and exits 0:
        /// internal consistency is computed from the file's own contents and
        /// says nothing about who issued it.
        #[arg(long, default_value_t = false)]
        strict: bool,
        /// Require the signature to be by this ed25519 public key (hex).
        /// Implies --strict. Obtain the key out of band - a key read from the
        /// certificate only tells you that it signed itself.
        #[arg(long)]
        expected_key: Option<String>,
        /// Require a Bitcoin attestation in the OTS stamp. A fresh stamp is a
        /// calendar server's promise and does not satisfy this.
        #[arg(long, default_value_t = false)]
        require_anchor: bool,
        /// Read the stamp from this .ots file (for example after `ots
        /// upgrade`) instead of the certificate. It must stamp this tip.
        #[arg(long, value_name = "FILE")]
        ots: Option<std::path::PathBuf>,
        /// Write the certificate's stamp as a .ots file for `ots upgrade`
        /// and `ots verify`, then verify.
        #[arg(long, value_name = "FILE")]
        export_ots: Option<std::path::PathBuf>,
        /// Require a countersignature by this installation issuer key (hex,
        /// from `ironvise issuer-key show`). On its own it satisfies --strict.
        #[arg(long, value_name = "HEX")]
        issuer: Option<String>,
    },

    /// List a session's data receipts (what its tools returned, by SHA-256)
    /// and check files against them. The session must verify first.
    ///
    ///   ironvise data-receipts <session> --file config.ini
    DataReceipts {
        /// Session UUID.
        session: Uuid,
        /// A file to check: does its SHA-256 match a text a tool returned?
        /// Repeatable; exits 1 when any file matches no receipt.
        #[arg(long = "file", value_name = "PATH")]
        files: Vec<std::path::PathBuf>,
    },

    /// The installation's issuer key, which countersigns every certificate
    /// this installation exports (offline, no database).
    IssuerKey {
        #[command(subcommand)]
        action: IssuerKeyAction,
    },

    /// [preview] Decode and verify a W3C VC-JWT issued by IronVise.
    ///
    /// Checks structure, expiry, and (when --issuer-hex is provided) the Ed25519 signature
    /// over the VC payload.  Prints the decoded credential subject to stdout.
    ///
    /// # Examples
    ///
    ///   ironvise verify-vc "eyJhbGci..."
    ///   ironvise verify-vc "eyJhbGci..." --issuer-hex <hex-encoded verifying key>
    VerifyVc {
        /// The VC-JWT string (three base64url parts separated by `.`).
        jwt: String,
        /// Optional hex-encoded Ed25519 verifying key (32 bytes / 64 hex chars).
        /// When provided, the JWT signature is verified against this key.
        #[arg(long)]
        issuer_hex: Option<String>,
        /// Who is verifying. A VC carrying `aud` (see ECTO_VC_AUDIENCE) is
        /// accepted only when this is one of its audiences.
        #[arg(long)]
        audience: Option<String>,
    },

    /// Import NVIDIA OpenShell decision logs (OCSF JSON lines) as signed receipts.
    ///
    /// One sealed ledger session per sandbox, every record signed with the
    /// SHA-256 of its original line, and a signed `.elc` receipt per session
    /// in --out. Audit-mode allows are recorded as `audit`. Re-importing a log
    /// adds nothing.
    ///
    ///   ironvise import-openshell /var/log/openshell-ocsf.2026-09-29.log
    ImportOpenshell {
        /// OCSF JSONL files written by OpenShell.
        #[arg(required = true)]
        files: Vec<std::path::PathBuf>,
        /// Where to write the signed receipts.
        #[arg(long, default_value = "openshell-receipts")]
        out: std::path::PathBuf,
    },

    /// Put IronVise between an MCP client and a stdio MCP server.
    ///
    /// Every `tools/call` is judged by the Observer (policy, allowed_mcp_tools,
    /// the command check on its arguments) and recorded before the server sees
    /// it; a refused call returns to the model as a tool error. Everything else
    /// passes through. Fail-closed. Needs ECTOLEDGER_TOKEN (agent role), and
    /// ECTOLEDGER_URL if the Observer is not on http://127.0.0.1:3000.
    ///
    ///   ironvise mcp-proxy --name github -- npx -y @modelcontextprotocol/server-github
    McpProxy {
        /// The server's name as policies and allowed_mcp_tools refer to it
        /// (`mcp:<name>/<tool>`). Letters, digits, `-`, `_`, `.`; no `__`.
        #[arg(long)]
        name: String,
        /// The MCP server command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Print the webhook signing key for one receiver.
    ///
    /// Derived from WEBHOOK_HMAC_SECRET and the receiver's exact URL. Give each
    /// receiver only its own key: it verifies X-EctoLedger-Signature-V1 and
    /// cannot sign a delivery another receiver would accept. Offline.
    ///
    ///   WEBHOOK_HMAC_SECRET=... ironvise webhook-key --url https://siem.example/hook
    WebhookKey {
        /// The receiver URL exactly as configured for the webhook.
        #[arg(long)]
        url: String,
    },
}

#[derive(Subcommand)]
enum IssuerKeyAction {
    /// Create the issuer key (issuer.key in ECTO_DATA_DIR, owner-only) and
    /// print its public key: the one to hand relying parties for --issuer.
    Init {
        /// Replace an existing key. Certificates it signed keep verifying
        /// against its public key; whoever pinned it needs the new one.
        #[arg(long)]
        replace: bool,
    },
    /// Print the issuer's public key.
    Show,
}

#[derive(Subcommand)]
enum HookAction {
    /// Add the hook to Claude Code's settings (or Codex's or Antigravity CLI's hooks.json), or update an older one.
    ///
    /// Writes .claude/settings.local.json in the project by default (this
    /// machine, not checked in). Keeps everything else in the file, and never
    /// adds a second IronVise hook. Then checks the Observer and token.
    ///
    ///   ironvise hook install
    ///   ironvise hook install --shared      # .claude/settings.json, for the team
    ///   ironvise hook install --user        # ~/.claude/settings.json, every project
    ///   ironvise hook install --codex       # .codex/hooks.json, for Codex
    ///   ironvise hook install --antigravity # .agents/hooks.json, for Antigravity CLI
    Install {
        /// Write the project's shared .claude/settings.json.
        #[arg(long, conflicts_with = "user")]
        shared: bool,
        /// Write ~/.claude/settings.json, for every project.
        #[arg(long)]
        user: bool,
        /// Install for Codex: .codex/hooks.json in the project, or
        /// ~/.codex/hooks.json with --user.
        #[arg(long, conflicts_with = "shared")]
        codex: bool,
        /// Install for Antigravity CLI: .agents/hooks.json in the project, or
        /// ~/.gemini/config/hooks.json with --user.
        #[arg(long, conflicts_with_all = ["shared", "codex"])]
        antigravity: bool,
        /// The project directory (default: the current directory).
        #[arg(long)]
        project: Option<std::path::PathBuf>,
        /// The command Claude Code should run (default: this binary's path + ` hook`).
        #[arg(long)]
        command: Option<String>,
    },
}

/// Print errors through `Display`, not `Debug`.
///
/// Returning `Result` from `main` renders the error with `Debug`, so every
/// carefully written multi-line hint in this binary shipped as a single line
/// of escaped `\n` inside double quotes. Two call sites had already been
/// hand-patched to work around it, each with a comment explaining why; the
/// eight-line message `prove-audit` prints on a default build had not, and
/// that is the one nearly every new user meets first.
///
/// One wrapper fixes it for every command, including ones not written yet.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => match e.downcast_ref::<cli::exit::ExitWith>() {
            Some(cli::exit::ExitWith(code)) => std::process::ExitCode::from(*code),
            None => {
                eprintln!("Error: {e}");
                std::process::ExitCode::FAILURE
            }
        },
    }
}

async fn run() -> Result<(), cli::BoxError> {
    // `--version` and `health` must not announce demo settings. Clap exits
    // from `parse` for `--version` and `--help`, before any of the rest.
    dotenvy::dotenv().ok();
    let args = Cli::parse();
    if matches!(args.command, Commands::Health) {
        let code = ectoledger::commands::health::run();
        return if code == 0 {
            Ok(())
        } else {
            Err(Box::new(cli::exit::ExitWith(code)))
        };
    }
    cli::startup::prepare()?;
    if matches!(
        args.command,
        Commands::Serve { .. } | Commands::Audit { .. }
    ) {
        ectoledger::config::warn_if_insecure_mode();
    }
    if cli::offline::run(&args.command).await? {
        return Ok(());
    }
    let cli::database::Ledger {
        pool,
        embedded: _embedded,
    } = cli::database::open(&args.command).await?;
    cli::database::check(&args.command, &pool).await?;
    cli::startup::confine()?;
    let cancel = cli::startup::cancel_on_ctrl_c();
    cli::dispatch::run(args.command, pool, cancel).await
}
