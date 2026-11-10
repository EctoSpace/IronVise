//! `POST /api/hook/tool-call` - the Claude Code `PreToolUse` enforcement point.
//!
//! This is the one integration where prevention can honestly be claimed. Claude
//! Code calls a `PreToolUse` hook *before* a tool runs and honours a `deny`, so
//! the decision recorded here is the decision that actually happened - unlike
//! the recording proxy, which sees a model saying it wants to run a command and
//! cannot stop it. Those two surfaces must never be described as one thing; see
//! `docs/guides/integrations.md`.
//!
//! ## What it does
//!
//! Maps a Claude Code tool call onto a [`ProposedIntent`], runs it through the
//! shared [`crate::verify::evaluate_intent`] pipeline - the same policy →
//! tripwire → guard path the cognitive loop uses - and appends the outcome to a
//! ledger session before answering. Nothing is executed here; Claude Code
//! executes, or does not, based on the answer.
//!
//! ## Honest limits
//!
//! IronVise's policy vocabulary has four actions. Claude Code has many tools.
//! Tools that map cleanly (`Bash`, `Read`, `WebFetch`) are evaluated; anything
//! else returns [`Decision::Ask`], which escalates to the human. An unmapped
//! tool is never silently allowed, and it is never reported as "evaluated"
//! either - the coverage matrix says which is which.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::guard::GuardExecutor;
use ectoledger_core::intent::ProposedIntent;

use super::AppState;
use super::auth::{Caller, Role};
use crate::config;
use crate::schema::EventPayload;
use crate::tripwire::{MCP_ACTION_PREFIX, Tripwire};
use crate::verify::{Coverage, DenyStage, EvaluationContext, Verdict, evaluate_intent};

/// Labels the session so hook-mediated events cannot be confused with ones the
/// native cognitive loop produced. An auditor reading `llm_backend` can tell
/// which surface a session came from.
const HOOK_BACKEND_LABEL: &str = "claude-code";
const CODEX_BACKEND_LABEL: &str = "codex";
const ANTIGRAVITY_BACKEND_LABEL: &str = "antigravity";
const MCP_PROXY_BACKEND_LABEL: &str = "mcp-proxy";

/// Claude Code has no `justification` field, and `Tripwire::validate` rejects
/// intents whose justification is shorter than `min_justification_length` -
/// naively mapped, every Bash call would be denied for the wrong reason.
///
/// This states the absence rather than inventing a rationale. Fabricating a
/// plausible-sounding justification would put words in the model's mouth in an
/// audit record, which is worse than a slightly awkward constant.
const NO_MODEL_JUSTIFICATION: &str = "Forwarded by a coding agent's PreToolUse hook; no model justification is \
     available on this surface.";

#[derive(Debug, Deserialize)]
pub(crate) struct HookRequest {
    /// Claude Code's own session id. One ledger session is created per distinct
    /// value so a whole Claude Code conversation forms one auditable chain.
    pub session_id: String,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub cwd: Option<String>,
    /// `$CLAUDE_PROJECT_DIR` from the hook client: the project root, which
    /// `cwd` is not once the agent has `cd`-ed. Preferred when present.
    #[serde(default)]
    pub project_dir: Option<String>,
    /// Claude Code's id for this one tool use; a repeat is a replay.
    #[serde(default)]
    pub tool_use_id: Option<String>,
    /// `codex` or `antigravity` from those agents' hooks; absent means
    /// Claude Code.
    #[serde(default)]
    pub agent: Option<String>,
}

/// A tool's result, from Claude Code's `PostToolUse` hook or `mcp-proxy`, as
/// the data receipt they built from it where the tool ran
/// (`crate::receipts::receipt`). The result itself never comes here.
#[derive(Debug, Deserialize)]
pub(crate) struct ToolResultRequest {
    pub session_id: String,
    pub receipt: EventPayload,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub project_dir: Option<String>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ToolResultResponse {
    pub ledger_session_id: Uuid,
    /// The receipt as recorded: hashes only.
    pub receipt: EventPayload,
}

/// `stage` of a refusal for a replayed request.
const REPLAY_STAGE: &str = "replay";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Decision {
    Allow,
    Deny,
    /// The tool has no equivalent in the policy vocabulary, so no judgement was
    /// made. Escalates to the human rather than defaulting either way.
    Ask,
}

#[derive(Debug, Serialize)]
pub(crate) struct HookResponse {
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Which check refused, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// The ledger session this call was recorded against.
    pub ledger_session_id: Uuid,
    /// True when the decision was recorded in the hash chain. A decision that
    /// could not be recorded is still returned, but the caller should know the
    /// audit trail is incomplete.
    pub recorded: bool,
    /// Which checks ran and which did not. An `allow` from a surface with no
    /// policy and no guard is a weaker statement than an `allow` from one with
    /// both, and the response should not make them look alike.
    pub coverage: Coverage,
}

/// The Claude Code and Codex tools [`map_tool`] understands. Anything else is
/// escalated as having no equivalent; one of these that still fails to map
/// was sent without what the check needs.
pub(crate) const MAPPED_TOOLS: &[&str] = &[
    "Bash",
    "Read",
    "WebFetch",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "Glob",
    "Grep",
    "apply_patch",
];

/// The Antigravity CLI tools [`map_tool`] understands, by their own names.
pub(crate) const ANTIGRAVITY_TOOLS: &[&str] = &[
    "run_command",
    "view_file",
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
    "list_dir",
    "find_by_name",
    "grep_search",
    "read_url_content",
];

/// Map a Claude Code tool call onto the policy vocabulary.
///
/// Returns `None` for tools with no equivalent. Adding a mapping here widens
/// what the hook claims to evaluate, so each one must correspond to an action
/// the policy engine and tripwire genuinely understand. `cwd` is Claude
/// Code's working directory, where `Glob` and `Grep` search by default.
fn map_tool(
    tool_name: &str,
    input: &serde_json::Value,
    cwd: Option<&str>,
) -> Option<ProposedIntent> {
    // `mcp__<server>__<tool>`: checked by name (policy, allowed_mcp_tools)
    // and by any shell command in its arguments.
    if let Some(rest) = tool_name.strip_prefix("mcp__") {
        let (server, tool) = rest.split_once("__")?;
        return Some(ProposedIntent {
            action: format!("{MCP_ACTION_PREFIX}{server}/{tool}"),
            params: serde_json::json!({ "server": server, "tool": tool, "arguments": input }),
            justification: NO_MODEL_JUSTIFICATION.to_string(),
            reasoning: String::new(),
        });
    }

    let str_field = |k: &str| input.get(k).and_then(|v| v.as_str()).map(str::to_string);

    let (action, params) = match tool_name {
        "Bash" => (
            "run_command",
            serde_json::json!({ "command": str_field("command")? }),
        ),
        "Read" => (
            "read_file",
            serde_json::json!({ "path": str_field("file_path")? }),
        ),
        "WebFetch" => ("http_get", serde_json::json!({ "url": str_field("url")? })),
        // Every tool that changes a file. The check is on the path: where the
        // write lands, not what it says, which the policy has no vocabulary
        // for yet.
        "Write" | "Edit" | "MultiEdit" => (
            "write_file",
            serde_json::json!({ "path": str_field("file_path")? }),
        ),
        "NotebookEdit" => (
            "write_file",
            serde_json::json!({ "path": str_field("notebook_path")? }),
        ),
        // Searches read what lies under a directory, so they are checked as a
        // read of that directory.
        "Glob" | "Grep" => (
            "read_file",
            serde_json::json!({ "path": search_root(tool_name, input, cwd)? }),
        ),
        // Codex's file edits: one patch can add, change, move and delete
        // several files, and each path is checked.
        "apply_patch" => (
            "write_file",
            serde_json::json!({ "paths": patch_paths(&str_field("command")?, cwd)? }),
        ),
        // Antigravity CLI's tools, with its PascalCase arguments. A search
        // reads under its directory; the pattern only filters names there.
        "run_command" => (
            "run_command",
            serde_json::json!({ "command": str_field("CommandLine")? }),
        ),
        "view_file" => (
            "read_file",
            serde_json::json!({ "path": str_field("AbsolutePath")? }),
        ),
        "write_to_file" | "replace_file_content" | "multi_replace_file_content" => (
            "write_file",
            serde_json::json!({ "path": str_field("TargetFile")? }),
        ),
        "list_dir" => (
            "read_file",
            serde_json::json!({ "path": str_field("DirectoryPath")? }),
        ),
        "find_by_name" => (
            "read_file",
            serde_json::json!({ "path": str_field("SearchDirectory")? }),
        ),
        "grep_search" => (
            "read_file",
            serde_json::json!({ "path": str_field("SearchPath")? }),
        ),
        "read_url_content" => ("http_get", serde_json::json!({ "url": str_field("Url")? })),
        _ => return None,
    };

    Some(ProposedIntent {
        action: action.to_string(),
        params,
        justification: NO_MODEL_JUSTIFICATION.to_string(),
        reasoning: String::new(),
    })
}

/// Every file an `apply_patch` patch writes, moves to or deletes, relative
/// paths taken from `cwd`. `None` for a patch that names no file, or a
/// relative one with no `cwd` to resolve it against.
fn patch_paths(patch: &str, cwd: Option<&str>) -> Option<Vec<String>> {
    const HEADERS: [&str; 4] = [
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    let mut paths = Vec::new();
    for line in patch.lines() {
        let Some(path) = HEADERS.iter().find_map(|h| line.strip_prefix(h)) else {
            continue;
        };
        let path = std::path::Path::new(path.trim());
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::path::Path::new(cwd?).join(path)
        };
        let path = path.to_string_lossy().into_owned();
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    (!paths.is_empty()).then_some(paths)
}

/// The directory a `Glob` or `Grep` call can reach.
///
/// Both search `path`, or Claude Code's working directory without one. A glob
/// pattern can reach further than that: `/etc/*.conf` ignores `path`, and
/// `src/**` never leaves `src`. So the literal leading part of the pattern is
/// joined on, which is the deepest directory every match lies under. A pattern
/// that climbs with `..`, even inside braces, is not resolved here: `None`,
/// and the call is escalated rather than checked against the wrong directory.
///
/// Grep's own pattern is a regex over file contents and its `glob` only
/// filters files already under the root, so neither moves it.
fn search_root(tool: &str, input: &serde_json::Value, cwd: Option<&str>) -> Option<String> {
    use std::path::{Path, PathBuf};
    let str_field = |k: &str| input.get(k).and_then(|v| v.as_str());
    let base = match str_field("path").filter(|p| !p.is_empty()) {
        Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
        Some(p) => Path::new(cwd?).join(p),
        None => PathBuf::from(cwd?),
    };
    let root = if tool == "Glob" {
        let pattern = str_field("pattern")?;
        if pattern
            .split(['/', '\\', '{', '}', ','])
            .any(|seg| seg == "..")
        {
            return None;
        }
        let literal: PathBuf = Path::new(pattern)
            .components()
            .take_while(|c| {
                !c.as_os_str()
                    .to_string_lossy()
                    .contains(['*', '?', '[', '{'])
            })
            .collect();
        if literal.as_os_str().is_empty() {
            base
        } else {
            base.join(literal)
        }
    } else {
        base
    };
    Some(root.to_string_lossy().into_owned())
}

/// Ledger sessions created for Claude Code sessions, with their signing keys.
///
/// The key only exists in memory - `create_session` returns it once and it is
/// never stored - so it has to be held for as long as the Claude Code session
/// may keep sending tool calls. Keyed by Claude Code's `session_id`.
///
/// A server restart drops the map, so a subsequent tool call from the same
/// Claude Code session opens a fresh ledger session. The events already written
/// remain valid and verifiable; the conversation is simply split across two
/// chains, which is recorded honestly rather than papered over.
#[derive(Clone)]
struct HookSession {
    ledger_id: Uuid,
    key: Arc<SigningKey>,
    /// The project the Claude Code session started in (see [`build_tripwire_for`]).
    root: Option<std::path::PathBuf>,
    /// The token that opened it. Claude Code's `session_id` is chosen by the
    /// client, so without this any agent token could add server-signed events
    /// to another client's session by reusing its id.
    owner: String,
}

static HOOK_SESSIONS: std::sync::OnceLock<Mutex<HashMap<String, HookSession>>> =
    std::sync::OnceLock::new();

fn hook_sessions() -> &'static Mutex<HashMap<String, HookSession>> {
    HOOK_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn session_for(
    state: &AppState,
    claude_session_id: &str,
    project: Option<&str>,
    agent: Option<&str>,
    caller: &str,
) -> Result<HookSession, (StatusCode, String)> {
    let mut map = hook_sessions().lock().await;
    if let Some(existing) = map.get(claude_session_id) {
        if existing.owner != caller {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "Session {claude_session_id} was opened with another token; \
                     its ledger session takes calls from that token only"
                ),
            ));
        }
        return Ok(existing.clone());
    }

    // `ironvise mcp-proxy` uses this endpoint too; History should say so.
    let (client, label) = match (claude_session_id.strip_prefix("mcp-proxy:"), agent) {
        (Some(rest), _) => (
            format!("MCP proxy for {}", rest.split(':').next().unwrap_or("?")),
            MCP_PROXY_BACKEND_LABEL,
        ),
        (None, Some("codex")) => ("Codex session".to_string(), CODEX_BACKEND_LABEL),
        (None, Some("antigravity")) => {
            ("Antigravity session".to_string(), ANTIGRAVITY_BACKEND_LABEL)
        }
        (None, _) => ("Claude Code session".to_string(), HOOK_BACKEND_LABEL),
    };
    let goal = match project {
        Some(dir) => format!("{client} in {dir}"),
        None => client,
    };
    let (session, key) = state
        .pool
        .create_session(&goal, label, "n/a", None)
        .await
        .map_err(|e| {
            tracing::error!("hook: creating a ledger session: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("creating a ledger session for the hook: {e}"),
            )
        })?;

    // Pinned at the first call: a later `cwd` does not move the workspace.
    let root = project.and_then(|d| std::path::Path::new(d).canonicalize().ok());
    let entry = HookSession {
        ledger_id: session.id,
        key: Arc::new(key),
        root,
        owner: caller.to_string(),
    };
    super::session_keys::remember(entry.ledger_id, entry.key.clone()).await;
    map.insert(claude_session_id.to_string(), entry.clone());
    Ok(entry)
}

/// Record a data receipt for what a tool returned: hashes of the response and
/// of each text the agent received, never the data (see `crate::receipts`).
/// Anything but a well-formed receipt is a 400. One receipt per tool use: a
/// second for the same `tool_use_id` is a 409.
pub(crate) async fn tool_result(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::Extension(caller): axum::Extension<Caller>,
    axum::Json(body): axum::Json<ToolResultRequest>,
) -> Result<axum::Json<ToolResultResponse>, (StatusCode, String)> {
    if role == Role::Auditor {
        return Err((
            StatusCode::FORBIDDEN,
            "Auditor role cannot record tool results".into(),
        ));
    }
    let receipt = crate::receipts::accept(body.receipt, body.tool_use_id.as_deref())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let session = session_for(
        &state,
        &body.session_id,
        body.project_dir.as_deref().or(body.cwd.as_deref()),
        body.agent.as_deref(),
        &caller.0,
    )
    .await?;
    if let Some(id) = body.tool_use_id.as_deref() {
        let fresh = state
            .pool
            .consume_request(&format!("hook-result:{}", body.session_id), id, &caller.0)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("replay check failed: {e}"),
                )
            })?;
        if !fresh {
            return Err((
                StatusCode::CONFLICT,
                format!("a receipt for tool_use_id {id} is already recorded in this session"),
            ));
        }
    }
    state
        .pool
        .append_event(
            receipt.clone(),
            Some(session.ledger_id),
            None,
            Some(session.key.as_ref()),
        )
        .await
        .map_err(|e| {
            tracing::error!("hook: recording a data receipt failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("recording the receipt failed: {e}"),
            )
        })?;
    state.metrics.inc_events_appended();
    Ok(axum::Json(ToolResultResponse {
        ledger_session_id: session.ledger_id,
        receipt,
    }))
}

type HookResult<T> = Result<T, (StatusCode, String)>;

pub(crate) async fn tool_call(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::Extension(caller): axum::Extension<Caller>,
    axum::Json(body): axum::Json<HookRequest>,
) -> HookResult<axum::Json<HookResponse>> {
    // Writes ledger events, so read-only auditors are refused.
    if role == Role::Auditor {
        return Err((
            StatusCode::FORBIDDEN,
            "Auditor role cannot submit tool calls for verification".into(),
        ));
    }

    let session = session_for(
        &state,
        &body.session_id,
        body.project_dir.as_deref().or(body.cwd.as_deref()),
        body.agent.as_deref(),
        &caller.0,
    )
    .await?;

    if let Some(refusal) = refuse_replay(&state, &body, &session, &caller.0).await? {
        return Ok(axum::Json(refusal));
    }

    let Some(intent) = map_tool(&body.tool_name, &body.tool_input, body.cwd.as_deref()) else {
        return Ok(axum::Json(escalate_unmapped(&state, &body, &session).await));
    };

    let (verdict, coverage) = judge(&state, session.root.as_deref(), &intent).await;
    let recorded = record(
        &state,
        &session,
        payload_for(&verdict, &intent),
        "appending the decision",
    )
    .await;
    if recorded {
        state.metrics.inc_events_appended();
    }
    Ok(axum::Json(respond(
        &state,
        verdict,
        session.ledger_id,
        recorded,
        coverage,
    )))
}

/// Append one signed event to the hook's ledger session. A failure is logged
/// and reported as `false`: the decision still stands, because refusing to
/// answer would let the agent proceed on a hook error, but the response says
/// it was not recorded.
async fn record(
    state: &AppState,
    session: &HookSession,
    payload: EventPayload,
    what: &str,
) -> bool {
    state
        .pool
        .append_event(
            payload,
            Some(session.ledger_id),
            None,
            Some(session.key.as_ref()),
        )
        .await
        .map_err(|e| tracing::error!("hook: {what} failed: {e}"))
        .is_ok()
}

/// The agent asks once per tool use. A second request with the same
/// `tool_use_id` is a replay: refused, and the refusal is signed into the
/// session like any other decision.
async fn refuse_replay(
    state: &AppState,
    body: &HookRequest,
    session: &HookSession,
    caller: &str,
) -> HookResult<Option<HookResponse>> {
    let Some(tool_use_id) = body.tool_use_id.as_deref() else {
        return Ok(None);
    };
    let fresh = state
        .pool
        .consume_request(&format!("hook:{}", body.session_id), tool_use_id, caller)
        .await
        .map_err(|e| {
            tracing::error!("hook: replay check failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("replay check failed: {e}"),
            )
        })?;
    if fresh {
        return Ok(None);
    }
    let reason =
        format!("replayed request: tool_use_id {tool_use_id} was already decided in this session");
    let refusal = EventPayload::TripwireRejection {
        action: Some(body.tool_name.clone()),
        reason: reason.clone(),
        stage: REPLAY_STAGE.to_string(),
        enforced: true,
    };
    let recorded = record(state, session, refusal, "recording a replay refusal").await;
    state.metrics.inc_tripwire_rejections();
    Ok(Some(HookResponse {
        decision: Decision::Deny,
        reason: Some(reason),
        stage: Some(REPLAY_STAGE.to_string()),
        ledger_session_id: session.ledger_id,
        recorded,
        coverage: Coverage {
            evaluated: vec!["replay"],
            skipped: vec!["policy", "tripwire", "guard"],
            policy_hash: None,
        },
    }))
}

/// A tool with no mapping cannot be judged, so no judgement is claimed. It is
/// recorded as an approval gate: the decision passes to a person (or, under
/// Codex, which cannot ask, to a refusal), and the ledger shows which call
/// left IronVise's hands.
async fn escalate_unmapped(
    state: &AppState,
    body: &HookRequest,
    session: &HookSession,
) -> HookResponse {
    let tool = body.tool_name.as_str();
    let why = if MAPPED_TOOLS.contains(&tool)
        || ANTIGRAVITY_TOOLS.contains(&tool)
        || tool.starts_with("mcp__")
    {
        "was sent without what its check needs (a path, a command, a URL, or a \
         search that stays inside its directory)"
    } else {
        "has no equivalent in IronVise's policy vocabulary"
    };
    let escalation = EventPayload::ApprovalRequired {
        gate_id: format!(
            "hook:{}",
            body.tool_use_id.as_deref().unwrap_or("unidentified")
        ),
        action_name: body.tool_name.clone(),
        action_params_summary: crate::webhook::preview(&body.tool_input.to_string()),
    };
    let recorded = record(state, session, escalation, "recording an escalation").await;
    if recorded {
        state.metrics.inc_events_appended();
    }
    HookResponse {
        decision: Decision::Ask,
        reason: Some(format!("{tool} {why}, so it was not evaluated.")),
        stage: None,
        ledger_session_id: session.ledger_id,
        recorded,
        coverage: Coverage {
            evaluated: Vec::new(),
            skipped: vec!["policy", "tripwire", "guard"],
            policy_hash: None,
        },
    }
}

/// Policy (from `ECTO_POLICY_PATH`), tripwire and, with `GUARD_REQUIRED`, the
/// server's shared guard worker. When the guard cannot run, the chain denies at
/// `guard_unavailable` rather than allowing what it did not check, and the
/// worker is discarded so the next call starts a fresh one.
async fn judge(
    state: &AppState,
    project_root: Option<&std::path::Path>,
    intent: &ProposedIntent,
) -> (Verdict, Coverage) {
    let tripwire = build_tripwire_for(project_root);
    let guard_required = config::guard_required();
    let ctx = EvaluationContext {
        policy: state.policy.as_ref().map(|p| &p.engine),
        tripwire: &tripwire,
        goal: "Claude Code session",
        step: 0,
        guard_required,
    };
    let mut guard = state.guard.acquire(guard_required).await;
    let verdict = evaluate_chain(&ctx, guard.executor(), intent).await;
    let coverage = Coverage::new(
        state.policy.as_ref().map(|p| p.hash.clone()),
        guard.running(),
    );
    if matches!(
        &verdict,
        Verdict::Deny {
            stage: DenyStage::GuardUnavailable,
            ..
        }
    ) {
        guard.discard();
    }
    (verdict, coverage)
}

fn payload_for(verdict: &Verdict, intent: &ProposedIntent) -> EventPayload {
    match verdict {
        Verdict::Allow => EventPayload::Action {
            name: intent.action.clone(),
            params: intent.params.clone(),
        },
        Verdict::Deny { reason, stage } if stage.is_guard() => EventPayload::GuardDenial {
            action: Some(intent.action.clone()),
            reason: reason.clone(),
            enforced: true,
        },
        Verdict::Deny { reason, stage } => EventPayload::TripwireRejection {
            action: Some(intent.action.clone()),
            reason: reason.clone(),
            stage: stage.as_str().to_string(),
            enforced: true,
        },
    }
}

fn respond(
    state: &AppState,
    verdict: Verdict,
    ledger_session_id: Uuid,
    recorded: bool,
    coverage: Coverage,
) -> HookResponse {
    let (decision, reason, stage) = match verdict {
        Verdict::Allow => (Decision::Allow, None, None),
        Verdict::Deny { reason, stage } => {
            if stage.is_guard() {
                state.metrics.inc_guard_denials();
            } else {
                state.metrics.inc_tripwire_rejections();
            }
            (
                Decision::Deny,
                Some(reason),
                Some(stage.as_str().to_string()),
            )
        }
    };
    HookResponse {
        decision,
        reason,
        stage,
        ledger_session_id,
        recorded,
        coverage,
    }
}

/// [`evaluate_intent`] for each command of a shell chain, and each file of a
/// multi-file write.
///
/// The policy's command rules look at a command's first program only, so a
/// chain checked whole would let `git status && rm -rf x` through a policy
/// that allows `git`; a patch is checked file by file for the same reason.
/// Each part goes through policy and tripwire on its own; the first refusal
/// decides, and names the part. Other actions pass through.
async fn evaluate_chain(
    ctx: &EvaluationContext<'_>,
    mut guard: Option<&mut dyn GuardExecutor>,
    intent: &ProposedIntent,
) -> Verdict {
    let parts: Vec<(String, serde_json::Value)> = match intent.action.as_str() {
        "run_command" => {
            let command = intent.params_command().unwrap_or_default();
            match crate::tripwire::split_command_chain(command) {
                Ok(parts) => parts
                    .into_iter()
                    .map(|p| (p.to_string(), serde_json::json!({ "command": p })))
                    .collect(),
                Err(e) => {
                    return Verdict::Deny {
                        reason: e.to_string(),
                        stage: DenyStage::Tripwire,
                    };
                }
            }
        }
        "write_file" if intent.params.get("paths").is_some() => intent.params["paths"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p.as_str())
            .map(|p| (p.to_string(), serde_json::json!({ "path": p })))
            .collect(),
        _ => return evaluate_intent(ctx, guard, intent).await,
    };
    if parts.is_empty() {
        return Verdict::Deny {
            reason: format!("{} names nothing to check", intent.action),
            stage: DenyStage::Tripwire,
        };
    }
    let chained = parts.len() > 1;
    for (part, params) in parts {
        let mut one = intent.clone();
        one.params = params;
        let segment_guard = guard.as_mut().map(|g| &mut **g as &mut dyn GuardExecutor);
        if let Verdict::Deny { reason, stage } = evaluate_intent(ctx, segment_guard, &one).await {
            let reason = if chained {
                format!("{reason} (in `{part}`)")
            } else {
                reason
            };
            return Verdict::Deny { reason, stage };
        }
    }
    Verdict::Allow
}

/// Build the tripwire from the same configuration the cognitive loop uses.
pub(crate) fn build_tripwire() -> Tripwire {
    build_tripwire_for(None)
}

/// [`build_tripwire`] for a Claude Code session started in `project`.
///
/// With no `tripwire.json`, the allowed paths default to the server's working
/// directory. For `ironvise serve` started in a project that is the
/// project; for the desktop app opened from Finder it is `/`, which allows
/// every read and write. The hook knows better: Claude Code sends the
/// directory it runs in. So without an operator's `allowed_paths`, a hook
/// session's workspace is its project. A `tripwire.json` still wins.
pub(crate) fn build_tripwire_for(project: Option<&std::path::Path>) -> Tripwire {
    let cfg = config::load_tripwire_config();
    let allowed_paths = match project {
        Some(dir) if !config::tripwire_config_path().exists() => vec![dir.to_path_buf()],
        _ => config::canonical_allowed_prefixes(&cfg.allowed_paths),
    };
    Tripwire::from_config(cfg, allowed_paths)
}

#[cfg(test)]
mod tests;
