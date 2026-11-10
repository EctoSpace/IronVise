//! `ironvise hook` - the Claude Code, Codex and Antigravity CLI
//! `PreToolUse` client, and the Claude Code and Codex `PostToolUse` one.
//!
//! Codex's hooks take the same input and the same decision JSON as Claude
//! Code's, with one difference that matters here: Codex cannot ask a person,
//! and treats an `ask` as a failed hook and runs the tool. Under Codex
//! (recognised by the `turn_id` only it sends) an escalation is therefore a
//! `deny` that says a person must approve it.
//!
//! Antigravity CLI sends its own shape (camelCase, the call under
//! `toolCall`) and takes `{"decision", "reason"}` back. It gives a hook no
//! tool result, so it gets no data receipt, and no tool-use id, so a replayed
//! call is not refused. Its exit-code contract is not documented: a failure
//! here prints a `deny` on stdout as well as exiting 2, so either reading
//! refuses the call.
//!
//! Reads Claude Code's hook JSON on stdin. Before a tool runs it asks the
//! Observer to evaluate the call and writes Claude Code's decision JSON on
//! stdout; after it runs it records a data receipt, the hashes of what the
//! tool returned (`crate::receipts`).
//!
//! A compiled subcommand rather than a shell script on purpose: the fail-closed
//! behaviour below is not something a `curl | jq` one-liner gets right, and it
//! has to work on Windows.
//!
//! ## Fail-closed, and why it needs care here
//!
//! Claude Code's exit-code contract makes the safe default the *unusual* one:
//!
//! | exit | effect |
//! |---|---|
//! | 0 | stdout is parsed for a decision |
//! | **2** | **blocked**, stderr shown to Claude |
//! | anything else | **non-blocking error - the tool runs** |
//!
//! So a crash (`101` on a Rust panic), an unhandled error (`1`), or a hook that
//! simply takes too long all end with the tool executing. Every failure path
//! here therefore exits **2**, including the panic hook. The default for a
//! guard that cannot answer must be "no", and nothing about the platform gives
//! that for free.
//!
//! ## What an `allow` becomes
//!
//! Claude Code treats a hook's `allow` as an approval: the call skips the
//! prompt it would otherwise show (a settings `deny` or `ask` rule still
//! applies). So forwarding IronVise's `allow` as-is made installing a
//! security hook quietly *remove* prompts, now including file edits.
//!
//! By default (`ECTOLEDGER_HOOK_MODE=veto`) an `allow` is therefore sent as no
//! decision at all: exit 0, empty stdout, and Claude Code's own permission flow
//! runs exactly as it would without the hook. IronVise only ever takes
//! permissions away. `ECTOLEDGER_HOOK_MODE=approve` restores the old
//! behaviour, for setups where the policy is meant to replace the prompts.
//! Either way the decision is recorded in the ledger.
//!
//! Timeouts matter for the same reason. Claude Code's own hook timeout appears
//! to be treated as a non-blocking error, so waiting for it would fail *open*.
//! This client enforces its own, much shorter deadline and blocks when it
//! fires.

use std::io::Read;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What an IronVise `allow` is sent to Claude Code as. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowMode {
    /// No decision: Claude Code's own permission flow decides.
    Veto,
    /// `allow`: the call skips Claude Code's default prompt.
    Approve,
}

impl AllowMode {
    /// Anything but an explicit `approve` is `Veto`: a typo must not turn the
    /// hook into one that approves.
    fn parse(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("approve") => Self::Approve,
            _ => Self::Veto,
        }
    }
}

/// Exit code that blocks the tool call. The only safe failure exit.
const EXIT_BLOCK: i32 = 2;

/// Deliberately well inside Claude Code's 600s command-hook default: the goal is
/// for *this* deadline to fire first, because ours blocks and theirs does not.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    tool_use_id: Option<String>,
    /// `PreToolUse` or `PostToolUse`; absent means `PreToolUse`.
    #[serde(default)]
    hook_event_name: Option<String>,
    /// What the tool returned (`PostToolUse` only).
    #[serde(default)]
    tool_response: serde_json::Value,
    /// Sent by Codex only.
    #[serde(default)]
    turn_id: Option<String>,
    #[serde(skip)]
    from_antigravity: bool,
}

/// The coding agent that ran the hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Agent {
    ClaudeCode,
    Codex,
    Antigravity,
}

impl Agent {
    /// What the Observer labels the ledger session with; none for Claude Code.
    fn label(self) -> Option<&'static str> {
        match self {
            Self::ClaudeCode => None,
            Self::Codex => Some("codex"),
            Self::Antigravity => Some("antigravity"),
        }
    }
}

impl HookInput {
    fn agent(&self) -> Agent {
        if self.from_antigravity {
            Agent::Antigravity
        } else if self.turn_id.is_some() {
            Agent::Codex
        } else {
            Agent::ClaudeCode
        }
    }
}

/// Antigravity CLI's hook input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AntigravityInput {
    conversation_id: String,
    tool_call: AntigravityToolCall,
    #[serde(default)]
    workspace_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AntigravityToolCall {
    name: String,
    #[serde(default)]
    args: serde_json::Value,
}

/// The hook payload, in Claude Code's terms whichever agent sent it.
fn parse_input(raw: &str) -> Result<HookInput, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    if value.get("toolCall").is_none() {
        return serde_json::from_value(value);
    }
    let input: AntigravityInput = serde_json::from_value(value)?;
    Ok(HookInput {
        session_id: input.conversation_id,
        tool_name: input.tool_call.name,
        tool_input: input.tool_call.args,
        cwd: input.workspace_paths.first().map(|p| workspace_dir(p)),
        tool_use_id: None,
        hook_event_name: None,
        tool_response: serde_json::Value::Null,
        turn_id: None,
        from_antigravity: true,
    })
}

/// A workspace as Antigravity may name it: a path, or a `file://` URI.
fn workspace_dir(raw: &str) -> String {
    let Some(encoded) = raw.strip_prefix("file://") else {
        return raw.to_string();
    };
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| encoded.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                decoded.push(byte);
                i += 3;
            }
            None => {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// IronVise's answer, before it is put in the calling agent's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    /// No objection; `approve` also skips the agent's own prompt.
    Allow {
        approve: bool,
    },
    Deny(String),
    /// A person decides, where the agent can ask one.
    Ask(String),
}

/// `decision` as `agent` reads it on stdout; `None` prints nothing.
fn render(agent: Agent, decision: Decision) -> Option<String> {
    if agent == Agent::Antigravity {
        let (decision, reason) = match decision {
            // `allow` defers to Antigravity's own rules and prompts.
            Decision::Allow { approve: false } => ("allow", None),
            Decision::Allow { approve: true } => ("auto_approve", None),
            Decision::Deny(reason) => ("deny", Some(reason)),
            Decision::Ask(reason) => ("ask", Some(format!("{reason} A person decides."))),
        };
        let mut out = serde_json::json!({ "decision": decision });
        if let Some(reason) = reason {
            out["reason"] = reason.into();
        }
        return Some(out.to_string());
    }
    let output = match decision {
        // Nothing printed leaves the call to the agent's own rules and
        // prompts, as if the hook were not installed.
        Decision::Allow { approve: false } => return None,
        Decision::Allow { approve: true } => HookOutput::new("allow", None),
        Decision::Deny(reason) => HookOutput::new("deny", Some(reason)),
        // Codex has no prompt, so the call is refused until a person
        // approves it outside the session.
        Decision::Ask(reason) if agent == Agent::Codex => HookOutput::new(
            "deny",
            Some(format!(
                "{reason} Codex cannot ask for approval, so IronVise refuses it; \
                 run it yourself if you approve."
            )),
        ),
        Decision::Ask(reason) => {
            HookOutput::new("ask", Some(format!("{reason} A person decides.")))
        }
    };
    Some(serde_json::json!(output).to_string())
}

/// Set once the payload is known to be Antigravity's, so [`block`] answers
/// in its terms too.
static ANTIGRAVITY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    session_id: &'a str,
    tool_name: &'a str,
    tool_input: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<&'a str>,
    /// `$CLAUDE_PROJECT_DIR`, which Claude Code sets for hook commands. The
    /// Observer confines the session to it; `cwd` can follow a `cd`.
    #[serde(skip_serializing_if = "Option::is_none")]
    project_dir: Option<&'a str>,
    /// Lets the Observer refuse a replay of this exact tool use.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_use_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<&'static str>,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    decision: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    stage: Option<String>,
    #[serde(default)]
    recorded: bool,
}

/// Claude Code's `PreToolUse` output envelope.
#[derive(Debug, Serialize)]
struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision_reason: Option<String>,
}

impl HookOutput {
    fn new(decision: &'static str, reason: Option<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: decision,
                permission_decision_reason: reason,
            },
        }
    }
}

/// After the tool ran: record its data receipt. The receipt is built here, so
/// only hashes leave this process; the result itself goes nowhere. Nothing
/// can be blocked now, so a failure exits 1, which Claude Code shows the user
/// as a hook error: the ledger has a gap they should know about.
async fn record_result(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    input: &HookInput,
    project_dir: Option<&str>,
) -> ! {
    let url = format!("{}/api/hook/tool-result", base.trim_end_matches('/'));
    let receipt = crate::receipts::receipt(
        &input.tool_name,
        &input.tool_input,
        &input.tool_response,
        input.tool_use_id.as_deref(),
    );
    let body = serde_json::json!({
        "session_id": input.session_id,
        "receipt": receipt,
        "cwd": input.cwd,
        "project_dir": project_dir,
        "tool_use_id": input.tool_use_id,
        "agent": input.agent().label(),
    });
    let failed = match client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => std::process::exit(0),
        Ok(r) => format!("{}: {}", r.status(), r.text().await.unwrap_or_default()),
        Err(e) => e.to_string(),
    };
    eprintln!(
        "IronVise: the data receipt for this {} call was NOT recorded ({})",
        input.tool_name,
        failed.chars().take(200).collect::<String>()
    );
    std::process::exit(1)
}

/// Block the tool call and stop. Stderr becomes the reason Claude is shown.
fn block(reason: &str) -> ! {
    if ANTIGRAVITY.load(std::sync::atomic::Ordering::Relaxed) {
        let deny = render(
            Agent::Antigravity,
            Decision::Deny(format!("IronVise: {reason}")),
        );
        println!("{}", deny.unwrap_or_default());
    }
    eprintln!("IronVise: {reason}");
    std::process::exit(EXIT_BLOCK);
}

pub async fn run() -> ! {
    // A panic would otherwise exit 101, which Claude Code treats as a
    // non-blocking error and runs the tool anyway. Fail closed instead.
    std::panic::set_hook(Box::new(|info| {
        block(&format!("hook panicked, blocking the tool call: {info}"));
    }));

    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        block(&format!("could not read the hook payload from stdin: {e}"));
    }

    let input = match parse_input(&raw) {
        Ok(v) => v,
        Err(e) => block(&format!("hook payload was not valid JSON: {e}")),
    };
    if input.agent() == Agent::Antigravity {
        ANTIGRAVITY.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let base =
        std::env::var("ECTOLEDGER_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let token = std::env::var("ECTOLEDGER_TOKEN").unwrap_or_default();
    if token.is_empty() {
        if input.hook_event_name.as_deref() == Some("PostToolUse") {
            eprintln!(
                "IronVise: ECTOLEDGER_TOKEN is not set, so this data receipt was NOT recorded"
            );
            std::process::exit(1);
        }
        block(
            "ECTOLEDGER_TOKEN is not set. Refusing to allow a tool call that \
             cannot be recorded or checked.",
        );
    }
    let timeout = std::env::var("ECTOLEDGER_HOOK_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
    {
        Ok(c) => c,
        Err(e) => block(&format!("could not build an HTTP client: {e}")),
    };

    let mode = AllowMode::parse(std::env::var("ECTOLEDGER_HOOK_MODE").ok().as_deref());
    let project_dir = std::env::var("CLAUDE_PROJECT_DIR")
        .ok()
        .filter(|d| !d.trim().is_empty());

    if input.hook_event_name.as_deref() == Some("PostToolUse") {
        record_result(&client, &base, &token, &input, project_dir.as_deref()).await;
    }

    let url = format!("{}/api/hook/tool-call", base.trim_end_matches('/'));
    let response = client
        .post(&url)
        .bearer_auth(&token)
        .json(&VerifyRequest {
            session_id: &input.session_id,
            tool_name: &input.tool_name,
            tool_input: &input.tool_input,
            cwd: input.cwd.as_deref(),
            project_dir: project_dir.as_deref(),
            tool_use_id: input.tool_use_id.as_deref(),
            agent: input.agent().label(),
        })
        .send()
        .await;

    let response = match response {
        Ok(r) => r,
        // Unreachable, refused, or timed out. All of these mean the guard did
        // not answer, and an unanswered guard denies.
        Err(e) => block(&format!(
            "could not reach IronVise at {url} ({e}). Blocking: a tool call \
             that cannot be checked is not permitted."
        )),
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        block(&format!(
            "IronVise returned {status}: {}. Blocking.",
            body.chars().take(200).collect::<String>()
        ));
    }

    let verdict: VerifyResponse = match response.json().await {
        Ok(v) => v,
        Err(e) => block(&format!(
            "could not parse IronVise's answer: {e}. Blocking."
        )),
    };

    let note = |r: Option<String>| -> String {
        let mut text = r.unwrap_or_else(|| "no reason given".to_string());
        if let Some(stage) = &verdict.stage {
            text = format!("{text} (refused at the {stage} stage)");
        }
        if !verdict.recorded {
            // The operator should know the audit trail has a hole in it, even
            // though the decision itself stands.
            text = format!("{text} [warning: this decision was NOT recorded in the ledger]");
        }
        text
    };

    let decision = match verdict.decision.as_str() {
        "allow" => Decision::Allow {
            approve: mode == AllowMode::Approve,
        },
        "deny" => Decision::Deny(note(verdict.reason)),
        "ask" => Decision::Ask(note(verdict.reason)),
        // An answer we do not understand is not an approval.
        other => block(&format!(
            "IronVise returned an unrecognised decision {other:?}. Blocking."
        )),
    };
    if let Some(json) = render(input.agent(), decision) {
        println!("{json}");
    }
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_output_envelope_matches_claude_codes_contract() {
        let json =
            serde_json::to_value(HookOutput::new("deny", Some("banned command".into()))).unwrap();
        let inner = &json["hookSpecificOutput"];
        assert_eq!(inner["hookEventName"], "PreToolUse");
        assert_eq!(inner["permissionDecision"], "deny");
        assert_eq!(inner["permissionDecisionReason"], "banned command");
    }

    #[test]
    fn an_allow_carries_no_reason_field() {
        let json = serde_json::to_value(HookOutput::new("allow", None)).unwrap();
        assert!(
            json["hookSpecificOutput"]
                .get("permissionDecisionReason")
                .is_none(),
            "an allow should not carry an empty reason"
        );
    }

    #[test]
    fn the_tool_use_id_is_forwarded_for_replay_checks() {
        let raw =
            r#"{"session_id":"s","tool_name":"Bash","tool_input":{},"tool_use_id":"toolu_9"}"#;
        let input: HookInput = serde_json::from_str(raw).unwrap();
        let req = |id| VerifyRequest {
            session_id: &input.session_id,
            tool_name: &input.tool_name,
            tool_input: &input.tool_input,
            cwd: None,
            project_dir: None,
            tool_use_id: id,
            agent: input.agent().label(),
        };
        let sent = serde_json::to_value(req(input.tool_use_id.as_deref())).unwrap();
        assert_eq!(sent["tool_use_id"], "toolu_9");
        let without = serde_json::to_value(req(None)).unwrap();
        assert!(without.get("tool_use_id").is_none());
    }

    #[test]
    fn only_an_explicit_approve_makes_an_allow_an_approval() {
        assert_eq!(AllowMode::parse(None), AllowMode::Veto);
        assert_eq!(AllowMode::parse(Some("veto")), AllowMode::Veto);
        assert_eq!(AllowMode::parse(Some(" Approve ")), AllowMode::Approve);
        for typo in ["", "aprove", "allow", "yes", "1"] {
            assert_eq!(AllowMode::parse(Some(typo)), AllowMode::Veto, "{typo:?}");
        }
    }

    #[test]
    fn the_blocking_exit_code_is_two_and_not_one() {
        // The distinction is the whole fail-closed story: 2 blocks, and every
        // other non-zero code lets the tool run.
        assert_eq!(EXIT_BLOCK, 2);
    }

    /// Claude Code's command-hook default is 600s, and a timeout there is
    /// treated as non-blocking, so ours has to fire first to fail closed.
    /// Checked at compile time - a later edit raising it above the platform
    /// default should not build.
    const _DEADLINE_BEATS_CLAUDE_CODES: () = assert!(DEFAULT_TIMEOUT_SECS < 600);

    fn input(json: serde_json::Value) -> HookInput {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn claude_code_sends_no_agent_name_and_the_others_do() {
        let claude = input(serde_json::json!({ "session_id": "s", "tool_name": "Bash" }));
        assert_eq!(claude.agent(), Agent::ClaudeCode);
        assert_eq!(claude.agent().label(), None);
        let codex =
            input(serde_json::json!({ "session_id": "s", "turn_id": "t1", "tool_name": "Bash" }));
        assert_eq!(codex.agent().label(), Some("codex"));
        let antigravity = parse_input(ANTIGRAVITY_CALL).unwrap();
        assert_eq!(antigravity.agent().label(), Some("antigravity"));
    }

    #[test]
    fn claude_code_is_asked_and_codex_is_refused() {
        let ask = || Decision::Ask("not evaluated.".into());
        let claude: serde_json::Value =
            serde_json::from_str(&render(Agent::ClaudeCode, ask()).unwrap()).unwrap();
        assert_eq!(claude["hookSpecificOutput"]["permissionDecision"], "ask");

        let codex: serde_json::Value =
            serde_json::from_str(&render(Agent::Codex, ask()).unwrap()).unwrap();
        let inner = &codex["hookSpecificOutput"];
        assert_eq!(inner["permissionDecision"], "deny");
        assert!(
            inner["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .starts_with("not evaluated. Codex cannot ask")
        );
    }

    /// Antigravity CLI's documented `PreToolUse` input.
    const ANTIGRAVITY_CALL: &str = r#"{
        "toolCall": { "name": "run_command", "args": { "CommandLine": "ls", "Cwd": "/w" } },
        "stepIdx": 3, "conversationId": "c-42", "workspacePaths": ["file:///Users/a/my%20app"],
        "transcriptPath": "/t", "artifactDirectoryPath": "/a", "modelName": "gemini-3.8-flash"
    }"#;

    #[test]
    fn an_antigravity_payload_becomes_a_tool_call() {
        let input = parse_input(ANTIGRAVITY_CALL).unwrap();
        assert_eq!(input.session_id, "c-42");
        assert_eq!(input.tool_name, "run_command");
        assert_eq!(input.tool_input["CommandLine"], "ls");
        assert_eq!(input.cwd.as_deref(), Some("/Users/a/my app"));
        assert_eq!(input.tool_use_id, None);
        assert_eq!(
            input.hook_event_name, None,
            "always checked before the tool runs"
        );
    }

    #[test]
    fn a_workspace_is_read_as_a_path_or_a_file_uri() {
        assert_eq!(workspace_dir("/w/p"), "/w/p");
        assert_eq!(workspace_dir("file:///w/a%20b"), "/w/a b");
        assert_eq!(
            workspace_dir("file:///w/100%"),
            "/w/100%",
            "a stray % is kept"
        );
    }

    #[test]
    fn antigravity_reads_its_own_decision_shape() {
        let out = |d| {
            serde_json::from_str::<serde_json::Value>(&render(Agent::Antigravity, d).unwrap())
                .unwrap()
        };
        assert_eq!(
            out(Decision::Allow { approve: false }),
            serde_json::json!({ "decision": "allow" })
        );
        assert_eq!(
            out(Decision::Allow { approve: true })["decision"],
            "auto_approve"
        );
        let deny = out(Decision::Deny("banned command".into()));
        assert_eq!(
            deny,
            serde_json::json!({ "decision": "deny", "reason": "banned command" })
        );
        let ask = out(Decision::Ask("not evaluated.".into()));
        assert_eq!(ask["decision"], "ask");
        assert_eq!(ask["reason"], "not evaluated. A person decides.");
    }

    #[test]
    fn an_allow_prints_nothing_for_claude_code_unless_it_approves() {
        assert_eq!(
            render(Agent::ClaudeCode, Decision::Allow { approve: false }),
            None
        );
        assert_eq!(
            render(Agent::Codex, Decision::Allow { approve: false }),
            None
        );
        assert!(render(Agent::ClaudeCode, Decision::Allow { approve: true }).is_some());
    }

    #[test]
    fn a_hook_payload_with_unknown_fields_still_parses() {
        // Claude Code adds fields over time (prompt_id, tool_use_id, effort,
        // agent_id). An unrecognised field must not become a blocked tool call.
        let raw = r#"{
            "session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"},
            "cwd":"/tmp","hook_event_name":"PreToolUse","tool_use_id":"t1",
            "permission_mode":"default","effort":{"level":"high"}
        }"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parses");
        assert_eq!(parsed.tool_name, "Bash");
        assert_eq!(parsed.session_id, "s1");
    }
}
