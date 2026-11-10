use crate::intent::ProposedIntent;
use crate::llm::{LlmBackend, LlmError};
use async_trait::async_trait;

/// Says what to allow as well as what to deny. Without the allow list, small
/// models (qwen2.5 7B, for one) judge whether an action *finishes* the goal and
/// deny ordinary inspection such as `ls` or a second read of a file.
const GUARD_SYSTEM: &str = "You are the guard of a security-audit agent. Given the audit goal and one proposed action (as JSON), decide only whether the action is safe and serves the goal. ALLOW read-only inspection that can help the goal, even if it repeats an earlier step or does not finish the goal by itself; on Unix and Windows these are read-only: ls, dir, cat, type, head, tail, grep, findstr, find (without -delete or -exec), stat, wc, where, whoami, hostname, ps, tasklist, netstat, git log, git status. DENY an action that changes or deletes data, downloads or runs code, sends data elsewhere, escalates privileges, or has nothing to do with the goal. Reply with exactly one line: \"ALLOW\" or \"DENY: <reason>\". No other output.";

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GuardDecision {
    Allow,
    Deny { reason: String },
}

/// Trait for guard implementations (in-process LLM or separate guard-worker process).
#[async_trait]
pub trait GuardExecutor: Send + Sync {
    async fn evaluate(
        &mut self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, Box<dyn std::error::Error + Send + Sync>>;
}

#[async_trait]
impl GuardExecutor for Guard {
    async fn evaluate(
        &mut self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, Box<dyn std::error::Error + Send + Sync>> {
        Guard::evaluate(self, goal, proposed)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

pub struct Guard {
    backend: Box<dyn LlmBackend>,
}

impl Guard {
    pub fn new(backend: Box<dyn LlmBackend>) -> Self {
        Self { backend }
    }

    /// Creates a Guard using the environment-configured guard backend
    /// (`GUARD_LLM_BACKEND` / `GUARD_LLM_MODEL`), falling back to the
    /// primary LLM backend if those variables are unset.
    pub fn from_env(client: &reqwest::Client) -> Result<Self, LlmError> {
        let backend = crate::llm::guard_backend_from_env(client)?;
        Ok(Self { backend })
    }

    pub async fn evaluate(
        &self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, LlmError> {
        let (system, user) = guard_prompt(goal, proposed)?;
        let raw = self.backend.raw_call(system, &user).await?;
        Ok(parse_verdict(&raw))
    }
}

/// The system prompt and user message the guard model is sent for `proposed`.
pub fn guard_prompt(
    goal: &str,
    proposed: &ProposedIntent,
) -> Result<(&'static str, String), LlmError> {
    let action_json = serde_json::to_string(proposed).map_err(LlmError::InvalidJson)?;
    Ok((
        GUARD_SYSTEM,
        format!("Goal: {goal}\nProposed action: {action_json}"),
    ))
}

/// Reads the guard model's reply. Fail-closed: only an unambiguous ALLOW allows.
///
/// A `<think>…</think>` block (thinking models served without a separate
/// thinking field) is ignored. The first non-empty line must then be the word
/// ALLOW, optionally in `**bold**` or backticks and optionally followed by a
/// reason, and the reply must not also give the verdict DENY: the capitalised
/// word, or `deny:` in any case ("nothing to deny" in a reason is prose).
/// Only the first line of a DENY is kept as its reason.
/// "ALLOWED? No.", "Allow, but DENY: it deletes data" and a reply that is only
/// reasoning all deny.
pub fn parse_verdict(raw: &str) -> GuardDecision {
    let answer = strip_think_blocks(raw);
    let first_line = answer
        .lines()
        .map(|l| l.trim().trim_matches(|c| c == '*' || c == '`').trim())
        .find(|l| !l.is_empty())
        .unwrap_or_default();
    let upper_line = first_line.to_ascii_uppercase();
    let says_deny = answer
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| word == "DENY")
        || answer.to_ascii_lowercase().contains("deny:");

    if starts_with_word(&upper_line, "ALLOW") && !says_deny {
        return GuardDecision::Allow;
    }
    if starts_with_word(&upper_line, "DENY") {
        let reason = first_line["DENY".len()..]
            .trim_start_matches([':', '-', ' ', '*', '`'])
            .trim();
        return GuardDecision::Deny {
            reason: reason.to_string(),
        };
    }
    tracing::warn!("Guard reply is not a clear verdict, denying (fail-closed): {raw:?}");
    GuardDecision::Deny {
        reason: format!(
            "Guard returned unparseable response (fail-closed): {}",
            raw.trim()
        ),
    }
}

/// `word` at the start of `line`, followed by the end or a non-letter.
fn starts_with_word(line: &str, word: &str) -> bool {
    line.strip_prefix(word)
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_alphanumeric()))
}

/// The reply after its reasoning: everything after the last `</think>`, in any
/// case, so nested or stray tags cannot expose text from inside a block. Text
/// before an unclosed `<think>` is kept; the block itself has no verdict.
fn strip_think_blocks(raw: &str) -> &str {
    let lower = raw.to_ascii_lowercase();
    if let Some(end) = lower.rfind("</think>") {
        return &raw[end + "</think>".len()..];
    }
    match lower.find("<think>") {
        Some(start) => &raw[..start],
        None => raw,
    }
}

#[cfg(test)]
mod tests;

// GuardProcess implements GuardExecutor in guard_process.rs
