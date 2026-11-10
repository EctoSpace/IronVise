//! Asking the model for the next action.

use super::{AgentError, CognitiveLoop};
use crate::intent::ProposedIntent;
use crate::schema::RestoredState;
use crate::{config, executor, llm};

/// How many of the session's latest events the prompt shows.
const PROMPT_EVENTS: usize = 50;

impl CognitiveLoop<'_> {
    /// The model's next action, or `None` after a failed call the session may
    /// retry. Failed calls in a row end the session at `LLM_ERROR_LIMIT`.
    pub(super) async fn propose(
        &mut self,
        state: &RestoredState,
    ) -> Result<Option<ProposedIntent>, AgentError> {
        let user = self.prompt(state);
        self.check_token_budget().await?;
        match self
            .config
            .llm
            .propose(llm::DEFAULT_SYSTEM_PROMPT, &user)
            .await
        {
            Ok(intent) => {
                if let Some(m) = self.metrics() {
                    m.add_tokens_for_text(&user);
                    m.add_tokens_for_text(&intent.action);
                    m.add_tokens_for_text(&intent.justification);
                }
                self.strikes.llm_errors = 0;
                Ok(Some(intent))
            }
            Err(e) => {
                self.strikes.llm_errors += 1;
                self.record_thought(format!("LLM error: {e}")).await?;
                let failures = self.strikes.llm_errors;
                if failures >= self.limits.llm_errors {
                    let reason = format!("{failures} consecutive LLM errors; aborting session.");
                    return Err(self.circuit_breaker(reason, failures).await);
                }
                Ok(None)
            }
        }
    }

    /// The goal, the host, the programs `run_command` may start and the
    /// session so far, with worked examples while the session is new.
    fn prompt(&self, state: &RestoredState) -> String {
        let few_shot = if state.replayed_events.len() <= 2 {
            llm::few_shot_examples()
        } else {
            ""
        };
        let programs = executor::programs_for_prompt(self.config.policy);
        let programs = if programs.is_empty() {
            "none".to_string()
        } else {
            programs.join(", ")
        };
        format!(
            "Current goal: {}\n\nHost: {}. run_command may start only these programs: {}.\n\n{}{}",
            self.config.session_goal,
            executor::host_os_for_prompt(),
            programs,
            few_shot,
            llm::state_to_prompt(state, PROMPT_EVENTS)
        )
    }

    /// Ends the session before a model call once the approximate tokens spent
    /// reach `AGENT_TOKEN_BUDGET_MAX`.
    async fn check_token_budget(&self) -> Result<(), AgentError> {
        let Some(budget) = config::token_budget_max() else {
            return Ok(());
        };
        let used = self.metrics().map_or(0, |m| m.current_token_count());
        if used < budget {
            return Ok(());
        }
        self.record_thought(format!(
            "Token budget exceeded: ~{used} tokens used, limit is {budget}. Aborting session."
        ))
        .await?;
        Err(AgentError::TokenBudgetExceeded)
    }
}
