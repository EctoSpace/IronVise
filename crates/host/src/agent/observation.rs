//! What an action returned, before it is recorded: the output scanner, then
//! the policy's observation rules.

use super::{AgentError, CognitiveLoop};
use crate::output_scanner;
use crate::policy::{ObservationOutcome, PolicyEngine};
use crate::webhook::EgressKind;

impl CognitiveLoop<'_> {
    /// Records `output` as the step's observation, with injection attempts
    /// and redacted matches replaced. A rule that aborts ends the session
    /// without recording it.
    pub(super) async fn record_output(&self, output: &str) -> Result<(), AgentError> {
        let scan = output_scanner::scan_observation(output);
        if scan.is_suspicious {
            if let Some(m) = self.metrics() {
                m.inc_scanner_detections();
            }
            self.record_thought(format!(
                "Security: suspicious content detected ({:?})",
                scan.matched_patterns
            ))
            .await?;
        }
        let content = match self.config.policy {
            Some(policy) => {
                self.apply_observation_rules(policy, scan.sanitized_content)
                    .await?
            }
            None => scan.sanitized_content,
        };
        self.record_observation(content).await
    }

    async fn apply_observation_rules(
        &self,
        policy: &PolicyEngine,
        content: String,
    ) -> Result<String, AgentError> {
        match policy.validate_observation(&content) {
            ObservationOutcome::Clean => Ok(content),
            ObservationOutcome::Redacted(redacted) => {
                self.record_thought("Policy: sensitive content redacted from observation.")
                    .await?;
                Ok(redacted)
            }
            ObservationOutcome::Flagged { labels, content } => {
                self.record_thought(format!(
                    "Policy: observation flagged ({labels}); continuing."
                ))
                .await?;
                self.notify(EgressKind::Observation, "flag", &labels, &content);
                Ok(content)
            }
            ObservationOutcome::Abort { reason, content } => {
                self.record_thought(format!("Policy: aborting session - {reason}."))
                    .await?;
                self.notify(EgressKind::Observation, "abort", &reason, &content);
                Err(AgentError::PolicyAbort(reason))
            }
        }
    }
}
