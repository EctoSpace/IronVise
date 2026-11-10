//! What a proposed action must pass before it runs: the policy and its
//! approval gates, the tripwire, and the semantic guard. Each refusal is
//! recorded, and the step ends there.

use super::{AgentError, CognitiveLoop};
use crate::guard::GuardDecision;
use crate::intent::{ProposedIntent, ValidatedIntent};
use crate::schema::EventPayload;
use crate::tripwire::TripwireError;
use crate::webhook::EgressKind;

impl CognitiveLoop<'_> {
    /// The policy's verdict on `intent` at `step`, then its approval gate, if
    /// one matches.
    pub(super) async fn policy_allows(
        &self,
        intent: &ProposedIntent,
        step: u32,
    ) -> Result<bool, AgentError> {
        let Some(policy) = self.config.policy else {
            return Ok(true);
        };
        if let Err(violation) = policy.validate_intent(intent, step) {
            if let Some(m) = self.metrics() {
                m.inc_tripwire_rejections();
            }
            self.record(EventPayload::TripwireRejection {
                action: Some(intent.action.clone()),
                reason: violation.to_string(),
                stage: "policy".to_string(),
                enforced: true,
            })
            .await?;
            return Ok(false);
        }
        match policy.check_approval_gates(intent) {
            Some(gate) => self.approve(intent, gate).await,
            None => Ok(true),
        }
    }

    /// The tripwire's check of `intent`: paths, commands, URLs and the
    /// justification. A missing justification is a schema error, and
    /// `JUSTIFICATION_FAILURE_LIMIT` of them in a row end the session.
    pub(super) async fn validate(
        &mut self,
        intent: &ProposedIntent,
    ) -> Result<Option<ValidatedIntent>, AgentError> {
        let error = match self.config.tripwire.validate(intent) {
            Ok(validated) => {
                self.strikes.justification_failures = 0;
                return Ok(Some(validated));
            }
            Err(e) => e,
        };
        if let Some(m) = self.metrics() {
            m.inc_tripwire_rejections();
        }

        let msg = if matches!(error, TripwireError::InsufficientJustification(_)) {
            self.strikes.justification_failures += 1;
            let msg = "Invalid justification: response is missing a valid \"justification\" field \
                       (must be at least 5 characters)."
                .to_string();
            self.record(EventPayload::SchemaError {
                message: msg.clone(),
                attempt: self.strikes.justification_failures,
                max_attempts: self.limits.justification_failures,
            })
            .await?;
            msg
        } else {
            let (stage, verdict) = match error {
                TripwireError::PolicyViolation(_) => ("policy", "Policy rejected"),
                _ => ("validation", "Tripwire rejected"),
            };
            self.record(EventPayload::TripwireRejection {
                action: Some(intent.action.clone()),
                reason: error.to_string(),
                stage: stage.to_string(),
                enforced: true,
            })
            .await?;
            format!("{verdict}: {error}")
        };

        if let Some(planner) = &self.config.compensation
            && let Some(compensation) = planner.plan(intent, &error)
        {
            let compensation = serde_json::to_string(&compensation).unwrap_or_default();
            self.record_thought(format!("Compensation proposed: {compensation}"))
                .await?;
        }
        self.notify(EgressKind::TripwireRejection, "abort", &msg, &msg);

        let failures = self.strikes.justification_failures;
        if failures >= self.limits.justification_failures {
            let reason = format!(
                "{failures} consecutive schema errors (missing justification); aborting session."
            );
            return Err(self.circuit_breaker(reason, failures).await);
        }
        Ok(None)
    }

    /// The semantic guard's verdict, when one is configured. An error from
    /// the guard denies (fail-closed). `GUARD_DENIAL_LIMIT` denials in a row,
    /// errors included, end the session: a guard that cannot answer must not
    /// leave the session running until its step limit.
    pub(super) async fn guard_allows(
        &mut self,
        intent: &ProposedIntent,
    ) -> Result<bool, AgentError> {
        let Some(guard) = self.config.guard.as_mut() else {
            return Ok(true);
        };
        let reason = match guard.evaluate(&self.config.session_goal, intent).await {
            Ok(GuardDecision::Allow) => {
                self.strikes.guard_denials = 0;
                return Ok(true);
            }
            Ok(GuardDecision::Deny { reason }) => reason,
            Err(e) => format!("guard error (fail-closed): {e}"),
        };
        self.strikes.guard_denials += 1;
        if let Some(m) = self.metrics() {
            m.inc_guard_denials();
        }
        self.record(EventPayload::GuardDenial {
            action: Some(intent.action.clone()),
            reason: reason.clone(),
            enforced: true,
        })
        .await?;
        self.notify(EgressKind::GuardDenial, "flag", &reason, &reason);

        let denials = self.strikes.guard_denials;
        if denials >= self.limits.guard_denials {
            self.record_thought(format!(
                "Security: Guard denied {denials} consecutive actions; aborting session."
            ))
            .await?;
            return Err(AgentError::GuardAbort);
        }
        Ok(false)
    }
}
