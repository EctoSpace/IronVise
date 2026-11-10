//! Running an approved action, in the strongest isolation configured.

use super::{AgentError, CognitiveLoop, TierFailureAction, tier_failure_action};
use crate::config;
use crate::executor::{self, ExecuteError};
use crate::intent::ValidatedIntent;
use crate::sandbox::{FirecrackerConfig, SandboxError};
use std::time::Duration;

impl CognitiveLoop<'_> {
    /// Replays the stored response to an `http_get` of the same URL instead of
    /// fetching it again. True when it did.
    pub(super) async fn replay_cached_http_get(
        &self,
        validated: &ValidatedIntent,
    ) -> Result<bool, AgentError> {
        if validated.action() != "http_get" {
            return Ok(false);
        }
        let Some(url) = validated.params().get("url").and_then(|v| v.as_str()) else {
            return Ok(false);
        };
        match self.pool.find_cached_http_get(url).await {
            Ok(Some(cached)) => {
                self.record_thought(format!("Idempotency: returning cached http_get for {url}"))
                    .await?;
                self.record_observation(cached).await?;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => {
                tracing::warn!("Idempotency check failed (proceeding): {e}");
                Ok(false)
            }
        }
    }

    /// Records the action and runs it. Its output, or `None` when it failed;
    /// the failure is then the step's observation.
    pub(super) async fn execute(
        &self,
        validated: ValidatedIntent,
    ) -> Result<Option<String>, AgentError> {
        let event_id = self.record_action(&validated).await?;
        self.pool
            .mark_action_executing(event_id)
            .await
            .map_err(AgentError::Db)?;
        match self.run(validated).await {
            Ok(output) => {
                self.pool
                    .mark_action_completed(event_id)
                    .await
                    .map_err(AgentError::Db)?;
                Ok(Some(output))
            }
            Err(e) => {
                let msg = format!("Execution error: {e}");
                // An action left "executing" is re-queued after a restart.
                // Recording what happened matters more, so this only warns.
                if let Err(db_err) = self.pool.mark_action_failed(event_id, &msg).await {
                    tracing::warn!(
                        "Failed to mark event {event_id} as failed in ledger (continuing): {db_err}"
                    );
                }
                self.record_observation(msg).await?;
                Ok(None)
            }
        }
    }

    /// A `run_command` runs in a Firecracker microVM, else a Docker/Podman
    /// container, when one is configured; everything else, and a command with
    /// no tier configured, on the host executor (Landlock and seccomp on
    /// Linux). Configuring a tier says isolation is required, so a tier that
    /// fails aborts the action unless `ECTO_SANDBOX_PERMISSIVE` allows the host.
    async fn run(&self, validated: ValidatedIntent) -> Result<String, ExecuteError> {
        let sandbox_err = match self.run_isolated(&validated).await {
            None => return self.run_on_host(validated).await,
            Some(Ok(output)) => return Ok(output),
            Some(Err(e)) => e,
        };
        match tier_failure_action(config::sandbox_permissive()) {
            TierFailureAction::FallBackToHost => {
                tracing::warn!(
                    "Container sandbox error; ECTO_SANDBOX_PERMISSIVE=true - \
                     falling back to host executor: {sandbox_err}"
                );
                self.run_on_host(validated).await
            }
            TierFailureAction::Abort => {
                tracing::error!(
                    "Container sandbox error; aborting action (fail-closed): {sandbox_err}"
                );
                Err(ExecuteError::SandboxUnavailable(format!(
                    "configured isolation tier failed ({sandbox_err}); refusing \
                     unsandboxed host fallback. Set ECTO_SANDBOX_PERMISSIVE=true \
                     to allow degraded execution."
                )))
            }
        }
    }

    async fn run_on_host(&self, validated: ValidatedIntent) -> Result<String, ExecuteError> {
        executor::execute_with_policy(
            validated,
            self.config.cloud_creds.clone(),
            self.config.policy,
        )
        .await
    }

    /// The result from the isolation tiers, or `None` when the action is not a
    /// `run_command` or no tier is configured. Docker is tried when
    /// Firecracker fails.
    async fn run_isolated(
        &self,
        validated: &ValidatedIntent,
    ) -> Option<Result<String, SandboxError>> {
        if validated.action() != "run_command" {
            return None;
        }
        let intent_json = serde_json::json!({
            "action": validated.action(),
            "params": validated.params(),
        })
        .to_string();
        if let Some(fc) = &self.config.firecracker_config {
            match run_in_firecracker(fc, &intent_json).await {
                Ok(output) => return Some(Ok(output)),
                Err(e) if self.config.docker_config.is_none() => return Some(Err(e)),
                Err(e) => tracing::warn!("Firecracker sandbox error (trying Docker next): {e}"),
            }
        }
        let docker = self.config.docker_config.as_ref()?;
        Some(crate::sandbox::run_in_docker(docker, &intent_json).await)
    }
}

/// The outer timeout covers the whole attempt, pre-launch I/O included, so a
/// guest kernel that panics without closing its serial port cannot stall the
/// loop.
async fn run_in_firecracker(
    fc: &FirecrackerConfig,
    intent_json: &str,
) -> Result<String, SandboxError> {
    let limit = Duration::from_secs(fc.outer_timeout_secs);
    match tokio::time::timeout(limit, crate::sandbox::run_in_firecracker(fc, intent_json)).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::warn!(
                "Firecracker outer timeout ({}s) elapsed - pre-launch IO or \
                 kernel hang; falling through to Docker/host",
                fc.outer_timeout_secs
            );
            Err(SandboxError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "Firecracker outer timeout after {} seconds \
                     (covers pre-launch IO + microVM execution)",
                    fc.outer_timeout_secs
                ),
            )))
        }
    }
}
