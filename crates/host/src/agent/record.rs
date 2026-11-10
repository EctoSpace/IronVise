//! Writing to the session: events, webhook notices, the key that signs them,
//! snapshots and the closing credential.

use super::{AgentError, CognitiveLoop};
use crate::config;
use crate::intent::ValidatedIntent;
use crate::metrics::Metrics;
use crate::schema::EventPayload;
use crate::webhook::{EgressEvent, EgressKind};
use std::sync::Arc;

impl CognitiveLoop<'_> {
    /// The goal stored with each event; only a session has one.
    pub(super) fn session_goal(&self) -> Option<&str> {
        self.config
            .session_id
            .map(|_| self.config.session_goal.as_str())
    }

    pub(super) fn metrics(&self) -> Option<&Metrics> {
        self.config.metrics.as_deref()
    }

    /// Appends `payload`, signed with the current session key, and counts it.
    pub(super) async fn record(&self, payload: EventPayload) -> Result<i64, AgentError> {
        let appended = self
            .pool
            .append_event(
                payload,
                self.config.session_id,
                self.session_goal(),
                self.config.session_signing_key.as_deref(),
            )
            .await
            .map_err(AgentError::Append)?;
        if let Some(m) = self.metrics() {
            m.inc_events_appended();
        }
        Ok(appended.id)
    }

    pub(super) async fn record_thought(
        &self,
        content: impl Into<String>,
    ) -> Result<(), AgentError> {
        self.record(EventPayload::Thought {
            content: content.into(),
        })
        .await
        .map(drop)
    }

    pub(super) async fn record_observation(
        &self,
        content: impl Into<String>,
    ) -> Result<(), AgentError> {
        self.record(EventPayload::Observation {
            content: content.into(),
        })
        .await
        .map(drop)
    }

    /// Records the action about to run; the id marks its progress.
    pub(super) async fn record_action(
        &self,
        validated: &ValidatedIntent,
    ) -> Result<i64, AgentError> {
        self.record(EventPayload::Action {
            name: validated.action().to_string(),
            params: validated.params().clone(),
        })
        .await
    }

    /// Records why the session stops after `failures` failures in a row, and
    /// returns the error that stops it.
    pub(super) async fn circuit_breaker(&self, reason: String, failures: u32) -> AgentError {
        let tripped = EventPayload::CircuitBreaker {
            reason,
            consecutive_failures: failures,
        };
        match self.record(tripped).await {
            Ok(_) => AgentError::CircuitBreaker,
            Err(e) => e,
        }
    }

    /// Queues a webhook notice; delivery happens in the background.
    pub(super) fn notify(&self, kind: EgressKind, severity: &str, label: &str, content: &str) {
        if let Some(tx) = &self.config.egress_tx {
            crate::webhook::try_enqueue_event(
                tx,
                EgressEvent {
                    session_id: self.config.session_id.unwrap_or_default(),
                    severity: severity.to_string(),
                    rule_label: label.to_string(),
                    observation_preview: crate::webhook::preview(content),
                    kind,
                },
            );
        }
    }

    /// Every `key_rotation_interval_steps` steps, signs a new session key's
    /// public half with the old key and signs from then on with the new one,
    /// so a verifier can follow the chain of keys. A failed rotation keeps the
    /// old key.
    pub(super) async fn rotate_key(&mut self, step: u32) {
        let Some(interval) = self.config.key_rotation_interval_steps.filter(|&n| n > 0) else {
            return;
        };
        if !step.is_multiple_of(interval) {
            return;
        }
        let (signing_key, verifying_key) = crate::signing::generate_keypair();
        let new_public_key = crate::signing::public_key_hex(&verifying_key);
        let rotation_index = u64::from(step / interval);
        let rotation = EventPayload::KeyRotation {
            new_public_key: new_public_key.clone(),
            rotation_index,
        };
        match self.record(rotation).await {
            Ok(_) => {
                tracing::info!(
                    "Session signing key rotated (index {rotation_index}, new public key: {})",
                    &new_public_key[..16]
                );
                self.config.session_signing_key = Some(Arc::new(signing_key));
            }
            Err(e) => tracing::warn!("Failed to append KeyRotation event: {e}"),
        }
    }

    /// Snapshots the ledger every `AGENT_SNAPSHOT_INTERVAL` steps, so a restart
    /// replays from there instead of from genesis.
    pub(super) async fn snapshot(&self, step: u32) -> Result<(), AgentError> {
        if step.is_multiple_of(config::snapshot_interval())
            && let Some((seq, _)) = self.pool.get_latest().await.map_err(AgentError::Db)?
            && self.pool.snapshot_at_sequence(seq).await.is_ok()
            && let Some(m) = self.metrics()
        {
            m.inc_snapshots_created();
        }
        Ok(())
    }

    /// Issues the completed session's W3C Verifiable Credential, signed with
    /// the session key. Best-effort: a failure is logged, and the session's
    /// events stand without it.
    pub(super) async fn issue_credential(&self) {
        let (Some(key), Some(session_id)) = (
            self.config.session_signing_key.as_deref(),
            self.config.session_id,
        ) else {
            return;
        };
        let policy_hash = self
            .pool
            .get_session_policy_hash(session_id)
            .await
            .ok()
            .flatten();
        let vc_jwt = crate::verifiable_credential::build_vc_jwt(
            session_id,
            &self.config.session_goal,
            policy_hash.as_deref(),
            Some(key),
            config::vc_audience().as_deref(),
        );
        match self
            .record(EventPayload::VerifiableCredential { vc_jwt })
            .await
        {
            Ok(_) => tracing::info!("Verifiable Credential issued for session {session_id}"),
            Err(e) => tracing::warn!("Failed to append VerifiableCredential event: {e}"),
        }
    }
}
