//! Before the first step: refuse a hostile goal, name the cloud credentials,
//! start the enclave.

use super::{AgentError, CognitiveLoop};
use crate::schema::EventPayload;
use crate::webhook::EgressKind;

impl CognitiveLoop<'_> {
    pub(super) async fn preflight(&mut self) -> Result<(), AgentError> {
        self.scan_goal().await?;
        self.announce_cloud_credentials().await?;
        self.start_enclave().await
    }

    /// Refuses a goal that names a banned command or reads like a prompt
    /// injection, even when the model would never act on it.
    async fn scan_goal(&self) -> Result<(), AgentError> {
        let Err(e) = self.config.tripwire.scan_prompt(&self.config.session_goal) else {
            return Ok(());
        };
        if let Some(m) = self.metrics() {
            m.inc_tripwire_rejections();
        }
        let msg = format!("Tripwire rejected: {e}");
        self.record(EventPayload::TripwireRejection {
            action: None,
            reason: e.to_string(),
            stage: "prompt_scan".to_string(),
            enforced: true,
        })
        .await?;
        self.notify(EgressKind::TripwireRejection, "abort", &msg, &msg);
        Err(AgentError::TripwireAbort(msg))
    }

    /// Names the credential set in the ledger; its values are never written.
    async fn announce_cloud_credentials(&self) -> Result<(), AgentError> {
        let Some(creds) = &self.config.cloud_creds else {
            return Ok(());
        };
        self.record_thought(format!(
            "Cloud credential set loaded: {} (provider: {})",
            creds.name, creds.provider
        ))
        .await
    }

    /// Starts the configured enclave and keeps its attestation for the
    /// certificate. An enclave that fails to start is dropped, and the model is
    /// called directly.
    async fn start_enclave(&mut self) -> Result<(), AgentError> {
        let Some(mut enclave) = self.config.enclave.take() else {
            return Ok(());
        };
        // The runtime blocks (a remote enclave does network I/O), so it starts
        // on the blocking pool rather than stalling the async executor.
        let (enclave, started) = tokio::task::spawn_blocking(move || {
            let started = enclave.initialize();
            (enclave, started)
        })
        .await
        .map_err(|e| {
            AgentError::Io(std::io::Error::other(format!(
                "Enclave init task panicked: {e}"
            )))
        })?;

        match started {
            Ok(attestation) => {
                // Stored, so a certificate built after this process exits
                // still embeds it.
                if let Some(sid) = self.config.session_id
                    && let Err(e) = self.pool.store_enclave_attestation(sid, &attestation).await
                {
                    tracing::warn!("Failed to persist enclave attestation for session {sid}: {e}");
                }
                self.record_thought(format!(
                    "Enclave initialized: level={}, measurement={}",
                    attestation.level, attestation.measurement_hash,
                ))
                .await?;
                self.config.enclave_attestation = Some(attestation);
                self.config.enclave = Some(enclave);
            }
            Err(e) => {
                self.record_thought(format!(
                    "Enclave initialization failed (falling back to plain LLM): {e}"
                ))
                .await?;
            }
        }
        Ok(())
    }
}
