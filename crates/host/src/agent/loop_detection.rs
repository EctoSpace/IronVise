//! A session that keeps proposing the same action is ended as complete.

use super::{AgentError, CognitiveLoop, Step};
use crate::executor;
use crate::intent::ProposedIntent;
use crate::schema::{EventPayload, LedgerEventRow};
use std::collections::HashMap;

/// How many of the latest actions are compared.
const WINDOW: usize = 6;
/// How many identical actions within the window make a loop.
const REPEATS: u32 = 3;

/// True when the same action, with the same parameters in any key order,
/// appears `REPEATS` times among the last `WINDOW` actions.
pub(super) fn detect_loop(events: &[LedgerEventRow]) -> bool {
    let latest: Vec<(&str, String)> = events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::Action { name, params } => Some((name.as_str(), canonical_json(params))),
            _ => None,
        })
        .rev()
        .take(WINDOW)
        .collect();

    let mut counts: HashMap<(&str, &str), u32> = HashMap::with_capacity(latest.len());
    latest.iter().any(|(action, params)| {
        let seen = counts.entry((action, params.as_str())).or_insert(0);
        *seen += 1;
        *seen >= REPEATS
    })
}

/// `value` as JSON with every object's keys sorted, at every depth, so the
/// same data written in a different key order compares equal.
pub(super) fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            let inner: Vec<String> = entries
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(v)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

impl CognitiveLoop<'_> {
    /// Completes the session through the same checks and records as a
    /// completion the model chose, so the ledger shows how it ended.
    pub(super) async fn complete_after_loop(&self) -> Result<Step, AgentError> {
        self.record_thought("Loop detected (repeated action); completing.")
            .await?;
        let intent = ProposedIntent {
            action: "complete".to_string(),
            params: serde_json::json!({}),
            justification: "loop detected".to_string(),
            reasoning: String::new(),
        };
        let validated = match self.config.tripwire.validate(&intent) {
            Ok(v) => v,
            Err(e) => {
                self.record(EventPayload::TripwireRejection {
                    action: Some("complete".to_string()),
                    reason: e.to_string(),
                    stage: "validation".to_string(),
                    enforced: true,
                })
                .await?;
                return Ok(Step::Next);
            }
        };
        let event_id = self.record_action(&validated).await?;
        self.pool
            .mark_action_executing(event_id)
            .await
            .map_err(AgentError::Db)?;
        executor::execute_with_policy(
            validated,
            self.config.cloud_creds.clone(),
            self.config.policy,
        )
        .await
        .map_err(|e| {
            tracing::warn!("Loop-detection complete action executor error: {e}");
            AgentError::Io(std::io::Error::other(e.to_string()))
        })?;
        self.pool
            .mark_action_completed(event_id)
            .await
            .map_err(AgentError::Db)?;
        self.record_observation("Completed due to loop detection.")
            .await?;
        self.issue_credential().await;
        Ok(Step::Done)
    }
}
