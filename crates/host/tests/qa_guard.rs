use async_trait::async_trait;
use ectoledger::guard::{Guard, GuardDecision};
use ectoledger::intent::ProposedIntent;
use ectoledger::llm::{LlmBackend, LlmError};

struct ScriptedBackend {
    raw: String,
}

impl ScriptedBackend {
    fn new(raw: &str) -> Self {
        Self {
            raw: raw.to_string(),
        }
    }
}

#[async_trait]
impl LlmBackend for ScriptedBackend {
    async fn propose(&self, _system: &str, _user: &str) -> Result<ProposedIntent, LlmError> {
        Err(LlmError::EmptyResponse)
    }

    async fn raw_call(&self, _system: &str, _user: &str) -> Result<String, LlmError> {
        Ok(self.raw.clone())
    }

    fn backend_name(&self) -> &str {
        "scripted"
    }

    fn model_name(&self) -> &str {
        "scripted-v1"
    }
}

fn goal_intent() -> ProposedIntent {
    ProposedIntent {
        action: "run_command".to_string(),
        params: serde_json::json!({ "command": "ls" }),
        justification: "qa justification long enough".to_string(),
        reasoning: "qa".to_string(),
    }
}

async fn evaluate_raw(raw: &str) -> GuardDecision {
    let guard = Guard::new(Box::new(ScriptedBackend::new(raw)));
    guard.evaluate("qa goal", &goal_intent()).await.unwrap()
}

mod allow_parsing {
    use super::*;

    #[tokio::test]
    async fn exact_allow_is_allowed() {
        assert_eq!(evaluate_raw("ALLOW").await, GuardDecision::Allow);
    }

    #[tokio::test]
    async fn lowercase_allow_is_allowed() {
        assert_eq!(evaluate_raw("allow").await, GuardDecision::Allow);
    }

    #[tokio::test]
    async fn mixed_case_allow_is_allowed() {
        assert_eq!(evaluate_raw("AlLoW").await, GuardDecision::Allow);
    }

    #[tokio::test]
    async fn allow_with_surrounding_whitespace_is_allowed() {
        assert_eq!(evaluate_raw("  ALLOW  \n").await, GuardDecision::Allow);
    }

    #[tokio::test]
    async fn allow_followed_by_trailing_text_still_allows() {
        assert_eq!(
            evaluate_raw("ALLOW, this is read-only").await,
            GuardDecision::Allow
        );
    }
}

mod deny_parsing {
    use super::*;

    #[tokio::test]
    async fn deny_with_colon_reason_extracts_the_reason() {
        let decision = evaluate_raw("DENY: deletes data").await;
        assert_eq!(
            decision,
            GuardDecision::Deny {
                reason: "deletes data".to_string()
            }
        );
    }

    #[tokio::test]
    async fn lowercase_deny_with_reason_extracts_the_reason() {
        let decision = evaluate_raw("deny: not read-only").await;
        assert_eq!(
            decision,
            GuardDecision::Deny {
                reason: "not read-only".to_string()
            }
        );
    }

    #[tokio::test]
    async fn bare_deny_with_no_reason_is_an_empty_reason_not_a_panic() {
        let decision = evaluate_raw("DENY").await;
        assert_eq!(
            decision,
            GuardDecision::Deny {
                reason: String::new()
            }
        );
    }

    #[tokio::test]
    async fn deny_without_a_colon_separator_keeps_the_remaining_text_as_the_reason() {
        let decision = evaluate_raw("DENY downloads code").await;
        assert_eq!(
            decision,
            GuardDecision::Deny {
                reason: "downloads code".to_string()
            }
        );
    }
}

mod fail_closed_on_unparseable_output {
    use super::*;

    #[tokio::test]
    async fn an_empty_response_is_denied_not_a_panic() {
        assert!(matches!(evaluate_raw("").await, GuardDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn whitespace_only_response_is_denied() {
        assert!(matches!(
            evaluate_raw("   \n\t  ").await,
            GuardDecision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn an_allow_embedded_mid_sentence_rather_than_at_the_start_is_denied() {
        let decision = evaluate_raw("I think we should ALLOW this action").await;
        assert!(
            matches!(decision, GuardDecision::Deny { .. }),
            "ALLOW must be at the start of the response to take effect, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn completely_unrelated_text_is_denied() {
        assert!(matches!(
            evaluate_raw("I am not sure what to do here").await,
            GuardDecision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn json_shaped_output_is_denied_not_parsed_as_a_verdict() {
        assert!(matches!(
            evaluate_raw(r#"{"verdict": "allow"}"#).await,
            GuardDecision::Deny { .. }
        ));
    }
}
