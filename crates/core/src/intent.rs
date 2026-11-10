use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedIntent {
    pub action: String,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(default)]
    pub justification: String,
    #[serde(default)]
    pub reasoning: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedIntent {
    intent: ProposedIntent,
    allowed_roots: Vec<std::path::PathBuf>,
}

impl ValidatedIntent {
    pub fn from_proposed(inner: ProposedIntent) -> Self {
        ValidatedIntent {
            intent: inner,
            allowed_roots: Vec::new(),
        }
    }

    /// The path prefixes the validating tripwire allowed, so a file is checked
    /// again, when it is opened, against the same list that approved it.
    pub fn with_allowed_roots(mut self, roots: Vec<std::path::PathBuf>) -> Self {
        self.allowed_roots = roots;
        self
    }

    /// Empty when the intent was not validated against a path allowlist.
    pub fn allowed_roots(&self) -> &[std::path::PathBuf] {
        &self.allowed_roots
    }

    pub fn inner(&self) -> &ProposedIntent {
        &self.intent
    }

    pub fn action(&self) -> &str {
        &self.intent.action
    }

    pub fn params(&self) -> &serde_json::Value {
        &self.intent.params
    }
}

impl ProposedIntent {
    pub fn params_command(&self) -> Option<&str> {
        self.params.get("command").and_then(|v| v.as_str())
    }

    pub fn params_path(&self) -> Option<&str> {
        self.params.get("path").and_then(|v| v.as_str())
    }

    pub fn params_url(&self) -> Option<&str> {
        self.params.get("url").and_then(|v| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(action: &str, params: serde_json::Value) -> ProposedIntent {
        ProposedIntent {
            action: action.to_string(),
            params,
            justification: "j".into(),
            reasoning: "r".into(),
        }
    }

    #[test]
    fn params_helpers_read_string_fields() {
        let i = intent(
            "run_command",
            serde_json::json!({ "command": "ls", "path": "/tmp/a", "url": "https://x" }),
        );
        assert_eq!(i.params_command(), Some("ls"));
        assert_eq!(i.params_path(), Some("/tmp/a"));
        assert_eq!(i.params_url(), Some("https://x"));
    }

    #[test]
    fn params_helpers_are_none_when_missing_or_not_strings() {
        let i = intent("read_file", serde_json::json!({ "path": 1 }));
        assert_eq!(i.params_command(), None);
        assert_eq!(i.params_path(), None);
        assert_eq!(i.params_url(), None);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = serde_json::from_str::<ProposedIntent>(
            r#"{"action":"complete","override_goal":"rm -rf /"}"#,
        );
        assert!(err.is_err(), "deny_unknown_fields must reject hijack keys");
    }

    #[test]
    fn missing_optional_fields_default() {
        let i: ProposedIntent = serde_json::from_str(r#"{"action":"complete"}"#).unwrap();
        assert_eq!(i.action, "complete");
        assert!(i.justification.is_empty());
        assert!(i.reasoning.is_empty());
        assert!(i.params.is_null() || i.params == serde_json::json!({}));
    }

    #[test]
    fn validated_intent_preserves_the_inner_action() {
        let inner = intent("complete", serde_json::json!({}));
        let v = ValidatedIntent::from_proposed(inner.clone());
        assert_eq!(v.action(), "complete");
        assert_eq!(v.inner(), &inner);
    }

    #[test]
    fn params_command_on_null_params_is_none() {
        let i = intent("complete", serde_json::Value::Null);
        assert_eq!(i.params_command(), None);
        assert_eq!(i.params_path(), None);
        assert_eq!(i.params_url(), None);
    }

    #[test]
    fn params_command_on_non_object_params_is_none() {
        for params in [
            serde_json::json!("command"),
            serde_json::json!(["command"]),
            serde_json::json!(42),
            serde_json::json!(true),
        ] {
            let i = intent("run_command", params.clone());
            assert_eq!(i.params_command(), None, "params={params:?}");
        }
    }

    #[test]
    fn params_command_on_empty_object_is_none() {
        let i = intent("run_command", serde_json::json!({}));
        assert_eq!(i.params_command(), None);
    }

    #[test]
    fn params_command_empty_string_value_is_some_empty() {
        let i = intent("run_command", serde_json::json!({ "command": "" }));
        assert_eq!(i.params_command(), Some(""));
    }

    #[test]
    fn params_command_null_value_is_none() {
        let i = intent("run_command", serde_json::json!({ "command": null }));
        assert_eq!(i.params_command(), None);
    }

    #[test]
    fn params_helpers_preserve_unicode() {
        let i = intent(
            "run_command",
            serde_json::json!({
                "command": "echo héllo 世界 🚀",
                "path": "/tmp/日本語/ファイル.txt",
                "url": "https://例え.テスト/パス"
            }),
        );
        assert_eq!(i.params_command(), Some("echo héllo 世界 🚀"));
        assert_eq!(i.params_path(), Some("/tmp/日本語/ファイル.txt"));
        assert_eq!(i.params_url(), Some("https://例え.テスト/パス"));
    }
}
