//! MCP tool calls: the tool against the allowlist, and any shell command in
//! its arguments.

use super::*;

impl Tripwire {
    /// An MCP tool call, as `mcp:<server>/<tool>`. The name must be well formed
    /// and, if an allowlist is set, on it. Arguments that carry a shell command
    /// get the same per-command check as `run_command`.
    pub(super) fn validate_mcp(
        &self,
        intent: &ProposedIntent,
    ) -> Result<ValidatedIntent, TripwireError> {
        let name = &intent.action[MCP_ACTION_PREFIX.len()..];
        let well_formed = name.split_once('/').is_some_and(|(server, tool)| {
            [server, tool].iter().all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            })
        });
        if !well_formed {
            return Err(TripwireError::InvalidMcpTool(name.to_string()));
        }
        let listed = self.allowed_mcp_tools.is_empty()
            || self.allowed_mcp_tools.iter().any(|p| {
                p == name
                    || p.strip_suffix("/*").is_some_and(|server| {
                        name.split_once('/').is_some_and(|(s, _)| s == server)
                    })
            });
        if !listed {
            return Err(TripwireError::McpToolNotAllowed(name.to_string()));
        }
        let args = intent.params.get("arguments");
        for key in ["command", "cmd", "script"] {
            if let Some(cmd) = args.and_then(|a| a.get(key)).and_then(|v| v.as_str()) {
                for part in split_command_chain(cmd)? {
                    self.validate_command(&ProposedIntent {
                        action: "run_command".into(),
                        params: serde_json::json!({ "command": part }),
                        justification: intent.justification.clone(),
                        reasoning: String::new(),
                    })?;
                }
            }
        }
        Ok(ValidatedIntent::from_proposed(intent.clone()))
    }
}
