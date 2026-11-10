use crate::intent::{ProposedIntent, ValidatedIntent};
use regex_lite::Regex;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Tripwire {
    allowed_path_prefixes: Vec<PathBuf>,
    allowed_domains: Vec<String>,
    banned_command_patterns: Vec<String>,
    /// Allowlist of permitted executable names (argv[0] basename).
    /// When empty (the default), allowlist checking is disabled for backward compatibility.
    /// Configure with `with_allowed_command_executables()` to enable strict allowlist mode.
    allowed_command_executables: Vec<String>,
    /// `server/tool` names (or `server/*`) an MCP call may use. Empty: any.
    allowed_mcp_tools: Vec<String>,
    min_justification_length: u32,
    require_https: bool,
}

mod command;
mod http;
mod mcp;
mod path;
mod prompt;

pub(crate) use command::protect_windows_paths;
pub use command::split_command_chain;
use command::*;
pub use path::{protected_write_target, validate_path_strict, validate_write_path};

impl Tripwire {
    pub fn new(
        allowed_path_prefixes: Vec<PathBuf>,
        allowed_domains: Vec<String>,
        banned_command_patterns: Vec<String>,
        min_justification_length: u32,
        require_https: bool,
    ) -> Self {
        Tripwire {
            allowed_path_prefixes,
            allowed_domains,
            banned_command_patterns,
            allowed_command_executables: Vec::new(),
            allowed_mcp_tools: Vec::new(),
            min_justification_length,
            require_https,
        }
    }

    /// The operator's `tripwire.json`, or its defaults when there is none.
    pub fn from_operator_config() -> Self {
        let cfg = crate::config::load_tripwire_config();
        let allowed_paths = crate::config::canonical_allowed_prefixes(&cfg.allowed_paths);
        Self::from_config(cfg, allowed_paths)
    }

    /// Every setting from `cfg` except the path allowlist, which the caller
    /// resolves.
    pub fn from_config(cfg: crate::config::TripwireConfig, allowed_paths: Vec<PathBuf>) -> Self {
        Self::new(
            allowed_paths,
            cfg.allowed_domains,
            cfg.banned_command_patterns,
            cfg.min_justification_length,
            cfg.require_https,
        )
        .with_allowed_mcp_tools(cfg.allowed_mcp_tools)
    }

    pub fn with_require_https(mut self, require: bool) -> Self {
        self.require_https = require;
        self
    }

    /// Configure an allowlist of permitted executable names (argv[0] basename).
    /// When set, only commands whose resolved executable basename is in this list are permitted.
    /// An empty list (the default) disables allowlist enforcement.
    pub fn with_allowed_command_executables(mut self, executables: Vec<String>) -> Self {
        self.allowed_command_executables = executables;
        self
    }

    /// Restrict MCP calls to these `server/tool` names; `server/*` allows a
    /// whole server. Empty (the default) allows any tool, still subject to the
    /// policy and to the command check on its arguments.
    pub fn with_allowed_mcp_tools(mut self, tools: Vec<String>) -> Self {
        self.allowed_mcp_tools = tools;
        self
    }

    pub fn validate(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        let min_len = self.min_justification_length as usize;
        if intent.action.as_str() != "complete" && intent.justification.trim().len() < min_len {
            return Err(TripwireError::InsufficientJustification(min_len));
        }

        let action = intent.action.as_str();
        match action {
            "run_command" => self.validate_command(intent),
            "read_file" => self.validate_path(intent),
            "write_file" => self.validate_write(intent),
            "http_get" => self.validate_url(intent),
            "complete" => Ok(ValidatedIntent::from_proposed(intent.clone())),
            a if a.starts_with(MCP_ACTION_PREFIX) => self.validate_mcp(intent),
            _ => Err(TripwireError::UnknownAction(intent.action.clone())),
        }
    }
}

/// Action names for MCP tool calls: `mcp:<server>/<tool>`, so a policy can
/// allow or forbid one tool by name.
pub const MCP_ACTION_PREFIX: &str = "mcp:";

pub fn default_banned_command_patterns() -> Vec<String> {
    vec![
        "rm -rf".to_string(),
        "sudo".to_string(),
        // Listed on its own because the word-boundary check in
        // `banned_pattern_matches` requires an exact word match: "sudo" alone
        // does not catch "sudoedit" (distinguishing it from "sudoku").
        "sudoedit".to_string(),
        "mkfs".to_string(),
        "dd".to_string(),
        "/dev/sda".to_string(),
        "chmod 777".to_string(),
        "> /dev/".to_string(),
        "wget".to_string(),
        "curl | sh".to_string(),
        "| sh".to_string(),
        "| bash".to_string(),
    ]
}

/// Returns a conservative default allowlist of executable names (argv[0] basename).
/// These mirror the executor's `ALLOWED_PROGRAMS` list so both layers are consistent.
/// Apply with `Tripwire::new(...).with_allowed_command_executables(default_allowed_command_executables())`.
pub fn default_allowed_command_executables() -> Vec<String> {
    vec![
        "ls".to_string(),
        "cat".to_string(),
        "find".to_string(),
        "grep".to_string(),
        "head".to_string(),
        "tail".to_string(),
        "wc".to_string(),
        "stat".to_string(),
        "file".to_string(),
        "diff".to_string(),
        "md5sum".to_string(),
        "sha256sum".to_string(),
        "sha1sum".to_string(),
        "ps".to_string(),
        "echo".to_string(),
        "date".to_string(),
        "id".to_string(),
        "hostname".to_string(),
        "uname".to_string(),
        "df".to_string(),
        "du".to_string(),
        "pwd".to_string(),
        "which".to_string(),
        "whoami".to_string(),
        "curl".to_string(),
        // NOTE: python3, node, git, and cargo are intentionally excluded.
        // They are interpreters / build tools that can execute arbitrary code
        // via -c, -e, hooks, or build scripts, bypassing banned pattern checks.
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum TripwireError {
    #[error("unknown action: {0}")]
    UnknownAction(String),
    #[error("missing param: {0}")]
    MissingParam(&'static str),
    #[error("banned command: {0}")]
    BannedCommand(String),
    #[error("path traversal: {0}")]
    PathTraversal(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("path not allowed: {0}")]
    PathNotAllowed(String),
    #[error("protected path: {0}")]
    ProtectedPath(String),
    #[error("malformed MCP tool name: {0}")]
    InvalidMcpTool(String),
    #[error("MCP tool not in allowed_mcp_tools: {0}")]
    McpToolNotAllowed(String),
    #[error("symlink escapes allowed path: {0}")]
    SymlinkEscape(String),
    #[error("policy violation: {0}")]
    PolicyViolation(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("https required: {0}")]
    HttpsRequired(String),
    #[error("domain not allowed: {0}")]
    DomainNotAllowed(String),
    #[error("justification missing or too short (min {0} chars)")]
    InsufficientJustification(usize),
}

#[cfg(test)]
mod write_tests;

#[cfg(test)]
mod tests;
