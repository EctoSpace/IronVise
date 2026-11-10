//! `run_command`: the program and every argument, banned patterns, and a
//! shell chain split into the commands it runs.

use super::*;

impl Tripwire {
    pub(super) fn validate_command(
        &self,
        intent: &ProposedIntent,
    ) -> Result<ValidatedIntent, TripwireError> {
        let cmd = intent
            .params_command()
            .ok_or(TripwireError::MissingParam("command"))?;

        // Tokenize via POSIX shell lexer so backslash escapes, quoting, and concatenated
        // tokens are resolved before any pattern matching.  shlex::split returns None for
        // unterminated quotes - treat that as a malformed (and therefore rejected) command.
        // Windows-style paths are protected first (see `protect_windows_paths`) so their
        // backslashes survive shlex's POSIX escape handling.
        let protected = protect_windows_paths(cmd);
        let tokens = shlex::split(&protected)
            .ok_or_else(|| TripwireError::BannedCommand(cmd.to_string()))?;
        if tokens.is_empty() {
            return Err(TripwireError::MissingParam("command"));
        }

        // Resolve the executable name: strip any leading path prefix so that
        // /usr/bin/sudo and sudo are treated identically.
        let executable = std::path::Path::new(&tokens[0])
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&tokens[0])
            .to_lowercase();

        // Allowlist check: if enabled, the resolved executable must be on the list.
        if !self.allowed_command_executables.is_empty()
            && !self
                .allowed_command_executables
                .iter()
                .any(|a| a.to_lowercase() == executable)
        {
            return Err(TripwireError::BannedCommand(cmd.to_string()));
        }

        // Defense-in-depth: reject shell command-chaining metacharacters.
        for token in &tokens {
            // Exact matches for logical operators (prevents blocking URLs with '&' or JSON with '>').
            // An `&` glued to a word (`echo hello&whoami`) is one token, so it
            // is not caught here. The host executor does not use a shell, except
            // for Windows CMD builtins, which `cmd_metacharacter` rejects.
            if matches!(
                token.as_str(),
                ";" | "&&" | "||" | "|" | "&" | ">" | ">>" | "<"
            ) {
                return Err(TripwireError::BannedCommand(format!(
                    "shell operator '{token}' detected"
                )));
            }
            // Substring matches for subshells, command substitutions, and
            // semicolons (these can be embedded in tokens by shlex when not
            // separated by whitespace, e.g. "dir;type").
            for dangerous in &[";", "$(", "`", "${", "<(", ">(", "\n", "\r"] {
                if token.contains(dangerous) {
                    return Err(TripwireError::BannedCommand(format!(
                        "shell metacharacter '{}' detected in: {}",
                        dangerous.escape_default(),
                        cmd
                    )));
                }
            }
        }

        // Defense-in-depth ban check operating on the normalised token stream.
        // Checking both individual tokens (single-word bans like "sudo") and
        // the space-joined reconstruction (multi-word bans like "rm -rf") catches
        // obfuscations that the old raw-string contains() check would have missed
        // (e.g. r\m -rf normalises to rm -rf after shlex tokenisation).
        let normalised_cmd = tokens.join(" ").to_lowercase();
        for banned in &self.banned_command_patterns {
            let banned_lower = banned.to_lowercase();
            let hit = |hay: &str| banned_pattern_matches(hay, &banned_lower);
            // Multi-word pattern: match against full normalised command string.
            if hit(&normalised_cmd) {
                return Err(TripwireError::BannedCommand(cmd.to_string()));
            }
            // Single-token patterns: also check each token individually so that a
            // banned word embedded in a pipeline is caught even if the join differs.
            if tokens.iter().any(|t| hit(&t.to_lowercase())) {
                return Err(TripwireError::BannedCommand(cmd.to_string()));
            }
        }

        Ok(ValidatedIntent::from_proposed(intent.clone()))
    }
}

/// Doubles backslashes inside Windows-style path tokens (`C:\Users\x`,
/// `\\server\share`) before the command string is handed to `shlex::split`.
///
/// `shlex::split` applies POSIX backslash-escaping: a lone `\` is an escape
/// character that is consumed and dropped, so `C:\Users\x` would otherwise be
/// mangled into `C:Usersx`. Doubling each backslash first means shlex's own
/// unescaping (`\\` -> `\`) restores the original single backslashes. Only
/// backslashes inside a token that looks like a Windows path are touched, so
/// ordinary POSIX escapes elsewhere in the command (e.g. an obfuscated
/// `r\m -rf`) are tokenised exactly as before.
pub(crate) fn protect_windows_paths(cmd: &str) -> std::borrow::Cow<'_, str> {
    static WINDOWS_PATH_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = WINDOWS_PATH_RE.get_or_init(|| {
        Regex::new(r#"[A-Za-z]:\\[^\s"']*|\\\\[^\s"']+"#)
            .expect("invalid windows path scanner pattern")
    });
    if !re.is_match(cmd) {
        return std::borrow::Cow::Borrowed(cmd);
    }
    let mut out = String::with_capacity(cmd.len());
    let mut last = 0;
    for m in re.find_iter(cmd) {
        out.push_str(&cmd[last..m.start()]);
        out.push_str(&m.as_str().replace('\\', "\\\\"));
        last = m.end();
    }
    out.push_str(&cmd[last..]);
    std::borrow::Cow::Owned(out)
}

/// Split a shell command at its unquoted `&&`, `||`, `;`, `|`, `&` and
/// newlines, so each command of a chain can be checked on its own.
///
/// Claude Code runs real shell commands, and `cd x && cargo test | tail` is
/// everyday. Checked whole, a chain is either refused outright (the tripwire
/// bans operators) or passes a policy that only looks at its first program.
/// Quotes are respected, and `2>&1`, `&>`, `>&` stay redirects.
///
/// One construct is rewritten first: `$(cat <<'EOF' … EOF)`, how Claude Code
/// writes commit messages. With a quoted delimiter the body is never expanded,
/// so it is text; it becomes a placeholder. Any other `$(` is left for the
/// tripwire to refuse.
pub fn split_command_chain(cmd: &str) -> Result<Vec<String>, TripwireError> {
    let text = replace_quoted_heredoc_substitutions(cmd);
    let chars: Vec<char> = text.chars().collect();
    let mut parts = Vec::new();
    let mut cur = String::new();
    let (mut single, mut double) = (false, false);
    let mut i = 0;
    let mut flush = |cur: &mut String| {
        let t = cur.trim();
        if !t.is_empty() {
            parts.push(t.to_string());
        }
        cur.clear();
    };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if single {
            single = c != '\'';
            cur.push(c);
        } else if c == '\\' {
            cur.push(c);
            if let Some(n) = next {
                cur.push(n);
                i += 1;
            }
        } else if c == '\'' && !double {
            single = true;
            cur.push(c);
        } else if c == '"' {
            double = !double;
            cur.push(c);
        } else if double
            || !matches!(c, '&' | '|' | ';' | '\n')
            || (c == '&' && (cur.ends_with('>') || next == Some('>')))
        {
            // Text, or the `&` of a redirect (`2>&1`, `&>`).
            cur.push(c);
        } else {
            flush(&mut cur);
            if (c == '&' && next == Some('&')) || (c == '|' && matches!(next, Some('|' | '&'))) {
                i += 1;
            }
        }
        i += 1;
    }
    if single || double {
        return Err(TripwireError::BannedCommand(format!(
            "unterminated quote in: {cmd}"
        )));
    }
    flush(&mut cur);
    if parts.is_empty() {
        return Err(TripwireError::MissingParam("command"));
    }
    Ok(parts)
}

/// Replace `$(cat <<'DELIM'` … `DELIM` `)` (quoted delimiter, optionally
/// `<<-`) with a placeholder. Anything else after the closing delimiter line
/// but before `)` leaves the substitution untouched.
pub(super) fn replace_quoted_heredoc_substitutions(cmd: &str) -> String {
    const PLACEHOLDER: &str = "heredoc-text";
    let mut out = String::with_capacity(cmd.len());
    let mut rest = cmd;
    while let Some(start) = rest.find("$(cat <<") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + "$(cat <<".len()..];
        match quoted_heredoc_len(tail) {
            Some(len) => {
                out.push_str(PLACEHOLDER);
                rest = &tail[len..];
            }
            None => {
                out.push_str("$(cat <<");
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Length of `['-'] ['"'] DELIM ['"'] \n body \n DELIM \s* )` at the start
/// of `s`, if that is what `s` starts with.
pub(super) fn quoted_heredoc_len(s: &str) -> Option<usize> {
    let strip_tabs = s.starts_with('-');
    let after_dash = if strip_tabs { &s[1..] } else { s };
    let quote = after_dash
        .chars()
        .next()
        .filter(|q| *q == '\'' || *q == '"')?;
    let delim_end = after_dash[1..].find(quote)?;
    let delim = &after_dash[1..1 + delim_end];
    if delim.is_empty() || !delim.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let header = &after_dash[1 + delim_end + 1..];
    let body_start = header.find('\n')?;
    if !header[..body_start].trim().is_empty() {
        return None;
    }
    let mut pos = body_start + 1;
    for line in header[body_start + 1..].split_inclusive('\n') {
        pos += line.len();
        let bare = line.trim_end_matches('\n');
        let bare = if strip_tabs {
            bare.trim_start_matches('\t')
        } else {
            bare
        };
        if bare == delim {
            let after = &header[pos..];
            let close = after.find(|c: char| !c.is_whitespace())?;
            if after[close..].starts_with(')') {
                return Some(s.len() - header.len() + pos + close + 1);
            }
            return None;
        }
    }
    None
}

/// Whether a (lowercased) banned pattern occurs in `hay`.
///
/// A single word must both start and end a word: `dd` matches `dd`, `/bin/dd`
/// and `dd.img` (`.` is not alphanumeric, so it still counts as a boundary),
/// but not `git add`, `address.txt`, or `sudoku` (a program that merely starts
/// with a banned word). Patterns with spaces or a `/` keep substring matching.
pub(super) fn banned_pattern_matches(hay: &str, pattern: &str) -> bool {
    let single_word = !pattern.is_empty()
        && pattern
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !single_word {
        return hay.contains(pattern);
    }
    hay.match_indices(pattern).any(|(i, _)| {
        let before_ok = hay[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        let after_ok = hay[i + pattern.len()..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        before_ok && after_ok
    })
}
