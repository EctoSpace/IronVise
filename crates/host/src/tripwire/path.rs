//! `read_file` and `write_file`: a path stays under an allowed root after
//! normalising and resolving it, and a write never lands on a protected file.

use super::*;

impl Tripwire {
    pub(super) fn validate_path(
        &self,
        intent: &ProposedIntent,
    ) -> Result<ValidatedIntent, TripwireError> {
        validate_path_strict(
            intent
                .params_path()
                .ok_or(TripwireError::MissingParam("path"))?,
            &self.allowed_path_prefixes,
        )
        .map(|_| {
            ValidatedIntent::from_proposed(intent.clone())
                .with_allowed_roots(self.allowed_path_prefixes.clone())
        })
    }

    /// A file an external agent wants to create or change. Evaluated for the
    /// Claude Code hook; the native loop never executes it (executor.rs).
    ///
    /// Same allowlist as reads, plus targets that are refused wherever they
    /// sit: an agent that can rewrite its own hook configuration can switch
    /// this check off, and git hooks and SSH configuration run or authorise
    /// code outside anything the hook sees.
    pub(super) fn validate_write(
        &self,
        intent: &ProposedIntent,
    ) -> Result<ValidatedIntent, TripwireError> {
        let path = intent
            .params_path()
            .ok_or(TripwireError::MissingParam("path"))?;
        let checked = validate_write_path(path, &self.allowed_path_prefixes)?;
        if let Some(why) = protected_write_target(&checked) {
            return Err(TripwireError::ProtectedPath(format!(
                "{} ({why})",
                checked.display()
            )));
        }
        Ok(ValidatedIntent::from_proposed(intent.clone()))
    }
}

/// Normalizes a path without requiring filesystem access: removes `.` components
/// and collapses redundant slashes.
///
/// Returns `Err(TripwireError::PathTraversal)` if the path contains `..`
/// (`Component::ParentDir`). Callers should pre-reject such paths; this provides
/// defense-in-depth so a future caller that forgets the pre-check gets a proper
/// error instead of a panic or silent wrong path.
pub(super) fn normalize_path(p: &Path) -> Result<PathBuf, TripwireError> {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(TripwireError::PathTraversal(p.display().to_string()));
            }
            Component::Normal(s) => out.push(s),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    Ok(out)
}

/// Strip a Windows verbatim prefix (`\\?\C:\...`) so prefix comparisons work
/// against ordinary drive paths. Identity on other platforms.
///
/// Windows `Path::canonicalize` returns a verbatim path. That is an
/// extended-length *local* prefix, not a network UNC (`\\server\share`).
/// `Path::starts_with` treats the two forms as unrelated, so a permitted
/// existing file would be denied on Windows unless both sides are normalised.
pub(super) fn comparable_path(path: &Path) -> PathBuf {
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let mut comps = path.components();
        match comps.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::VerbatimDisk(disk) | Prefix::Disk(disk) => {
                    let mut out = PathBuf::from(format!("{}:", disk as char));
                    out.extend(comps);
                    out
                }
                Prefix::Verbatim(rest) => {
                    let mut out = PathBuf::from(rest);
                    out.extend(comps);
                    out
                }
                _ => path.to_path_buf(),
            },
            Some(first) => {
                let mut out = PathBuf::new();
                out.push(first);
                out.extend(comps);
                out
            }
            None => PathBuf::new(),
        }
    }
}

/// Bring an allowed prefix into the same namespace as the candidate.
///
/// `validate_path_strict` always compares against a *canonicalized* candidate
/// (the path itself when it exists, otherwise its canonicalized parent). The
/// prefixes, by contrast, arrive as raw configuration text. Comparing the two
/// directly compares different namespaces: on Windows `canonicalize` expands
/// 8.3 short names (`C:\Users\RUNNER~1` → `C:\Users\runneradmin`) and resolves
/// junctions, and on Unix it resolves symlinks (macOS `/tmp` → `/private/tmp`).
/// Either difference denies a legitimate path. Canonicalizing both sides is the
/// fix; the lexical fallback keeps a prefix that does not exist yet usable
/// rather than turning it into an error or a wildcard.
pub(super) fn comparable_prefix(prefix: &Path) -> PathBuf {
    match prefix.canonicalize() {
        Ok(canonical) => comparable_path(&canonical),
        Err(_) => comparable_path(prefix),
    }
}

/// Whether `path` sits at or below `prefix`, comparing whole components.
///
/// Windows paths are case-insensitive, so a policy written `c:\users\...` must
/// match a canonical `C:\Users\...`. Everywhere else paths *are* case-sensitive
/// and the comparison stays byte-exact - do not extend the Windows arm to macOS
/// on the grounds that APFS is usually case-insensitive; the POSIX API is not,
/// and existing tests depend on that.
#[cfg(windows)]
pub(super) fn prefix_matches(path: &Path, prefix: &Path) -> bool {
    let mut have = path.components();
    for want in prefix.components() {
        // Component-wise, never byte-wise: a byte-prefix test would let
        // `C:\allowedX` match the prefix `C:\allowed`.
        //
        // ASCII-only folding, and on the raw encoded bytes rather than
        // `to_string_lossy`. Lossy conversion maps distinct unpaired surrogates
        // onto the same replacement character, which could make two different
        // filenames compare equal - a false *allow*. ASCII folding is strictly
        // less folding than Windows itself does, so relative to the OS this can
        // only ever fail closed, and it avoids the Turkish dotless-I trap.
        match have.next() {
            Some(got)
                if got
                    .as_os_str()
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(want.as_os_str().as_encoded_bytes()) => {}
            _ => return false,
        }
    }
    true
}

#[cfg(not(windows))]
pub(super) fn prefix_matches(path: &Path, prefix: &Path) -> bool {
    path.starts_with(prefix)
}

pub(super) fn path_under_allowed_prefix(path: &Path, allowed_prefixes: &[PathBuf]) -> bool {
    let path = comparable_path(path);
    allowed_prefixes.iter().any(|p| {
        // An empty prefix has no components, and `starts_with` against no
        // components is vacuously true - i.e. one empty string in the allowlist
        // would permit every path on the machine. Nothing legitimate is
        // expressed by an empty prefix, so reject it rather than let a stray
        // blank line in tripwire.json disable the allowlist.
        !p.as_os_str().is_empty() && prefix_matches(&path, &comparable_prefix(p))
    })
}

/// Reject network UNC and device-namespace paths. Verbatim *local* paths
/// (`\\?\C:\...`) are allowed - that is what Windows `canonicalize()` emits.
pub(super) fn reject_non_local_windows_path(path_str: &str) -> Result<(), TripwireError> {
    #[cfg(windows)]
    {
        use std::path::Prefix;
        // Normalise forward slashes so `//server/share` parses as UNC.
        let normalized = path_str.replace('/', "\\");
        let path = Path::new(&normalized);
        if let Some(Component::Prefix(prefix)) = path.components().next() {
            match prefix.kind() {
                Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _) | Prefix::DeviceNS(_) => {
                    return Err(TripwireError::InvalidPath(
                        "UNC paths are not allowed".to_string(),
                    ));
                }
                Prefix::VerbatimDisk(_) | Prefix::Disk(_) | Prefix::Verbatim(_) => {}
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path_str;
    }
    Ok(())
}

/// Strict path validation: reject `..` before any canonicalization, resolve without
/// requiring existence, then for existing paths verify canonical form and symlink targets.
pub fn validate_path_strict(
    path_str: &str,
    allowed_prefixes: &[PathBuf],
) -> Result<PathBuf, TripwireError> {
    reject_non_local_windows_path(path_str)?;
    // Reject NTFS Alternate Data Streams (colon after drive letter position).
    // Enforced on ALL platforms: user-supplied paths may target Windows filesystems
    // or shared mounts even when the host is Linux/macOS.
    // Strip a Windows verbatim prefix first: `\\?\C:\foo` has a drive colon at
    // index 4, which is not an ADS. `C:\foo:stream` still has a colon after skip(2).
    let ads_haystack = path_str
        .strip_prefix(r"\\?\")
        .or_else(|| path_str.strip_prefix("//?/"))
        .unwrap_or(path_str);
    if ads_haystack.chars().skip(2).any(|c| c == ':') {
        return Err(TripwireError::InvalidPath(path_str.to_string()));
    }
    let raw = Path::new(path_str);
    for component in raw.components() {
        if component == Component::ParentDir {
            return Err(TripwireError::PathTraversal(path_str.to_string()));
        }
    }
    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| TripwireError::InvalidPath(path_str.to_string()))?
            .join(raw)
    };
    let normalized = normalize_path(&absolute)?;
    let check_path = if normalized.exists() {
        let canonical = normalized
            .canonicalize()
            .map_err(|_| TripwireError::InvalidPath(path_str.to_string()))?;
        if !path_under_allowed_prefix(&canonical, allowed_prefixes) {
            // Only a symlink that resolved somewhere else is an escape; a
            // plain file outside the allowlist is simply not allowed.
            let shown = canonical.display().to_string();
            return Err(if canonical == normalized {
                TripwireError::PathNotAllowed(shown)
            } else {
                TripwireError::SymlinkEscape(shown)
            });
        }
        canonical
    } else {
        // File does not yet exist.  To prevent an attacker from planting a symlink
        // in an *intermediate* directory that redirects a write outside the allowed
        // prefix via a non-existent leaf path, canonicalize the parent directory
        // (resolving any symlinks there) and then re-attach the filename component.
        let file_name = normalized
            .file_name()
            .ok_or_else(|| TripwireError::InvalidPath(path_str.to_string()))?;
        let parent = normalized
            .parent()
            .ok_or_else(|| TripwireError::InvalidPath(path_str.to_string()))?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| TripwireError::PathTraversal(path_str.to_string()))?;
        canonical_parent.join(file_name)
    };
    if !path_under_allowed_prefix(&check_path, allowed_prefixes) {
        return Err(TripwireError::PathNotAllowed(
            check_path.display().to_string(),
        ));
    }
    Ok(check_path)
}

/// [`validate_path_strict`] for a write, which may create directories.
///
/// The strict check canonicalises the parent, so `src/new/mod.rs` with no
/// `src/new` yet fails as if it were a traversal. Claude Code's Write creates
/// missing directories, so here the nearest existing ancestor is checked
/// instead and the missing names are put back. They cannot be symlinks,
/// since they do not exist, and `..` was already refused.
pub fn validate_write_path(
    path_str: &str,
    allowed_prefixes: &[PathBuf],
) -> Result<PathBuf, TripwireError> {
    match validate_path_strict(path_str, allowed_prefixes) {
        Err(TripwireError::PathTraversal(_)) => {}
        other => return other,
    }
    let err = || TripwireError::PathTraversal(path_str.to_string());
    let raw = Path::new(path_str);
    if raw.components().any(|c| c == Component::ParentDir) {
        return Err(err());
    }
    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| TripwireError::InvalidPath(path_str.to_string()))?
            .join(raw)
    };
    let normalized = normalize_path(&absolute)?;
    let mut existing = normalized.as_path();
    let mut missing = Vec::new();
    while !existing.exists() {
        missing.push(existing.file_name().ok_or_else(err)?);
        existing = existing.parent().ok_or_else(err)?;
    }
    let base = validate_path_strict(existing.to_str().ok_or_else(err)?, allowed_prefixes)?;
    let full = missing.iter().rev().fold(base, |p, name| p.join(name));
    if !path_under_allowed_prefix(&full, allowed_prefixes) {
        return Err(TripwireError::PathNotAllowed(full.display().to_string()));
    }
    Ok(full)
}

/// Why a write to `path` is refused regardless of the allowlist, if it is.
pub fn protected_write_target(path: &Path) -> Option<&'static str> {
    let names: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    let file = names.last().map(String::as_str).unwrap_or("");
    let parent = names.len().checked_sub(2).map(|i| names[i].as_str());
    if parent == Some(".claude") && file.starts_with("settings") {
        return Some("the agent's own hook configuration: editing it can switch this check off");
    }
    // Codex reads its hooks from hooks.json or the [hooks] tables of config.toml.
    if parent == Some(".codex") && matches!(file, "hooks.json" | "config.toml") {
        return Some("the agent's own hook configuration: editing it can switch this check off");
    }
    // Antigravity CLI reads a workspace's .agents/hooks.json and the global
    // ~/.gemini/config/hooks.json.
    let grandparent = names.len().checked_sub(3).map(|i| names[i].as_str());
    let antigravity_hooks =
        parent == Some(".agents") || (parent == Some("config") && grandparent == Some(".gemini"));
    if file == "hooks.json" && antigravity_hooks {
        return Some("the agent's own hook configuration: editing it can switch this check off");
    }
    if names.windows(2).any(|w| w[0] == ".git" && w[1] == "hooks") {
        return Some("git hooks run code outside the agent's tool calls");
    }
    if names.iter().any(|n| n == ".ssh") {
        return Some("SSH keys and configuration");
    }
    None
}
