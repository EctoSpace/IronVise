//! Base-URL normalisation for OpenAI-compatible endpoints.
//!
//! Every OpenAI-compatible server - LM Studio, llama.cpp, vLLM, MLX-LM,
//! LocalAI, OpenAI itself - exposes the same `/v1/chat/completions` route, but
//! they disagree about what they call "the base URL" in their own UI. LM Studio,
//! llama.cpp and vLLM all print `http://localhost:PORT/v1`, while OpenAI's docs
//! use `https://api.openai.com` with no version segment.
//!
//! Appending `/v1/chat/completions` unconditionally therefore produces
//! `/v1/v1/chat/completions` - a 404 - for exactly the string most local-server
//! users will paste. [`normalize_openai_base`] collapses both conventions onto
//! one canonical form so the caller can append the route safely.

/// Canonicalise an OpenAI-compatible base URL to end in exactly one `/v1`.
///
/// Handles the strings users actually paste: with or without a trailing slash,
/// with or without the `/v1` segment, and the full endpoint copied out of a
/// server's example `curl` command.
///
/// An empty or whitespace-only input returns an empty string - the caller
/// decides whether that is a configuration error or a cue to use a default.
pub fn normalize_openai_base(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }

    // A pasted full endpoint. Strip the route back to its base rather than
    // building `/v1/chat/completions/chat/completions`.
    let base = trimmed
        .strip_suffix("/chat/completions")
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    if base.is_empty() {
        return String::new();
    }

    if last_segment_is_v1(base) || has_version_segment(base) {
        base.to_string()
    } else {
        format!("{base}/v1")
    }
}

/// Full chat-completions endpoint for an OpenAI-compatible base URL.
///
/// This is the call site that matters: it is the only place the `/v1` segment
/// should ever be appended.
pub fn chat_completions_url(base: &str) -> String {
    format!("{}/chat/completions", normalize_openai_base(base))
}

/// True when the URL's final path segment is exactly `v1`.
///
/// Compares the whole segment, so a host such as `http://apiv1.example.com` or
/// a path such as `/openai-v1` is not mistaken for an already-versioned base.
fn last_segment_is_v1(url: &str) -> bool {
    url.rsplit('/')
        .next()
        .is_some_and(|seg| seg.eq_ignore_ascii_case("v1"))
}

/// True when a path segment names an API version (`v1beta`, `v2`), as in
/// Gemini's `…/v1beta/openai`: that base already carries its version, and a
/// `/v1` after it is a 404. The host is not a path segment, so
/// `https://v2.example.com` still gains `/v1`.
fn has_version_segment(url: &str) -> bool {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let Some((_, path)) = after_scheme.split_once('/') else {
        return false;
    };
    path.split('/').any(is_version_segment)
}

/// `v` and a number, optionally a stability word and its number: `v1`,
/// `v1beta`, `v2alpha1`.
fn is_version_segment(segment: &str) -> bool {
    let Some(rest) = segment.strip_prefix(['v', 'V']) else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    let suffix = &rest[digits..];
    let word = suffix.trim_end_matches(|c: char| c.is_ascii_digit());
    digits > 0 && ["", "alpha", "beta"].contains(&word.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests;
