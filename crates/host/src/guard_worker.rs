// Guard worker: reads one HMAC-authenticated JSON line per request from stdin,
// verifies the HMAC, evaluates the intent, and writes an HMAC-signed
// "ALLOW\t<hmac>" or "DENY: <reason>\t<hmac>" line to stdout.
// Running in a separate process provides real guard isolation.

use crate::guard::Guard;
use crate::intent::ProposedIntent;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::io::{BufRead, BufReader, Write};

type HmacSha256 = Hmac<Sha256>;

const HMAC_KEY_ENV: &str = "GUARD_HMAC_KEY";

const MAX_REQUEST_AGE_MS: u64 = 30_000;

/// Parent and worker share a clock, so a timestamp ahead of ours only absorbs
/// rounding.
const MAX_FUTURE_SKEW_MS: u64 = 1_000;

/// The nonce is read from the raw JSON, since the HMAC covers it there.
#[derive(serde::Deserialize)]
struct GuardRequest {
    goal: String,
    intent: IntentPart,
    /// Unix timestamp in milliseconds when the request was sent.
    #[serde(default)]
    timestamp_ms: u64,
}

/// Refuse a request that is not fresh: no timestamp, too old or from the
/// future, or a nonce not above the last one accepted (the parent's nonces
/// only grow). Runs after the HMAC check, so a forged line cannot move
/// `last_nonce`.
fn admit(
    nonce: u64,
    timestamp_ms: u64,
    now_ms: u64,
    last_nonce: &mut Option<u64>,
) -> Result<(), String> {
    if timestamp_ms == 0 {
        return Err("request has no timestamp".into());
    }
    if timestamp_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
        return Err(format!(
            "request timestamp is {}ms in the future",
            timestamp_ms - now_ms
        ));
    }
    let age_ms = now_ms.saturating_sub(timestamp_ms);
    if age_ms > MAX_REQUEST_AGE_MS {
        return Err(format!(
            "request timestamp too old ({age_ms}ms > {MAX_REQUEST_AGE_MS}ms)"
        ));
    }
    if last_nonce.is_some_and(|last| nonce <= last) {
        return Err(format!("replayed nonce {nonce}"));
    }
    *last_nonce = Some(nonce);
    Ok(())
}

/// Write one verdict line, HMAC-signed over the request's nonce when a key is set.
/// A guard's reason may span lines; the protocol is one line per answer, so a
/// newline left in would hand the next request this answer's remainder.
fn respond(
    out: &mut impl Write,
    key: Option<&[u8]>,
    nonce: u64,
    verdict: &str,
) -> std::io::Result<()> {
    let verdict = verdict.replace(['\r', '\n'], " ");
    match key {
        Some(k) => writeln!(out, "{verdict}\t{}", compute_hmac(k, nonce, &verdict))?,
        None => writeln!(out, "{verdict}")?,
    }
    out.flush()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(serde::Deserialize)]
struct IntentPart {
    action: String,
    params: serde_json::Value,
    #[serde(default)]
    justification: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
}

fn compute_hmac(key: &[u8], nonce: u64, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce.to_string().as_bytes());
    mac.update(b":");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn verify_hmac(key: &[u8], nonce: u64, body: &str, expected_hex: &str) -> bool {
    let Ok(expected_bytes) = hex::decode(expected_hex) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce.to_string().as_bytes());
    mac.update(b":");
    mac.update(body.as_bytes());
    mac.verify_slice(&expected_bytes).is_ok()
}

/// The worker loop: run by the `guard-worker` binary and by the desktop app
/// as `<app> --guard-worker` (see `guard_process::set_worker_command`).
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Apply seccomp filter before any user-controlled input is processed.
    // On non-Linux or without the sandbox feature this is a no-op.
    if let Err(e) = crate::sandbox::apply_guard_worker_seccomp() {
        eprintln!("guard-worker: seccomp setup failed: {e}; continuing without filter");
    }

    // Load the session-scoped HMAC key injected by the parent process.
    let hmac_key: Vec<u8> = std::env::var(HMAC_KEY_ENV)
        .ok()
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default();

    let hmac_enabled = hmac_key.len() == 32;
    if !hmac_enabled {
        eprintln!(
            "guard-worker: FATAL - {HMAC_KEY_ENV} not set or not a valid 32-byte hex key. \
             Refusing to run without HMAC authentication. \
             Set {HMAC_KEY_ENV} to a 64-char hex string or pass --no-hmac to explicitly opt out."
        );
        // Allow explicit opt-out via --no-hmac for local development only.
        if !std::env::args().any(|a| a == "--no-hmac") {
            std::process::exit(1);
        }
        eprintln!("guard-worker: --no-hmac passed - running WITHOUT HMAC (development only)");
    }

    let key = hmac_enabled.then_some(hmac_key.as_slice());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            crate::config::llm_timeout_secs(),
        ))
        .build()?;
    let guard = Guard::from_env(&client)?;
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();
    let mut line = String::new();
    let mut last_nonce: Option<u64> = None;

    while reader.read_line(&mut line)? > 0 {
        let trimmed = line.trim().to_string();
        line.clear();
        if trimmed.is_empty() {
            continue;
        }

        // Parse `<json>\t<hmac_hex>` (or plain JSON if HMAC was not set).
        let (json_part, maybe_hmac) = match trimmed.rsplit_once('\t') {
            Some((j, h)) => (j, Some(h)),
            None => (trimmed.as_str(), None),
        };

        // Extract nonce from the raw JSON before full deserialization so we can
        // verify HMAC (which covers the original json_part including the nonce).
        let nonce: u64 = serde_json::from_str::<serde_json::Value>(json_part)
            .ok()
            .and_then(|v| v.get("nonce").and_then(|n| n.as_u64()))
            .unwrap_or(0);

        if let Some(k) = key
            && !maybe_hmac.is_some_and(|mac| verify_hmac(k, nonce, json_part, mac))
        {
            respond(
                &mut stdout,
                key,
                nonce,
                "DENY: request HMAC verification failed",
            )?;
            continue;
        }

        let req: GuardRequest = match serde_json::from_str(json_part) {
            Ok(r) => r,
            Err(e) => {
                respond(
                    &mut stdout,
                    key,
                    nonce,
                    &format!("DENY: invalid request JSON: {e}"),
                )?;
                continue;
            }
        };

        // A captured ALLOW request must not be evaluated twice.
        if let Err(reason) = admit(nonce, req.timestamp_ms, now_ms(), &mut last_nonce) {
            respond(&mut stdout, key, nonce, &format!("DENY: {reason}"))?;
            continue;
        }

        let intent = ProposedIntent {
            action: req.intent.action,
            params: req.intent.params,
            justification: req.intent.justification.unwrap_or_default(),
            reasoning: req.intent.reasoning.unwrap_or_default(),
        };
        let verdict = match guard.evaluate(&req.goal, &intent).await {
            Ok(crate::guard::GuardDecision::Allow) => "ALLOW".to_string(),
            Ok(crate::guard::GuardDecision::Deny { reason }) => format!("DENY: {reason}"),
            Err(e) => format!("DENY: guard error: {e}"),
        };
        respond(&mut stdout, key, nonce, &verdict)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000_000;

    #[test]
    fn a_multi_line_reason_is_answered_on_one_line() {
        let mut out = Vec::new();
        respond(&mut out, Some(&[1; 32]), 4, "DENY: no\r\nreally").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        let (verdict, mac) = text.trim_end().rsplit_once('\t').unwrap();
        assert_eq!(verdict, "DENY: no  really");
        assert!(verify_hmac(&[1; 32], 4, verdict, mac));
    }

    #[test]
    fn a_request_without_a_timestamp_is_refused() {
        let mut last = None;
        let err = admit(0, 0, NOW, &mut last).unwrap_err();
        assert!(err.contains("no timestamp"), "{err}");
        assert_eq!(last, None);
    }

    #[test]
    fn stale_and_future_requests_are_refused() {
        let mut last = None;
        assert!(admit(0, NOW - MAX_REQUEST_AGE_MS - 1, NOW, &mut last).is_err());
        assert!(admit(0, NOW + MAX_FUTURE_SKEW_MS + 1, NOW, &mut last).is_err());
        assert_eq!(last, None);
        assert!(admit(0, NOW - MAX_REQUEST_AGE_MS, NOW, &mut last).is_ok());
    }

    #[test]
    fn a_nonce_is_accepted_once_and_only_upwards() {
        let mut last = None;
        assert!(admit(0, NOW, NOW, &mut last).is_ok());
        assert!(
            admit(0, NOW, NOW, &mut last)
                .unwrap_err()
                .contains("replayed")
        );
        assert!(admit(1, NOW, NOW, &mut last).is_ok());
        assert!(admit(5, NOW, NOW, &mut last).is_ok());
        assert!(admit(3, NOW, NOW, &mut last).is_err());
        assert_eq!(last, Some(5));
    }
}
