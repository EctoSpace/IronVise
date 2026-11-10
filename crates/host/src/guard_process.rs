// Process-isolated guard: spawns the guard-worker binary and communicates
// over stdin/stdout with a HMAC-SHA256 authenticated JSON protocol.
// Each request line is `<json>\t<hmac_hex>` where the HMAC covers the
// serialized nonce + goal + intent. Responses are likewise HMAC-authenticated.
// This prevents injected payload lines from spoofing approval messages.

use crate::guard::{GuardDecision, GuardExecutor};
use crate::intent::ProposedIntent;
use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

type HmacSha256 = Hmac<Sha256>;

const HMAC_KEY_ENV: &str = "GUARD_HMAC_KEY";

#[derive(serde::Serialize)]
struct GuardRequest {
    goal: String,
    intent: ProposedIntent,
    nonce: u64,
    /// Unix timestamp in milliseconds when the request was sent.
    /// The worker rejects requests older than 30 seconds to prevent replay attacks.
    timestamp_ms: u64,
}

/// Compute HMAC-SHA256 over `nonce:json_body` using the session key.
fn compute_hmac(key: &[u8], nonce: u64, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce.to_string().as_bytes());
    mac.update(b":");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn verify_hmac(key: &[u8], nonce: u64, body: &str, expected_hex: &str) -> bool {
    let got = compute_hmac(key, nonce, body);
    // Constant-time comparison using HMAC verify machinery.
    let Ok(expected_bytes) = hex::decode(expected_hex) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce.to_string().as_bytes());
    mac.update(b":");
    mac.update(body.as_bytes());
    mac.verify_slice(&expected_bytes).is_ok() && !got.is_empty()
}

/// A program (and arguments) that runs the worker instead of a `guard-worker`
/// binary beside this one. The desktop app registers itself here with
/// `--guard-worker`, so the semantic guard works there without a second
/// executable in the bundle.
static WORKER_COMMAND: std::sync::OnceLock<(PathBuf, Vec<String>)> = std::sync::OnceLock::new();

/// Register the program that runs the worker. Only the first call counts.
pub fn set_worker_command(program: PathBuf, args: Vec<String>) {
    let _ = WORKER_COMMAND.set((program, args));
}

/// The worker command: `ECTO_GUARD_WORKER` when a package or a test puts the
/// binary elsewhere, else a registered command, else `guard-worker` beside the
/// running binary.
fn guard_worker_command() -> Result<(PathBuf, Vec<String>), GuardProcessError> {
    if let Some(path) = std::env::var_os("ECTO_GUARD_WORKER").filter(|p| !p.is_empty()) {
        return Ok((PathBuf::from(path), Vec::new()));
    }
    if let Some(registered) = WORKER_COMMAND.get() {
        return Ok(registered.clone());
    }
    let current_exe = std::env::current_exe().map_err(GuardProcessError::CurrentExe)?;
    let dir = current_exe.parent().ok_or(GuardProcessError::NoParent)?;
    let name = format!("guard-worker{}", std::env::consts::EXE_SUFFIX);
    Ok((dir.join(name), Vec::new()))
}

pub struct GuardProcess {
    #[allow(dead_code)]
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    reader: BufReader<tokio::process::ChildStdout>,
    hmac_key: Vec<u8>,
    nonce: AtomicU64,
}

#[derive(Debug, thiserror::Error)]
pub enum GuardProcessError {
    #[error("guard-worker spawn: {0}")]
    Spawn(String),
    #[error("current exe: {0}")]
    CurrentExe(std::io::Error),
    #[error("no parent directory for executable")]
    NoParent,
    #[error("io: {0}")]
    Io(std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("guard-worker closed stdout unexpectedly")]
    UnexpectedEof,
    #[error("worker: {0}")]
    WorkerError(String),
    #[error("guard-worker response HMAC mismatch - possible spoofing attempt")]
    HmacMismatch,
}

impl GuardProcess {
    /// Spawn the guard-worker binary. Generates a random session-scoped HMAC key
    /// and passes it to the child via `GUARD_HMAC_KEY` so the worker can
    /// authenticate requests and sign responses.
    pub fn spawn() -> Result<Self, GuardProcessError> {
        let (path, args) = guard_worker_command()?;
        if !path.exists() {
            return Err(GuardProcessError::Spawn(format!(
                "guard-worker binary not found at {} (build with `cargo build` to produce both binaries)",
                path.display()
            )));
        }

        // Generate a 32-byte random HMAC key for this session.
        let hmac_key: [u8; 32] = rand::random();
        let hmac_key_hex = hex::encode(hmac_key);

        let mut command = Command::new(&path);
        command.args(&args);
        // A key the desktop app keeps in the OS credential store is not in
        // the environment the worker inherits; hand it over explicitly.
        for name in ectoledger_llm::api_key::known_names() {
            if let Some(key) = ectoledger_llm::api_key::from_store(name) {
                command.env(name, key);
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env(HMAC_KEY_ENV, &hmac_key_hex)
            // A worker dropped after a failure must not outlive its handle.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| GuardProcessError::Spawn(e.to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| GuardProcessError::Spawn("stdin not captured".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| GuardProcessError::Spawn("stdout not captured".to_string()))?;
        let reader = BufReader::new(stdout);
        Ok(GuardProcess {
            child,
            stdin,
            reader,
            hmac_key: hmac_key.to_vec(),
            nonce: AtomicU64::new(0),
        })
    }

    pub async fn evaluate(
        &mut self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, GuardProcessError> {
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let req = GuardRequest {
            goal: goal.to_string(),
            intent: proposed.clone(),
            nonce,
            timestamp_ms,
        };
        let json = serde_json::to_string(&req).map_err(GuardProcessError::Json)?;
        let mac = compute_hmac(&self.hmac_key, nonce, &json);

        // Format: `<json>\t<hmac_hex>\n`
        let line = format!("{json}\t{mac}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(GuardProcessError::Io)?;
        self.stdin.flush().await.map_err(GuardProcessError::Io)?;

        let mut response = String::new();
        let n = self
            .reader
            .read_line(&mut response)
            .await
            .map_err(GuardProcessError::Io)?;
        if n == 0 {
            return Err(GuardProcessError::UnexpectedEof);
        }

        // Parse response: `ALLOW\t<hmac_hex>` or `DENY: reason\t<hmac_hex>`
        let raw = response.trim();
        let (verdict, resp_mac) = match raw.rsplit_once('\t') {
            Some(parts) => parts,
            None => {
                // No HMAC tab separator - treat as unauthenticated/spoofed.
                tracing::error!("Guard response missing HMAC tab; treating as deny");
                return Ok(GuardDecision::Deny {
                    reason: "unauthenticated guard response".to_string(),
                });
            }
        };

        if !verify_hmac(&self.hmac_key, nonce, verdict, resp_mac) {
            tracing::error!("Guard response HMAC mismatch - possible spoofing attempt");
            return Err(GuardProcessError::HmacMismatch);
        }

        // The worker writes canonical verdicts; the same strict reading applies.
        Ok(crate::guard::parse_verdict(verdict))
    }
}

#[async_trait]
impl GuardExecutor for GuardProcess {
    async fn evaluate(
        &mut self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, Box<dyn std::error::Error + Send + Sync>> {
        GuardProcess::evaluate(self, goal, proposed)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

#[cfg(test)]
mod hmac_tests {
    use super::*;

    const KEY: &[u8] = b"a-session-scoped-test-key";

    #[test]
    fn a_freshly_computed_mac_verifies_against_itself() {
        let mac = compute_hmac(KEY, 1, "ALLOW");
        assert!(verify_hmac(KEY, 1, "ALLOW", &mac));
    }

    #[test]
    fn a_tampered_body_fails_verification() {
        let mac = compute_hmac(KEY, 1, "ALLOW");
        assert!(!verify_hmac(KEY, 1, "DENY: tampered", &mac));
    }

    #[test]
    fn a_tampered_nonce_fails_verification() {
        let mac = compute_hmac(KEY, 1, "ALLOW");
        assert!(!verify_hmac(KEY, 2, "ALLOW", &mac));
    }

    #[test]
    fn a_mac_computed_with_a_different_key_fails_verification() {
        let mac = compute_hmac(KEY, 1, "ALLOW");
        assert!(!verify_hmac(b"a-different-key", 1, "ALLOW", &mac));
    }

    #[test]
    fn non_hex_expected_value_fails_closed_not_a_panic() {
        assert!(!verify_hmac(KEY, 1, "ALLOW", "not valid hex!!"));
    }

    #[test]
    fn an_empty_expected_value_fails_closed() {
        assert!(!verify_hmac(KEY, 1, "ALLOW", ""));
    }

    #[test]
    fn uppercase_hex_mac_still_verifies() {
        let mac = compute_hmac(KEY, 1, "ALLOW").to_uppercase();
        assert!(verify_hmac(KEY, 1, "ALLOW", &mac));
    }

    #[test]
    fn an_empty_body_still_produces_a_verifiable_mac() {
        let mac = compute_hmac(KEY, 0, "");
        assert!(verify_hmac(KEY, 0, "", &mac));
    }

    #[test]
    fn a_zero_length_key_does_not_panic() {
        let mac = compute_hmac(b"", 1, "ALLOW");
        assert!(verify_hmac(b"", 1, "ALLOW", &mac));
    }

    #[test]
    fn same_inputs_are_deterministic_across_calls() {
        assert_eq!(
            compute_hmac(KEY, 7, "DENY: x"),
            compute_hmac(KEY, 7, "DENY: x")
        );
    }
}
