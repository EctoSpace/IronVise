//! W3C Verifiable Credential (VC-JWT) issuance for completed IronVise sessions.
//!
//! Issues a self-signed JWT Verifiable Credential (EdDSA / Ed25519) when an agent session
//! completes.  The credential records the session identity, goal, policy hash, and completion
//! timestamp in a tamper-evident, portable format that can be verified by any W3C VC-aware
//! system without access to the IronVise instance.
//!
//! # Format
//!
//! JWT with three base64url-encoded parts separated by `.`:
//! - **Header:** `{"alg":"EdDSA","typ":"JWT"}` (or `{"alg":"none",...}` if no key is provided)
//! - **Payload:** W3C VC JSON (see below)
//! - **Signature:** Ed25519 signature over `header.payload` (empty when `alg=none`)
//!
//! # Verifiable Credential payload
//!
//! ```json
//! {
//!   "iss": "did:key:z...",
//!   "sub": "did:key:z...",
//!   "jti": "urn:uuid:<session_id>",
//!   "iat": 1234567890,
//!   "exp": 1234567890,
//!   "vc": {
//!     "@context": ["https://www.w3.org/2018/credentials/v1"],
//!     "type": ["VerifiableCredential", "EctoLedgerSessionCredential"],
//!     "credentialSubject": {
//!       "id": "did:key:z...",
//!       "sessionId": "<uuid>",
//!       "goal": "...",
//!       "policyHash": "...",
//!       "status": "completed",
//!       "issuedAt": "2026-02-22T..."
//!     }
//!   }
//! }
//! ```

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bs58;
use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde_json::json;
use uuid::Uuid;

/// Derive a `did:key:` W3C DID from an Ed25519 signing key.
///
/// The multicodec prefix `[0xed, 0x01]` identifies the key type as Ed25519 Public Key
/// (per <https://w3c-ccg.github.io/did-method-key/>).  The result is a base58btc-encoded
/// multibase string prefixed with `z`.
pub fn derive_did_from_signing_key(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.as_bytes();
    let mut prefixed = Vec::with_capacity(34);
    prefixed.push(0xed_u8); // Ed25519 multicodec varint
    prefixed.push(0x01_u8);
    prefixed.extend_from_slice(pub_bytes);
    let encoded = bs58::encode(&prefixed).into_string();
    format!("did:key:z{encoded}")
}

/// The Ed25519 key a `did:key` names: the inverse of
/// [`derive_did_from_signing_key`]. `None` for any other DID or key type.
pub fn verifying_key_from_did(did: &str) -> Option<VerifyingKey> {
    let bytes = bs58::decode(did.strip_prefix("did:key:z")?)
        .into_vec()
        .ok()?;
    let key: [u8; 32] = bytes.strip_prefix(&[0xed, 0x01])?.try_into().ok()?;
    VerifyingKey::from_bytes(&key).ok()
}

/// A VC-JWT's `iss` and `alg`, read without verifying anything, so a verifier
/// can decide which key to verify with.
pub fn unverified_issuer(vc_jwt: &str) -> Option<(String, String)> {
    let mut parts = vc_jwt.splitn(3, '.');
    let decode = |p: &str| -> Option<serde_json::Value> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()
    };
    let header = decode(parts.next()?)?;
    let payload = decode(parts.next()?)?;
    Some((
        payload.get("iss")?.as_str()?.to_string(),
        header.get("alg")?.as_str()?.to_string(),
    ))
}

fn b64url(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Build a W3C VC-JWT for a completed IronVise agent session.
///
/// # Arguments
///
/// - `session_id` - UUID of the completed session.
/// - `goal` - The session goal string (stored verbatim in `credentialSubject`).
/// - `policy_hash` - Optional SHA-256 hash of the policy pack used (from `agent_sessions`).
/// - `signing_key` - Optional Ed25519 signing key.  When `Some`, the JWT is signed with
///   EdDSA; when `None`, `alg=none` and the signature part is empty (structural VC only).
///
/// # Returns
///
/// A JWT string `header.payload.signature` (or `header.payload.` when unsigned).
pub fn build_vc_jwt(
    session_id: Uuid,
    goal: &str,
    policy_hash: Option<&str>,
    signing_key: Option<&SigningKey>,
    audience: Option<&str>,
) -> String {
    let did = signing_key
        .map(derive_did_from_signing_key)
        .unwrap_or_else(|| format!("did:ectoledger:session:{session_id}"));

    let now = Utc::now();
    let iat = now.timestamp();
    let exp = iat + 90 * 24 * 3600; // 90-day credential lifetime
    let issued_at_iso = now.to_rfc3339();

    let mut payload = json!({
        "iss": did,
        "sub": did,
        "jti": format!("urn:uuid:{}", session_id),
        "iat": iat,
        "exp": exp,
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://ectoledger.security/2026/credentials/v1"
            ],
            "type": ["VerifiableCredential", "EctoLedgerSessionCredential"],
            "credentialSubject": {
                "id": did,
                "sessionId": session_id.to_string(),
                "goal": goal,
                "policyHash": policy_hash,
                "status": "completed",
                "issuedAt": issued_at_iso,
            }
        }
    });

    if let Some(aud) = audience {
        payload["aud"] = aud.into();
    }

    let alg = if signing_key.is_some() {
        "EdDSA"
    } else {
        "none"
    };
    let header_json = json!({"alg": alg, "typ": "JWT"}).to_string();
    let header_b64 = b64url(header_json.as_bytes());
    let payload_b64 = b64url(payload.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    if let Some(key) = signing_key {
        use ed25519_dalek::Signer;
        let sig = key.sign(signing_input.as_bytes());
        let sig_b64 = b64url(&sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    } else {
        // Unsigned: `header.payload.` (trailing dot, empty signature)
        format!("{signing_input}.")
    }
}

/// Decode and return the payload portion of a VC-JWT as pretty-printed JSON.
/// Returns `None` if the JWT is malformed.
pub fn decode_vc_payload(vc_jwt: &str) -> Option<serde_json::Value> {
    let mut parts = vc_jwt.splitn(3, '.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

/// Derive a `did:key:` DID from a P-256 ECDSA signing key.
///
/// Uses the compressed (33-byte) public key with the P-256 multicodec varint prefix
/// `[0x80, 0x24]` (encoding of `0x1200` per the DID Key Method spec).
/// See <https://w3c-ccg.github.io/did-method-key/#p-256>.
#[cfg(feature = "vc-ecdsa")]
pub fn derive_did_from_p256_key(signing_key: &p256::ecdsa::SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let compressed = verifying_key.to_sec1_point(true);
    let pub_bytes = compressed.as_bytes();
    // P-256 multicodec varint prefix: 0x1200 → [0x80, 0x24]
    let mut prefixed = Vec::with_capacity(2 + pub_bytes.len());
    prefixed.push(0x80_u8);
    prefixed.push(0x24_u8);
    prefixed.extend_from_slice(pub_bytes);
    let encoded = bs58::encode(&prefixed).into_string();
    format!("did:key:z{}", encoded)
}

/// Signing scheme for VC-JWT issuance.
///
/// Use [`build_vc_jwt_with_scheme`] instead of calling scheme-specific builders directly
/// when you want call-site code to be independent of the chosen signing algorithm.
pub enum SigningScheme<'a> {
    /// Ed25519 (EdDSA) - default; produces `did:key:z` with the Ed25519 multicodec prefix.
    EdDSA(&'a ed25519_dalek::SigningKey),
    /// ECDSA P-256 (ES256).  Requires `--features vc-ecdsa` at compile time.
    #[cfg(feature = "vc-ecdsa")]
    ES256(&'a p256::ecdsa::SigningKey),
}

/// Build a W3C VC-JWT using the specified signing scheme.
///
/// This is the multi-scheme generalisation of [`build_vc_jwt`].
pub fn build_vc_jwt_with_scheme(
    session_id: Uuid,
    goal: &str,
    policy_hash: Option<&str>,
    scheme: Option<SigningScheme<'_>>,
) -> String {
    match scheme {
        None => build_vc_jwt(session_id, goal, policy_hash, None, None),
        Some(SigningScheme::EdDSA(key)) => {
            build_vc_jwt(session_id, goal, policy_hash, Some(key), None)
        }
        #[cfg(feature = "vc-ecdsa")]
        Some(SigningScheme::ES256(key)) => build_vc_jwt_p256(session_id, goal, policy_hash, key),
    }
}

/// Build a W3C VC-JWT signed with ECDSA P-256 (ES256 / `alg: "ES256"`).
///
/// Requires the `vc-ecdsa` Cargo feature.
#[cfg(feature = "vc-ecdsa")]
pub fn build_vc_jwt_p256(
    session_id: Uuid,
    goal: &str,
    policy_hash: Option<&str>,
    signing_key: &p256::ecdsa::SigningKey,
) -> String {
    use p256::ecdsa::{Signature, signature::Signer};
    let did = derive_did_from_p256_key(signing_key);
    let now = chrono::Utc::now();
    let iat = now.timestamp();
    let exp = iat + 90 * 24 * 3600;
    let issued_at_iso = now.to_rfc3339();

    let payload = serde_json::json!({
        "iss": did,
        "sub": did,
        "jti": format!("urn:uuid:{}", session_id),
        "iat": iat,
        "exp": exp,
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://ectoledger.security/2026/credentials/v1"
            ],
            "type": ["VerifiableCredential", "EctoLedgerSessionCredential"],
            "credentialSubject": {
                "id": did,
                "sessionId": session_id.to_string(),
                "goal": goal,
                "policyHash": policy_hash,
                "status": "completed",
                "issuedAt": issued_at_iso,
            }
        }
    });

    let header_json = serde_json::json!({"alg": "ES256", "typ": "JWT"}).to_string();
    let header_b64 = b64url(header_json.as_bytes());
    let payload_b64 = b64url(payload.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let sig: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = b64url(&sig.to_bytes());
    format!("{}.{}", signing_input, sig_b64)
}

/// Verify a P-256 (ES256) VC-JWT produced by [`build_vc_jwt_p256`].
///
/// Performs structure, expiry, and ECDSA P-256 signature checks.
/// Requires `--features vc-ecdsa`.
#[cfg(feature = "vc-ecdsa")]
pub fn verify_vc_jwt_p256(
    vc_jwt: &str,
    verifying_key: Option<&p256::ecdsa::VerifyingKey>,
) -> Result<serde_json::Value, VcVerifyError> {
    use p256::ecdsa::{Signature, signature::Verifier};

    let mut parts = vc_jwt.splitn(3, '.');
    let header_b64 = parts.next().ok_or(VcVerifyError::Malformed)?;
    let payload_b64 = parts.next().ok_or(VcVerifyError::Malformed)?;
    let sig_b64 = parts.next().ok_or(VcVerifyError::Malformed)?;

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| VcVerifyError::Malformed)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| VcVerifyError::Malformed)?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("none");
    if alg != "ES256" {
        return Err(VcVerifyError::Malformed);
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VcVerifyError::Malformed)?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| VcVerifyError::Malformed)?;

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64())
        && exp < chrono::Utc::now().timestamp()
    {
        return Err(VcVerifyError::Expired);
    }

    match verifying_key {
        Some(vk) => {
            let sig_bytes = URL_SAFE_NO_PAD
                .decode(sig_b64)
                .map_err(|_| VcVerifyError::Malformed)?;
            let sig = Signature::from_slice(&sig_bytes).map_err(|_| VcVerifyError::Malformed)?;
            let signing_input = format!("{}.{}", header_b64, payload_b64);
            vk.verify(signing_input.as_bytes(), &sig)
                .map_err(|_| VcVerifyError::InvalidSignature)?;
        }
        None => {
            // Decode-only mode - signature is not verified.
        }
    }

    Ok(payload)
}

/// Error returned by [`verify_vc_jwt`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VcVerifyError {
    /// The JWT does not have the expected `header.payload.signature` structure.
    #[error("JWT is malformed (expected header.payload.signature)")]
    Malformed,
    /// The `exp` claim is in the past - the credential has expired.
    #[error("VC-JWT has expired (exp claim is in the past)")]
    Expired,
    /// The Ed25519 signature does not match the signing input.
    #[error("Ed25519 signature verification failed")]
    InvalidSignature,
    /// The credential is unsigned (`alg=none`) but a verifying key was required.
    #[error("VC-JWT is unsigned (alg=none) but a verifying key was provided")]
    Unsigned,

    #[error("VC-JWT is addressed to another audience (aud), or the verifier named none")]
    WrongAudience,
}

/// Verify a W3C VC-JWT produced by [`build_vc_jwt`].
///
/// Performs the following checks in order:
/// 1. **Structure** - the token must split into exactly three `.`-separated parts.
/// 2. **Expiry** - the `exp` claim (Unix timestamp) must be in the future.
/// 3. **Signature** - when `verifying_key` is `Some`, the Ed25519 signature over
///    `header.payload` is verified.  When `verifying_key` is `None` and the
///    credential is unsigned (`alg=none`), the signature part is allowed to be
///    empty; a non-empty signature part paired with `None` is treated as `Malformed`.
///
/// # Returns
///
/// `Ok(payload)` - the decoded JSON payload on success.
/// `Err(VcVerifyError)` - a structured error indicating why verification failed.
/// `audience` is who is verifying. A credential naming an audience is refused
/// unless `audience` is one of them (RFC 7519 §4.1.3); one naming none is for
/// anyone.
pub fn verify_vc_jwt(
    vc_jwt: &str,
    verifying_key: Option<&VerifyingKey>,
    audience: Option<&str>,
) -> Result<serde_json::Value, VcVerifyError> {
    let mut parts = vc_jwt.splitn(3, '.');
    let header_b64 = parts.next().ok_or(VcVerifyError::Malformed)?;
    let payload_b64 = parts.next().ok_or(VcVerifyError::Malformed)?;
    let sig_b64 = parts.next().ok_or(VcVerifyError::Malformed)?;

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| VcVerifyError::Malformed)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| VcVerifyError::Malformed)?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("none");

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VcVerifyError::Malformed)?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| VcVerifyError::Malformed)?;

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64())
        && exp < Utc::now().timestamp()
    {
        return Err(VcVerifyError::Expired);
    }

    if let Some(aud) = payload.get("aud") {
        let named = |a: &str| match aud {
            serde_json::Value::String(s) => s == a,
            serde_json::Value::Array(v) => v.iter().any(|x| x.as_str() == Some(a)),
            _ => false,
        };
        if !audience.is_some_and(named) {
            return Err(VcVerifyError::WrongAudience);
        }
    }

    match (alg, verifying_key) {
        ("EdDSA", Some(vk)) => {
            use ed25519_dalek::Verifier;
            let sig_bytes = URL_SAFE_NO_PAD
                .decode(sig_b64)
                .map_err(|_| VcVerifyError::Malformed)?;
            let signature =
                Signature::from_slice(&sig_bytes).map_err(|_| VcVerifyError::Malformed)?;
            let signing_input = format!("{header_b64}.{payload_b64}");
            vk.verify(signing_input.as_bytes(), &signature)
                .map_err(|_| VcVerifyError::InvalidSignature)?;
        }
        ("none", None) => {
            // Unsigned credential - signature part must be empty.
            if !sig_b64.is_empty() {
                return Err(VcVerifyError::Malformed);
            }
        }
        ("none", Some(_)) => {
            // Caller provided a key but credential is unsigned.
            return Err(VcVerifyError::Unsigned);
        }
        ("EdDSA", None) => {
            // Signed credential but no verifying key available - cannot verify.
            // Return an explicit error instead of silently passing through.
            return Err(VcVerifyError::Unsigned);
        }
        _ => return Err(VcVerifyError::Malformed),
    }

    Ok(payload)
}

#[cfg(test)]
mod tests;
