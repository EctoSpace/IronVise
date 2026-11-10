//! Level 3 - Remote Hardware Enclave Runtime.
//!
//! Connects to a remote attestation service (AWS Nitro Enclave or Azure SEV-SNP)
//! over HTTPS.  The protocol:
//!
//! 1. The host generates a fresh random challenge nonce and
//!    `POST /enclave/attest`s it (as a one-field CBOR map, `{"nonce": bytes}`);
//!    the server returns a COSE-Sign1 attestation document containing the
//!    enclave measurement, PCR values, a session public key, and that same
//!    nonce, signed.
//! 2. The host verifies the document: COSE_Sign1 signature (ES384), the
//!    certificate chain up to the pinned AWS Nitro root, each certificate's
//!    validity, the configured PCR policy, and - this is what closes the
//!    reflected-response issue (a response that echoes its own nonce) - the
//!    document's `nonce` must equal the challenge just sent. See
//!    [`crate::enclave::nitro_attestation`] for the verifier itself.
//!    `initialize()` fails closed (returns `Err`, establishes no session) if
//!    any of this does not check out.
//! 3. Only once verified, the enclave's session public key is trusted. An
//!    X25519 key exchange establishes a ChaCha20-Poly1305 encrypted channel
//!    (protocol v2): HKDF-SHA256, salted with both public keys, yields one key
//!    per direction, and every message's AAD binds its direction, counter and
//!    both public keys to this session.
//! 4. `POST /enclave/infer` - prompt is encrypted client-side, decrypted inside
//!    the enclave, processed, and the response is returned encrypted. The
//!    response nonce must be the counter of the request it answers.
//!
//! When the `enclave-remote` feature is disabled, this module provides a stub
//! implementation that returns `Err` from `initialize()`.
//!
//! Not covered: this runtime is not wired into the agent loop today
//! (`AgentLoopConfig.enclave` is always `None`; see `crates/host/src/agent/mod.rs`),
//! so none of the above runs in a shipped audit session yet.

use crate::enclave::runtime::{
    EnclaveAttestation, EnclaveLevel, EnclaveRequest, EnclaveResponse, EnclaveRuntime,
};

/// Level 3 remote hardware enclave runtime.
///
/// Connects to a remote enclave service at the URL specified by
/// `ECTO_ENCLAVE_REMOTE_URL`.  All prompt data is end-to-end encrypted
/// between the host and the enclave using X25519 + ChaCha20-Poly1305.
///
/// Mutable session state (keys, request counter) is wrapped in a `Mutex` so
/// that `execute(&self)` can be called without `&mut self`.
pub struct RemoteEnclaveRuntime {
    /// Base URL of the remote enclave service (e.g. `https://enclave.example.com`).
    url: String,
    /// Blocking HTTP client for synchronous enclave calls.
    #[cfg(feature = "enclave-remote")]
    client: reqwest::blocking::Client,
    /// Interior-mutable session state protected by a Mutex.
    #[cfg(feature = "enclave-remote")]
    session: std::sync::Mutex<SessionState>,
    /// Cached attestation from the most recent `initialize()` call.
    attestation: std::sync::Mutex<Option<EnclaveAttestation>>,
}

/// Mutable cryptographic session state for the remote enclave channel.
#[cfg(feature = "enclave-remote")]
pub(crate) struct SessionState {
    /// Established session; `None` until `initialize()` succeeds.
    pub keys: Option<SessionKeys>,
    /// Monotonic counter for outgoing requests; a response must echo the
    /// counter of the request it answers.
    pub nonce_counter: u64,
}

/// Directional ciphers derived from X25519 DH with the enclave's session key,
/// and the public keys that bind every message to this session.
#[cfg(feature = "enclave-remote")]
pub(crate) struct SessionKeys {
    /// Host → enclave cipher.
    pub request_cipher: chacha20poly1305::ChaCha20Poly1305,
    /// Enclave → host cipher.
    pub response_cipher: chacha20poly1305::ChaCha20Poly1305,
    pub host_pubkey: [u8; 32],
    pub enclave_pubkey: [u8; 32],
}

impl RemoteEnclaveRuntime {
    /// Create a new remote enclave runtime targeting `url`.
    ///
    /// If `url` is empty, `initialize()` will fail with an error.
    pub fn new_with_url(url: String) -> Self {
        Self {
            url,
            #[cfg(feature = "enclave-remote")]
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|e| {
                    tracing::error!(
                        "reqwest blocking client init failed (TLS?): {e}; using default"
                    );
                    reqwest::blocking::Client::new()
                }),
            #[cfg(feature = "enclave-remote")]
            session: std::sync::Mutex::new(SessionState {
                keys: None,
                nonce_counter: 0,
            }),
            attestation: std::sync::Mutex::new(None),
        }
    }

    /// Backward-compatible constructor (no URL - will error on `initialize`).
    pub fn new() -> Self {
        Self::new_with_url(String::new())
    }

    /// Convenience constructor that reads `ECTO_ENCLAVE_REMOTE_URL` from env.
    pub fn from_env() -> Result<Self, String> {
        let url = std::env::var("ECTO_ENCLAVE_REMOTE_URL")
            .map_err(|_| "ECTO_ENCLAVE_REMOTE_URL not set".to_string())?;
        if url.is_empty() {
            return Err("ECTO_ENCLAVE_REMOTE_URL is empty".to_string());
        }
        Ok(Self::new_with_url(url))
    }
}

impl Default for RemoteEnclaveRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "enclave-remote")]
mod inner {
    use super::*;
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Protocol label, bound into both directional keys and every AAD.
    pub(super) const PROTOCOL: &[u8] = b"ectoledger-enclave-remote-v2";

    /// Direction bytes (AAD): host → enclave requests and enclave → host responses.
    pub(super) const DIR_REQUEST: u8 = 0x01;
    pub(super) const DIR_RESPONSE: u8 = 0x02;

    /// Derive the `(host→enclave, enclave→host)` keys. The salt is
    /// `host_pubkey ‖ enclave_pubkey`, so the keys are unique to this session.
    pub(super) fn directional_keys(
        shared_secret: &[u8; 32],
        host_pubkey: &[u8; 32],
        enclave_pubkey: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        let salt = [host_pubkey.as_slice(), enclave_pubkey.as_slice()].concat();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let expand = |label: &[u8]| {
            let mut key = [0u8; 32];
            hkdf.expand_multi_info(&[PROTOCOL, label], &mut key)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            key
        };
        (expand(b" host->enclave"), expand(b" enclave->host"))
    }

    /// Nonce for message `counter`: 8 bytes little-endian ‖ 4 zero bytes.
    pub(super) fn nonce_for(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// AAD: `PROTOCOL ‖ direction ‖ counter ‖ host pubkey ‖ enclave pubkey`.
    pub(super) fn aad_for(
        direction: u8,
        counter: u64,
        host_pubkey: &[u8; 32],
        enclave_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        [
            PROTOCOL,
            &[direction],
            &counter.to_le_bytes(),
            host_pubkey,
            enclave_pubkey,
        ]
        .concat()
    }

    impl RemoteEnclaveRuntime {
        /// POST the host's fresh challenge `nonce` to `/enclave/attest` and
        /// return the raw COSE-Sign1 response bytes, **unverified**. The
        /// caller (`initialize`) must run them through
        /// [`crate::enclave::nitro_attestation::verify_attestation_document`]
        /// before trusting anything extracted from them - this method does
        /// no checking of its own.
        pub(super) fn fetch_attestation(&self, nonce: &[u8]) -> Result<Vec<u8>, String> {
            let url = format!("{}/enclave/attest", self.url.trim_end_matches('/'));

            let request = ciborium::Value::Map(vec![(
                ciborium::Value::Text("nonce".to_string()),
                ciborium::Value::Bytes(nonce.to_vec()),
            )]);
            let mut body = Vec::new();
            ciborium::into_writer(&request, &mut body)
                .map_err(|e| format!("Failed to encode attestation challenge: {e}"))?;

            let resp = self
                .client
                .post(&url)
                .header("Content-Type", "application/cbor")
                .body(body)
                .send()
                .map_err(|e| format!("Attestation request failed: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!(
                    "Attestation endpoint returned HTTP {}",
                    resp.status()
                ));
            }

            resp.bytes()
                .map(|b| b.to_vec())
                .map_err(|e| format!("Failed to read attestation body: {e}"))
        }

        /// Derive the directional session keys via X25519 DH with the enclave.
        pub(super) fn establish_session_key(
            &self,
            enclave_pubkey: &[u8; 32],
        ) -> Result<(), String> {
            let secret = StaticSecret::random_from_rng(&mut rand::rng());
            let host_pubkey = *PublicKey::from(&secret).as_bytes();
            let shared = secret.diffie_hellman(&PublicKey::from(*enclave_pubkey));

            let (request_key, response_key) =
                directional_keys(shared.as_bytes(), &host_pubkey, enclave_pubkey);

            let mut sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
            sess.keys = Some(SessionKeys {
                request_cipher: ChaCha20Poly1305::new((&request_key).into()),
                response_cipher: ChaCha20Poly1305::new((&response_key).into()),
                host_pubkey,
                enclave_pubkey: *enclave_pubkey,
            });
            sess.nonce_counter = 0;
            Ok(())
        }

        /// Encrypt a plaintext prompt for the remote enclave.
        ///
        /// Returns the request counter, which the response must echo, and the
        /// wire bytes.
        pub(super) fn encrypt_prompt(&self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), String> {
            let mut sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
            let keys = sess.keys.as_ref().ok_or("Session not established")?;

            let counter = sess.nonce_counter;
            let next = counter
                .checked_add(1)
                .ok_or("Nonce counter exhausted (u64::MAX) - session must be re-established")?;
            let nonce_bytes = nonce_for(counter);
            let aad = aad_for(
                DIR_REQUEST,
                counter,
                &keys.host_pubkey,
                &keys.enclave_pubkey,
            );

            let ciphertext = keys
                .request_cipher
                .encrypt(
                    &Nonce::from(nonce_bytes),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|e| format!("Encrypt failed: {e}"))?;
            sess.nonce_counter = next;

            // Wire format: [nonce (12) ‖ ciphertext]
            let mut out = Vec::with_capacity(12 + ciphertext.len());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ciphertext);
            Ok((counter, out))
        }

        /// Decrypt the response to the request that used `counter`.
        ///
        /// The nonce must be exactly that counter's, checked before decrypting.
        pub(super) fn decrypt_response(
            &self,
            counter: u64,
            data: &[u8],
        ) -> Result<Vec<u8>, String> {
            let sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
            let keys = sess.keys.as_ref().ok_or("Session not established")?;

            if data.len() < 12 {
                return Err(format!("Encrypted response too short: {}", data.len()));
            }

            let nonce_bytes = nonce_for(counter);
            if data[..12] != nonce_bytes {
                return Err(format!(
                    "Rejected replayed or mismatched response: nonce does not match request counter {counter}"
                ));
            }

            let aad = aad_for(
                DIR_RESPONSE,
                counter,
                &keys.host_pubkey,
                &keys.enclave_pubkey,
            );
            keys.response_cipher
                .decrypt(
                    &Nonce::from(nonce_bytes),
                    Payload {
                        msg: &data[12..],
                        aad: &aad,
                    },
                )
                .map_err(|e| format!("Decrypt failed: {e}"))
        }

        /// POST an encrypted prompt to `/enclave/infer` and return the decrypted response.
        pub(super) fn remote_infer(&self, prompt: &[u8]) -> Result<Vec<u8>, String> {
            let (counter, encrypted_prompt) = self.encrypt_prompt(prompt)?;

            // Include the host's public key so the enclave can derive the same session keys.
            let host_pk = {
                let sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
                sess.keys
                    .as_ref()
                    .ok_or("Session not established")?
                    .host_pubkey
            };

            let url = format!("{}/enclave/infer", self.url.trim_end_matches('/'));
            let resp = self
                .client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("X-EctoLedger-Session-Pubkey", hex::encode(host_pk))
                .body(encrypted_prompt)
                .send()
                .map_err(|e| format!("Infer request failed: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!("Infer endpoint returned HTTP {}", resp.status()));
            }

            let body = resp
                .bytes()
                .map_err(|e| format!("Failed to read infer response: {e}"))?;

            self.decrypt_response(counter, &body)
        }
    }
}

impl EnclaveRuntime for RemoteEnclaveRuntime {
    fn initialize(&mut self) -> Result<EnclaveAttestation, String> {
        if self.url.is_empty() {
            return Err("Remote enclave URL is empty".to_string());
        }

        #[cfg(feature = "enclave-remote")]
        {
            use crate::enclave::nitro_attestation::{
                NitroAttestationPolicy, verify_attestation_document,
            };
            use rand::Rng;
            use sha2::{Digest, Sha256};

            // 1. Fresh challenge nonce, sent with the attestation request.
            //    Generated per call: a stale document echoing an old nonce
            //    is refused below, which is what stops a reflected or
            //    replayed response from being accepted as fresh (E5).
            let mut nonce = [0u8; 32];
            rand::rng().fill_bytes(&mut nonce);

            // 2. Fetch the raw COSE-Sign1 document. Not trusted yet.
            let raw_cose = self.fetch_attestation(&nonce)?;

            // 3. Verify it: COSE signature, certificate chain to the pinned
            //    AWS Nitro root, cert validity, nonce match, PCR policy.
            //    Fail closed - any error here means `initialize()` returns
            //    `Err` and no session is established.
            let policy = NitroAttestationPolicy::from_env();
            let verified = verify_attestation_document(
                &raw_cose,
                &nonce,
                std::time::SystemTime::now(),
                &policy,
            )
            .map_err(|e| format!("[enclave/remote] attestation verification failed: {e}"))?;

            let public_key = verified
                .public_key
                .as_ref()
                .ok_or("[enclave/remote] attestation document has no public_key")?;
            if public_key.len() != 32 {
                return Err(format!(
                    "[enclave/remote] attestation public_key has wrong length: {} (expected 32 for X25519)",
                    public_key.len()
                ));
            }
            let mut session_pubkey = [0u8; 32];
            session_pubkey.copy_from_slice(public_key);

            let measurement = verified
                .pcrs
                .get(&0)
                .map(hex::encode)
                .unwrap_or_else(|| hex::encode(Sha256::digest(verified.module_id.as_bytes())));

            tracing::info!(
                "[enclave/remote] Attestation verified: module_id={}, PCR0={}",
                verified.module_id,
                verified.pcrs.get(&0).map(hex::encode).unwrap_or_default()
            );

            // 4. Only now is the enclave's session public key trusted.
            //    Establish the encrypted session via X25519 DH.
            self.establish_session_key(&session_pubkey)?;

            let att = EnclaveAttestation {
                level: EnclaveLevel::RemoteHardwareEnclave,
                measurement_hash: measurement,
                raw_attestation: Some(raw_cose),
            };
            *self.attestation.lock().map_err(|e| format!("Lock: {e}"))? = Some(att.clone());
            Ok(att)
        }

        #[cfg(not(feature = "enclave-remote"))]
        Err("enclave-remote feature not enabled".to_string())
    }

    fn execute(&self, req: EnclaveRequest) -> Result<EnclaveResponse, String> {
        #[cfg(feature = "enclave-remote")]
        {
            let output = self.remote_infer(&req.prompt)?;
            let att = self.attestation.lock().map_err(|e| format!("Lock: {e}"))?;
            Ok(EnclaveResponse {
                output,
                attestation: att.clone().unwrap_or_else(|| EnclaveAttestation {
                    level: EnclaveLevel::RemoteHardwareEnclave,
                    measurement_hash: "unknown".to_string(),
                    raw_attestation: None,
                }),
            })
        }

        #[cfg(not(feature = "enclave-remote"))]
        {
            let _ = req;
            Err("enclave-remote feature not enabled".to_string())
        }
    }

    fn level(&self) -> EnclaveLevel {
        EnclaveLevel::RemoteHardwareEnclave
    }

    fn destroy(&mut self) -> Result<(), String> {
        #[cfg(feature = "enclave-remote")]
        {
            let mut sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
            sess.keys = None;
            sess.nonce_counter = 0;
        }
        *self.attestation.lock().map_err(|e| format!("Lock: {e}"))? = None;
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "enclave-remote")]
mod tests {
    use super::inner::{DIR_REQUEST, DIR_RESPONSE, aad_for, directional_keys, nonce_for};
    use super::*;
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    use x25519_dalek::{PublicKey, StaticSecret};

    // Attestation-document verification (COSE chain, nonce, PCR policy) is
    // tested in `crates/host/src/enclave/nitro_attestation.rs`.

    /// Enclave side of an established session, built from the same helpers.
    struct MockEnclave {
        host_pk: [u8; 32],
        enclave_pk: [u8; 32],
        /// Host → enclave key.
        request_key: [u8; 32],
        /// Enclave → host key.
        response_key: [u8; 32],
    }

    impl MockEnclave {
        /// Open a request from the host, which must carry `counter`.
        fn open_request(&self, wire: &[u8], counter: u64) -> Vec<u8> {
            assert_eq!(wire[..12], nonce_for(counter));
            let aad = aad_for(DIR_REQUEST, counter, &self.host_pk, &self.enclave_pk);
            ChaCha20Poly1305::new((&self.request_key).into())
                .decrypt(
                    &Nonce::from(nonce_for(counter)),
                    Payload {
                        msg: &wire[12..],
                        aad: &aad,
                    },
                )
                .expect("enclave decrypt failed")
        }

        /// The genuine response to request `counter`.
        fn respond(&self, counter: u64, msg: &[u8]) -> Vec<u8> {
            let aad = aad_for(DIR_RESPONSE, counter, &self.host_pk, &self.enclave_pk);
            seal(&self.response_key, counter, &aad, msg)
        }
    }

    /// Wire response `[nonce ‖ ciphertext]` for `counter` under any key and AAD.
    fn seal(key: &[u8; 32], counter: u64, aad: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut wire = nonce_for(counter).to_vec();
        wire.extend(
            ChaCha20Poly1305::new(key.into())
                .encrypt(&Nonce::from(nonce_for(counter)), Payload { msg, aad })
                .unwrap(),
        );
        wire
    }

    fn established() -> (RemoteEnclaveRuntime, MockEnclave) {
        let enclave_secret = StaticSecret::random_from_rng(&mut rand::rng());
        let enclave_pk = *PublicKey::from(&enclave_secret).as_bytes();

        let rt = RemoteEnclaveRuntime::new_with_url("http://localhost:9999".to_string());
        rt.establish_session_key(&enclave_pk).unwrap();

        let host_pk = rt
            .session
            .lock()
            .unwrap()
            .keys
            .as_ref()
            .unwrap()
            .host_pubkey;
        let shared = enclave_secret.diffie_hellman(&PublicKey::from(host_pk));
        let (request_key, response_key) =
            directional_keys(shared.as_bytes(), &host_pk, &enclave_pk);
        let enclave = MockEnclave {
            host_pk,
            enclave_pk,
            request_key,
            response_key,
        };
        (rt, enclave)
    }

    #[test]
    fn round_trip() {
        let (rt, enclave) = established();
        for i in 0..4u64 {
            let prompt = format!("request {i}");
            let (counter, wire) = rt.encrypt_prompt(prompt.as_bytes()).unwrap();
            assert_eq!(counter, i);
            assert_eq!(enclave.open_request(&wire, counter), prompt.as_bytes());

            let reply = format!("response {i}");
            let response = enclave.respond(counter, reply.as_bytes());
            assert_eq!(
                rt.decrypt_response(counter, &response).unwrap(),
                reply.as_bytes()
            );
        }
    }

    /// The host's own request, handed back as the response, is not a response.
    #[test]
    fn reflected_request_is_rejected() {
        let (rt, _enclave) = established();
        let (counter, wire) = rt.encrypt_prompt(b"ping").unwrap();

        // The nonce is the right one; the key and AAD direction are what stop it.
        let err = rt.decrypt_response(counter, &wire).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");
    }

    #[test]
    fn replayed_response_is_rejected() {
        let (rt, enclave) = established();

        let (first, _) = rt.encrypt_prompt(b"one").unwrap();
        let old = enclave.respond(first, b"answer one");
        assert_eq!(rt.decrypt_response(first, &old).unwrap(), b"answer one");

        let (second, _) = rt.encrypt_prompt(b"two").unwrap();
        let err = rt.decrypt_response(second, &old).unwrap_err();
        assert!(
            err.contains("replayed or mismatched response"),
            "got: {err}"
        );

        // The genuine answer to the second request still goes through.
        let fresh = enclave.respond(second, b"answer two");
        assert_eq!(rt.decrypt_response(second, &fresh).unwrap(), b"answer two");
    }

    #[test]
    fn nonce_with_nonzero_tail_is_rejected() {
        let (rt, enclave) = established();
        let (counter, _) = rt.encrypt_prompt(b"ping").unwrap();

        let mut response = enclave.respond(counter, b"pong");
        response[11] = 1;
        let err = rt.decrypt_response(counter, &response).unwrap_err();
        assert!(
            err.contains("replayed or mismatched response"),
            "got: {err}"
        );
    }

    /// A response is bound to the session's host pubkey, not just to its keys.
    #[test]
    fn response_for_another_session_is_rejected() {
        let (rt, enclave) = established();
        let (counter, _) = rt.encrypt_prompt(b"ping").unwrap();

        // Same keys, AAD naming a different host pubkey.
        let other_host = [0x5Au8; 32];
        let aad = aad_for(DIR_RESPONSE, counter, &other_host, &enclave.enclave_pk);
        let response = seal(&enclave.response_key, counter, &aad, b"pong");
        let err = rt.decrypt_response(counter, &response).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");

        // A whole other session, answering its own request 0.
        let (_other_rt, other) = established();
        let response = other.respond(counter, b"pong");
        let err = rt.decrypt_response(counter, &response).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");
    }

    #[test]
    fn wrong_direction_is_rejected() {
        let (rt, enclave) = established();
        let (counter, _) = rt.encrypt_prompt(b"ping").unwrap();
        let response_aad = aad_for(DIR_RESPONSE, counter, &enclave.host_pk, &enclave.enclave_pk);
        let request_aad = aad_for(DIR_REQUEST, counter, &enclave.host_pk, &enclave.enclave_pk);

        // Host → enclave key on a response.
        let response = seal(&enclave.request_key, counter, &response_aad, b"pong");
        let err = rt.decrypt_response(counter, &response).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");

        // Right key, request direction in the AAD.
        let response = seal(&enclave.response_key, counter, &request_aad, b"pong");
        let err = rt.decrypt_response(counter, &response).unwrap_err();
        assert!(err.contains("Decrypt failed"), "got: {err}");
    }

    #[test]
    fn directional_keys_differ_and_bind_both_pubkeys() {
        let (host, enclave) = ([1u8; 32], [2u8; 32]);
        let (request, response) = directional_keys(&[7u8; 32], &host, &enclave);
        assert_ne!(request, response);
        assert_eq!(
            directional_keys(&[7u8; 32], &host, &enclave),
            (request, response)
        );
        assert_ne!(directional_keys(&[7u8; 32], &enclave, &host).0, request);
        assert_ne!(directional_keys(&[7u8; 32], &host, &[3u8; 32]).0, request);
    }

    /// `initialize()` must fail closed - no session established - when the
    /// attestation endpoint cannot even be reached. This mainly pins the
    /// wiring: a nonce is generated, `fetch_attestation` is actually called,
    /// and a transport failure propagates as an error rather than falling
    /// back to an unauthenticated session.
    #[test]
    fn initialize_fails_closed_when_the_attestation_endpoint_is_unreachable() {
        let mut rt = RemoteEnclaveRuntime::new_with_url("http://127.0.0.1:1".to_string());
        let err = rt.initialize().unwrap_err();
        assert!(err.contains("Attestation request failed"), "got: {err}");
        assert!(rt.session.lock().unwrap().keys.is_none());
    }

    #[test]
    fn destroy_clears_state() {
        let mut rt = RemoteEnclaveRuntime::new_with_url("http://localhost:9999".to_string());
        *rt.attestation.lock().unwrap() = Some(EnclaveAttestation {
            level: EnclaveLevel::RemoteHardwareEnclave,
            measurement_hash: "test".to_string(),
            raw_attestation: None,
        });
        rt.destroy().unwrap();
        assert!(rt.attestation.lock().unwrap().is_none());
        assert!(rt.session.lock().unwrap().keys.is_none());
    }
}
