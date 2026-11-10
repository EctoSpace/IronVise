// Ed25519 signing of event content hashes for tamper-proof verification.
// Key persistence: the signing key is encrypted with AES-256-GCM using a key
// derived from a user-supplied password via Argon2id. The ciphertext is stored at
// <data_dir>/session-<session_id>.key so that a crash does not invalidate the
// cryptographic audit trail of an ongoing session.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The operating system's random source, which every key, salt and nonce
/// here is drawn from.
pub fn os_rng() -> rand::rand_core::UnwrapErr<rand::rngs::SysRng> {
    rand::rand_core::UnwrapErr(rand::rngs::SysRng)
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut os_rng());
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn sign_content_hash(signing_key: &SigningKey, content_hash: &str) -> String {
    let sig = signing_key.sign(content_hash.as_bytes());
    hex::encode(sig.to_bytes())
}

pub fn verify_signature(
    public_key_hex: &str,
    content_hash: &str,
    signature_hex: &str,
) -> Result<(), SigningError> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| SigningError::InvalidHex)?;
    let vk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidKey)?,
    )
    .map_err(|_| SigningError::InvalidKey)?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| SigningError::InvalidHex)?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidSignature)?,
    );
    vk.verify(content_hash.as_bytes(), &sig)
        .map_err(|_| SigningError::VerificationFailed)
}

pub fn public_key_hex(verifying_key: &VerifyingKey) -> String {
    hex::encode(verifying_key.as_bytes())
}

/// Verify that `signature_hex` (hex-encoded Ed25519 signature) is a valid
/// signature of `content_hash` under `verifying_key`.
///
/// Returns `true` when verification succeeds, `false` on any decode or
/// cryptographic failure.
pub fn verify_content_hash(
    verifying_key: &VerifyingKey,
    content_hash: &str,
    signature_hex: &str,
) -> bool {
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = match <[u8; 64]>::try_from(sig_bytes.as_slice()) {
        Ok(arr) => Signature::from_bytes(&arr),
        Err(_) => return false,
    };
    verifying_key.verify(content_hash.as_bytes(), &sig).is_ok()
}

/// On-disk representation of a password-encrypted Ed25519 signing key.
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    /// Argon2id salt (base64-encoded, stored in the file for self-containment).
    pub salt: String,
    /// AES-256-GCM nonce, hex-encoded.
    pub nonce_hex: String,
    /// AES-256-GCM ciphertext (32-byte key), hex-encoded.
    pub ciphertext_hex: String,
    /// Session UUID this key belongs to.
    pub session_id: String,
    /// HMAC-SHA256 under the derived AES key over the session id. AES-GCM is
    /// not key-committing: without this a crafted file could decrypt under
    /// more than one password. Empty in files written before 0.8.
    #[serde(default)]
    pub commitment_hex: String,
}

fn key_commitment(aes_key: &[u8; 32], session_id: &str) -> hmac::Hmac<sha2::Sha256> {
    use hmac::{KeyInit, Mac};
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(aes_key)
        .expect("HMAC takes a key of any length");
    mac.update(b"ectoledger-key-commit-v1\n");
    mac.update(session_id.as_bytes());
    mac
}

/// A fresh 16-byte salt, in the unpadded base64 a key file stores.
fn new_salt() -> String {
    let mut salt = [0u8; 16];
    os_rng().fill_bytes(&mut salt);
    STANDARD_NO_PAD.encode(salt)
}

/// A fresh 96-bit AES-GCM nonce.
fn new_nonce() -> Nonce<aes_gcm::aead::consts::U12> {
    let mut nonce = [0u8; 12];
    os_rng().fill_bytes(&mut nonce);
    Nonce::from(nonce)
}

/// The 32-byte AES key for `password` and a key file's `salt`: Argon2id with
/// its default parameters (19 MiB, 2 passes, 1 lane, 32-byte output, version
/// 0x13) over the raw bytes of the unpadded base64 salt.
///
/// That is what official v0.6.3 computed. Its code called
/// `Argon2::default().hash_password` on a `SaltString` (argon2 0.5.3); the
/// salt string decodes to those same bytes, and argon2 0.6 keeps the same
/// defaults, so `hash_password_into` matches.
fn derive_key(password: &str, salt: &str) -> Result<[u8; 32], SigningError> {
    let salt = STANDARD_NO_PAD
        .decode(salt)
        .map_err(|_| SigningError::Kdf("the salt is not base64".to_string()))?;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| SigningError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Encrypt a `SigningKey` with `password` using Argon2id KDF + AES-256-GCM.
///
/// The `session_id` is bound as Additional Authenticated Data (AAD) so that
/// the JSON wrapper's `session_id` field cannot be swapped without failing
/// decryption.
pub fn encrypt_signing_key(
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
) -> Result<EncryptedKeyFile, SigningError> {
    let salt = new_salt();
    let aes_key_bytes = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(&aes_key_bytes.into());
    let nonce = new_nonce();
    let sid_str = session_id.to_string();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key.as_bytes().as_ref(),
                aad: sid_str.as_bytes(),
            },
        )
        .map_err(|e| SigningError::Encrypt(e.to_string()))?;
    let commitment = {
        use hmac::Mac;
        key_commitment(&aes_key_bytes, &sid_str)
            .finalize()
            .into_bytes()
    };
    Ok(EncryptedKeyFile {
        salt,
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
        session_id: sid_str,
        commitment_hex: hex::encode(commitment),
    })
}

/// Decrypt the key of `session_id` from `enc` with `password`.
///
/// The session asked for, not the one the file names, is the GCM AAD, so a
/// file copied over another session's is refused rather than trusted.
/// The key commitment is checked first, so a wrong password or a crafted
/// file fails before any decryption.
pub fn decrypt_signing_key(
    enc: &EncryptedKeyFile,
    session_id: Uuid,
    password: &str,
) -> Result<SigningKey, SigningError> {
    let sid = session_id.to_string();
    if enc.session_id != sid {
        return Err(SigningError::WrongSession {
            expected: sid,
            found: enc.session_id.clone(),
        });
    }
    if enc.commitment_hex.is_empty() {
        return Err(SigningError::UncommittedKeyFile);
    }
    let aes_key_bytes = derive_key(password, &enc.salt)?;
    let commitment = hex::decode(&enc.commitment_hex).map_err(|_| SigningError::InvalidHex)?;
    {
        use hmac::Mac;
        key_commitment(&aes_key_bytes, &sid)
            .verify_slice(&commitment)
            .map_err(|_| SigningError::Decrypt)?;
    }
    open_key(&aes_key_bytes, enc, sid.as_bytes())
}

/// Decrypt a key file written by official v0.6.3.
///
/// That release (public tag `cf7d29d`) stored `salt`, `nonce_hex`,
/// `ciphertext_hex` and `session_id`, with no key commitment. AES-256-GCM
/// authenticated the session id as additional data, the same way 0.8 does.
/// A reader that authenticates an empty string instead fails every such file
/// with [`SigningError::Decrypt`] even when the password is right.
///
/// Nothing else in the file binds the key to the session's registered public
/// key, so `certificate::build_certificate` still checks that before signing.
pub fn decrypt_legacy_signing_key(
    enc: &EncryptedKeyFile,
    session_id: Uuid,
    password: &str,
) -> Result<SigningKey, SigningError> {
    let sid = session_id.to_string();
    if enc.session_id != sid {
        return Err(SigningError::WrongSession {
            expected: sid,
            found: enc.session_id.clone(),
        });
    }
    open_key(&derive_key(password, &enc.salt)?, enc, sid.as_bytes())
}

/// After a v0.6.3 key file has decrypted, rewrite it in the 0.8 format.
///
/// The original bytes are kept as `session-<id>.key.v063.bak` beside the new
/// file. An existing backup is left alone, so a second attempt cannot replace
/// the v0.6.3 bytes with a later copy. A failure here does not undo the
/// decrypt: the caller already holds the key.
pub fn upgrade_legacy_key_file(
    key_dir: &Path,
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
) -> Result<(), SigningError> {
    let path = key_file_path(key_dir, session_id);
    let original = std::fs::read(&path).map_err(|e| SigningError::Io(e.to_string()))?;
    let backup = key_dir.join(format!("session-{session_id}.key.v063.bak"));
    if !backup.exists() {
        write_private(&backup, &original)?;
    }
    save_session_key(key_dir, session_id, key, password)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SigningError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| SigningError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| SigningError::Io(e.to_string()))?;
    }
    #[cfg(windows)]
    restrict_to_owner(path).map_err(SigningError::Io)?;
    file.write_all(bytes)
        .map_err(|e| SigningError::Io(e.to_string()))?;
    file.sync_all().map_err(|e| SigningError::Io(e.to_string()))
}

fn open_key(
    aes_key_bytes: &[u8; 32],
    enc: &EncryptedKeyFile,
    aad: &[u8],
) -> Result<SigningKey, SigningError> {
    let cipher = Aes256Gcm::new(&(*aes_key_bytes).into());
    let nonce_bytes = hex::decode(&enc.nonce_hex).map_err(|_| SigningError::InvalidHex)?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SigningError::InvalidKey)?;
    let nonce = Nonce::from(nonce_arr);
    let ct_bytes = hex::decode(&enc.ciphertext_hex).map_err(|_| SigningError::InvalidHex)?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct_bytes.as_ref(),
                aad,
            },
        )
        .map_err(|_| SigningError::Decrypt)?;
    let key_bytes: [u8; 32] = plaintext.try_into().map_err(|_| SigningError::InvalidKey)?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn key_file_path(key_dir: &Path, session_id: Uuid) -> PathBuf {
    key_dir.join(format!("session-{session_id}.key"))
}

/// The encrypted key file `audit` saved for this session, if there is one.
pub fn read_key_file(
    key_dir: &Path,
    session_id: Uuid,
) -> Result<Option<EncryptedKeyFile>, SigningError> {
    let path = key_file_path(key_dir, session_id);
    if !path.exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(&path).map_err(|e| SigningError::Io(e.to_string()))?;
    serde_json::from_str(&json)
        .map(Some)
        .map_err(|e| SigningError::Io(e.to_string()))
}

/// Restrict a key file to the current user with `icacls`: inheritance removed,
/// then Full access for `%USERNAME%` alone. Fatal on any failure, including
/// icacls running and refusing, since a key file left readable by others is
/// worse than no key file.
#[cfg(windows)]
pub(crate) fn restrict_to_owner(path: &Path) -> Result<(), String> {
    let path_str = path.to_string_lossy();
    let user = std::env::var("USERNAME").map_err(|_| {
        "SECURITY: USERNAME is not set; cannot restrict the key file's ACL".to_string()
    })?;
    let grant = format!("{user}:F");
    for args in [
        vec![path_str.as_ref(), "/inheritance:r"],
        vec![path_str.as_ref(), "/grant:r", grant.as_str()],
    ] {
        let out = std::process::Command::new("icacls")
            .args(&args)
            .output()
            .map_err(|e| format!("SECURITY: could not run icacls on {path_str}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "SECURITY: icacls {} failed on {path_str}: {}. Refusing to leave the key file with a permissive ACL.",
                args[1..].join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    Ok(())
}

/// Rename `from` over `to`. Windows can refuse a replacing rename with
/// "Access is denied" while another rename of the same target is in progress,
/// so it is retried briefly there.
fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut attempt = 0;
    loop {
        match std::fs::rename(from, to) {
            Err(e)
                if cfg!(windows)
                    && e.kind() == std::io::ErrorKind::PermissionDenied
                    && attempt < 50 =>
            {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

/// Persist a `SigningKey` to disk encrypted with `password`.
///
/// The password must be at least `MIN_PASSWORD_LEN` characters long
///. Short passwords are rejected with `SigningError::PasswordTooShort`.
pub fn save_session_key(
    key_dir: &Path,
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
) -> Result<(), SigningError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(SigningError::PasswordTooShort);
    }
    std::fs::create_dir_all(key_dir).map_err(|e| SigningError::Io(e.to_string()))?;
    let enc = encrypt_signing_key(session_id, key, password)?;
    let json = serde_json::to_string_pretty(&enc).map_err(|e| SigningError::Io(e.to_string()))?;
    let path = key_file_path(key_dir, session_id);
    // Write a private temporary file and rename it over the key file, so a
    // reader never sees a half-written key and two saves of the same session
    // cannot interleave. On Windows the temporary file matters for a second
    // reason: restrict_to_owner runs icacls twice, and between the two calls
    // the file has an empty ACL, so a concurrent save that opened the shared
    // path in that window failed with "Access is denied".
    let tmp = key_dir.join(format!(".session-{session_id}.{}.tmp", Uuid::new_v4()));
    let written = (|| {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| SigningError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| SigningError::Io(e.to_string()))?;
        }
        #[cfg(windows)]
        restrict_to_owner(&tmp).map_err(SigningError::Io)?;
        file.write_all(json.as_bytes())
            .map_err(|e| SigningError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| SigningError::Io(e.to_string()))?;
        drop(file);
        replace_file(&tmp, &path).map_err(|e| SigningError::Io(e.to_string()))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    Ok(())
}

/// Prompt the user for a key-protection password, or read it from
/// `ECTO_KEY_PASSWORD`. Returns `None` if the user enters an empty string
/// (key persistence is skipped) or if stdin is not a terminal.
///
/// **`ECTO_KEY_PASSWORD` is deprecated.** It remains functional for
/// non-interactive CI pipelines, but a loud deprecation warning is emitted.
/// Prefer `--key-password-fd` (reading from a file descriptor) in production.
pub fn prompt_or_env_password(prompt_msg: &str) -> Option<String> {
    use std::io::IsTerminal;
    if let Some(from_env) = env_password(std::env::var("ECTO_KEY_PASSWORD").ok()) {
        return from_env;
    }
    // rpassword reads the console itself (/dev/tty, or CONIN$ on Windows), not
    // stdin, so a scripted run with stdin redirected would still wait for a
    // keypress that never comes.
    if !std::io::stdin().is_terminal() {
        return None;
    }
    entered(rpassword::prompt_password(prompt_msg))
}

/// What `ECTO_KEY_PASSWORD` decides: `None` when it is unset (ask the user),
/// `Some(None)` when it is set but empty (no key file, and no prompt), and
/// `Some(Some(pw))` when it holds a password, with the deprecation warning.
fn env_password(value: Option<String>) -> Option<Option<String>> {
    let pw = value?;
    if pw.is_empty() {
        return Some(None);
    }
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  DEPRECATED: ECTO_KEY_PASSWORD is set via env var            ║");
    eprintln!("║  This is INSECURE: the password is visible in process        ║");
    eprintln!("║  listings (/proc/self/environ, `ps auxe`, docker inspect).   ║");
    eprintln!("║  Use --key-password-fd or the interactive prompt instead.    ║");
    eprintln!("║  It still works; no release that removes it is planned.      ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    Some(Some(pw))
}

/// A prompt's answer: a blank line, or no terminal to ask on, skips the key.
fn entered(answer: std::io::Result<String>) -> Option<String> {
    match answer {
        Ok(pw) if !pw.is_empty() => Some(pw),
        _ => None,
    }
}

/// Read a password from file descriptor `fd`.
///
/// This avoids placing the password in environment variables or command-line
/// arguments, both of which are visible via `/proc` and `ps`. Typical usage:
///
/// ```bash
/// ectoledger audit "…" --key-password-fd 3   3< <(pass show ectoledger)
/// ```
///
/// The entire content of the FD is read (up to 1 KiB), trimmed of trailing
/// whitespace, and returned. Returns `None` on read failure.
pub fn read_password_from_fd(fd: i32) -> Option<String> {
    // Cross-platform: on Unix use FromRawFd; on Windows this path is not
    // reachable (the CLI validator rejects --key-password-fd on Windows).
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::io::FromRawFd;
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = vec![0u8; 1024];
        match file.read(&mut buf) {
            Ok(n) => {
                let s = String::from_utf8_lossy(&buf[..n]).trim_end().to_string();
                if s.is_empty() { None } else { Some(s) }
            }
            Err(e) => {
                eprintln!("Failed to read password from fd {fd}: {e}");
                None
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        eprintln!("--key-password-fd is only supported on Unix platforms.");
        None
    }
}

/// Try to load the Ed25519 `VerifyingKey` for a session from its stored
/// `session_public_key` hex string in the database.  Returns `None` if the
/// session doesn't exist or has no stored key.
pub async fn load_session_verifying_key(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> Option<VerifyingKey> {
    let pk_hex: Option<String> =
        sqlx::query_scalar("SELECT session_public_key FROM agent_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(pool)
            .await
            .ok()?
            .flatten();
    let pk_hex = pk_hex?;
    let pk_bytes = hex::decode(&pk_hex).ok()?;
    let arr: [u8; 32] = pk_bytes.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid hex")]
    InvalidHex,
    #[error("invalid key bytes")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("password too short (minimum {MIN_PASSWORD_LEN} characters)")]
    PasswordTooShort,
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("encryption error: {0}")]
    Encrypt(String),
    #[error("decryption failed (wrong password or corrupted key file)")]
    Decrypt,
    #[error("key file I/O error: {0}")]
    Io(String),
    #[error("key file belongs to session {found}, not {expected}")]
    WrongSession { expected: String, found: String },
    #[error("key file has no key commitment (written before 0.8): save the key again")]
    UncommittedKeyFile,
}

/// Minimum password length for key encryption.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Encrypt exactly as official v0.6.3 (`cf7d29d`) did: Argon2id defaults over
/// the salt bytes, AES-256-GCM with the session id as additional data, and no
/// commitment field. The salt and nonce are arguments so a fixture can be
/// reproduced byte for byte.
#[cfg(test)]
pub(crate) fn encrypt_v063_key(
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
    salt: &str,
    nonce_bytes: &[u8; 12],
) -> EncryptedKeyFile {
    let aes_key_bytes = derive_key(password, salt).expect("v0.6.3 kdf");
    let cipher = Aes256Gcm::new(&aes_key_bytes.into());
    let nonce = Nonce::from(*nonce_bytes);
    let sid = session_id.to_string();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key.as_bytes().as_ref(),
                aad: sid.as_bytes(),
            },
        )
        .expect("v0.6.3 encrypt");
    EncryptedKeyFile {
        salt: salt.to_string(),
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
        session_id: sid,
        commitment_hex: String::new(),
    }
}

/// Write a key file the way official v0.6.3 did: session id as AES-GCM
/// additional data, and no key commitment.
#[cfg(test)]
pub(crate) fn save_legacy_key_file(
    key_dir: &Path,
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
) -> PathBuf {
    let salt = new_salt();
    let nonce = new_nonce();
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce);
    let file = encrypt_v063_key(session_id, key, password, &salt, &nonce_bytes);
    let file = serde_json::json!({
        "salt": file.salt,
        "nonce_hex": file.nonce_hex,
        "ciphertext_hex": file.ciphertext_hex,
        "session_id": file.session_id,
    });
    std::fs::create_dir_all(key_dir).unwrap();
    let path = key_file_path(key_dir, session_id);
    std::fs::write(&path, file.to_string()).unwrap();
    path
}

/// Official v0.6.3 key-file fixture. Password, secret and session are fixed so
/// the committed JSON can be decrypted without regenerating it.
#[cfg(test)]
pub(crate) const V063_PASSWORD: &str = "upgrade-check-password";
#[cfg(test)]
pub(crate) const V063_SECRET: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
#[cfg(test)]
pub(crate) const V063_SESSION: &str = "6f3c1a20-9b4e-4d17-8c2a-5e7f0b1d3a64";
#[cfg(test)]
pub(crate) const V063_KEY_FILE: &str = include_str!("signing/known_answer_key_file_v063.json");

#[cfg(test)]
mod key_file_tests;
#[cfg(test)]
mod known_answer_tests;
