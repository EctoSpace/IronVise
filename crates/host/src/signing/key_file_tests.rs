use super::*;

const PASSWORD: &str = "correct horse battery";

#[test]
fn the_environment_password_is_used_skipped_or_asked_for() {
    assert_eq!(env_password(None), None, "unset: ask");
    assert_eq!(env_password(Some(String::new())), Some(None), "empty: skip");
    assert_eq!(
        env_password(Some("a long passphrase".into())),
        Some(Some("a long passphrase".into()))
    );
}

/// A console prompt that ignores redirected stdin waits forever, so the
/// child is killed after a deadline: a hang fails the test instead of
/// stalling the suite.
#[test]
fn a_redirected_stdin_is_never_prompted() {
    const CHILD: &str = "ECTO_TEST_PROMPT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert_eq!(prompt_or_env_password("never shown: "), None);
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "signing::key_file_tests::a_redirected_stdin_is_never_prompted",
            "--exact",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env_remove("ECTO_KEY_PASSWORD")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            panic!("the prompt waited for a keypress although stdin was redirected");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "the child returned a password: {status}");
}

#[test]
fn a_blank_or_failed_prompt_skips_the_key() {
    assert_eq!(entered(Ok("pw".into())), Some("pw".into()));
    assert_eq!(entered(Ok(String::new())), None);
    assert_eq!(entered(Err(std::io::Error::other("no tty"))), None);
}

/// `--key-password-fd`: the descriptor's content, without the trailing
/// newline a shell adds; nothing at all is no password.
#[cfg(unix)]
#[test]
fn a_password_is_read_from_a_file_descriptor() {
    use std::io::Write;
    use std::os::unix::io::IntoRawFd;
    let read = |content: &[u8]| {
        let (mut tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
        tx.write_all(content).unwrap();
        drop(tx);
        read_password_from_fd(rx.into_raw_fd())
    };
    assert_eq!(read(b"correct horse\n"), Some("correct horse".into()));
    assert_eq!(read(b"  spaced  \r\n"), Some("  spaced".into()));
    assert_eq!(read(b""), None);
    assert_eq!(read(b"\n"), None);
}

/// The minimum is inclusive: a password of exactly that length is kept,
/// one shorter is refused before anything is written.
#[test]
fn a_password_must_be_at_least_the_minimum_length() {
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = generate_keypair();
    let at = "p".repeat(MIN_PASSWORD_LEN);
    let under = "p".repeat(MIN_PASSWORD_LEN - 1);
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    assert!(save_session_key(dir.path(), a, &key, &at).is_ok());
    assert!(matches!(
        save_session_key(dir.path(), b, &key, &under),
        Err(SigningError::PasswordTooShort)
    ));
    assert!(read_key_file(dir.path(), b).unwrap().is_none());
}

/// The check the PostgreSQL verifier runs on every signed event.
#[test]
fn a_signature_verifies_only_for_its_hash_and_its_key() {
    let (key, vk) = generate_keypair();
    let pk = public_key_hex(&vk);
    let hash = "ab".repeat(32);
    let sig = sign_content_hash(&key, &hash);
    assert!(verify_signature(&pk, &hash, &sig).is_ok());
    assert!(verify_content_hash(&vk, &hash, &sig));

    let other_hash = "cd".repeat(32);
    assert!(matches!(
        verify_signature(&pk, &other_hash, &sig),
        Err(SigningError::VerificationFailed)
    ));
    assert!(!verify_content_hash(&vk, &other_hash, &sig));
    let (_, other_vk) = generate_keypair();
    assert!(matches!(
        verify_signature(&public_key_hex(&other_vk), &hash, &sig),
        Err(SigningError::VerificationFailed)
    ));
    assert!(!verify_content_hash(&other_vk, &hash, &sig));

    assert!(matches!(
        verify_signature("zz", &hash, &sig),
        Err(SigningError::InvalidHex)
    ));
    assert!(matches!(
        verify_signature(&pk[..62], &hash, &sig),
        Err(SigningError::InvalidKey)
    ));
    assert!(matches!(
        verify_signature(&pk, &hash, "zz"),
        Err(SigningError::InvalidHex)
    ));
    assert!(matches!(
        verify_signature(&pk, &hash, &sig[..126]),
        Err(SigningError::InvalidSignature)
    ));
    assert!(!verify_content_hash(&vk, &hash, "zz"));
    assert!(!verify_content_hash(&vk, &hash, &sig[..126]));
}

#[test]
fn a_legacy_key_file_opens_only_on_the_legacy_path() {
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = generate_keypair();
    let sid = Uuid::new_v4();
    save_legacy_key_file(dir.path(), sid, &key, PASSWORD);
    let enc = read_key_file(dir.path(), sid).unwrap().unwrap();
    assert!(matches!(
        decrypt_signing_key(&enc, sid, PASSWORD),
        Err(SigningError::UncommittedKeyFile)
    ));
    let opened = decrypt_legacy_signing_key(&enc, sid, PASSWORD).unwrap();
    assert_eq!(opened.to_bytes(), key.to_bytes());
    assert!(matches!(
        decrypt_legacy_signing_key(&enc, sid, "wrong password!"),
        Err(SigningError::Decrypt)
    ));
    assert!(matches!(
        decrypt_legacy_signing_key(&enc, Uuid::new_v4(), PASSWORD),
        Err(SigningError::WrongSession { .. })
    ));
}

fn saved() -> (tempfile::TempDir, Uuid, SigningKey) {
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = generate_keypair();
    let sid = Uuid::new_v4();
    save_session_key(dir.path(), sid, &key, PASSWORD).unwrap();
    (dir, sid, key)
}

/// Read a session's key file and decrypt it, as certificate export does.
fn load(dir: &Path, sid: Uuid, password: &str) -> Result<SigningKey, SigningError> {
    let enc = read_key_file(dir, sid).unwrap().expect("key file saved");
    decrypt_signing_key(&enc, sid, password)
}

fn read(dir: &Path, sid: Uuid) -> EncryptedKeyFile {
    serde_json::from_str(&std::fs::read_to_string(key_file_path(dir, sid)).unwrap()).unwrap()
}

#[test]
fn a_saved_key_loads_back_with_its_password() {
    let (dir, sid, key) = saved();
    let loaded = load(dir.path(), sid, PASSWORD).unwrap();
    assert_eq!(loaded.to_bytes(), key.to_bytes());
}

#[test]
fn a_wrong_password_fails_at_the_commitment() {
    let (dir, sid, _) = saved();
    assert!(matches!(
        load(dir.path(), sid, "wrong password here"),
        Err(SigningError::Decrypt)
    ));
}

/// Copying one session's key file over another's must not hand the second
/// session the first one's key, whatever the file claims.
#[test]
fn a_key_file_moved_to_another_session_is_refused() {
    let (dir, a, _) = saved();
    let b = Uuid::new_v4();
    std::fs::copy(key_file_path(dir.path(), a), key_file_path(dir.path(), b)).unwrap();
    assert!(matches!(
        load(dir.path(), b, PASSWORD),
        Err(SigningError::WrongSession { .. })
    ));

    // Relabelled inside as well: the commitment and the AAD still hold it to `a`.
    let mut enc = read(dir.path(), a);
    enc.session_id = b.to_string();
    assert!(matches!(
        decrypt_signing_key(&enc, b, PASSWORD),
        Err(SigningError::Decrypt)
    ));
}

#[test]
fn a_tampered_or_missing_commitment_is_refused() {
    let (dir, sid, _) = saved();
    let mut enc = read(dir.path(), sid);
    enc.commitment_hex = "00".repeat(32);
    assert!(matches!(
        decrypt_signing_key(&enc, sid, PASSWORD),
        Err(SigningError::Decrypt)
    ));
    enc.commitment_hex.clear();
    assert!(matches!(
        decrypt_signing_key(&enc, sid, PASSWORD),
        Err(SigningError::UncommittedKeyFile)
    ));
}

#[cfg(windows)]
#[test]
fn restrict_to_owner_leaves_an_acl_that_excludes_other_users() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.key");
    std::fs::write(&path, b"shh").unwrap();
    restrict_to_owner(&path).unwrap();

    let out = std::process::Command::new("icacls")
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_uppercase();
    let user = std::env::var("USERNAME").unwrap().to_uppercase();
    assert!(
        text.contains(&user),
        "owner must still have an ACE on the key file: {text}"
    );
    for broad_group in [
        "EVERYONE",
        "BUILTIN\\USERS",
        "AUTHENTICATED USERS",
        "\\USERS:",
    ] {
        assert!(
            !text.contains(broad_group),
            "{broad_group} must not have an ACE on the key file: {text}"
        );
    }
}

#[test]
fn an_altered_ciphertext_is_refused() {
    let (dir, sid, _) = saved();
    let mut enc = read(dir.path(), sid);
    let mut ct = hex::decode(&enc.ciphertext_hex).unwrap();
    ct[0] ^= 1;
    enc.ciphertext_hex = hex::encode(ct);
    assert!(matches!(
        decrypt_signing_key(&enc, sid, PASSWORD),
        Err(SigningError::Decrypt)
    ));
}
