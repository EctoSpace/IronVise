use ectoledger::signing::{
    EncryptedKeyFile, SigningError, decrypt_signing_key, generate_keypair, read_key_file,
    read_password_from_fd, save_session_key, verify_content_hash, verify_signature,
};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const PASSWORD_A: &str = "a password long enough";
const PASSWORD_B: &str = "a different password!!";

fn key_file_path(dir: &Path, sid: Uuid) -> PathBuf {
    dir.join(format!("session-{sid}.key"))
}

fn read_enc(dir: &Path, sid: Uuid) -> EncryptedKeyFile {
    serde_json::from_str(&std::fs::read_to_string(key_file_path(dir, sid)).unwrap()).unwrap()
}

mod verify_signature_edge_cases {
    use super::*;

    #[test]
    fn an_all_zero_public_key_does_not_panic_and_does_not_verify() {
        let hash = "ab".repeat(32);
        let zero_pk = "00".repeat(32);
        let sig = "11".repeat(64);
        assert!(verify_signature(&zero_pk, &hash, &sig).is_err());
    }

    #[test]
    fn an_all_zero_signature_does_not_panic_and_does_not_verify() {
        let (_, vk) = generate_keypair();
        let pk = ectoledger::signing::public_key_hex(&vk);
        let hash = "ab".repeat(32);
        let zero_sig = "00".repeat(64);
        assert!(verify_signature(&pk, &hash, &zero_sig).is_err());
        assert!(!verify_content_hash(&vk, &hash, &zero_sig));
    }

    #[test]
    fn a_public_key_one_byte_too_long_is_invalid_key() {
        let hash = "ab".repeat(32);
        let sig = "11".repeat(64);
        let too_long_pk = "00".repeat(33);
        assert!(matches!(
            verify_signature(&too_long_pk, &hash, &sig),
            Err(SigningError::InvalidKey)
        ));
    }

    #[test]
    fn a_signature_one_byte_too_long_is_invalid_signature() {
        let (key, vk) = generate_keypair();
        let pk = ectoledger::signing::public_key_hex(&vk);
        let hash = "ab".repeat(32);
        let sig = ectoledger::signing::sign_content_hash(&key, &hash);
        let too_long_sig = format!("{sig}00");
        assert!(matches!(
            verify_signature(&pk, &hash, &too_long_sig),
            Err(SigningError::InvalidSignature)
        ));
    }

    #[test]
    fn odd_length_hex_is_invalid_hex_not_a_panic() {
        let hash = "ab".repeat(32);
        assert!(matches!(
            verify_signature("abc", &hash, &"11".repeat(64)),
            Err(SigningError::InvalidHex)
        ));
    }
}

mod decrypt_tampering {
    use super::*;

    fn saved_key() -> (tempfile::TempDir, Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = generate_keypair();
        let sid = Uuid::new_v4();
        save_session_key(dir.path(), sid, &key, PASSWORD_A).unwrap();
        (dir, sid)
    }

    #[test]
    fn a_truncated_ciphertext_fails_closed() {
        let (dir, sid) = saved_key();
        let mut enc = read_enc(dir.path(), sid);
        let ct = hex::decode(&enc.ciphertext_hex).unwrap();
        enc.ciphertext_hex = hex::encode(&ct[..ct.len() / 2]);
        assert!(matches!(
            decrypt_signing_key(&enc, sid, PASSWORD_A),
            Err(SigningError::Decrypt)
        ));
    }

    #[test]
    fn an_empty_ciphertext_fails_closed() {
        let (dir, sid) = saved_key();
        let mut enc = read_enc(dir.path(), sid);
        enc.ciphertext_hex.clear();
        assert!(matches!(
            decrypt_signing_key(&enc, sid, PASSWORD_A),
            Err(SigningError::Decrypt)
        ));
    }

    #[test]
    fn non_hex_ciphertext_is_invalid_hex_not_a_panic() {
        let (dir, sid) = saved_key();
        let mut enc = read_enc(dir.path(), sid);
        enc.ciphertext_hex = "not hex at all!!".to_string();
        assert!(matches!(
            decrypt_signing_key(&enc, sid, PASSWORD_A),
            Err(SigningError::InvalidHex)
        ));
    }

    #[test]
    fn a_tampered_nonce_fails_closed() {
        let (dir, sid) = saved_key();
        let mut enc = read_enc(dir.path(), sid);
        let mut nonce = hex::decode(&enc.nonce_hex).unwrap();
        nonce[0] ^= 0xff;
        enc.nonce_hex = hex::encode(nonce);
        assert!(matches!(
            decrypt_signing_key(&enc, sid, PASSWORD_A),
            Err(SigningError::Decrypt)
        ));
    }
}

mod read_key_file_edge_cases {
    use super::*;

    #[test]
    fn a_missing_key_file_is_ok_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_key_file(dir.path(), Uuid::new_v4()).unwrap().is_none());
    }

    #[test]
    fn non_utf8_content_is_an_io_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let sid = Uuid::new_v4();
        std::fs::write(key_file_path(dir.path(), sid), [0xff, 0xfe, 0x00, 0x01]).unwrap();
        assert!(matches!(
            read_key_file(dir.path(), sid),
            Err(SigningError::Io(_))
        ));
    }

    #[test]
    fn a_large_garbage_file_is_rejected_quickly_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let sid = Uuid::new_v4();
        let garbage = "x".repeat(5 * 1024 * 1024);
        std::fs::write(key_file_path(dir.path(), sid), garbage).unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(
            read_key_file(dir.path(), sid),
            Err(SigningError::Io(_))
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn an_empty_file_is_rejected_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let sid = Uuid::new_v4();
        std::fs::write(key_file_path(dir.path(), sid), b"").unwrap();
        assert!(matches!(
            read_key_file(dir.path(), sid),
            Err(SigningError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_real_key_file_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = generate_keypair();
        let real_sid = Uuid::new_v4();
        save_session_key(dir.path(), real_sid, &key, PASSWORD_A).unwrap();

        let linked_sid = Uuid::new_v4();
        std::os::unix::fs::symlink(
            key_file_path(dir.path(), real_sid),
            key_file_path(dir.path(), linked_sid),
        )
        .unwrap();

        let enc = read_key_file(dir.path(), linked_sid).unwrap().unwrap();
        assert_eq!(enc.session_id, real_sid.to_string());
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_is_treated_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let sid = Uuid::new_v4();
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            key_file_path(dir.path(), sid),
        )
        .unwrap();
        assert!(read_key_file(dir.path(), sid).unwrap().is_none());
    }
}

mod save_session_key_repeated_and_concurrent {
    use super::*;

    #[test]
    fn saving_twice_overwrites_and_only_the_latest_password_unlocks() {
        let dir = tempfile::tempdir().unwrap();
        let sid = Uuid::new_v4();
        let (key1, _) = generate_keypair();
        let (key2, _) = generate_keypair();
        save_session_key(dir.path(), sid, &key1, PASSWORD_A).unwrap();
        save_session_key(dir.path(), sid, &key2, PASSWORD_B).unwrap();

        let enc = read_enc(dir.path(), sid);
        assert!(decrypt_signing_key(&enc, sid, PASSWORD_A).is_err());
        let loaded = decrypt_signing_key(&enc, sid, PASSWORD_B).unwrap();
        assert_eq!(loaded.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn concurrent_saves_of_different_sessions_do_not_interfere() {
        let dir = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let mut sessions = Vec::new();
        let mut handles = Vec::new();
        for _ in 0..4 {
            let dir_path = dir.path().to_path_buf();
            let barrier = barrier.clone();
            let sid = Uuid::new_v4();
            let password = format!("password for {sid}!!");
            sessions.push((sid, password.clone()));
            handles.push(std::thread::spawn(move || {
                let (key, _) = generate_keypair();
                barrier.wait();
                save_session_key(&dir_path, sid, &key, &password).unwrap();
                key
            }));
        }
        let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        for ((sid, password), key) in sessions.iter().zip(keys.iter()) {
            let enc = read_enc(dir.path(), *sid);
            let loaded = decrypt_signing_key(&enc, *sid, password).unwrap();
            assert_eq!(loaded.to_bytes(), key.to_bytes());
        }
    }

    #[test]
    fn concurrent_saves_of_the_same_session_leave_exactly_one_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let sid = Uuid::new_v4();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let dir_a = dir.path().to_path_buf();
        let barrier_a = barrier.clone();
        let a = std::thread::spawn(move || {
            let (key, _) = generate_keypair();
            barrier_a.wait();
            save_session_key(&dir_a, sid, &key, PASSWORD_A).unwrap();
            key
        });
        let dir_b = dir.path().to_path_buf();
        let barrier_b = barrier.clone();
        let b = std::thread::spawn(move || {
            let (key, _) = generate_keypair();
            barrier_b.wait();
            save_session_key(&dir_b, sid, &key, PASSWORD_B).unwrap();
            key
        });
        let key_a = a.join().unwrap();
        let key_b = b.join().unwrap();

        let enc = read_enc(dir.path(), sid);
        let from_a = decrypt_signing_key(&enc, sid, PASSWORD_A);
        let from_b = decrypt_signing_key(&enc, sid, PASSWORD_B);
        assert_ne!(
            from_a.is_ok(),
            from_b.is_ok(),
            "exactly one writer's password must unlock the final file"
        );
        if let Ok(loaded) = from_a {
            assert_eq!(loaded.to_bytes(), key_a.to_bytes());
        }
        if let Ok(loaded) = from_b {
            assert_eq!(loaded.to_bytes(), key_b.to_bytes());
        }
    }

    #[test]
    fn a_save_leaves_only_the_key_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let sid = Uuid::new_v4();
        let (key, _) = generate_keypair();
        save_session_key(dir.path(), sid, &key, PASSWORD_A).unwrap();
        save_session_key(dir.path(), sid, &key, PASSWORD_B).unwrap();
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![format!("session-{sid}.key")]);
    }
}

mod password_fd {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn key_password_fd_is_unsupported_on_windows() {
        assert_eq!(read_password_from_fd(3), None);
        assert_eq!(read_password_from_fd(-1), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_password_longer_than_the_1kib_buffer_is_truncated_not_rejected() {
        use std::io::Write;
        use std::os::unix::io::IntoRawFd;
        let (mut tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let long = "x".repeat(2000);
        let writer = std::thread::spawn(move || {
            let _ = tx.write_all(long.as_bytes());
        });
        let got = read_password_from_fd(rx.into_raw_fd());
        writer.join().unwrap();
        let got = got.expect("content was available");
        assert!(got.len() <= 1024);
        assert!(got.chars().all(|c| c == 'x'));
    }
}
