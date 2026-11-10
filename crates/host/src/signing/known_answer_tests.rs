//! Known answers for signing and the key store, independent of the crate
//! versions behind them. A dependency update that changes a signature, or
//! stops a key file written today from opening, fails here first.

use super::*;

/// RFC 8032 §7.1, test 1: the secret key, its public key, and the signature
/// of the empty message.
#[test]
fn ed25519_signs_the_rfc_8032_vector_byte_for_byte() {
    let secret: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let key = SigningKey::from_bytes(&secret);
    assert_eq!(
        public_key_hex(&key.verifying_key()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let signature = sign_content_hash(&key, "");
    assert_eq!(
        signature,
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    verify_signature(&public_key_hex(&key.verifying_key()), "", &signature).unwrap();
}

/// A key file written by this release, committed: it must keep opening with
/// its password and yield the same key, whatever Argon2, AES-GCM or HMAC
/// version reads it.
#[test]
fn a_key_file_written_by_0_8_still_opens() {
    let enc: EncryptedKeyFile = serde_json::from_str(KEY_FILE_0_8).unwrap();
    let session = Uuid::parse_str("4d2f8a10-6c1e-4b7a-9f3d-2a5b8c7e1f00").unwrap();
    let key = decrypt_signing_key(&enc, session, KEY_FILE_PASSWORD).unwrap();
    assert_eq!(hex::encode(key.to_bytes()), KEY_FILE_SECRET);
    assert!(decrypt_signing_key(&enc, session, "a different password").is_err());
}

const KEY_FILE_PASSWORD: &str = "correct horse battery staple";
const KEY_FILE_SECRET: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0";
const KEY_FILE_0_8: &str = include_str!("known_answer_key_file.json");

/// A key file written by the official v0.6.3 algorithm (public tag cf7d29d):
/// no commitment, and the session id authenticated by AES-GCM. The password
/// is the one the 0.6.3 upgrade check recorded with.
#[test]
fn a_key_file_written_by_0_6_3_still_opens() {
    let enc: EncryptedKeyFile = serde_json::from_str(V063_KEY_FILE).unwrap();
    assert!(
        enc.commitment_hex.is_empty(),
        "a v0.6.3 file has no commitment field"
    );
    let session = Uuid::parse_str(V063_SESSION).unwrap();
    let key = decrypt_legacy_signing_key(&enc, session, V063_PASSWORD).unwrap();
    assert_eq!(hex::encode(key.to_bytes()), V063_SECRET);
    assert!(matches!(
        decrypt_legacy_signing_key(&enc, session, "wrong password!"),
        Err(SigningError::Decrypt)
    ));
    // The bug: authenticating an empty string, which 0.8 did, rejects the file.
    let aes = derive_key(V063_PASSWORD, &enc.salt).unwrap();
    assert!(matches!(
        open_key(&aes, &enc, b""),
        Err(SigningError::Decrypt)
    ));
    assert!(matches!(
        decrypt_signing_key(&enc, session, V063_PASSWORD),
        Err(SigningError::UncommittedKeyFile)
    ));
}

/// Writes the v0.6.3 fixture. Run once with `ECTO_WRITE_V063_KEY_FIXTURE=1`.
/// Salt and nonce are fixed, so a second run writes the same bytes.
#[test]
#[ignore = "writes the v0.6.3 fixture; run only to create it"]
fn write_the_v063_key_file_fixture() {
    if std::env::var("ECTO_WRITE_V063_KEY_FIXTURE").as_deref() != Ok("1") {
        return;
    }
    let secret: [u8; 32] = hex::decode(V063_SECRET).unwrap().try_into().unwrap();
    let session = Uuid::parse_str(V063_SESSION).unwrap();
    let enc = encrypt_v063_key(
        session,
        &SigningKey::from_bytes(&secret),
        V063_PASSWORD,
        "AAAAAAAAAAAAAAAAAAAAAA",
        &[0u8; 12],
    );
    // Field order matches `serde_json::to_string_pretty` of the v0.6.3 struct,
    // which had no commitment field. serde_json's map would sort the keys.
    let json = format!(
        "{{\n  \"salt\": \"{}\",\n  \"nonce_hex\": \"{}\",\n  \"ciphertext_hex\": \"{}\",\n  \"session_id\": \"{}\"\n}}\n",
        enc.salt, enc.nonce_hex, enc.ciphertext_hex, enc.session_id
    );
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/signing/known_answer_key_file_v063.json"
    );
    std::fs::write(path, json).unwrap();
}

/// Writes the committed key file. Run once with `ECTO_WRITE_KEY_FIXTURE=1`;
/// the file must then never change.
#[test]
#[ignore = "writes the fixture; run only to create it"]
fn write_the_key_file_fixture() {
    if std::env::var("ECTO_WRITE_KEY_FIXTURE").as_deref() != Ok("1") {
        return;
    }
    let secret: [u8; 32] = hex::decode(KEY_FILE_SECRET).unwrap().try_into().unwrap();
    let session = Uuid::parse_str("4d2f8a10-6c1e-4b7a-9f3d-2a5b8c7e1f00").unwrap();
    let enc =
        encrypt_signing_key(session, &SigningKey::from_bytes(&secret), KEY_FILE_PASSWORD).unwrap();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/signing/known_answer_key_file.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&enc).unwrap() + "\n").unwrap();
}
