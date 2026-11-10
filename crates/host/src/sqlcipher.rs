//! SQLCipher at-rest encryption for the SQLite ledger.
//!
//! `--features sqlcipher` builds SQLCipher in place of SQLite
//! (`libsqlite3-sys/bundled-sqlcipher`, which links the system libcrypto) and
//! requires `ECTOLEDGER_SQLCIPHER_KEY` (at least 16 characters).
//!
//! The key is read once, moved into zeroize-on-drop memory and removed from
//! the environment, so child processes (guard worker, audited commands) never
//! inherit it. It is set as the first pragma of every connection a pool opens,
//! read-only pools included: a pool opens connections lazily, and one keyed
//! connection says nothing about the next.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::sync::OnceLock;

use crate::secrets::{SecretString, load_env_secret};

/// Minimum passphrase length for SQLCipher encryption.
pub const MIN_SQLCIPHER_KEY_LEN: usize = 16;

const KEY_ENV: &str = "ECTOLEDGER_SQLCIPHER_KEY";

/// Error type for SQLCipher operations.
#[derive(Debug, thiserror::Error)]
pub enum SqlCipherError {
    #[error("ECTOLEDGER_SQLCIPHER_KEY not set or empty")]
    KeyNotSet,
    #[error("ECTOLEDGER_SQLCIPHER_KEY too short (minimum {MIN_SQLCIPHER_KEY_LEN} characters)")]
    KeyTooShort,
    #[error("SQLCipher PRAGMA failed: {0}")]
    Pragma(String),
    #[error(
        "the `sqlcipher` feature is built in, but this SQLite library is not \
         SQLCipher-enabled (`PRAGMA cipher_version` returned nothing). The \
         ledger would be written in plaintext."
    )]
    NotSqlCipher,
}

fn check_key(key: &str) -> Result<(), SqlCipherError> {
    if key.is_empty() {
        return Err(SqlCipherError::KeyNotSet);
    }
    if key.len() < MIN_SQLCIPHER_KEY_LEN {
        return Err(SqlCipherError::KeyTooShort);
    }
    Ok(())
}

static KEY: OnceLock<Option<SecretString>> = OnceLock::new();

/// The key from `ECTOLEDGER_SQLCIPHER_KEY`. The first call moves it out of the
/// environment; later calls (a second pool, a read-only pool) get the same one.
pub fn read_sqlcipher_key() -> Result<&'static SecretString, SqlCipherError> {
    let key = KEY
        .get_or_init(|| load_env_secret(KEY_ENV))
        .as_ref()
        .ok_or(SqlCipherError::KeyNotSet)?;
    check_key(key.expose_secret())?;
    Ok(key)
}

/// `opts` with the key as the first pragma of every connection. The `x'…'`
/// hex form keeps the passphrase out of SQL quoting.
pub fn keyed(opts: SqliteConnectOptions, key: &SecretString) -> SqliteConnectOptions {
    opts.pragma(
        "key",
        format!("\"x'{}'\"", hex::encode(key.expose_secret().as_bytes())),
    )
}

/// Refuse to continue unless the pool really is SQLCipher and the key opens
/// the file. Stock SQLite ignores an unknown `PRAGMA key`, so without this the
/// sequence "ask for encryption, be silently refused, write a plaintext
/// ledger" would look like success.
pub async fn check_pool(pool: &SqlitePool) -> Result<(), SqlCipherError> {
    let version: Option<String> = sqlx::query_scalar("PRAGMA cipher_version;")
        .fetch_optional(pool)
        .await
        .map_err(|e| SqlCipherError::Pragma(e.to_string()))?
        .flatten();
    let Some(version) = version.filter(|v| !v.trim().is_empty()) else {
        return Err(SqlCipherError::NotSqlCipher);
    };
    sqlx::query("SELECT count(*) FROM sqlite_master;")
        .execute(pool)
        .await
        .map_err(|e| SqlCipherError::Pragma(format!("Key verification failed: {e}")))?;
    tracing::info!("SQLCipher {version} encryption enabled for the SQLite ledger.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_empty_keys_are_refused() {
        assert!(matches!(check_key(""), Err(SqlCipherError::KeyNotSet)));
        assert!(matches!(
            check_key("short"),
            Err(SqlCipherError::KeyTooShort)
        ));
        assert!(check_key("this-is-a-reasonably-long-key!!").is_ok());
    }
}
