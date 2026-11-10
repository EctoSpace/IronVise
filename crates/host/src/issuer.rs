//! The installation's issuer key: one long-lived Ed25519 key that countersigns
//! every certificate this installation exports.
//!
//! A session key lives only as long as the process that opened the session,
//! so an export made after a restart could not be signed at all. The issuer
//! key can sign it, and a relying party pins one key per installation instead
//! of one per session (`verify-cert --issuer`).
//!
//! The key is a hex file, `issuer.key` in the data directory, readable by its
//! owner only: the server signs unattended, so it cannot be behind a password.
//! Without the file, certificates carry no issuer, as before.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;

pub fn key_path() -> PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    PathBuf::from(base).join("issuer.key")
}

/// The issuer key, or `None` when this installation has none.
pub fn load() -> Result<Option<SigningKey>, String> {
    let path = key_path();
    if !path.exists() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is readable by other users (mode {:o}); `chmod 600` it",
                path.display(),
                mode & 0o777
            ));
        }
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bytes: [u8; 32] = hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{} does not hold a 32-byte hex key", path.display()))?;
    Ok(Some(SigningKey::from_bytes(&bytes)))
}

/// Create the issuer key. Refuses to replace one unless `replace`: every
/// certificate it signed keeps verifying against its public key, but a relying
/// party that pinned it must be given the new one.
pub fn init(replace: bool) -> Result<SigningKey, String> {
    use std::io::Write;
    let path = key_path();
    if path.exists() && !replace {
        return Err(format!(
            "{} already exists; pass --replace to make a new one",
            path.display()
        ));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // `mode` applies only to a new file; a replaced one keeps its old mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    // Before the key is written, as for session key files.
    #[cfg(windows)]
    crate::signing::restrict_to_owner(&path)?;
    file.write_all(hex::encode(key.to_bytes()).as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(key)
}

pub fn public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}
