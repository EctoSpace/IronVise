use ectoledger::issuer;
use std::sync::Mutex;

static ECTO_DATA_DIR_LOCK: Mutex<()> = Mutex::new(());

struct DataDirGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
    _dir: tempfile::TempDir,
}

fn with_fresh_data_dir() -> DataDirGuard<'static> {
    let lock = ECTO_DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("ECTO_DATA_DIR", dir.path());
    }
    DataDirGuard {
        _lock: lock,
        _dir: dir,
    }
}

#[test]
fn load_on_a_fresh_install_is_ok_none() {
    let _guard = with_fresh_data_dir();
    assert!(issuer::load().unwrap().is_none());
}

#[test]
fn init_then_load_round_trips_the_same_key() {
    let _guard = with_fresh_data_dir();
    let created = issuer::init(false).unwrap();
    let loaded = issuer::load().unwrap().unwrap();
    assert_eq!(created.to_bytes(), loaded.to_bytes());
    assert_eq!(
        issuer::public_key_hex(&created),
        issuer::public_key_hex(&loaded)
    );
}

#[test]
fn init_without_replace_refuses_to_clobber_an_existing_key() {
    let _guard = with_fresh_data_dir();
    let first = issuer::init(false).unwrap();
    let err = issuer::init(false).unwrap_err();
    assert!(err.contains("--replace"));
    let still_there = issuer::load().unwrap().unwrap();
    assert_eq!(first.to_bytes(), still_there.to_bytes());
}

#[test]
fn init_with_replace_overwrites_and_the_old_key_is_gone() {
    let _guard = with_fresh_data_dir();
    let first = issuer::init(false).unwrap();
    let second = issuer::init(true).unwrap();
    assert_ne!(first.to_bytes(), second.to_bytes());
    let loaded = issuer::load().unwrap().unwrap();
    assert_eq!(second.to_bytes(), loaded.to_bytes());
}

#[test]
fn a_corrupt_key_file_is_an_error_not_a_panic() {
    let _guard = with_fresh_data_dir();
    issuer::init(false).unwrap();
    std::fs::write(issuer::key_path(), "not hex\n").unwrap();
    let err = issuer::load().unwrap_err();
    assert!(err.contains("32-byte hex key"));
}

#[test]
fn a_short_key_file_is_an_error_not_a_panic() {
    let _guard = with_fresh_data_dir();
    issuer::init(false).unwrap();
    std::fs::write(issuer::key_path(), "ab".repeat(16)).unwrap();
    let err = issuer::load().unwrap_err();
    assert!(err.contains("32-byte hex key"));
}

#[test]
fn an_empty_key_file_is_an_error_not_a_panic() {
    let _guard = with_fresh_data_dir();
    issuer::init(false).unwrap();
    std::fs::write(issuer::key_path(), "").unwrap();
    let err = issuer::load().unwrap_err();
    assert!(err.contains("32-byte hex key"));
}

#[test]
fn key_path_defaults_under_dot_ectoledger_without_the_env_var() {
    let _guard = ECTO_DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        std::env::remove_var("ECTO_DATA_DIR");
    }
    assert_eq!(
        issuer::key_path(),
        std::path::PathBuf::from(".ectoledger").join("issuer.key")
    );
}

#[cfg(windows)]
#[test]
fn init_restricts_the_key_file_acl_to_the_owner() {
    let _guard = with_fresh_data_dir();
    issuer::init(false).unwrap();
    let out = std::process::Command::new("icacls")
        .arg(issuer::key_path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_uppercase();
    let user = std::env::var("USERNAME").unwrap().to_uppercase();
    assert!(text.contains(&user), "{text}");
    for broad_group in ["EVERYONE", "BUILTIN\\USERS", "AUTHENTICATED USERS"] {
        assert!(!text.contains(broad_group), "{broad_group} in {text}");
    }
}

#[cfg(unix)]
#[test]
fn a_key_file_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = with_fresh_data_dir();
    issuer::init(false).unwrap();
    let path = issuer::key_path();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = issuer::load().unwrap_err();
    assert!(err.contains("readable by other users"));
}
