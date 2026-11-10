use super::*;
use std::path::PathBuf;

/// The core TOCTOU case: validation passes on a genuine regular file, then
/// the leaf is swapped for a symlink pointing at a secret outside the
/// allowed root *before* the open. This reproduces the exact check/use
/// window; without `O_NOFOLLOW` the read would follow the swapped link and
/// return the secret.
#[cfg(unix)]
#[test]
fn symlink_swapped_after_validation_is_rejected() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("tempdir");
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "TOP SECRET").expect("write secret");

    let target = root.path().join("innocent.txt");
    std::fs::write(&target, "benign contents").expect("write target");

    let allowed = vec![root.path().canonicalize().expect("canonicalize root")];

    // Step 1 - validation succeeds while the path is a real regular file.
    let canonical =
        crate::tripwire::validate_path_strict(target.to_str().expect("utf8 path"), &allowed)
            .expect("validation should pass for a regular file inside the allowed root");

    // Step 2 - the attacker wins the race: replace the validated leaf with
    // a symlink to the secret outside the allowed root.
    std::fs::remove_file(&canonical).expect("remove target");
    std::os::unix::fs::symlink(&secret, &canonical).expect("plant symlink");

    // Step 3 - the open must refuse to follow it.
    let result = open_and_read_verified(&canonical);
    assert!(
        result.is_err(),
        "symlink planted after validation must be rejected, got: {result:?}"
    );
    if let Ok(contents) = result {
        assert!(
            !contents.contains("TOP SECRET"),
            "read followed the swapped symlink and leaked the secret"
        );
    }
}

/// A symlink that already exists at request time and points outside the
/// allowed roots is rejected by path validation (it canonicalizes to an
/// out-of-root target), before any open happens.
#[cfg(unix)]
#[test]
fn preexisting_symlink_out_of_root_is_rejected() {
    let root = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("tempdir");
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "TOP SECRET").expect("write secret");

    let link = root.path().join("link-to-secret");
    std::os::unix::fs::symlink(&secret, &link).expect("create symlink");

    let allowed = vec![root.path().canonicalize().expect("canonicalize root")];
    let result = read_file_locked_down(link.to_str().expect("utf8 path"), &allowed);

    assert!(
        result.is_err(),
        "symlink escaping the allowed root must be rejected, got: {result:?}"
    );
    if let Ok(contents) = result {
        assert!(
            !contents.contains("TOP SECRET"),
            "symlink escape leaked the secret"
        );
    }
}

/// False-positive guard: an ordinary regular file inside the allowed root
/// still reads normally. Without this, the tests above could pass simply
/// because reading is broken.
#[test]
fn regular_file_inside_root_still_reads() {
    let root = tempfile::tempdir().expect("tempdir");
    let file = root.path().join("notes.txt");
    std::fs::write(&file, "hello from inside the workspace").expect("write file");

    let allowed = vec![root.path().canonicalize().expect("canonicalize root")];
    let contents = read_file_locked_down(file.to_str().expect("utf8 path"), &allowed)
        .expect("a regular file inside the allowed root must read successfully");

    assert_eq!(contents, "hello from inside the workspace");
}

/// A FIFO is not a regular file: opening it could block indefinitely, and
/// its contents are attacker-controlled. It must be refused.
#[cfg(unix)]
#[test]
fn fifo_is_rejected() {
    let root = tempfile::tempdir().expect("tempdir");
    let fifo = root.path().join("pipe");
    let c_path =
        std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("path to CString");
    // SAFETY: c_path is a valid NUL-terminated path inside a temp dir.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
    assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

    let allowed = vec![root.path().canonicalize().expect("canonicalize root")];
    let result = read_file_locked_down(fifo.to_str().expect("utf8 path"), &allowed);
    assert!(
        result.is_err(),
        "a FIFO must be rejected as a non-regular file, got: {result:?}"
    );
}

/// A directory is likewise not a regular file.
#[test]
fn directory_is_rejected() {
    let root = tempfile::tempdir().expect("tempdir");
    let subdir = root.path().join("subdir");
    std::fs::create_dir(&subdir).expect("create subdir");

    let allowed: Vec<PathBuf> = vec![root.path().canonicalize().expect("canonicalize root")];
    let result = read_file_locked_down(subdir.to_str().expect("utf8 path"), &allowed);
    assert!(
        result.is_err(),
        "a directory must be rejected as a non-regular file, got: {result:?}"
    );
}
