use super::validate_model_name;

#[test]
fn accepts_ollama_model_names() {
    for name in [
        "llama3",
        "llama3.2:3b",
        "qwen2.5:0.5b",
        "llama3.3:70b-instruct-q4_K_M",
        "mistral:latest",
        "library/llama3",
        "someone/my_model.v2:Q4_K_M",
        "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M",
        "Llama3",
    ] {
        assert!(
            validate_model_name(name).is_ok(),
            "{name} should be accepted"
        );
    }
}

#[test]
fn rejects_option_injection() {
    for name in ["-h", "--help", "-", "--insecure", "-x:latest"] {
        assert!(
            validate_model_name(name).is_err(),
            "{name} should be rejected"
        );
    }
}

#[test]
fn rejects_whitespace_and_shell_metacharacters() {
    for name in [
        "llama3 --insecure",
        "llama3\tx",
        "llama3\n",
        "llama3;id",
        "llama3&&id",
        "llama3|id",
        "$(id)",
        "`id`",
        "llama3>out",
        "llama3'x",
        "llama3\"x",
        "llama3\\x",
        "llama3*",
        "llama3\0",
    ] {
        assert!(
            validate_model_name(name).is_err(),
            "{name:?} should be rejected"
        );
    }
}

#[test]
fn rejects_malformed_structure() {
    for name in [
        "",
        ":",
        ":tag",
        "llama3:",
        "llama3:a:b",
        "/llama3",
        "ns/",
        "a/b/c/d",
        "hf.co//model",
        "llama3:tag/x",
        "llama3:t ag",
        "llama3:t;g",
        "модель",
    ] {
        assert!(
            validate_model_name(name).is_err(),
            "{name:?} should be rejected"
        );
    }
}

#[test]
fn enforces_the_length_limit() {
    assert!(validate_model_name(&"a".repeat(128)).is_ok());
    assert!(validate_model_name(&"a".repeat(129)).is_err());
}

#[cfg(not(target_os = "windows"))]
mod private_dir {
    use super::super::PrivateDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn is_owner_only_unique_and_removed_on_drop() {
        let base = std::env::temp_dir();
        let a = PrivateDir::create_in(&base).unwrap();
        let b = PrivateDir::create_in(&base).unwrap();
        assert_ne!(a.0, b.0);
        let mode = std::fs::metadata(&a.0).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let path = a.0.clone();
        drop(a);
        assert!(!path.exists());
    }

    #[test]
    fn script_is_owner_only_and_never_overwritten() {
        let dir = PrivateDir::create_in(&std::env::temp_dir()).unwrap();
        let script = dir.write_script("#!/bin/sh\nexit 0\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&script).unwrap(),
            "#!/bin/sh\nexit 0\n"
        );
        let mode = std::fs::metadata(&script).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(dir.write_script("other").is_err());
        assert_eq!(
            std::fs::read_to_string(&script).unwrap(),
            "#!/bin/sh\nexit 0\n"
        );
    }
}
