//! API keys entered in Settings, kept in the OS credential store: the macOS
//! Keychain, the Windows Credential Manager, or the Secret Service on Linux.
//!
//! The key never goes into `settings.json`, the config API or the webview:
//! Settings sends it here once, and afterwards only learns whether a key is
//! stored. The model backends get it through `ectoledger::llm::api_key`
//! (registered by [`register`] at startup), the guard worker through its
//! environment when it is spawned. A key in the store wins over the
//! environment variable of the same name.
//!
//! Without a usable store (a Linux session with no Secret Service, say) saving
//! fails with a message and the environment keeps working.

#[allow(unused_imports)]
use super::*;

use std::collections::HashMap;
use std::sync::Mutex;

/// The app's bundle identifier, so the entries are recognisably the app's.
#[cfg(not(test))]
const SERVICE: &str = "io.ectoledger.agent-ledger";
/// Tests use their own service, so they can never read, overwrite or delete
/// a key the user saved in the app.
#[cfg(test)]
const SERVICE: &str = "io.ectoledger.agent-ledger.test";

/// Keys read once per run: a store lookup can be slow, and on macOS each
/// read by a newly signed build may ask the user for permission.
static CACHE: Mutex<Option<HashMap<String, Option<String>>>> = Mutex::new(None);

fn store_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "the macOS Keychain"
    } else if cfg!(windows) {
        "Windows Credential Manager"
    } else {
        "the system keyring"
    }
}

/// Only the variable names a preset reads; anything else is refused.
fn check_name(name: &str) -> Result<(), String> {
    if ectoledger::llm::api_key::known_names().contains(&name) {
        Ok(())
    } else {
        Err(format!("'{name}' is not an API key this app uses"))
    }
}

fn entry(name: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, name).map_err(|e| format!("Credential store unavailable: {e}"))
}

/// Run a credential-store call on a thread of its own. On Linux the keyring
/// reaches the Secret Service through zbus, whose blocking API starts its own
/// runtime and panics on a thread that is driving async tasks. [`read`] is
/// called from such threads (the model backends, the guard spawn, the
/// first-run setup check); a plain thread has no runtime. The commands below
/// already run on the `spawn_blocking` pool, where the call is allowed. Each
/// key is read from the store once per run, so the thread is cheap.
fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> Result<T, String> {
    std::thread::scope(|s| s.spawn(f).join())
        .map_err(|_| format!("{} failed unexpectedly", store_name()))
}

/// The stored key for `name`, if any. Errors count as "no key" (logged
/// without the key), so a missing store never breaks a run that has the
/// environment variable.
pub fn read(name: &str) -> Option<String> {
    let mut cache = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    let cache = cache.get_or_insert_with(HashMap::new);
    if let Some(hit) = cache.get(name) {
        return hit.clone();
    }
    let value = match off_runtime(|| entry(name).map(|e| e.get_password())) {
        Ok(Ok(Ok(key))) => Some(key),
        Ok(Ok(Err(keyring::Error::NoEntry))) => None,
        Ok(Ok(Err(e))) => {
            tracing::warn!("reading {name} from {}: {e}", store_name());
            None
        }
        Ok(Err(e)) | Err(e) => {
            tracing::warn!("reading {name}: {e}");
            None
        }
    };
    cache.insert(name.to_string(), value.clone());
    value
}

fn remember(name: &str, value: Option<String>) {
    let mut cache = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    cache
        .get_or_insert_with(HashMap::new)
        .insert(name.to_string(), value);
}

/// Make stored keys visible to the model backends. Call once, at startup.
pub fn register() {
    ectoledger::llm::api_key::set_store(read);
}

#[derive(serde::Serialize)]
pub struct ApiKeyStatus {
    /// A key for this variable is in the credential store.
    pub stored: bool,
    /// The variable is set in the app's environment (used when none is stored).
    pub environment: bool,
    /// Where stored keys live on this OS, for the Settings text.
    pub store: &'static str,
}

fn status(name: &str) -> ApiKeyStatus {
    ApiKeyStatus {
        stored: read(name).is_some(),
        environment: std::env::var(name).is_ok_and(|v| !v.trim().is_empty()),
        store: store_name(),
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn api_key_status(name: String) -> Result<ApiKeyStatus, String> {
    check_name(&name)?;
    blocking(move || Ok(status(&name))).await
}

#[tauri::command]
pub async fn set_api_key(name: String, key: String) -> Result<ApiKeyStatus, String> {
    check_name(&name)?;
    let key = key.trim().to_string();
    if key.is_empty() || key.len() > 1024 || key.chars().any(char::is_whitespace) {
        return Err(
            "That does not look like an API key (empty, too long, or contains spaces).".into(),
        );
    }
    blocking(move || {
        entry(&name)?
            .set_password(&key)
            .map_err(|e| format!("Could not save the key in {}: {e}", store_name()))?;
        remember(&name, Some(key));
        Ok(status(&name))
    })
    .await
}

#[tauri::command]
pub async fn delete_api_key(name: String) -> Result<ApiKeyStatus, String> {
    check_name(&name)?;
    blocking(move || {
        match entry(&name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => {
                return Err(format!(
                    "Could not remove the key from {}: {e}",
                    store_name()
                ));
            }
        }
        remember(&name, None);
        Ok(status(&name))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::check_name;

    #[test]
    fn only_the_presets_key_names_are_accepted() {
        assert!(check_name("ANTHROPIC_API_KEY").is_ok());
        assert!(check_name("OPENAI_API_KEY").is_ok());
        assert!(check_name("UNLISTED_PRIVATE_KEY").is_err());
        assert!(check_name("").is_err());
    }

    /// The model backends, the guard spawn and the setup check read keys from
    /// async code on a tokio worker. On Linux the keyring talks to the Secret
    /// Service through zbus, whose blocking API starts its own runtime and
    /// panicked there ("Cannot start a runtime from within a runtime"), killing
    /// the caller: seen at the first launch of the Linux .deb, from the setup
    /// check. Only reads, under the test service.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_read_from_async_code_does_not_panic() {
        *super::CACHE.lock().unwrap_or_else(|p| p.into_inner()) = None;
        let _ = super::read("OPENAI_API_KEY");
    }

    #[tokio::test]
    async fn a_read_from_a_current_thread_runtime_does_not_panic() {
        *super::CACHE.lock().unwrap_or_else(|p| p.into_inner()) = None;
        let _ = super::read("ANTHROPIC_API_KEY");
    }

    /// A saved key survives a restart and wins over the environment; Remove
    /// deletes it. Writes to the real OS credential store (under the test
    /// service only), so it is ignored by default and run by
    /// `make test-mac` (scripts/mac/run-scenarios.sh).
    #[tokio::test]
    #[ignore = "writes to the OS credential store; run by make test-mac"]
    async fn a_saved_key_survives_a_restart_and_remove_deletes_it() {
        use super::{CACHE, api_key_status, delete_api_key, read, set_api_key};
        let name = "ANTHROPIC_API_KEY".to_string();
        let _ = delete_api_key(name.clone()).await;

        let status = set_api_key(name.clone(), " sk-test-0123456789 ".into())
            .await
            .expect("save");
        assert!(status.stored);

        // A restart: nothing cached, the store is read again.
        *CACHE.lock().unwrap() = None;
        assert_eq!(read(&name).as_deref(), Some("sk-test-0123456789"));
        assert!(api_key_status(name.clone()).await.unwrap().stored);

        // The stored key wins over the environment.
        super::register();
        // SAFETY: test-only variable; this test runs alone (ignored by default).
        unsafe { std::env::set_var("ANTHROPIC_API_KEY", "from-environment") };
        assert_eq!(
            ectoledger::llm::api_key::resolve("ANTHROPIC_API_KEY").as_deref(),
            Some("sk-test-0123456789")
        );

        let status = delete_api_key(name.clone()).await.expect("remove");
        assert!(!status.stored);
        *CACHE.lock().unwrap() = None;
        assert_eq!(read(&name), None);
        assert_eq!(
            ectoledger::llm::api_key::resolve("ANTHROPIC_API_KEY").as_deref(),
            Some("from-environment")
        );
        unsafe { std::env::remove_var("ANTHROPIC_API_KEY") };
    }
}
