//! Where an API key comes from.
//!
//! The CLI, the server and the container read keys from the environment
//! (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`). The desktop app also lets the user
//! enter a key in Settings and keeps it in the OS credential store; it
//! registers that store here once at startup with [`set_store`]. A key in the
//! store wins over the environment, as `settings.json` does for the other
//! settings.
//!
//! This crate never touches the credential store itself, so nothing outside
//! the desktop app gains a dependency on one (the container has no keyring).

use std::sync::OnceLock;

type Store = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

static STORE: OnceLock<Store> = OnceLock::new();

/// Register the credential store lookup, keyed by the variable name the key
/// would have in the environment. Only the first call takes effect.
pub fn set_store(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static) {
    let _ = STORE.set(Box::new(lookup));
}

/// The key from the registered store only (not the environment).
pub fn from_store(env_name: &str) -> Option<String> {
    STORE
        .get()
        .and_then(|lookup| lookup(env_name))
        .filter(|k| !k.trim().is_empty())
}

/// The key for `env_name`: the store first, then the environment.
pub fn resolve(env_name: &str) -> Option<String> {
    from_store(env_name).or_else(|| {
        std::env::var(env_name)
            .ok()
            .filter(|k| !k.trim().is_empty())
    })
}

/// Every environment name a preset reads its key from.
pub fn known_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = crate::provider::PRESETS
        .iter()
        .filter_map(|p| p.api_key_env)
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_store_wins_over_the_environment_and_blank_counts_as_absent() {
        set_store(|name| match name {
            "ECTO_TEST_STORED_KEY" => Some("from-store".into()),
            "ECTO_TEST_BLANK_KEY" => Some("  ".into()),
            _ => None,
        });
        // SAFETY: test-only variables no other test reads.
        unsafe {
            std::env::set_var("ECTO_TEST_STORED_KEY", "from-env");
            std::env::set_var("ECTO_TEST_BLANK_KEY", "from-env");
            std::env::set_var("ECTO_TEST_ENV_KEY", "from-env");
        }
        assert_eq!(
            resolve("ECTO_TEST_STORED_KEY").as_deref(),
            Some("from-store")
        );
        assert_eq!(resolve("ECTO_TEST_BLANK_KEY").as_deref(), Some("from-env"));
        assert_eq!(resolve("ECTO_TEST_ENV_KEY").as_deref(), Some("from-env"));
        assert_eq!(from_store("ECTO_TEST_ENV_KEY"), None);
        assert_eq!(resolve("ECTO_TEST_NOWHERE_KEY"), None);
    }

    #[test]
    fn the_known_names_are_the_presets_variables() {
        assert_eq!(
            known_names(),
            vec![
                "ANTHROPIC_API_KEY",
                "AZURE_OPENAI_API_KEY",
                "DEEPSEEK_API_KEY",
                "GEMINI_API_KEY",
                "GROQ_API_KEY",
                "MISTRAL_API_KEY",
                "OPENAI_API_KEY",
                "OPENROUTER_API_KEY",
                "XAI_API_KEY"
            ]
        );
    }
}
