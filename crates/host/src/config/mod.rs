//! Configuration from the environment, `.env` and the settings files, one
//! module per concern. Every setting is reached as `config::<name>`.

mod agent;
mod database;
mod files;
mod guard;
mod llm;
mod server;
#[cfg(test)]
mod tests;
mod webhooks;

pub use agent::*;
pub use database::*;
pub use files::*;
pub use guard::*;
pub use llm::*;
pub use server::*;
pub use webhooks::*;

/// Serializes tests that mutate process-global environment variables.
/// Shared with `llm` factory tests so they cannot race this module.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
