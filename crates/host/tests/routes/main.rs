//! Route tests against the full Observer on an in-memory SQLite ledger,
//! one module per area. Each test starts its own server on a random port; no
//! external services are needed.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;

mod access;
mod append_provenance;
mod common;
mod contracts;
mod hook;
#[cfg(target_os = "linux")]
mod linux_guards;
#[cfg(target_os = "macos")]
mod macos_guards;
mod metrics;
mod sessions;
mod tripwire;
mod verify_intent;
#[cfg(target_os = "windows")]
mod windows_guards;

use common::*;
