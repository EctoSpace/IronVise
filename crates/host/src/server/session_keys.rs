//! Signing keys this process holds for sessions it opened without an audit
//! loop: Claude Code hook sessions and SDK recorder sessions.
//!
//! A certificate exported for such a session is signed with its key. The key
//! is never written down, so after a restart it is gone and a certificate
//! exported then is unsigned and says so.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use ed25519_dalek::SigningKey;
use tokio::sync::Mutex;
use uuid::Uuid;

static KEYS: OnceLock<Mutex<HashMap<Uuid, Arc<SigningKey>>>> = OnceLock::new();

fn keys() -> &'static Mutex<HashMap<Uuid, Arc<SigningKey>>> {
    KEYS.get_or_init(Default::default)
}

pub(crate) async fn remember(session_id: Uuid, key: Arc<SigningKey>) {
    keys().lock().await.insert(session_id, key);
}

pub(crate) async fn signing_key_for(session_id: Uuid) -> Option<Arc<SigningKey>> {
    keys().lock().await.get(&session_id).cloned()
}
