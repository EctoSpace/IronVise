//! The `ectoledger` binary's own modules: start-up, the commands that need no
//! ledger, opening the ledger, and dispatching the rest. They are not part of
//! the library; the argument definitions are in `main.rs`.

pub mod database;
pub mod dispatch;
pub mod exit;
pub mod offline;
pub mod startup;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
