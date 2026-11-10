//! CLI command handlers.
//!
//! Each submodule corresponds to one (or a small group of related) CLI subcommands.
//! The `main()` function dispatches to these handlers after performing shared
//! setup (database, migrations, chain verification, platform sandbox).

pub mod anchor;
pub mod audit;
pub mod health;
pub mod hook;
pub mod hook_install;
pub mod mcp_proxy;
pub mod openshell;
pub mod orchestrate;
pub mod prove;
pub mod proxy;
pub mod receipts;
pub mod report;
pub mod serve;
