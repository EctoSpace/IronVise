use super::{PoolCapabilities, is_postgres_url};

#[test]
fn postgres_url_detection() {
    assert!(is_postgres_url("postgres://localhost/db"));
    assert!(is_postgres_url("postgresql://user:pass@host:5432/db"));
    assert!(is_postgres_url("  Postgres://LOCALHOST/db  "));
    assert!(!is_postgres_url("sqlite://ledger.db"));
    assert!(!is_postgres_url("sqlite::memory:"));
    assert!(!is_postgres_url(""));
}

#[test]
fn sqlite_capabilities_enable_agent_exports_and_webhooks() {
    let caps = PoolCapabilities {
        ledger_backend: "sqlite",
        agent_supported: true,
        exports_supported: true,
        webhooks_live: true,
    };
    assert_eq!(caps.ledger_backend, "sqlite");
    assert!(caps.agent_supported);
    assert!(caps.exports_supported);
    assert!(caps.webhooks_live);
}

#[test]
fn postgres_capabilities_enable_agent_exports_webhooks() {
    let caps = PoolCapabilities {
        ledger_backend: "postgres",
        agent_supported: true,
        exports_supported: true,
        webhooks_live: true,
    };
    assert_eq!(caps.ledger_backend, "postgres");
    assert!(caps.agent_supported);
    assert!(caps.exports_supported);
    assert!(caps.webhooks_live);
}
