-- Align agent_snapshots with the Postgres shape used by snapshot.rs / wakeup.rs.
--
-- Migration 002 created a divergent SQLite table (merkle_root only). Snapshots
-- were never written on the SQLite path while the cognitive loop was Postgres-only,
-- so drop-and-recreate loses no recoverable checkpoint data.

DROP TABLE IF EXISTS agent_snapshots;

CREATE TABLE agent_snapshots (
    id         TEXT    PRIMARY KEY,
    sequence   INTEGER NOT NULL UNIQUE,
    state_hash TEXT    NOT NULL,
    payload    TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_agent_snapshots_created_at ON agent_snapshots (created_at);
