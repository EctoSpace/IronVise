-- SQLite counterpart of 20260929000015_consumed_requests.sql.
CREATE TABLE IF NOT EXISTS consumed_requests (
    scope       TEXT NOT NULL,
    request_id  TEXT NOT NULL,
    caller      TEXT NOT NULL,
    consumed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (scope, request_id)
);
CREATE INDEX IF NOT EXISTS idx_consumed_requests_at ON consumed_requests (consumed_at);
