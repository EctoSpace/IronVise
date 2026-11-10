-- Request ids already acted on, so a replayed request is refused rather than
-- recorded twice: a hook call's Claude Code `tool_use_id`, an SDK append's
-- `Idempotency-Key`. `caller` is the SHA-256 of the token that sent it.
-- Rows older than pool::REPLAY_RETENTION_DAYS are purged at server start; a
-- replay older than that is no longer recognised.
CREATE TABLE IF NOT EXISTS consumed_requests (
    scope       TEXT        NOT NULL,
    request_id  TEXT        NOT NULL,
    caller      TEXT        NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, request_id)
);
CREATE INDEX IF NOT EXISTS idx_consumed_requests_at ON consumed_requests (consumed_at);
