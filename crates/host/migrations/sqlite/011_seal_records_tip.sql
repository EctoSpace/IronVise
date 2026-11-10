-- SQLite counterpart of 20260812000014_seal_records_tip.sql.
-- See that file for why these columns exist and what they do not protect.

ALTER TABLE agent_sessions ADD COLUMN sealed_tip_hash TEXT;
ALTER TABLE agent_sessions ADD COLUMN sealed_event_count INTEGER;
