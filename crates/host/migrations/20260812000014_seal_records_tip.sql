-- Record the ledger tip and event count when a session is sealed.
--
-- docs/security-findings-open.md, F-2: deleting events from the end of a
-- session verified clean, because nothing recorded how long the session was
-- supposed to be. "Sealed" was doing work the schema did not back.
--
-- Read the limit honestly. These columns live in the same database as the
-- events they describe, so anyone who can truncate agent_events can update
-- agent_sessions in the same transaction. This raises the cost of careless
-- tampering; it is not a defence against someone who owns the file. What
-- actually closes F-2 is out-of-band: an exported .elc (which commits to both
-- of these values), an anchor, or webhook egress to a system the attacker does
-- not control.

ALTER TABLE agent_sessions ADD COLUMN sealed_tip_hash VARCHAR(64);
ALTER TABLE agent_sessions ADD COLUMN sealed_event_count BIGINT;

COMMENT ON COLUMN agent_sessions.sealed_tip_hash IS
  'content_hash of the last event at seal time. NULL for unsealed sessions and for sessions sealed before 0.8.0.';
COMMENT ON COLUMN agent_sessions.sealed_event_count IS
  'Number of events in the session at seal time. Compared on verification; see F-2.';
