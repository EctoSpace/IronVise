# Running more than one instance

Several `ironvise serve` processes can share one PostgreSQL database
behind a load balancer. This page says what they share, what each keeps to
itself, and how to route clients so that the difference does not matter.
SQLite serves one process only.

## Backend matrix

| | SQLite | PostgreSQL |
|---|---|---|
| Instances | one | any number, on one database |
| Appends | serialised by the file lock | serialised across instances by a transaction-level advisory lock, so the chain never forks |
| Live event stream (SSE) | in process | every append sends `NOTIFY`; each instance `LISTEN`s and wakes its own SSE clients |
| Approval gates | in memory | the `pending_approvals` table: a gate opened on one instance is decided through any |
| Replay protection for hook and MCP calls | in the database | in the database, shared |
| Rate limits | per process | per instance |
| Hook and SDK recorder sessions | in process | held by the instance that opened them |

## What the instances share

**The chain.** Every append takes `pg_advisory_xact_lock(42)` in its
transaction before reading the head, so two instances appending at once get
consecutive sequence numbers, each linked to the one before. Verification
does not care which instance wrote an event.

**The live stream.** `crates/host/src/pg_notify.rs`: an append sends
`NOTIFY ectoledger_events`; each instance's listener wakes its SSE
subscribers, who then read the new rows from the database
(`tests/pg_notify.rs`).

**Approval gates.** A loop that reaches a policy approval gate publishes it
to `pending_approvals` and polls for the decision. `GET
/api/approvals/:id/pending` and `POST /api/approvals/:id` on any instance
read and decide it. Deciding is one conditional `UPDATE`, so two operators
clicking on two instances record one decision and the other gets a 409; a
timeout withdraws the gate with one `DELETE … RETURNING`, so a decision and
a timeout cannot both win. `crates/host/src/approvals.rs`;
`tests/multi_instance_postgres.rs` runs two instances against one database.

**Replay protection.** Consumed hook `tool_use_id`s and MCP request ids are
rows in the database, so a call replayed to another instance is refused
too.

## What each instance keeps

**Its audit loops.** A loop runs in the process whose `POST /api/sessions`
created its session, and no endpoint starts a loop for a session that
already exists, so two instances never drive one session. Its approval gate
is the exception above.

**Hook and SDK recorder sessions.** The instance that opens one holds its
signing key in memory and never writes it down (`server/session_keys.rs`),
so only that instance signs the session's events and certificates. A hook
call for the same agent session that reaches another instance opens a
second ledger session there: both verify, and the conversation is split
across them, as after a restart. Point each agent's `ECTOLEDGER_URL` at one
instance, or route `/api/hook/*` and the recorder endpoints by session.

**Rate limits.** Each instance limits on its own, so the fleet allows the
configured rate times the number of instances. Put a global limit in the
load balancer if that matters.

**Guard workers.** Each instance starts its own; they hold no state.

## Checklist

- PostgreSQL, with migrations applied (every instance applies them at start).
- The same `ECTOLEDGER_*` configuration and policy files on every instance.
- Hook clients and SDK recorders pinned to one instance each, or routed by
  session.
- A global rate limit at the load balancer, if the per-instance one is not
  enough.
