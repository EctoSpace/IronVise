# IronVise - Schema


For the certificate container built on top of these events - the `.elc`
format, its Merkle construction and its signing bytes - see
[`docs/reference/elc-spec.md`](elc-spec.md).

## Design

- **Agent state** lives in the configured ledger backend (PostgreSQL or SQLite). The Rust process is a transient worker.
- **Event log** is append-only and hash-chained to prevent tampering and support verification.
- **Snapshots** are derived from the log for fast state recovery (wake-up).
- **Sessions** group events into goal-scoped runs with per-session Ed25519 signing and optional DID identity.
- **RBAC tokens** control API access via hashed bearer tokens with role-based checks.
- **Webhooks** push real-time events to SIEM / external systems in JSON, CEF, or LEEF format.

## Tables

### `agent_events` (immutable)

| Column         | Type         | Description |
|----------------|--------------|-------------|
| `id`           | BIGSERIAL    | Primary key. |
| `sequence`     | BIGINT       | Strict ordering; unique. Genesis block uses `sequence = 0`. |
| `previous_hash`| VARCHAR(64)  | SHA-256 hex of the **previous** row’s `content_hash`. For genesis, a fixed constant (e.g. 64 zero hex chars). |
| `content_hash` | VARCHAR(64)  | Hex content hash of this event; see **Content-hash schemes** below. |
| `payload`      | JSONB        | Event body (e.g. thought, action, observation, genesis). |
| `created_at`   | TIMESTAMPTZ  | Insert time (microsecond precision; the value bound into `content_hash`). |
| `session_id`   | UUID         | FK → `agent_sessions(id)`. Links event to the session that produced it. |

**Invariants:** No `UPDATE` or `DELETE` in application code - enforced by a `prevent_updates()` trigger. Each row's `previous_hash` must equal the previous row's `content_hash`.

#### Content-hash schemes

Since v0.8.0 all write paths (PostgreSQL backend, SQLite backend, and the SP1
guest's re-derivation) use one canonical **v2** input, defined in
`crates/core/src/hash.rs::content_hash_input_v2`:

```text
"ELv2\0" previous_hash \0 sequence \0 payload_json \0 session_id \0 created_at
```

- Fields are joined by single null bytes after the fixed `ELv2\0` version tag,
  which domain-separates v2 from every earlier layout.
- `session_id` is the empty string for global events (e.g. genesis).
- `created_at` is the RFC 3339 rendering of the stored timestamp, truncated to
  microseconds **before** hashing, so re-reading the row reproduces the exact
  hashed string on both backends.
- The digest is SHA-256 by default, or BLAKE3 when built with `hash-blake3`.

**Verification / migration path:** ledgers written before v0.8.0 used v1
layouts that bound different subsets of these fields (both `session_id` and
`created_at`; `session_id` only; `created_at` only; or neither). Verification
(`crates/core/src/hash.rs::verify_content_hash_any_scheme`, used identically
by both database backends and the SP1 guest) checks the canonical v2 input
first and then falls back through each v1 layout - plus a SHA-256 fallback for
events written before a `hash-blake3` migration - so existing ledgers keep
verifying without rewriting rows. New events are only ever written with v2;
mixed chains verify per event.

**Indexes:** `idx_agent_events_sequence`, `idx_agent_events_created_at`, `idx_agent_events_content_hash`, `idx_agent_events_session_id`.

#### Event kinds (`payload.type`)

Every event's `payload` is a tagged union; `payload.type` carries the kind. The
list below is the complete set and is **kept in sync with the `EventPayload`
enum by a test** (`crates/host/src/schema.rs`, `docs_event_kinds_match_enum`) -
adding a variant without documenting it here fails the build.

<!-- BEGIN:event-kinds -->
| Kind | Meaning |
|---|---|
| `genesis` | First event in a ledger; pins the session key and a nonce. |
| `prompt_input` | The user's original prompt / audit goal. |
| `thought` | Agent narration. |
| `schema_error` | The model's output failed strict schema validation. |
| `circuit_breaker` | Too many consecutive failures of one kind; loop stopped. |
| `action` | An action the agent proposed and that passed every check. |
| `observation` | Result returned by an executed action. |
| `approval_required` | Human-in-the-loop gate opened. |
| `approval_decision` | Human-in-the-loop gate resolved. `reason` says who decided: `operator:cli` or `operator:api`, with the operator's note after a colon; `timeout: no decision within Ns; on_timeout=allow\|deny`; or `no approver configured; on_timeout=…`. |
| `cross_ledger_seal` | Seal binding this chain to another ledger. |
| `anchor` | Chain tip timestamped externally (OpenTimestamps). |
| `key_rotation` | Session signing key rotated. |
| `key_revocation` | Session signing key revoked. |
| `verifiable_credential` | W3C VC-JWT issued on session completion. |
| `chat_message` | Direct LLM chat outside the agent loop. |
| `guard_denial` | The semantic guard refused a proposed action. |
| `tripwire_rejection` | A tripwire, policy rule, or prompt scan rejected an action. |
| `data_receipt` | What a tool returned, by SHA-256 only: which data the agent received. |
<!-- END:event-kinds -->

**Control decisions are structured.** `guard_denial` and `tripwire_rejection`
carry `reason`, an optional `action`, and `enforced` - `true` when the decision
prevented execution rather than merely flagging it. They are appended *before*
the action could run, so they record something that did not happen.

Both were previously written as `thought` events with a `"Guard denied: "` text
prefix. That was tamper-evident but not enumerable, which is why EU AI Act
Article 12(2)(a) could only be claimed as partial; see
[`eu-ai-act-article12.md`](../compliance/eu-ai-act-article12.md).

**Data receipts are hashes, not data.** `data_receipt` carries `tool`, an
optional `source` (path, URL, query) and `call_id`, `response_sha256` (the whole
response as canonical JSON: keys sorted at every level, compact), `text_sha256`
(one SHA-256 per text the agent received: a file's contents, command output,
page text, each MCP text block) and `text_bytes`. Whoever holds the data can
check it against the receipt with `sha256sum` or `ironvise data-receipts
--file`; nobody can recover the data from the ledger. The hook and
`mcp-proxy` compute the hashes where the tool ran, so the data does not reach
the Observer either; `POST /api/hook/tool-result` takes the receipt, refuses
one whose hashes are not SHA-256 digests, and sets `call_id` to the request's
`tool_use_id`.

**Not to be confused with webhook egress kinds.** `webhooks.filter_kinds` matches
on `EgressKind` (`crates/host/src/webhook.rs`) - `observation`, `guard_denial`,
`tripwire_rejection` - a separate and much smaller set. The names overlap; the
domains do not.

### `agent_snapshots` (mutable)

| Column       | Type        | Description |
|--------------|-------------|-------------|
| `id`         | UUID        | Primary key. |
| `sequence`   | BIGINT      | Last replayed event `sequence` for this snapshot. |
| `state_hash` | VARCHAR(64) | SHA-256 hex of canonical snapshot payload (for verification). |
| `payload`    | JSONB       | Aggregated state / performance summary. |
| `created_at` | TIMESTAMPTZ | Insert time. |

Used by the **wake-up protocol**: load latest snapshot by `sequence`, then replay events where `sequence > snapshot.sequence`.

### `agent_action_log`

| Column               | Type        | Description |
|----------------------|-------------|-------------|
| `id`                 | UUID        | Primary key (auto-generated). |
| `event_id`           | BIGINT      | References the event that triggered this action. |
| `status`             | VARCHAR(16) | One of: `pending`, `executing`, `completed`, `failed`. |
| `started_at`         | TIMESTAMPTZ | When execution began. |
| `finished_at`        | TIMESTAMPTZ | When execution ended (nullable). |
| `error_msg`          | TEXT        | Error details on failure (nullable). |
| `compensating_action`| JSONB       | Rollback / undo payload proposed by the agent (nullable). |
| `compensation_status`| VARCHAR(16) | One of: `proposed`, `executing`, `executed`, `failed`, `skipped` (nullable). |

### `agent_sessions`

| Column                     | Type         | Description |
|----------------------------|--------------|-------------|
| `id`                       | UUID         | Primary key (auto-generated). |
| `goal`                     | TEXT         | Human-readable goal for the agent run. |
| `goal_hash`                | VARCHAR(64)  | SHA-256 hex of the goal text. |
| `status`                   | VARCHAR(16)  | One of: `running`, `completed`, `failed`, `aborted`. |
| `llm_backend`              | VARCHAR(32)  | LLM provider (e.g. `ollama`, `openai`, `anthropic`). |
| `llm_model`                | VARCHAR(128) | Model identifier used for the run. |
| `created_at`               | TIMESTAMPTZ  | Session start time. |
| `finished_at`              | TIMESTAMPTZ  | Session end time (nullable). |
| `policy_hash`              | VARCHAR(64)  | SHA-256 hex of the TOML policy active during this session. |
| `session_public_key`       | VARCHAR(128) | Ed25519 public key (hex) used to sign events in this session. |
| `session_did`              | TEXT         | W3C Decentralized Identifier (`did:key:…`) derived from session key. |
| `enclave_attestation_json` | TEXT         | Serialised enclave attestation evidence (TPM quote / Apple HV report). |
| `sealed_tip_hash`          | VARCHAR(64)  | `content_hash` of the last event at seal time. NULL when unsealed, or sealed before 0.8.0. |
| `sealed_event_count`       | BIGINT       | Event count at seal time. Verification reports `TruncatedSinceSealing` on a mismatch - see F-2 in CHANGELOG.md (0.8.0) for what that does and does not protect. |

### `agent_event_signatures`

| Column        | Type         | Description |
|---------------|--------------|-------------|
| `event_id`    | BIGINT       | Primary key; FK → `agent_events(id)`. |
| `content_hash`| VARCHAR(64)  | Hash that was signed (must match the event's `content_hash`). |
| `signature`   | VARCHAR(128) | Ed25519 signature (hex). |
| `public_key`  | VARCHAR(128) | Signer's public key (hex); must match `agent_sessions.session_public_key`. |

### `api_tokens`

| Column       | Type        | Description |
|--------------|-------------|-------------|
| `token_hash` | VARCHAR(64) | Primary key. SHA-256 hex of the raw bearer token (raw value is never stored). |
| `role`       | VARCHAR(16) | One of: `admin`, `auditor`, `agent`. |
| `label`      | TEXT        | Human-readable label (nullable). |
| `created_at` | TIMESTAMPTZ | Creation time. |
| `expires_at` | TIMESTAMPTZ | Optional expiry (nullable). |

**Index:** `api_tokens_role_idx`.

### `webhooks`

| Column         | Type        | Description |
|----------------|-------------|-------------|
| `id`           | UUID        | Primary key (auto-generated). |
| `label`        | TEXT        | Human-readable name for the webhook. |
| `url`          | TEXT        | Destination URL. |
| `bearer_token` | TEXT        | Optional bearer token for `Authorization` header (nullable). |
| `siem_format`  | VARCHAR(8)  | Output format: `json`, `cef`, or `leef`. Default `json`. |
| `filter_kinds` | TEXT[]      | Event kinds to forward. Default `{observation, guard_denial, tripwire_rejection}`. |
| `enabled`      | BOOLEAN     | Whether the hook is active. Default `true`. |
| `created_at`   | TIMESTAMPTZ | Creation time. |
| `updated_at`   | TIMESTAMPTZ | Last modification time. |

**Index:** `webhooks_enabled_idx`.

## Genesis rule

- The first event has `sequence = 0` and `previous_hash = GENESIS_PREVIOUS_HASH` (e.g. 64 zero hex characters).
- `content_hash` is computed the same way as for any other event.

## Migration history

| # | File | Summary |
|---|------|---------|
| 1 | `20250219000001_create_agent_events.sql` | Create `agent_events` table + immutability trigger. |
| 2 | `20250219000002_create_agent_snapshots.sql` | Create `agent_snapshots` table. |
| 3 | `20250219000003_create_agent_action_log.sql` | Create `agent_action_log` table. |
| 4 | `20250219000004_create_agent_sessions.sql` | Create `agent_sessions` table. |
| 5 | `20250219000005_add_session_id_to_events.sql` | Add `session_id` FK to `agent_events`. |
| 6 | `20250219000006_add_policy_hash_to_sessions.sql` | Add `policy_hash` to `agent_sessions`. |
| 7 | `20250219000007_add_event_signing.sql` | Add `session_public_key` to sessions; create `agent_event_signatures`. |
| 8 | `20260221000008_add_session_did.sql` | Add `session_did` to sessions. |
| 9 | `20260222000009_add_rbac_tokens.sql` | Create `api_tokens` table. |
| 10 | `20260222000010_add_webhook_config.sql` | Create `webhooks` table. |
| 11 | `20260222000011_add_compensating_actions.sql` | Add compensation columns to `agent_action_log`. |
| 12 | `20260223000012_add_enclave_attestation.sql` | Add `enclave_attestation_json` to sessions. |
| 13 | `20260224000013_add_pending_approvals.sql` | Create `pending_approvals` table for horizontal-scaling approval state. |
| 14 | `20260812000014_seal_records_tip.sql` | Add `sealed_tip_hash` / `sealed_event_count` to `agent_sessions` so a sealed session commits to its own length (F-2). |
| 15 | `20260929000015_consumed_requests.sql` | Create `consumed_requests` table for replay protection across `hook`, `proxy`, and `append_event`. |

> **SQLite backend:** In addition to the PostgreSQL migrations above, a parallel migration set lives in `crates/host/migrations/sqlite/` (`001` - `013`) providing the equivalent schema for the SQLite ledger backend. `011_seal_records_tip.sql`, `012_fix_agent_snapshots_schema.sql`, and `013_consumed_requests.sql` are the SQLite halves of the 0.8.0 schema changes described above.

### `pending_approvals`

| Column                | Type        | Description |
|-----------------------|-------------|-------------|
| `id`                  | BIGSERIAL   | Primary key. |
| `session_id`          | UUID        | Session requiring approval. |
| `gate_id`             | TEXT        | Identifier for the policy approval gate. |
| `action_name`         | TEXT        | Action that triggered the gate. |
| `action_params_summary` | TEXT      | Summary of action parameters (default empty). |
| `approved`            | BOOLEAN     | `NULL` = pending, `TRUE` = approved, `FALSE` = denied. |
| `reason`              | TEXT        | Human-provided reason for the decision (nullable). |
| `created_at`          | TIMESTAMPTZ | When the approval was requested. |
| `decided_at`          | TIMESTAMPTZ | When the decision was made (nullable). |

**Constraints:** `UNIQUE (session_id, gate_id)` prevents duplicate pending records for the same gate in the same session.

**Index:** `idx_pending_approvals_session_decided` - plain composite index on `(session_id, gate_id, approved)` (no `WHERE` clause) for efficient agent-side polling.

### `consumed_requests`

| Column        | Type        | Description |
|---------------|-------------|-------------|
| `scope`       | TEXT        | Endpoint scope (`hook:<session_id>`, `proxy:<session_id>`, `append:<session_id>`). |
| `request_id`  | TEXT        | Caller-supplied idempotency / replay token (`tool_use_id` or `X-Request-Id`). |
| `caller`      | TEXT        | Authenticated token hash or caller identifier. |
| `consumed_at` | TIMESTAMPTZ | When the request ID was first accepted (Unix epoch seconds on SQLite). |

**Constraints:** `PRIMARY KEY (scope, request_id)` - a second write with the same `(scope, request_id)` is rejected with HTTP 409 (`replay_detected`).

**Index:** `idx_consumed_requests_consumed_at` on `(consumed_at)` for 24-hour TTL pruning.
