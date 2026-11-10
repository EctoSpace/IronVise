# IronVise TypeScript SDK

**Tamper-evident, offline-verifiable audit logs for AI agents. Built for EU AI Act Article 12 record-keeping - which applies from 2 December 2027.**

Lightweight TypeScript / JavaScript client for the IronVise agent harness and audit system. Zero runtime dependencies - works in Node 18+, Deno, Bun, and modern browsers that support `fetch`.

IronVise is a policy-checked execution harness with a tamper-evident audit trail for AI agents. It helps you show what your AI did, in what order, and whether actions stayed within policy.

This is not a crypto trading product. Here, "ledger" means an auditable evidence log for AI behavior.

This SDK lets you create sessions, append events, and export verifiable `.elc` audit certificates from TypeScript and JavaScript apps.

## Scope: this SDK is client-only

The TypeScript SDK is a **client**: sessions, events, chain verification,
certificates, and `verifyIntent`, plus a receiver-side webhook verifier. It has no framework integrations.

The Python SDK has two (LangChain and AutoGen). That asymmetry is deliberate and
stated here rather than left for you to discover: one maintainer cannot keep
four framework adapters honest, and a half-maintained adapter to a governance
system is worse than none. If you need LangChain.js or Vercel AI SDK coverage,
`verifyIntent` and `appendEvent` are the primitives to build it on - and please
open an issue, because that is the signal that would change the decision.

## Installation

The package is not on npm yet. Build the single `ironvise` package from a clone:

```bash
cd sdk/typescript
npm install
npm run build
# From your application directory:
npm install /absolute/path/to/IronVise/sdk/typescript
```

After publication, install `ironvise@^0.8.0`. The former `ectoledger-sdk`
package and `EctoLedgerClient` API aliases are not included. Update imports
and use `IronViseClient`, `IronViseApiError` and `IronViseUsageError`.

Use 0.8.0 or newer. Earlier releases (0.6.x) predate `verifyIntent`, the call
that lets the SDK ask permission before an action instead of only recording it.


## Quick start

```ts
import { IronViseClient } from "ironvise";

const client = new IronViseClient({
  baseUrl: "http://localhost:3000",
  bearerToken: "my-api-token",       // optional - sent as Authorization: Bearer …
});

// 1. Create a session (record: true - you append to it yourself, no server LLM needed)
const session = await client.createSession({ goal: "audit-run-42", record: true });

// 2. Append events
await client.appendEvent(session.id, {
  event_type: "model_invocation",
  payload: { model: "gpt-4o", prompt_tokens: 120 },
});

// 3. Seal (finish) the session
await client.sealSession(session.id);

// 4. List all sessions (with optional filters)
const sessions = await client.listSessions({ limit: 10, status: "active" });
```

> **Note on `record`:** with `record: true` the server creates a recorder session
> that stays `running` for appends until you seal it. Without it the server runs
> its own audit loop (503 if it has no LLM) and seals the session when the loop
> ends; a later `appendEvent` gets a 409 (`IronViseApiError`) telling you to
> create the session with `record: true`.

> **Note on event signing:** events appended through the SDK are *unsigned*
> (external).  Only events created server-side carry an Ed25519 signature, and
> `getEvents` does not return it: `verifySession` reports the signatures.

> **Note on `createSession`:** the server never accepted `policy_hash` or
> `session_did` on creation - it records the hash of the policy the run
> actually used (or none) and derives `session_did` itself - so
> `CreateSessionOptions` only has `goal` and `record`. Both fields remain on
> `Session`, read-only.

---

## API reference

### Constructor

```ts
new IronViseClient({
  baseUrl?: string;
  bearerToken?: string;
  timeoutMs?: number;
  retries?: number;
})
```

| Param         | Description |
|---------------|-------------|
| `baseUrl`     | Root URL of the IronVise server (no trailing slash). Optional; defaults to `http://localhost:3000`. |
| `bearerToken` | If set, every request includes `Authorization: Bearer <token>`. |
| `timeoutMs`   | Aborts a non-streaming request after this many milliseconds, per attempt. Default `30_000`. |
| `retries`     | Retries for **GET requests only** (they're idempotent): a network error or an HTTP 502/503/504 is retried with exponential backoff (250 ms, 500 ms, …, capped at 4 s), honouring a `Retry-After` header in seconds when the server sends one (also capped at 4 s). POST/PUT/DELETE are never retried, and neither is a timeout or any 4xx. Streaming methods (`streamEvents`, `askStream`, `chatStream`) are never retried. Default `2`; pass `0` to disable. |

---

### Core

| Method | HTTP | Description |
|--------|------|-------------|
| `createSession(opts)` | `POST /api/sessions` | Create a new agent session. `record: true` creates a recorder session you append to yourself. |
| `listSessions(limitOrOpts?)` | `GET /api/sessions` | List sessions. Accepts a plain number (limit) or `ListSessionsOptions`. |
| `getSessionById(id)` | `GET /api/sessions/:id` | Fetch a single session by ID. |
| `getEvents(sessionId)` | `GET /api/events?session_id=:id` | Retrieve all events for a session, as the server sends them: `id`, `sequence`, `previous_hash`, `content_hash`, `payload`, `created_at`. |
| `appendEvent(sessionId, payload)` | `POST /api/sessions/:id/events` | Append an external event. |
| `sealSession(sessionId)` | `POST /api/sessions/:id/seal` | Seal (finish) a session. |

### Integrity & Compliance

| Method | HTTP | Description |
|--------|------|-------------|
| `verifyChain(sessionId)` | `GET /api/sessions/:id/verify` | `true` only if the hash chain is intact **and** every signature verified. |
| `verifySession(sessionId)` | `GET /api/sessions/:id/verify` | The full `VerifySessionResult`: `ok` (hash chain) and `signatures` (`verified`, `verdict`, `message`, `signed`, `unsigned`; absent on servers that predate signature checks). |
| `proveCompliance(sessionId)` | `GET /api/sessions/:id/compliance` | Get `session_id`, `event_count` and each event's `sequence` and `content_hash` (no signatures or policy: see `verifySession`). |
| `exportCertificate(sessionId)` | `GET /api/certificates/:id` | Download the audit certificate as a `Blob`. |
| `verifyIntent(sessionId, intent)` | `POST /api/sessions/:id/verify-intent` | Ask whether an action would be permitted - **before** performing it. Runs the same policy → tripwire → guard pipeline the cognitive loop uses; nothing is executed and nothing is recorded by asking. |

```ts
const verdict = await client.verifyIntent(sid, {
  action: "run_command",
  params: { command: cmd },
  justification: "…",
});
assertAllowed(verdict);
```

### Reports & Verifiable Credentials

| Method | HTTP | Description |
|--------|------|-------------|
| `getReport(sessionId)` | `GET /api/reports/:id` | Audit report as JSON. |
| `getSessionVc(sessionId)` | `GET /api/sessions/:id/vc` | W3C Verifiable Credential for a session. |
| `verifySessionVc(sessionId, audience?)` | `GET /api/sessions/:id/vc/verify` | Verify VC structural integrity and expiry. `audience`, when given, is sent as `?audience=` and checked against the VC's `aud` claim. |

### Policies

| Method | HTTP | Description |
|--------|------|-------------|
| `listPolicies()` | `GET /api/policies` | List loaded audit policy names. |
| `getPolicy(name)` | `GET /api/policies/:name` | Retrieve a policy's TOML content as text. |
| `savePolicy(name, content)` | `PUT /api/policies/:name` | Create or overwrite a policy. **Admin.** |
| `deletePolicy(name)` | `DELETE /api/policies/:name` | Delete a policy. **Admin.** |

### Approval Gates

| Method | HTTP | Description |
|--------|------|-------------|
| `getPendingApproval(sessionId)` | `GET /api/approvals/:id/pending` | Get the pending approval gate, or `null` if none. |
| `postApprovalDecision(sessionId, decision)` | `POST /api/approvals/:id` | Submit an `approve` or `deny` decision. **Admin.** |

### AI / Chat

| Method | HTTP | Description |
|--------|------|-------------|
| `chat(sessionId, message)` | `POST /api/sessions/:id/chat` | Send a chat message within a session. |
| `chatStream(sessionId, message)` | `POST /api/sessions/:id/chat/stream` | `chat`, streamed: yields `{ type: "delta", text }` as the model writes, then `{ type: "done", reply, backend, model }`. |
| `ask(message)` | `POST /api/chat` | Ask the configured model directly, outside any session. |
| `askStream(message)` | `POST /api/chat/stream` | `ask`, streamed like `chatStream`. |

Every exchange is recorded in the ledger as two `chat_message` events, the
reply once it is complete; no guard or tripwire applies to chat.

```ts
for await (const ev of client.askStream("Summarise OWASP A01 in one line")) {
  if (ev.type === "delta") process.stdout.write(ev.text);
}
```

### Admin

Rows marked **Admin** need a bearer token created with the `admin` role
(`createToken({ role: "admin", ... })`); any other role gets `403`. The
rest of this section needs only a valid token.

| Method | HTTP | Description |
|--------|------|-------------|
| `getStatus()` | `GET /api/status` | Server health / version (no auth required). |
| `getConfig()` | `GET /api/config` | Read current server configuration, including `guard_required_source`, `ledger_backend`, `agent_supported`, `exports_supported`, `webhooks_live`, `active_policy` and `policy_from_environment`. **Admin.** |
| `updateConfig(patch)` | `PUT /api/config` | Update server configuration. `openai_base_url`, `show_developer_tools` and `active_policy` are also accepted; `""` on a text field clears it, and an `active_policy` that fails to load returns 422. **Admin.** |
| `resetDemo()` | `POST /api/admin/reset-demo` | Wipe demo data and re-seed. **Admin.** |
| `getTripwireConfig()` | `GET /api/tripwire` | Read tripwire / guardrail settings, including `allowed_mcp_tools` and (GET only) `saved`. |
| `updateTripwireConfig(patch)` | `PUT /api/tripwire` | Update tripwire settings. Omit `allowed_mcp_tools` to keep the saved list. **Admin.** |
| `checkTripwire(req)` | `POST /api/tripwire/check` | Ask whether `{ action, params?, justification? }` would pass the tripwire - no session, no ledger event. Returns `{ allowed, reason, rule, matched }`. |
| `listTokens()` | `GET /api/tokens` | List RBAC API tokens. **Admin.** |
| `createToken(req)` | `POST /api/tokens` | Create a new RBAC token. **Admin.** |
| `deleteToken(tokenHash)` | `DELETE /api/tokens/:hash` | Revoke a token by its hash. **Admin.** |
| `listWebhooks()` | `GET /api/webhooks` | List webhook configurations. **Admin.** |
| `createWebhook(req)` | `POST /api/webhooks` | Register a new webhook. **Admin.** |
| `deleteWebhook(id)` | `DELETE /api/webhooks/:id` | Remove a webhook. **Admin.** |
| `toggleWebhook(id, enabled)` | `PUT /api/webhooks/:id` | Enable or disable a webhook. **Admin.** |

### Observability

| Method | HTTP | Description |
|--------|------|-------------|
| `getMetrics()` | `GET /api/metrics` | Metrics summary as JSON. |
| `getSecurityMetrics()` | `GET /api/metrics/security` | Security event counters (injections, denials, aborts). |
| `getPrometheusMetrics()` | `GET /metrics` | Raw Prometheus text (for scraping). **Admin.** |
| `streamEvents(opts?)` | `GET /api/stream` | Server-Sent Events stream (async iterator). |

---

## Verifying webhooks

```ts
import { MemoryReplayCache, verifyWebhook } from "ironvise";

const cache = new MemoryReplayCache(); // one per process, not one per request
const verdict = verifyWebhook({
  receiverKey: process.env.WEBHOOK_KEY!, // from `ironvise webhook-key --url <url>`
  receiverUrl: "https://siem.example/ectoledger",
  headers: req.headers,
  body: rawBody, // the body string exactly as received, not re-serialised JSON
  cache,
});
if (!verdict.ok) return res.status(401).send(verdict.reason);
```

Each receiver gets its own key from `ironvise webhook-key --url <url>`, and the verifier refuses deliveries signed for another receiver, timestamps more than 300 s off, and replayed delivery ids (`verdict.reason` is `missing_headers`, `stale`, `bad_signature` or `replayed`). It uses `node:crypto`, so it is for Node, Deno and Bun receivers rather than browsers.

---

## Error handling

Every non-2xx response throws an `IronViseApiError`, which extends `Error`
and exposes `.status` (number) and `.body` (raw response text). The message
carries the first 300 characters of the body (never cutting a character in
half), so a server explanation such as the 409 for appending to a sealed
session is visible without digging; `.body` is always whole:

```ts
import { IronViseClient, IronViseApiError } from "ironvise";

try {
  await client.getSessionById("nonexistent-id");
} catch (e) {
  if (e instanceof IronViseApiError) {
    console.error(e.status); // e.g. 404
    console.error(e.body);   // e.g. '{"error":"not found"}'
  }
}
```

Network failures and timeouts propagate as standard `TypeError` /
`AbortError`, once any retries (see `retries` above) are exhausted. The
`timeoutMs` timeout (default 30 s) covers reading the response body as well
as waiting for the headers, so a server that stalls mid-body cannot hang a
call, and applies per attempt, not to the call as a whole.

Misuse that the client can detect itself throws an `IronViseUsageError` (also
extends `Error`) before any request is sent. Today that is an id or policy name
of `""`, `"."` or `".."`: URL parsing would resolve the dot segments and address
a different resource. Ids that merely contain dots (`"a.b"`, `".hidden"`,
`"..."`) are sent as one encoded path segment as usual.

---

## Troubleshooting

### Cannot connect to server

- Confirm `baseUrl` points to a reachable IronVise instance.
- In containerized deployments, use the service DNS name (not browser localhost assumptions).
- Validate server availability with `/api/status`.

### 401 / 403 responses

- Ensure `bearerToken` is present and not revoked.
- Confirm the token role has permission for the endpoint you are calling.

### Method works locally but fails in another environment

- Check backend mode and feature availability (some operations require PostgreSQL).
- Inspect thrown `IronViseApiError.status` and `.body` to diagnose exact server-side cause.

---

## Streaming events

`streamEvents` returns an `AsyncGenerator<StreamEvent>` that yields parsed SSE
objects in real time:

```ts
for await (const evt of client.streamEvents({ session_id: "abc" })) {
  console.log(evt.event_type, evt.payload);
}
```

`StreamOptions` accepts:

| Option       | Type          | Description |
|--------------|---------------|-------------|
| `after`      | `number`      | Only yield events after this sequence number. |
| `since`      | `number`      | Only yield events since this timestamp/sequence. |
| `session_id` | `string`      | Filter to a single session; omit for all events. |
| `signal`     | `AbortSignal` | Abort the stream (e.g. to cancel the underlying fetch). |

---

## Building from source

```bash
npm install
npm run build     # tsc  →  dist/
```

The build produces ESM (`dist/index.js`) and CJS (`dist/index.cjs`) outputs,
plus TypeScript declaration files.

---

## Running tests

```bash
npm test          # vitest run
```

All tests use mocked `fetch` - no running server required.

---

## Licence

Apache-2.0 - see the `LICENSE` file in this directory.

This differs from the rest of the repository, which is under the Business
Source License 1.1. The split is deliberate: this is a client library with no
server code in it, meant to be embedded freely. The BUSL covers what produces
the evidence, not what talks to it.

Verifying an IronVise certificate is also explicitly carved out of the BUSL's
Production Use restriction, so an auditor can check evidence without needing a
licence from us. See the repository root `LICENSE`.
