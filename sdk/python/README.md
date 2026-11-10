# IronVise Python SDK

**Tamper-evident, offline-verifiable audit logs for AI agents. Built for EU AI Act Article 12 record-keeping - which applies from 2 December 2027.**

A typed async REST client for the IronVise agent harness and audit system.

IronVise is a policy-checked execution harness with a tamper-evident audit trail for AI agents. It helps you show what your AI did, in what order, and whether actions stayed within policy.

This is not a crypto trading product. Here, "ledger" means an auditable evidence log for AI behavior.

This SDK lets you create sessions, append events, and export verifiable `.elc` audit certificates from your Python applications.

## Installation

The complete implementation lives in `ironvise_sdk/`. LangChain and AutoGen
adapters are included under `ironvise_sdk.langchain` and `ironvise_sdk.autogen`.
The former `ectoledger_sdk` namespace is no longer shipped. Update existing
imports to `ironvise_sdk` before upgrading.

Build fresh artifacts from the repository root with
`./scripts/build-python-sdk.sh`. It checks the wheel and source archive for
extra code namespaces and replaces stale files in `sdk/python/dist/`. The files
are named `ironvise-0.8.0...`. A `.ectoledger/` folder is runtime
state created by the CLI/server, not a Python package. It can hold signing keys
and configuration, so keep it when upgrading or renaming the SDK.

When replacing an installed `ectoledger-sdk` distribution, uninstall it before
installing `ironvise` (`python -m pip uninstall ectoledger-sdk`). This does not
remove ledger data or signing keys.

Install the `ironvise` package from PyPI:

```bash
pip install "ironvise>=0.8.0"

# With a framework adapter
pip install "ironvise[langchain]>=0.8.0"
pip install "ironvise[autogen]>=0.8.0"

# Or from a clone of this repository
pip install -e ./sdk/python
# Development install, including framework adapters and test dependencies:
pip install -e './sdk/python[dev]'
```

Use 0.8.0 or newer. Earlier releases (0.6.x) predate `verify_intent`, the
fail-closed `LedgerHook` and the `LedgerCallbackHandler`, the parts that let
the SDK ask permission before an action instead of only recording it.

## Quick start

```python
import asyncio
from ironvise_sdk import LedgerClient

async def main():
    async with LedgerClient("http://localhost:3000", bearer_token="your_token") as client:
        sessions = await client.list_sessions()
        print(f"Found {len(sessions)} active sessions.")

asyncio.run(main())
```

## Constructor

```python
LedgerClient(
    base_url="http://localhost:3000",  # Server URL (required in production)
    bearer_token=None,                 # Optional RBAC token
    timeout=30.0,                      # HTTP timeout in seconds, per attempt
    retries=2,                         # GET-only retry count; see below
)
```

> **Note:** The default `base_url` only works for local development. In Docker Compose or Kubernetes you **must** pass the correct service URL.

`retries` applies only to GET requests, which are idempotent: a connection
error (refused, reset, …) or an HTTP 502/503/504 is retried with exponential
backoff (0.25 s, 0.5 s, …, capped at 4 s), honouring a `Retry-After` header in
seconds when the server sends one (also capped at 4 s). POST/PUT/DELETE are
never retried, and neither is a timeout or any 4xx - those reach the caller
immediately. Streaming (`stream_events`, `ask_stream`, `chat_stream`) is not
retried either. Pass `retries=0` to disable retrying.

## Error handling

All methods raise `LedgerSdkError` on non-2xx responses:

```python
from ironvise_sdk import LedgerSdkError

try:
    await client.append_event(session_id, {"observation": "read config"})
except LedgerSdkError as exc:
    print(exc)  # append_event: HTTP 409: session … is completed: it is sealed, … create the session with "record": true; …
    print(exc.status_code, exc.body)
```

The message ends with the server's own explanation: the JSON `error` or `message` field when the body is JSON, else the body text, cut at 300 characters. `exc.body` is always the whole response text. This holds for `stream_events` too, which raises before yielding anything.

`LedgerSdkError` is also raised, with `status_code` and `body` attached, for a 2xx response the method cannot use:

- a body that is not JSON: `get_session: server returned non-JSON body`;
- JSON of the wrong shape: `get_session: unexpected response shape: Session: Input should be a valid dictionary …`, with the pydantic `ValidationError` as `__cause__`.

An identifier passed as a path segment (a session id, policy name, token hash or webhook id) that is `""`, `"."` or `".."` is refused with `LedgerSdkError` before any request is sent (`delete_policy: name must not be '..': it cannot be sent as a path segment`; `status_code` is `None`), because no encoding keeps it inside its segment. Any other identifier, dots included (`"a.b"`, `".hidden"`, `"..."`), is sent percent-encoded as exactly one segment.

Transport failures (refused connections, timeouts) are not wrapped: the `httpx` exception reaches the caller unchanged.

## Recording a run

To record a run yourself, directly or through `LedgerCallbackHandler` / `LedgerHook`, create the session in record mode:

```python
session = await client.create_session(goal="audit-run-42", record=True)
await client.append_event(session.session_id, {"observation": "read config"})
await client.seal_session(session.session_id)
```

A record-mode session needs no LLM on the server and stays `running` for appends until you seal it. Without `record=True` the server starts its own audit loop (and answers 503 if it has no LLM), then seals the session when the loop ends; a later `append_event` gets a 409 whose `LedgerSdkError.body` says to create the session with `record=True`.

`verify_chain` returns `True` only if the hash chain is intact **and** every signature verified. For the two verdicts separately, use `verify_session`:

```python
result = await client.verify_session(session.session_id)
result.ok                    # hash chain
result.signatures            # None on servers that predate signature checks
result.signatures.verified   # signatures; .verdict / .message say why not
```

## Verifying webhooks

```python
import os
from ironvise_sdk import MemoryReplayCache, verify_webhook

cache = MemoryReplayCache()  # one per process, not one per request
verdict = verify_webhook(
    receiver_key=os.environ["WEBHOOK_KEY"],  # `ironvise webhook-key --url <url>`
    receiver_url="https://siem.example/ectoledger",
    headers=request.headers, body=raw_body, cache=cache,  # raw_body: exactly as received
)
if not verdict.ok:
    abort(401, verdict.reason)
```

Each receiver gets its own key from `ironvise webhook-key --url <url>`, and the verifier refuses deliveries signed for another receiver, timestamps more than 300 s off, and replayed delivery ids (`verdict.reason` is `missing_headers`, `stale`, `bad_signature` or `replayed`).

## LangChain integration

`LedgerTool` was removed in 0.8.0. It was a tool the *model* chose to call, so
the audit trail existed only when the model cooperated - and nothing detected
the times it did not. `LedgerCallbackHandler` fires because the framework calls
it, so there is nothing for the model to decline.

```python
from ironvise_sdk.langchain import LedgerCallbackHandler

handler = LedgerCallbackHandler(
    session_id="your-session-uuid",
    base_url="http://localhost:3000",
)
agent.invoke({"input": "..."}, config={"callbacks": [handler]})
```

Fail-closed: a recording failure raises `RecordingFailed` and stops the run.
The handler sets LangChain's `raise_error`, without which the callback manager
catches the exception, logs it and lets the tool run anyway - which is what
an earlier cut of this handler did. `tests/test_langchain_callback.py` drives a
real `StructuredTool`
through the real callback manager, sync and async, and asserts the tool's side
effect did not happen.

A failure in `on_tool_start` prevents the call. A failure in `on_tool_end`
cannot: the tool has run, so that error reports an incomplete record rather
than a prevented action. Pass `fail_open=True` to accept gaps deliberately.

The handler (like `LedgerHook`) records through one HTTP client on a background
event loop thread, so it works from sync and async agents alike and reuses
its connection. Close it with `handler.close()` or use it as a context manager
(`with LedgerCallbackHandler(...) as handler:`); `timeout` bounds each record.

## AutoGen integration

Requires `autogen-agentchat>=0.4` - the version this package declares.

`LedgerHook.attach()` is gone. It called AutoGen **0.2**'s
`ConversableAgent.register_hook("process_last_received_message", ...)`, which
0.4+ does not have, so it raised `AttributeError` against every version the
dependency allowed. Calling it now raises `NotImplementedError` naming the
replacement.

0.4+ runs tools as `autogen_core.tools.BaseTool` objects, so wrapping the tools
puts the ledger between the decision and the action:

```python
from autogen_agentchat.agents import AssistantAgent
from ironvise_sdk.autogen import LedgerHook

with LedgerHook(session_id="your-session-uuid") as hook:
    agent = AssistantAgent(
        "auditor",
        model_client=model_client,
        tools=hook.wrap_tools([read_file, run_scan], agent_name="auditor"),
    )
    await agent.run(task="...")
```

Each call is recorded *before* it runs, so a recording failure prevents it, and
`tests/test_autogen_hook.py` proves that by checking the tool's side effect
rather than the return value. Two honest limits:

- AutoGen turns a raising tool into a failed `FunctionExecutionResult`, so the
  **action** is prevented but the **agent** keeps going with an error in its
  context. It is not a halt.
- The result is recorded after the call. A failure there reports an incomplete
  trail; nothing is rolled back, and the error says so.

Pass `fail_open=True` to accept gaps deliberately.

## Testing

```bash
cd sdk/python
pip install ".[dev]"   # includes langchain-core and autogen-agentchat: the
                       # framework tests run against the real frameworks
pytest tests/ -v
```

## Troubleshooting

### Connection errors or timeouts

- Ensure `base_url` points to the running IronVise server (`http://localhost:3000` in local default setups).
- In Docker/Kubernetes, use the correct service hostname instead of localhost.
- Check that your network path allows access to `/api/status`.

### Authentication failures (401/403)

- Verify `bearer_token` is valid and has sufficient RBAC scope.
- Confirm token creation/revocation status in the server UI/API.

### Unexpected API errors

- Catch `LedgerSdkError` and inspect `status_code` + `body` for exact server response.
- Check backend mode constraints (some commands/features require PostgreSQL backend).

## API Reference

Methods marked **Admin** need a bearer token created with the `admin` role
(`create_token(role="admin", ...)`); any other role gets `403`.

### Status

| Method | Returns | Description |
|--------|---------|-------------|
| `get_status()` | `StatusResponse` | Server status (demo mode, version) |

### Sessions

| Method | Returns | Description |
|--------|---------|-------------|
| `list_sessions(limit=50, offset=None, status=None)` | `list[Session]` | List recent sessions with optional pagination and status filter |
| `create_session(goal, *, record=False)` | `Session` | Open a new audit session (no `policy_hash` / `session_did` params - the server never accepted either; it sets both itself); `record=True` opens a recorder session you append to yourself (no server LLM) |
| `get_session(session_id)` | `Session` | Fetch a single session |
| `seal_session(session_id)` | `None` | Mark session as finished |

### Chat

| Method | Returns | Description |
|--------|---------|-------------|
| `chat(session_id, message)` | `dict` | Send a message within a running session (`POST /api/sessions/{id}/chat`) |
| `chat_stream(session_id, message)` | `AsyncIterator[dict]` | `chat`, streamed: `{"type": "delta", "text"}` as the model writes, then `{"type": "done", "reply", "backend", "model"}` (`POST /api/sessions/{id}/chat/stream`) |
| `ask(message)` | `dict` | Ask the configured model directly, outside any session (`POST /api/chat`) |
| `ask_stream(message)` | `AsyncIterator[dict]` | `ask`, streamed like `chat_stream` (`POST /api/chat/stream`) |

Every exchange is recorded in the ledger as two `chat_message` events, the
reply once it is complete; no guard or tripwire applies to chat.

```python
async for event in client.ask_stream("Summarise OWASP A01 in one line"):
    if event["type"] == "delta":
        print(event["text"], end="", flush=True)
```

### Events

| Method | Returns | Description |
|--------|---------|-------------|
| `get_events(session_id)` | `list[LedgerEvent]` | Fetch all events for a session: `id`, `sequence`, `prev_hash`, `payload_hash`, `payload`, `created_at`. The server sends no per-event signature; `verify_session` reports them |
| `append_event(session_id, payload)` | `AppendResult` | Append an event (hash-chained, unsigned - see docs/guides/integrations.md) |
| `stream_events(session_id=None)` | `AsyncIterator[dict]` | SSE live event stream: one session's events, or every session's when `session_id` is omitted |

### Verify Intent

| Method | Returns | Description |
|--------|---------|-------------|
| `verify_intent(session_id, action, params=None, justification="", reasoning="")` | `IntentVerdict` | Ask whether an action would be permitted - **before** performing it. Runs the same policy → tripwire → guard pipeline the cognitive loop uses; nothing is executed and nothing is recorded by asking |

```python
verdict = await client.verify_intent(
    sid, "run_command", {"command": cmd}, justification="…",
)
verdict.raise_if_denied()
subprocess.run(cmd, shell=True)
```

### Chain Verification & Compliance

| Method | Returns | Description |
|--------|---------|-------------|
| `verify_chain(session_id)` | `bool` | `True` only if the chain is intact and every signature verified |
| `verify_session(session_id)` | `VerifySessionResult` | Chain verdict (`ok`) and signature verdict (`signatures`) separately |
| `prove_compliance(session_id)` | `ComplianceBundle` | `session_id`, `event_count` and each event's `sequence` and `content_hash` (no signatures or policy: see `verify_session`) |
| `export_certificate(session_id)` | `bytes` | Download `.elc` audit certificate |

### Reports & Verifiable Credentials

| Method | Returns | Description |
|--------|---------|-------------|
| `get_report(session_id)` | `dict` | Audit report as a dictionary |
| `get_session_vc(session_id)` | `dict` | W3C Verifiable Credential (VC-JWT) |
| `verify_session_vc(session_id, audience=None)` | `dict` | Verify VC structural integrity; `audience`, when given, is sent as `?audience=` and checked against the VC's `aud` claim |

### Metrics

| Method | Returns | Description |
|--------|---------|-------------|
| `get_metrics()` | `MetricsSummary` | System metrics summary |
| `get_security_metrics()` | `SecurityMetrics` | Security event counters |
| `get_prometheus_metrics()` | `str` | Raw Prometheus text output. **Admin.** |

### Configuration

| Method | Returns | Description |
|--------|---------|-------------|
| `get_config()` | `ConfigResponse` | Current server configuration, including `guard_required_source`, `ledger_backend`, `agent_supported`, `exports_supported`, `webhooks_live`, `active_policy` and `policy_from_environment`. **Admin.** |
| `update_config(patch)` | `dict` | Apply partial config update. Also accepts `openai_base_url`, `show_developer_tools` and `active_policy`; `""` on a text field clears it, and an `active_policy` that fails to load returns 422. **Admin.** |

### Tripwire Configuration

| Method | Returns | Description |
|--------|---------|-------------|
| `get_tripwire_config()` | `TripwireConfig` | Current tripwire guard config, including `allowed_mcp_tools` and (this call only) `saved` |
| `update_tripwire_config(patch)` | `dict` | Apply partial tripwire update. Omit `allowed_mcp_tools` to keep the saved list. **Admin.** |
| `check_tripwire(action, params=None, justification=None)` | `TripwireCheckResult` | Ask whether an action would pass the tripwire - no session, no ledger event. `justification` omitted uses the server's own placeholder |

### Policies

| Method | Returns | Description |
|--------|---------|-------------|
| `list_policies()` | `list[str]` | List available policy names |
| `get_policy(name)` | `str` | Retrieve policy TOML content |
| `save_policy(name, content)` | `None` | Create or overwrite a policy. **Admin.** |
| `delete_policy(name)` | `None` | Remove a policy. **Admin.** |

### RBAC Tokens

All three need **Admin.**

| Method | Returns | Description |
|--------|---------|-------------|
| `list_tokens()` | `list[TokenListRow]` | List tokens (hashed, not raw) |
| `create_token(role, label=None, expires_in_days=None)` | `CreateTokenResponse` | Create a new API token |
| `delete_token(token_hash)` | `None` | Revoke a token |

### Webhooks

All four need **Admin.**

| Method | Returns | Description |
|--------|---------|-------------|
| `list_webhooks()` | `list[WebhookListRow]` | List configured webhooks |
| `create_webhook(label, url, *, bearer_token=None, siem_format="json", filter_kinds=None, enabled=True)` | `WebhookListRow` | Register a webhook (`bearer_token` / `siem_format` / `filter_kinds` / `enabled` are keyword-only) |
| `delete_webhook(webhook_id)` | `None` | Remove a webhook |
| `toggle_webhook(webhook_id, enabled)` | `None` | Enable/disable a webhook. The server answers `200` with an empty body, so this returns nothing |

### Approval Gates

| Method | Returns | Description |
|--------|---------|-------------|
| `get_pending_approval(session_id)` | `PendingApproval \| None` | Get pending approval gate |
| `post_approval_decision(session_id, gate_id, approved, reason=None)` | `None` | Submit decision. **Admin.** |

### Admin

| Method | Returns | Description |
|--------|---------|-------------|
| `reset_demo()` | `dict` | Reset server to demo defaults. **Admin.** |

## Licence

Apache-2.0 - see the `LICENSE` file in this directory.

This differs from the rest of the repository, which is under the Business
Source License 1.1. The split is deliberate: this is a client library with no
server code in it, meant to be embedded freely. The BUSL covers what produces
the evidence, not what talks to it.

Verifying an IronVise certificate is also explicitly carved out of the BUSL's
Production Use restriction, so an auditor can check evidence without needing a
licence from us. See the repository root `LICENSE`.
