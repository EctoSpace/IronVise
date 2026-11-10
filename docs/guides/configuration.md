# Configuration Reference

Configuration is loaded from environment variables (with optional `.env` file
support via `dotenvy`). Values marked **[required]** have no sensible default and
must be set for the described feature to be active.

> ### `settings.json` wins over the environment - except for the guard
>
> The desktop GUI persists its Settings screen to
> `.ectoledger/settings.json` - or `$ECTO_DATA_DIR/settings.json` when that is
> set - and **eight keys read that file first and only fall back to the
> environment**: `database_url`, `llm_backend`, `llm_provider`,
> `ollama_base_url`, `ollama_model`, `openai_base_url`, `guard_llm_backend`,
> `guard_llm_model`. In `PUT /api/config` (what the Settings screen saves
> through), a text key sent as `""` removes it from the file, so the
> environment or built-in default applies again; a key left out keeps its
> stored value.
>
> `guard_required` used to be a ninth, and that was a defect: `export
> GUARD_REQUIRED=true`, which [running-securely.md](../getting-started/running-securely.md)
> instructs, was silently discarded on any machine where the GUI had written
> `"guard_required": false`. The export is the thing that looks authoritative,
> and it was the thing being ignored.
>
> **`GUARD_REQUIRED` is now resolved most-restrictive-wins.** If either the
> environment or the settings file requires the guard, the guard is required.
> Neither source can switch it off over the other's objection, and the default
> with both silent is still `true`. A GUI user who has not set the environment
> variable keeps their toggle; an operator who has set it keeps their guard.
>
> The other two guard keys keep settings-first precedence on purpose: they
> select *which* guard runs, not whether one is required.
>
> The server reports the effective value and its source at startup -
>
> ```
> INFO guard_required = true (from: environment)
> ```
>
> - and disagreement is a WARN, not a silent resolution. `GET /api/config`
> returns the same pair as `guard_required` and `guard_required_source`. To see
> what a settings file is contributing:
>
> ```bash
> cat .ectoledger/settings.json 2>/dev/null || echo "no settings override"
> ```
>
> The file is written only by the GUI; a server-only deployment never creates
> one.

### Core Agent

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | none - required (dev default `postgres://ectoledger:ectoledger@localhost:5432/ectoledger` applies only when `ECTO_DEV_MODE=true`) | Ledger backend. Use `sqlite://ledger.db` for SQLite. An unreachable local Postgres URL triggers an embedded PostgreSQL v15 instance (`pg-embed`). |
| `DATABASE_POOL_SIZE` | `2×CPU` (min 5, max 50) | DB connection pool size. Scales automatically to available CPU cores. |
| `LLM_PROVIDER` | `ollama` | Primary LLM provider preset. Local: `ollama`, `lmstudio`, `llamacpp`, `vllm`, `mlx`, `localai`. Hosted: `openai`, `anthropic`, `gemini`, `azure-openai`, `mistral`, `groq`, `openrouter`, `deepseek`, `xai`. Any other server speaking the OpenAI format: `openai-compatible`. All except `ollama` and `anthropic` share one OpenAI-compatible code path; a preset only supplies defaults (see [Hosted providers](#hosted-providers)). |
| `LLM_BACKEND` | - | **Deprecated alias for `LLM_PROVIDER`**, kept so existing `.env` files keep working. Warns once at startup. Removing it is out of scope for 0.8, so it keeps working. When both are set, `LLM_PROVIDER` wins. |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama server URL. Prefer `127.0.0.1` to `localhost`: on Windows with WSL, `localhost` can reach the WSL relay and a different Ollama. |
| `OLLAMA_MODEL` | `mistral` | Model to pull and use for agent inference. |
| `OPENAI_API_KEY` | - | **[required for openai]** OpenAI API key. In the desktop app a key entered in Settings is kept in the OS credential store and wins over this variable. |
| `GEMINI_API_KEY`, `AZURE_OPENAI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY` | - | **[required for that preset]** Each hosted preset reads its own key variable, not `OPENAI_API_KEY`; the desktop app's credential store wins over each, as for OpenAI. |
| `ANTHROPIC_API_KEY` | - | **[required for anthropic]** Anthropic API key. In the desktop app a key entered in Settings is kept in the OS credential store (macOS Keychain, Windows Credential Manager, Secret Service on Linux) and wins over this variable; it is never written to `settings.json`. |
| `ECTO_LLM_TIMEOUT_SECS` | `300` | Total per-request HTTP timeout for every LLM call - the primary backend and the Guard backend alike, since they share one `reqwest::Client`. 300s is sized for a large local Ollama model; the previous hard-coded 60s timed out every call to a 26B model under load (`error sending request for url (...)`). `0`, negative and non-numeric values are rejected (same as `AGENT_KEY_ROTATION_STEPS`) and fall back to the default rather than producing an instant-timeout client. On timeout, the agent's error names this variable and the configured number of seconds. |
| `AGENT_MAX_STEPS` | `20` | Maximum cognitive loop steps per session. |
| `AGENT_SNAPSHOT_INTERVAL` | `50` | Steps between automatic state snapshots. |
| `AGENT_LLM_ERROR_LIMIT` | `5` | Consecutive LLM errors before aborting the session. |
| `AGENT_GUARD_DENIAL_LIMIT` | `3` | Consecutive guard denials before aborting; a guard error counts as a denial. |
| `AGENT_JUSTIFICATION_FAILURE_LIMIT` | `3` | Consecutive schema failures before aborting. |
| `AGENT_TOKEN_BUDGET_MAX` | unlimited | Maximum approximate token budget per session. |
| `AGENT_KEY_ROTATION_STEPS` | disabled | Steps between Ed25519 signing-key rotations. |
| `AGENT_ALLOWED_DOMAINS` | `[]` | Comma-separated `http_get` domains, used only to seed `tripwire.json` the first time no saved Tripwire configuration exists. Once Tripwire has been saved (CLI or the desktop app), its list is the one enforced and this variable is not read again. |
| `ECTO_POLICY_PATH` | unset | Path to the server-wide `audit_policy.toml`. See below. |

#### `ECTO_POLICY_PATH` - the server's declarative policy

The CLI takes a policy with `--policy`. The Observer had no equivalent until
0.8.0, so every HTTP surface - the Claude Code hook, the SDK's `verify-intent`,
the REST run endpoint - evaluated with **no policy at all** while describing
itself as running "the same pipeline the loop uses". It ran the same *function*;
the rules were missing.

Set this to make the policy apply to all three:

```bash
export ECTO_POLICY_PATH=/etc/ectoledger/audit_policy.toml
```

Unset means no declarative policy, which is the historical behaviour. It is
reported as a skipped layer in every verdict's `coverage`, never passed off as
an evaluation that happened.

**The desktop app's choice (`active_policy`).** Without `ECTO_POLICY_PATH`,
the Policy screen's **Use for new runs** stores a policy name as
`active_policy` in `settings.json`: a built-in pack (`soc2-audit`,
`pci-dss-audit`, `owasp-top10`, `iso42001`) or `policies/<name>.toml` in the
data directory. It applies to Home → Run (`POST /api/sessions`) only, is read
at each session's start (so an edit applies to the next run), and must load
when it is saved (`PUT /api/config` answers 422 otherwise). `ECTO_POLICY_PATH`,
when set, wins. A run session records the hash of the policy it was checked
against, or none.

**Set but unloadable is a startup failure.** A missing file, bad TOML or an
invalid regex stops the `ironvise` binary and the desktop GUI's embedded
backend, rather than serving with the layer silently off. (The router builder
itself logs and continues, so an embedder that skips the startup check gets a
loud error and no policy; both shipped entry points call the check.) The SHA-256
of the file is logged at startup and returned as `coverage.policy_hash`, so a
decision can be tied to the exact rules that made it.


### Hosted providers

| Preset | Base URL | Default model | Key variable |
|---|---|---|---|
| `openai` | `https://api.openai.com/v1` | `gpt-6-astra` | `OPENAI_API_KEY` |
| `anthropic` | `https://api.anthropic.com` | `claude-opus-5-5` | `ANTHROPIC_API_KEY` |
| `gemini` | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-flash-latest` | `GEMINI_API_KEY` |
| `azure-openai` | your resource, `https://<resource>.openai.azure.com/openai/v1` | none: your deployment name | `AZURE_OPENAI_API_KEY` (sent as `api-key`) |
| `mistral` | `https://api.mistral.ai/v1` | `mistral-large-latest` | `MISTRAL_API_KEY` |
| `groq` | `https://api.groq.com/openai/v1` | `openai/gpt-oss-120b` | `GROQ_API_KEY` |
| `openrouter` | `https://openrouter.ai/api/v1` | `openrouter/auto` | `OPENROUTER_API_KEY` |
| `deepseek` | `https://api.deepseek.com/v1` | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| `xai` | `https://api.x.ai/v1` | none: set `OPENAI_MODEL` | `XAI_API_KEY` |

`OPENAI_BASE_URL` and `OPENAI_MODEL` override the address and model of any
OpenAI-compatible preset. A preset with no default address (Azure, LocalAI,
`openai-compatible`) or no default model (Azure, xAI) refuses to start until
one is set, rather than guessing: an Azure key sent to api.openai.com, or a
model name the provider does not serve, fails later and less clearly.
Defaults that name an alias (`-latest`, `auto`, `deepseek-chat`) follow the
provider's current model. The Gemini, Azure, Mistral, Groq, OpenRouter,
DeepSeek and xAI presets follow each provider's API reference and are tested
against recorded request shapes (address, key header, model); they have not
been run live in this repository's test suite.

### Guard Process

| Variable | Default | Description |
|---|---|---|
| `GUARD_REQUIRED` | `true` | Abort startup if guard LLM config is missing. Set `false` only for development. Resolved most-restrictive-wins against `settings.json` - see the box at the top. |
| `GUARD_LLM_BACKEND` | - | **[required when `GUARD_REQUIRED=true`]** Guard LLM provider: same preset names as `LLM_PROVIDER`. |
| `GUARD_LLM_MODEL` | - | **[required when `GUARD_REQUIRED=true`]** Guard LLM model name. |

> **Base URLs.** `OPENAI_BASE_URL` accepts the URL your server prints, with or
> without a trailing `/v1` - both work. LM Studio, llama.cpp, vLLM and MLX-LM all
> print the `/v1` form; appending `/v1` a second time used to produce a 404.
> Servers that are not in the preset list are still supported: use
> `LLM_PROVIDER=openai-compatible` with their base URL.

### Observer Dashboard & API

| Variable | Default | Description |
|---|---|---|
| `OBSERVER_TOKEN` | auto-generated | Bearer token for the dashboard API. Printed to stdout on first run if unset. |
| `ECTO_BIND_HOST` | `127.0.0.1` | Network interface to bind the dashboard listener (loopback only by default). Set to `0.0.0.0` explicitly to expose on all interfaces - the Bearer token then becomes the only access control, so front the server with TLS / a reverse proxy. |
| `ECTO_BIND_PORT` | `3000` | TCP port for the dashboard listener. Override to avoid conflicts in multi-instance deployments. |
| `ECTO_CORS_ALLOWED_ORIGINS` | empty | Extra origins for the Observer API's CORS allowlist (comma-separated). The Tauri webview and local Vite dev-server origins are always allowed. |
| `ECTO_TRUSTED_PROXIES` | empty | Reverse-proxy addresses (comma-separated IPs or CIDRs, e.g. `127.0.0.1,10.0.0.0/8`) allowed to set the rate-limiting client IP via `X-Forwarded-For` / `X-Real-Ip` / `Forwarded`. Default empty: those headers are never trusted and the TCP socket peer is always the rate-limit key, so a direct caller cannot evade its own limit with a spoofed header. A malformed entry is logged and skipped rather than failing startup. |
| `SCANNER_SENSITIVITY` | `medium` | Output scanner level: `low` (structural only), `medium` (default), `high` (broadest). |

### Sandbox Failure Policy

| Variable | Default | Description |
|---|---|---|
| `ECTO_SANDBOX_PERMISSIVE` | `false` | Fail-closed by default: if OS-level sandboxing (Landlock/Seatbelt) or a configured isolation tier (Firecracker/Docker) fails, the action is aborted. Set `true` only in development to permit degraded, less-isolated execution. |

### Webhook / SIEM Egress

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | disabled | Target URL for security event POSTs. Required to enable egress. |
| `WEBHOOK_BEARER_TOKEN` | - | `Authorization: Bearer <token>` header added to every POST. |
| `WEBHOOK_HMAC_SECRET` | disabled | When set, each POST is signed for its receiver: `X-EctoLedger-Delivery`, `X-EctoLedger-Timestamp` and `X-EctoLedger-Signature-V1`, an HMAC over id, timestamp, receiver URL and body under that receiver's own key (`ironvise webhook-key --url`). Verify with the SDKs' `verifyWebhook` / `verify_webhook`, which refuse another receiver's delivery, a timestamp more than 300 s off, and a replayed id. |
| `ECTO_VC_AUDIENCE` | unset | Who session Verifiable Credentials are issued to. Set, each VC carries it as `aud` and a verifier must name it (`verify-vc --audience`, `GET /api/sessions/{id}/vc/verify?audience=`) to accept the VC. Unset, a VC is for anyone to verify. |
| `WEBHOOK_LEGACY_SIGNATURE` | `false` | `true` also sends the pre-0.8 `X-EctoLedger-Signature: sha256=<hex>`, a body-only HMAC under the shared secret that any receiver can replay to any other. Logs a warning at startup. For receivers not yet moved to v1. |
| `WEBHOOK_RATE_LIMIT_PER_SECOND` | `10` | Maximum outbound webhook deliveries per second per URL. |
| `WEBHOOK_INCLUDE_GUARD` | `true` | Include `GuardDenial` events in egress. `false` or `0` (case-insensitive) excludes them. |
| `WEBHOOK_INCLUDE_TRIPWIRE` | `true` | Include `TripwireRejection` events in egress. `false` or `0` (case-insensitive) excludes them. |
| `SIEM_FORMAT` | `json` | Output format: `json`, `cef` (ArcSight), `leef` (IBM LEEF 2.0). |

### Firecracker microVM Sandbox

| Variable | Default | Description |
|---|---|---|
| `ECTO_FC_BINARY` | `/usr/local/bin/firecracker` | Path to Firecracker binary. Setting this opts in to sandbox mode. |
| `ECTO_FC_KERNEL` | `/opt/ectoledger/vmlinux` | Path to Linux kernel image (ELF or Image format). |
| `ECTO_FC_ROOTFS` | `/opt/ectoledger/rootfs.ext4` | Path to root filesystem ext4 image. |
| `ECTO_FC_VCPUS` | `1` | Number of vCPUs per microVM. |
| `ECTO_FC_MEM_MIB` | `128` | Memory (MiB) per microVM. |
| `ECTO_FC_TIMEOUT_SECS` | `30` | Hard execution timeout (seconds). |

### Orchestrator Policy Injection

| Variable | Default | Description |
|---|---|---|
| `ECTO_RECON_POLICY` | built-in | Path to a TOML policy file that overrides the built-in Recon sub-agent policy. |
| `ECTO_ANALYSIS_POLICY` | built-in | Path to a TOML policy file that overrides the built-in Analysis sub-agent policy. |
| `ECTO_VERIFY_POLICY` | built-in | Path to a TOML policy file that overrides the built-in Verify sub-agent policy. |

---


## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | none - required (dev default `postgres://ectoledger:ectoledger@localhost:5432/ectoledger` applies only when `ECTO_DEV_MODE=true`) | Connection string - `postgres://…` or `sqlite://…`. An unreachable local Postgres URL falls back to embedded PostgreSQL v15 (`pg-embed`). |
| `OBSERVER_TOKEN` | *(random, printed at startup)* | Bearer token for Observer dashboard access |
| `LLM_PROVIDER` | `ollama` | Primary LLM provider preset (see above); `LLM_BACKEND` is a deprecated alias |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `mistral` | Ollama model name |
| `GUARD_LLM_BACKEND` | - | Guard process LLM backend (use a different model from primary) |
| `GUARD_LLM_MODEL` | - | Guard process model name |
| `GUARD_REQUIRED` | `true` | Set `true` in production - startup fails if Guard env is missing |
| `AGENT_ALLOWED_DOMAINS` | - | Seeds the Tripwire `http_get` allow-list when no `tripwire.json` exists yet; the saved list wins afterwards |
| `AGENT_MAX_STEPS` | `20` | Maximum agent loop iterations |
| `AGENT_LLM_ERROR_LIMIT` | `5` | Circuit-breaker threshold for consecutive LLM errors |
| `AGENT_GUARD_DENIAL_LIMIT` | `3` | Circuit-breaker threshold for consecutive Guard denials, guard errors included |
| `ECTO_DATA_DIR` | `.ectoledger` | Base data directory (encrypted session keys live in its `keys/` subdirectory) |
| `ECTO_KEY_PASSWORD` | - | Session key password (skips interactive password prompt) |
| `AGENT_CLOUD_CREDS_FILE` | - | Path to JSON cloud credential file |
| `WEBHOOK_URL` | - | HTTP endpoint for async SIEM/webhook egress |
| `WEBHOOK_BEARER_TOKEN` | - | Bearer token appended to webhook requests |
| `SIEM_FORMAT` | `json` | Webhook egress format: `json`, `cef`, `leef` |
| `WEBHOOK_INCLUDE_GUARD` | `true` | Emit `GuardDenial` events to the configured webhook |
| `WEBHOOK_INCLUDE_TRIPWIRE` | `true` | Emit `TripwireRejection` events to the configured webhook |
| `ECTO_DEV_MODE` | `false` | Enable dev defaults (e.g. fall back to the default `DATABASE_URL`). Never set in production |
| `ECTO_DEMO_MODE` | `false` | Demo flag (`1` or `true`). Enables `/api/admin/reset-demo`; on the PostgreSQL path also selects an isolated embedded instance on port 5433. `GET /api/status` field `demo_mode` is this flag only. The insecure-defaults banner is the separate field `insecure_demo` (guard off, or dev mode on). See [demo.md](../getting-started/demo.md) |
| `OPENAI_MODEL` | `gpt-6-astra` | Model name for the OpenAI backend |
| `OPENAI_BASE_URL` | `https://api.openai.com` | OpenAI-compatible API base URL for the **primary** provider (proxies / Azure / local servers). A guard on a different preset uses that preset's default (e.g. `GUARD_LLM_BACKEND=openai` → `https://api.openai.com/v1`), not this value. |
| `ANTHROPIC_MODEL` | `claude-opus-5-5` | Model name for the Anthropic backend |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` | Anthropic API base URL |
| `AGENT_ALLOWED_PROGRAMS` | - | Comma-separated extra programs added to the executor allowlist |
| `ECTO_DOCKER_IMAGE` | `alpine:3.19` | Container image for the Docker sandbox tier |
| `ECTO_DOCKER_MEMORY` | `256m` | Memory limit for Docker-sandboxed `run_command` |
| `ECTO_DOCKER_CPUS` | `1` | CPU limit for Docker-sandboxed `run_command` |
| `ECTO_DOCKER_TIMEOUT` | `30` | Execution timeout (seconds) for the Docker sandbox |
| `ECTO_DOCKER_RUNTIME` | `auto` | Container runtime: `auto`, `docker`, or `podman` |
| `FC_OUTER_TIMEOUT_SECS` | `60` | Outer wall-clock timeout (seconds) for Firecracker microVM execution |
| `ECTO_ENCLAVE_REMOTE_URL` | - | Remote guard-enclave endpoint (feature: `enclave-remote`) |
| `ECTO_ENCLAVE_REMOTE_PCR0` | - | Expected PCR0 (enclave image measurement), hex-encoded SHA-384 (96 hex chars). When set, a remote attestation whose PCR0 does not match is refused (feature: `enclave-remote`) |
| `ECTO_ENCLAVE_REMOTE_PCR1` | - | Expected PCR1 (bootstrap/kernel measurement), hex-encoded SHA-384. Same refuse-on-mismatch behavior as `ECTO_ENCLAVE_REMOTE_PCR0`; unset means unchecked (feature: `enclave-remote`) |
| `ECTO_ENCLAVE_REMOTE_PCR2` | - | Expected PCR2 (application measurement), hex-encoded SHA-384. Same refuse-on-mismatch behavior as `ECTO_ENCLAVE_REMOTE_PCR0`; unset means unchecked (feature: `enclave-remote`) |
| `ECTO_ENCLAVE_REMOTE_PCR8` | - | Expected PCR8 (enclave signing certificate digest), hex-encoded SHA-384. Same refuse-on-mismatch behavior as `ECTO_ENCLAVE_REMOTE_PCR0`; unset means unchecked (feature: `enclave-remote`) |
| `API_RATE_LIMIT_PER_SECOND` | `60` | Global per-IP API request rate limit |
| `API_RATE_LIMIT_BURST` | `120` | Burst allowance for the global API rate limiter |
| `SESSION_RATE_LIMIT_PER_SECOND` | `2` | Per-IP rate limit for `POST /api/sessions` |
| `SESSION_RATE_LIMIT_BURST` | `5` | Burst allowance for the session rate limiter |
| `SSE_RATE_LIMIT_PER_SECOND` | `4` | Per-IP rate limit for the SSE `/api/stream` endpoint |
| `SSE_RATE_LIMIT_BURST` | `10` | Burst allowance for the SSE stream rate limiter |
| `SSE_KEEPALIVE_SECS` | `15` | SSE keep-alive heartbeat interval (seconds) |
| `ECTO_GUARD_WORKER` | `guard-worker` beside the binary | Path of the guard worker binary, for packages or tests that install it elsewhere |
| `ECTOLEDGER_SQLCIPHER_KEY` | - | At-rest encryption passphrase for the SQLite backend (feature: `sqlcipher`). Minimum 16 characters; startup fails if the feature is built in and the key is missing, empty, or shorter. Read once and removed from the environment, so child processes do not inherit it |
| `ECTO_FORCE_PORT_RECLAIM` | `false` | Set `1`/`true` to restore the pre-0.8.0 behaviour of force-killing whatever holds the embedded PostgreSQL port. By default IronVise only reclaims instances it started (verified via its own PID file) and otherwise errors out rather than SIGKILL a process it does not own |
| `ECTO_FORCE_SETUP` | `false` | Set `1`/`true` to make the GUI show the first-run setup wizard even when the environment already looks configured |
| `ECTO_HOST` | - | GUI only: base URL of the Observer backend (e.g. `http://127.0.0.1:3000`). Overrides the GUI's in-process embedded server - useful when developing the frontend against a standalone `ironvise serve` |
| `ECTO_HTTP_CONNECT_TIMEOUT_MS` | `5000` | GUI only: how long the app waits to connect to the Observer backend, in milliseconds; 0 or an invalid value keeps the default |
| `ECTO_HTTP_TIMEOUT_MS` | `30000` | GUI only: how long one request from the app to the Observer backend may take, in milliseconds; 0 or an invalid value keeps the default |

---


## Optional Cargo Features

Beyond the default (`sandbox`), the following optional features are available:

| Feature | Flag | Description |
|---|---|---|
| **ECDSA VC signing** | `--features vc-ecdsa` | P-256 (ECDSA) VC signing alongside the default Ed25519 (EdDSA) scheme |
| **SQLCipher encryption** | `--features sqlcipher` | At-rest encryption for the SQLite backend; set `ECTOLEDGER_SQLCIPHER_KEY`. Builds SQLCipher in place of SQLite and links the system libcrypto, so OpenSSL development files are needed at build time (`libssl-dev`, `brew install openssl@3`) |
| **BLAKE3 hashing** | `--features hash-blake3` | Use BLAKE3 instead of SHA-256 for new events' chain hashes (falls back to SHA-256 for older events). Goal and policy hashes stay SHA-256, as every verifier expects |
| **Enclave IPC** | `--features enclave` | X25519 + ChaCha20-Poly1305 IPC for the guard unikernel |
| **Remote attestation** | `--features enclave-remote` | AWS Nitro COSE_Sign1 attestation, verified against the pinned AWS Nitro root (certificate chain, ES384 signature, nonce, PCR policy) before the enclave's session key is trusted (includes `enclave`) |
| **Apple Hypervisor** | `--features sandbox-apple-enclave` | Boot the guard unikernel on Apple Hypervisor (macOS Silicon; includes `enclave`) |
| **Firecracker microVM** | `--features sandbox-firecracker` | Firecracker-based execution isolation (Linux + KVM required) |
| **Windows icon** | `--features embed-resource` | Embed Windows icon / version-info resource into binaries |

Some features need system dependencies: SQLCipher needs OpenSSL development
files, and Apple Hypervisor needs the bare-metal Rust target and codesigning.

> **Note:** The `sandbox` feature activates Linux-specific Landlock LSM + seccomp-BPF. On macOS and Windows, OS-level sandboxing (Seatbelt / Job Objects) is compiled unconditionally - the `sandbox` flag is a no-op on those platforms.

> **ZK proving is unavailable in 0.8.** The `zk` feature and SP1 host
> dependencies were removed because of RUSTSEC-2026-0387. `prove-audit` exits
> with an explanation; use `report --format certificate` for audit provenance.

---

