# IronVise - Quickstart

---

## 0. Verify something first (no setup, no trust required)

The fastest useful thing you can do with IronVise is check a certificate it
produced, and then fail to forge one. This needs Rust and nothing else - no
Docker, no PostgreSQL, no model, no network, and no licence from us (the BUSL's
Additional Use Grant states that verification is not Production Use).

```bash
git clone https://github.com/EctoSpace/IronVise.git IronVise
cd IronVise
cargo build --release --bin verify-cert

./target/release/verify-cert examples/verified-session/session.elc
#   CERTIFICATE VALID     exit 0

./target/release/verify-cert examples/verified-session/session-tampered.elc
#   CERTIFICATE INVALID   exit 1   (one hex character was changed)
```

Once built, both checks take under a second. The build itself is the cost, and
on a clean machine it is minutes, not seconds - the crate graph behind the
verifier is the same one behind the server. `scripts/audit-quickstart.sh` runs
this whole path and times it if you want the number for your own hardware.

[`examples/verified-session/`](../../examples/verified-session/) explains what is
in the certificate, what the tampered copy changes, and which mutations are
worth trying against it.

---

## 1. Prerequisites

| Tool | Install | Required? |
|---|---|---|
| **Rust 1.94+** | [rustup.rs](https://rustup.rs/) | Yes - all builds |
| **Docker Desktop** | [docker.com](https://www.docker.com/products/docker-desktop/) | Only for the Docker demo stack and integration tests - the default embedded-PostgreSQL backend, `make demo`, and SQLite mode need no Docker |
| **Node.js 20.19+** (22.13+ for the GUI's unit tests) | [nodejs.org](https://nodejs.org/) | Only for the desktop GUI, which runs on macOS 11+, Windows 10+ and Linux |
| **An LLM** | [Ollama](https://ollama.com/) (local) or an OpenAI / Anthropic API key | Yes - powers the agent |

Release builds of the Linux CLI, `.deb`, and `.AppImage` are made on Ubuntu 22.04 and need glibc 2.35 or newer. A binary you build on this machine needs this machine's glibc instead. The published 0.6.3 Linux binaries needed glibc 2.38 or 2.39 and do not run on Ubuntu 22.04. The Windows `.msi` and `.exe` install the desktop app and do not put `ironvise` on PATH; the CLI is the Windows zip on the Releases page.

---

## 2. Clone & Launch

### One-command start (recommended)

**macOS / Linux:**
```bash
git clone https://github.com/EctoSpace/IronVise.git IronVise
cd IronVise
make setup     # builds the CLI binary, installs GUI deps, creates .env
make start     # opens the desktop GUI
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/EctoSpace/IronVise.git IronVise
cd IronVise
.\ironvise-win.ps1
```

`make setup` checks for `cargo` and `npm`, creates `.env` from
`.env.example` if you don't have one, builds `target/release/ironvise`,
and installs the GUI's npm packages. `make start` then launches the Tauri
desktop app, which runs its own backend in-process on an ephemeral
loopback port - there is no separate server to start.

Press **Ctrl+C** to stop.

> The first `make setup` compiles the whole Rust workspace and takes a few
> minutes. Later runs are incremental.

### Zero-config demo

Want to see it running without an LLM, Docker, or PostgreSQL?

```bash
make demo                    # macOS / Linux
.\ironvise-win.ps1 -demo   # Windows
```

This serves the Observer dashboard on <http://127.0.0.1:3000> against a
local SQLite ledger with `ECTO_DEMO_MODE=1`. The startup banner prints the
access token - open the printed URL. Note that demo mode disables the
semantic guard; see [running-securely.md](running-securely.md) before using
any of this for real work.

### Make shortcuts (macOS/Linux)

| Command | What it does |
|---|---|
| `make` or `make start` | Launch the desktop GUI (backend runs in-process) |
| `make setup` | First-time build + deps + `.env`, no servers started |
| `make backend` | Observer server only, no GUI, on `127.0.0.1:3000` |
| `make demo` | SQLite + demo mode, no LLM or Docker needed |
| `make rebuild` | Force-rebuild the CLI binary, then start |
| `make reset-db` | Wipe the embedded PostgreSQL data directory |
| `make test` | Run all Rust unit tests |
| `make check` | Type-check the Svelte/TypeScript GUI |
| `make clean` | Remove build artifacts and `node_modules` |

Run `make help` to list every target.

---

## 3. Choose Your Backend

| Backend | Setup | Connection string |
|---|---|---|
| **SQLite** (simplest) | Nothing - zero infrastructure | `DATABASE_URL=sqlite://ledger.db` |
| **PostgreSQL** | Embedded - auto-provisioned via `pg-embed` (no Docker required) | `DATABASE_URL=postgres://ectoledger:ectoledger@localhost:5432/ectoledger` |

SQLite is the zero-config default and supports `audit`, certificate export,
`prove-audit`, `anchor-session`, and live webhook delivery. PostgreSQL is still
required for multi-agent `orchestrate`, `diff-audit`, and `red-team`.

**`DATABASE_URL` has no default** - set it explicitly, or set `ECTO_DEV_MODE=true`
to opt into the embedded PostgreSQL with default dev credentials. Running a
command without either prints the three options and exits. Switch backends any
time by changing `DATABASE_URL` in `.env`.

If the embedded PostgreSQL reports that port 5432 is already in use, IronVise
will **not** kill the process holding it - point `DATABASE_URL` at your existing
server, switch to SQLite, or stop the other process yourself.

---

## 4. Configure an LLM

Edit `.env` (created by `make setup`; otherwise `cp .env.example .env`):

**Option A - Ollama (local, free):**
```bash
LLM_PROVIDER=ollama
OLLAMA_MODEL=mistral
# Start Ollama: ollama serve
# Pull model:   ollama pull mistral
```

**Option B - a local OpenAI-compatible server (LM Studio, llama.cpp, vLLM, MLX-LM, LocalAI):**
```bash
LLM_PROVIDER=lmstudio                          # or llamacpp / vllm / mlx / localai
OPENAI_BASE_URL=http://127.0.0.1:1234/v1       # the URL your server prints
OPENAI_MODEL=<the model id the server reports>
# Many local servers want any non-empty key:
# OPENAI_API_KEY=not-needed
```
These all speak the same protocol on their own port, so one code path serves
them. The trailing `/v1` is optional - with or without it works. Anything else
speaking that format works too: use `LLM_PROVIDER=openai-compatible` with its
base URL.

**Option C - OpenAI:**
```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

**Option D - Anthropic:**
```bash
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

**Option E - another hosted API (Gemini, Azure OpenAI, Mistral, Groq, OpenRouter, DeepSeek, xAI):**
```bash
LLM_PROVIDER=groq                              # or gemini / mistral / openrouter / deepseek / xai / azure-openai
GROQ_API_KEY=gsk_...                           # each preset reads its own key variable
```
Addresses, default models and key variables are listed under
[Hosted providers](../guides/configuration.md#hosted-providers).

> `LLM_BACKEND` still works as a deprecated alias for `LLM_PROVIDER`, so an
> existing `.env` needs no change. It warns once at startup; removing it is
> out of scope for 0.8, so it keeps working.

---

## 5. Your First Audit

### Run the audit

`audit` runs the full cognitive loop and needs a reachable LLM (see steps 3
and 4). It also runs the guard, a second model that reviews every step
before it executes. The guard is on by default (`GUARD_REQUIRED=true`) and
needs its model named, or `audit` stops before recording anything:

```bash
GUARD_LLM_BACKEND=ollama
GUARD_LLM_MODEL=llama3.2   # ideally a different model from the agent's
```

For a first local try only, `GUARD_REQUIRED=false` runs without it.
The guard runs as its own `guard-worker` binary, which `cargo run` does not
build; build the package once first:

```bash
cargo build -p ectoledger   # ectoledger, ironvise, guard-worker and verify-cert
```

SQLite is the zero-config default; PostgreSQL remains available for
production and multi-agent work:

```bash
# Zero-config SQLite ledger (file created under the app data dir if needed)
DATABASE_URL=sqlite://ledger.db cargo run -- audit "Read server_config.txt"

# Embedded PostgreSQL with dev credentials
ECTO_DEV_MODE=true cargo run -- audit "Read server_config.txt"

# …or against your own PostgreSQL
DATABASE_URL=postgres://user:pass@localhost:5432/ectoledger \
  cargo run -- audit "Read server_config.txt"
```

SQLite supports `serve`, `audit`, `replay`, `verify-session`, `report`
(including certificate export), `prove-audit`, `anchor-session`,
`verify-certificate`, and `verify-vc`. Multi-agent `orchestrate` / `diff-audit` / `red-team` also require
PostgreSQL. The desktop GUI on SQLite can run audits from Home → Run:

```bash
DATABASE_URL=sqlite://ledger.db cargo run -- serve
# or: make start / make demo
```

```bash
DATABASE_URL=sqlite://ledger.db cargo run -- audit "Read server_config.txt"
# or: make demo-hook
```

### View the dashboard

The server prints an `OBSERVER_TOKEN` on startup. Open:

```
http://localhost:3000?token=<printed-token>
```

The page reads the token from its own URL and sends it as an
`Authorization` header. The API itself takes `?token=` only on event streams
and `/metrics`, where a browser cannot send a header.

Or use the Tauri desktop GUI which connects automatically.

`audit` prints the session id when it starts (`Session <id> started.`) and the
commands below when it finishes.

### Export a certificate

Works on both backends. On SQLite:

```bash
DATABASE_URL=sqlite://ledger.db cargo run -- report <session_id> \
  --format certificate --output audit.elc
```

On PostgreSQL:

```bash
DATABASE_URL=postgres://… cargo run -- report <session_id> \
  --format certificate --output audit.elc
```

The certificate is **signed** when `audit` saved the session's signing key,
which it does when you give it a password at its prompt (or with
`--key-password-fd`); `report` then asks for that password. Without one it is
written unsigned, and the verifier says `CERTIFICATE INTERNALLY CONSISTENT …
but unsigned` instead of `CERTIFICATE VALID`: every check holds, but nothing
in the file says who issued it.

`report` also submits the session's chain-tip hash, and nothing else, to a
public OpenTimestamps calendar, so the certificate carries a pending Bitcoin
timestamp. Pass `--no-ots` to stay offline.

### Verify offline

```bash
# With cargo
cargo run -- verify-certificate audit.elc

# Or use the standalone binary (ship to auditors - no Rust/Postgres/Ollama needed)
./target/release/verify-cert audit.elc
```

---

## 6. Your First Orchestration

Run a multi-agent security audit (Recon → Analysis → Verify):

```bash
cargo run -- orchestrate "Audit the Rust dependency tree for known vulnerabilities"
```

Each sub-agent runs in its own ledger session. On completion, a `CrossLedgerSeal` cryptographically binds all sessions together.

---

## 7. Apply a Compliance Policy

```bash
# SOC 2
cargo run -- audit "Audit access controls" \
    --policy crates/host/policies/soc2-audit.toml

# OWASP Top 10
cargo run -- audit "Audit web app security" \
    --policy crates/host/policies/owasp-top10.toml

# PCI-DSS
cargo run -- audit "Audit cardholder data environment" \
    --policy crates/host/policies/pci-dss-audit.toml
```

`iso42001.toml` is a controls mapping (ISO 42001 clauses to ledger evidence),
not a set of rules, so it cannot govern an audit; see
[docs/compliance/iso42001.md](../compliance/iso42001.md).

---

## 8. SDK Integration

### Python

```bash
pip install ./sdk/python     # from a clone; installs the ironvise package
```

The server requires a bearer token on every API call - it prints an
`OBSERVER_TOKEN` at startup, and you can also set one yourself. Both examples
below read it from the environment:

```bash
export ECTOLEDGER_TOKEN=<the token the server printed>
```

```python
import asyncio
import os

from ironvise_sdk import LedgerClient

async def main():
    async with LedgerClient(
        "http://localhost:3000",
        bearer_token=os.environ["ECTOLEDGER_TOKEN"],
    ) as client:
        session = await client.create_session(goal="Audit Cargo.toml", record=True)
        await client.append_event(session.session_id, {"step": "read", "file": "Cargo.toml"})
        ok = await client.verify_chain(session.session_id)
        print("Chain intact:", ok)
        await client.seal_session(session.session_id)

asyncio.run(main())
```

LangChain and AutoGen integrations are also available - see [sdk/python/README.md](../../sdk/python/README.md).

### TypeScript

```bash
cd sdk/typescript && npm install && npm run build
# Then install the built package into your application:
# npm install /absolute/path/to/IronVise/sdk/typescript
```

Use 0.8.0 or newer of either SDK: the 0.6.x releases have no `verifyIntent`,
the call that asks permission before an action instead of only recording it.

```typescript
import { IronViseClient } from "ironvise";

const client = new IronViseClient({
  baseUrl: "http://localhost:3000",
  bearerToken: process.env.ECTOLEDGER_TOKEN,
});
const session = await client.createSession({ goal: "Summarise report", record: true });
await client.appendEvent(session.id, { step: "retrieved_docs" });
const ok = await client.verifyChain(session.id);
await client.sealSession(session.id);
```

Zero external dependencies - uses native `fetch` (Node 18+, browsers, Deno, Bun). See [sdk/typescript/README.md](../../sdk/typescript/README.md).

---

## 9. Production Checklist

Before deploying to production, review these settings in `.env`:

- [ ] **`GUARD_REQUIRED=true`** - enforce dual-LLM guard on every intent
- [ ] **`GUARD_LLM_BACKEND` / `GUARD_LLM_MODEL`** - configure the guard LLM (use a different model from primary)
- [ ] **`OBSERVER_TOKEN`** - set explicitly (don't rely on auto-generated)
- [ ] **`WEBHOOK_URL`** - point to your SIEM for real-time security event egress
- [ ] **`WEBHOOK_HMAC_SECRET`** - enable HMAC signing for webhook integrity
- [ ] **`AGENT_ALLOWED_DOMAINS`** - restrict `http_get` to known-good domains
- [ ] **`DATABASE_URL`** - use PostgreSQL for multi-instance deployments
- [ ] Review [sandboxing.md](../reference/sandboxing.md) for platform-specific isolation

---

## 10. Running Tests

```bash
# Unit tests (no database required)
cargo test --workspace

# Adversarial prompt injection tests (124 payloads, pure Rust, < 0.1s)
cargo test -p ectoledger --test adversarial_guards

# Integration tests (Docker Postgres)
./scripts/test-integration.sh

# Integration tests (SQLite)
DATABASE_URL=sqlite://test.db cargo test --features integration
```

---

## Next Steps

| Resource | Description |
|---|---|
| [README.md](../../README.md) | Full documentation - architecture, CLI reference, configuration, policy DSL |
| [docs/reference/schema.md](../reference/schema.md) | Database schema and migration history |
| [docs/compliance/iso42001.md](../compliance/iso42001.md) | ISO 42001:2023 control mapping reference |
| [docs/guides/scaling.md](../guides/scaling.md) | Horizontal scaling guide (PostgreSQL) |
| [audit_policy.example.toml](../../audit_policy.example.toml) | Annotated example policy file |
| [sdk/python/README.md](../../sdk/python/README.md) | Python SDK full API reference |
| [sdk/typescript/README.md](../../sdk/typescript/README.md) | TypeScript SDK full API reference |
