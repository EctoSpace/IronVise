# IronVise

Formerly EctoLedger. v0.8 installs the `ironvise` command, which replaces the
old `ectoledger` command. Existing configuration and data remain valid; update
scripts and SDK imports as described in
[upgrade and naming compatibility](docs/reference/compatibility.md).


[![Checks](https://github.com/EctoSpace/IronVise/actions/workflows/checks.yml/badge.svg)](https://github.com/EctoSpace/IronVise/actions/workflows/checks.yml)
[![CI](https://github.com/EctoSpace/IronVise/actions/workflows/ci.yml/badge.svg)](https://github.com/EctoSpace/IronVise/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.8.0-orange.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-1.94%2B%20%7C%20edition%202024-orange.svg)](https://www.rust-lang.org)
[![GitHub issues](https://img.shields.io/github/issues/EctoSpace/IronVise.svg)](https://github.com/EctoSpace/IronVise/issues)
[![Last commit](https://img.shields.io/github/last-commit/EctoSpace/IronVise.svg)](https://github.com/EctoSpace/IronVise/commits/main)

<p align="center">
  <img src="assets/ironvise-logo.webp" alt="IronVise Logo" width="250" />
</p>

**Pre-execution firewall and tamper-evident flight recorder for AI agents.**
It blocks risky tool calls (reading SSH keys outside the workspace,
`rm -rf /`, fetching from a domain you did not allow) before they run, and
exports offline-verifiable audit certificates for EU AI Act Article 12
record-keeping and ISO 42001 evidence.

IronVise sits between an AI agent and the things it does. Every action the
agent proposes is checked against your policy, run inside an
[OS sandbox](docs/reference/sandboxing.md), and written to a hash-chained,
Ed25519-signed ledger. Later, anyone can verify that record offline, without
your database, your keys, or your cooperation.

Built for EU AI Act Article 12 record-keeping, which applies to Annex III
high-risk systems from [2 December 2027](docs/compliance/eu-ai-act-article12.md)
(2 August 2028 for Annex I). Article 12 requires high-risk
AI systems to keep automatic logs. It does not require those logs to be hard to
edit afterwards, and that gap is the whole point of this project: it is for
teams who will have to hand agent logs to somebody who does not trust them.

**It complements your sandbox; it does not replace it.** A sandbox such as
[Docker Sandboxes (`sbx`)](https://docs.docker.com/ai/sandboxes),
[Perplexity SPACE](https://github.com/perplexityai/SPACE) or
[E2B](https://e2b.dev) limits what an agent can reach once a command runs.
IronVise decides whether the command should run at all, and keeps a signed
record of what was proposed, allowed, refused and returned that someone else
can check later. Use both: IronVise in front, the sandbox underneath.

**Status: prototype, not independently audited.** What it catches and what
bypasses it is written down in [docs/reference/threat-model.md](docs/reference/threat-model.md).

<p align="center">
  <img src="site/marketing_assets/videos/ironvise_gui_demo.gif" alt="IronVise 0.8 interface walkthrough with demonstration data" width="820" />
</p>

## Try it

**In your browser, nothing to install.** Open
[ectospace.com/IronVise/verify.html](https://ectospace.com/IronVise/verify.html),
click a sample certificate, then the one with a single character changed. The
verifier is the same Rust code compiled to WebAssembly; nothing is uploaded.

**With Docker** (dashboard, REST API and a small local model, no Rust needed;
the first run downloads the images and a 0.5B Ollama model). The published
image and `docker-compose.demo.yml` are a demo, not a locked-down deployment:

- semantic guard off (`GUARD_REQUIRED=false`)
- dev mode on (`ECTO_DEV_MODE=true`, so the well-known dev database credentials are accepted)
- dashboard bound to every interface (`ECTO_BIND_HOST=0.0.0.0`)

Startup logs `WARN INSECURE DEMO MODE` while any of that is true. Do not expose
that process beyond your own machine.

```bash
git clone https://github.com/EctoSpace/IronVise.git IronVise && cd IronVise
docker compose -f docker-compose.demo.yml up
# open http://localhost:3000
```

Build the image from this checkout, without publishing it and without embedding
the source repository URL in the manifest:

```bash
scripts/docker-build.sh --load -t ironvise:local
```

A secure run (guard required, dev mode off, port published only on loopback)
is [docs/getting-started/running-securely.md](docs/getting-started/running-securely.md).

**From source** (Rust 1.94+), watch it refuse a command:

```bash
git clone https://github.com/EctoSpace/IronVise.git IronVise && cd IronVise
make demo-hook
```

![a disallowed command denied, recorded, and the record shown to be tamper-evident](docs/assets/hook-denial-demo.gif)

A Claude Code `PreToolUse` call for `rm -rf /` is denied before it runs, the
refusal lands in the hash chain, and `verify-session` passes. Then one field of
that record is rewritten in the database and `verify-session` fails. No
Postgres, no model, and the script asserts every step, so it doubles as an
end-to-end test ([`examples/demo/`](examples/demo/)). The same hook has run
inside real Claude Code, Codex CLI and Antigravity CLI
([docs/reference/testing.md](docs/reference/testing.md)).

Want to try breaking it instead? [`examples/challenge/`](examples/challenge/)
ships five ledgers, two genuine, and asks you to say which.

## Install

| You want | Get it |
|---|---|
| Desktop app (macOS, Windows, Linux) | Installers on the [Releases page](https://github.com/EctoSpace/IronVise/releases) (`.dmg`, `.msi` / `.exe`, `.AppImage` / `.deb`), or `make start` from a clone |
| CLI and server (`ironvise`, `verify-cert`, `guard-worker`) | Archives on the [Releases page](https://github.com/EctoSpace/IronVise/releases), or `cargo build --release -p ectoledger` |
| Docker image | `docker pull ghcr.io/ectospace/ironvise:0.8.0` |
| Python SDK (LangChain and AutoGen adapters) | `pip install ironvise` ([sdk/python](sdk/python/README.md)) |
| TypeScript / JavaScript SDK | `npm install ironvise` ([sdk/typescript](sdk/typescript/README.md)) |
| Windows, from a clone | `.\ironvise-win.ps1` (checks prerequisites, builds, starts the app) |

The Windows `.msi` and `.exe` install the desktop app only. They do not add `ironvise` to PATH. The Windows command-line tools are the release zip `ironvise-x86_64-pc-windows-msvc.zip` (`ironvise.exe`, `guard-worker.exe`, `verify-cert.exe`). Unzip it and add that folder to PATH, or run the executables by path.

Linux `.deb`, `.AppImage`, and CLI archives on the Releases page are built on Ubuntu 22.04 and need glibc 2.35 or newer (Ubuntu 22.04, Debian 12, and later). The official 0.6.3 Linux binaries needed glibc 2.38 or 2.39 and do not run on Ubuntu 22.04. A binary you compile yourself needs the glibc of the machine that linked it.

The Linux package is now `iron-vise`. It replaces the 0.6.3 package `ecto-ledger` instead of installing beside it. The desktop data directory stays `io.ectoledger.agent-ledger`. See [docs/reference/compatibility.md](docs/reference/compatibility.md).

The guided walkthrough, from demo mode to a first real audit, is
[docs/getting-started/quickstart.md](docs/getting-started/quickstart.md).

## Where to read more

| | |
|---|---|
| What it catches, and what bypasses it | [docs/reference/threat-model.md](docs/reference/threat-model.md) |
| How each claim here is tested, with the numbers | [docs/reference/testing.md](docs/reference/testing.md) |
| Which integrations can *stop* an action, and which only record one | [docs/guides/integrations.md](docs/guides/integrations.md) |
| The Article 12 mapping, requirement by requirement | [docs/compliance/eu-ai-act-article12.md](docs/compliance/eu-ai-act-article12.md) |
| Every doc, with a one-line description | [docs/README.md](docs/README.md) |

---

## Security model (read this first)

IronVise governs agents that run **on its own cognitive loop** (or that call
it through the SDKs). Every proposed action passes a verification pipeline
before it is committed and executed:

1. **Policy engine** - allow/forbid lists, conditional command rules,
   observation content rules, approval gates (TOML policy packs).
2. **Guard process (dual-LLM)** - a secondary model in a separate
   process reviews each intent against the session goal. On by default for
   the CLI (`GUARD_REQUIRED`, with `GUARD_LLM_BACKEND`/`GUARD_LLM_MODEL`);
   off by default in the embedded desktop app.
3. **Strict schema validation** - sealed intent schema with
   `deny_unknown_fields`; anything outside the four allowed keys is rejected.
4. **Tripwire** - structural rules: path traversal/symlink checks, domain
   allowlist + HTTPS, banned command patterns, shell-metacharacter rejection,
   justification minimums.

Approved actions execute under OS-level sandboxes - Linux Landlock + seccomp,
macOS Seatbelt, Windows Job Objects - with optional Docker/Podman and
Firecracker microVM tiers. **Sandbox failures abort the action** (fail-closed;
`ECTO_SANDBOX_PERMISSIVE=true` opts into degraded execution for development).
Every event is appended to a hash-chained, Ed25519-signed ledger (PostgreSQL
or SQLite) that can be replayed, exported as `.elc` certificates or W3C
Verifiable Credentials, and timestamped with OpenTimestamps. Through the Claude
Code and Codex hooks and the MCP proxy it also keeps **data receipts**: SHA-256 of what each tool returned, never the data, so whoever holds
a file can later show it is exactly what the agent read
([how](docs/guides/integrations.md#data-receipts-what-the-agent-actually-received)).

### Honest limitations

- **This is a prototype.** It has not been independently audited.
- It only governs what runs through it. An agent (or attacker) that executes
  outside the IronVise loop is invisible to it.
- The ledger is tamper-***evident***, not tamper-*proof*: rewrites by an
  attacker with database access are detectable - and externally provable once
  the tip is anchored - but not physically impossible. Detection assumes you
  know the session's public key independently; someone who can rewrite the
  ledger can also substitute the key and re-sign, which is what anchoring, not
  signing, defends against. The findings fixed in 0.8.0 are listed in
  [CHANGELOG.md](CHANGELOG.md); the remaining limits are in
  [docs/reference/threat-model.md](docs/reference/threat-model.md).
- The deterministic guard layers have documented bypasses (encodings, word
  splitting, semantic rephrasing); see [docs/reference/threat-model.md](docs/reference/threat-model.md).
- No LLM-based check is absolute. The guard raises the cost of prompt
  injection; it does not eliminate it.
- macOS Seatbelt denies network access to sandboxed commands as a whole;
  it does not provide per-domain allowances (see
  [Security warnings](#security-warnings) and
  [docs/reference/sandboxing.md](docs/reference/sandboxing.md)).
- The **Firecracker microVM tier needs a guest image you supply.**
  `scripts/setup-firecracker.sh` installs the Firecracker project's `hello`
  demo rootfs, which is a connectivity/plumbing test only - it has no guest
  agent and cannot execute intents. `scripts/provision-firecracker.sh` builds
  a minimal busybox rootfs that *does* implement the protocol when the
  official rootfs it tries first is unavailable. Running real intents in a
  microVM otherwise requires a rootfs implementing the `/dev/vdb` intent
  protocol documented in
  [docs/reference/sandboxing.md](docs/reference/sandboxing.md#firecracker-guest-image-contract).
  For working isolation without building an image, use the Docker tier
  (`ECTO_DOCKER_IMAGE`).
- Certificates and credentials are supporting evidence for your compliance
  processes; they are not a legal guarantee, and IronVise itself cannot be
  "ISO 42001 certified" - see [docs/compliance/iso42001.md](docs/compliance/iso42001.md).

## What it is not

IronVise uses no blockchain. It is not a SIEM, ticketing, or GRC suite; not a
guarantee that a compromised host or out-of-loop process behaves; and not a
legal shield by itself.

## Quick start

Prerequisites: Rust 1.94+ (edition 2024). Docker only for the Postgres demo;
Node only for the GUI - 20.19+ (Vite 8), 22.13+ to run its unit tests
(Vitest 5); the desktop app runs on macOS 11+, Windows 10+ and Linux. A model is needed for `audit`/`orchestrate`/`red-team`:
a local one (Ollama, LM Studio, llama.cpp, vLLM, MLX-LM, LocalAI) or a hosted
API (OpenAI, Anthropic, Gemini, Azure OpenAI, Mistral, Groq, OpenRouter,
DeepSeek, xAI); see [providers](docs/guides/configuration.md#hosted-providers).

**Cold paths (Makefile):**

```bash
make start       # Desktop GUI (embedded backend; SQLite by default, audits included)
make demo        # SQLite + demo mode, no Docker
make demo-hook   # Honest Claude Code hook demo (records + can deny)
make backend     # Observer API alone (default DATABASE_URL=sqlite://…; postgres:// for multi-agent)
```

**CLI:**

```bash
# Zero-infrastructure Observer (browse / verify - not the cognitive loop)
DATABASE_URL="sqlite://ledger.db" cargo run -p ectoledger -- serve
# Dashboard: http://127.0.0.1:3000 (loopback-only by default; use the printed token)

# The guard is on by default: name the model that reviews each step, and
# build its guard-worker binary once (cargo run builds only ectoledger)
export GUARD_LLM_BACKEND=ollama GUARD_LLM_MODEL="your-pulled-model"
cargo build -p ectoledger

# Run an audit against a Postgres ledger (started automatically if missing)
ECTO_DEV_MODE=true cargo run -p ectoledger -- audit "Audit the login endpoint for OWASP Top 10"

# With a compliance policy pack
ECTO_DEV_MODE=true cargo run -p ectoledger -- audit "..." --policy crates/host/policies/soc2-audit.toml

# Export a certificate from the same ledger (audit prints the session id),
# then verify it offline: the verifier needs no database
ECTO_DEV_MODE=true cargo run -p ectoledger -- report --format certificate --output audit.elc <session-id>
cargo run -p ectoledger -- verify-certificate audit.elc
```

Home → Run in the desktop GUI works with the default embedded SQLite ledger
(or PostgreSQL if you set a `postgres://` URL in Settings / Custom setup).

The guided walkthrough (demo mode, GUI, first production audit) lives in
[docs/getting-started/quickstart.md](docs/getting-started/quickstart.md). Doc index: [docs/README.md](docs/README.md).

## Architecture

The cognitive loop is a strict pipeline: **Perceive → Propose → Verify →
Commit → Execute.**

```mermaid
flowchart LR
  Perceive[Perceive State]
  Propose[Propose Intent]
  Policy[Policy Engine]
  Guard[Guard Process]
  Tripwire[Tripwire]
  Commit[Commit to Ledger]
  Execute[Execute Side Effect]
  LLM[Primary LLM]
  DB[(Ledger Backend\nPostgres · SQLite)]
  Host[Host]
  Perceive -->|restore from backend| Propose
  Propose -->|LLM JSON| LLM
  LLM --> Propose
  Propose --> Policy
  Policy --> Guard
  Guard --> Tripwire
  Tripwire -->|allowed only| Commit
  Commit -->|hash-chain + Ed25519| DB
  Commit --> Execute
  Execute -->|run / read / http| Host
  Execute -->|observation scanned| DB
```

1. **Perceive** - restore agent state from the ledger (latest snapshot +
   replayed events).
2. **Propose** - the primary LLM returns a single JSON intent
   (`run_command`, `read_file`, `http_get`, `complete`).
3. **Verify** - policy engine → guard process → tripwire; reject or accept.
4. **Commit** - verify the goal hash, append the action to the ledger
   (hash-chained, Ed25519-signed, canonical v2 hash scheme - see
   [docs/reference/schema.md](docs/reference/schema.md)).
5. **Execute** - run the side effect under the sandbox, scan the observation,
   append it. Loop until `complete` or `max_steps`.

**The agent is the database:** the Rust process is a transient worker; all
durable state lives in the ledger and is restored on each run. Nothing is
ever updated or deleted - the schema enforces append-only writes.

## Ledger backends

| Backend | Connection string | Best for |
|---|---|---|
| **PostgreSQL** | `postgres://user:pass@host/db` | Production, multi-agent, high throughput |
| **SQLite** | `sqlite://ledger.db` | Local development, CI, single-machine audits, desktop GUI |

SQLite mode supports `serve`, `audit`, `replay`, `verify-session`, `report`
(including certificate export), `anchor-session`, live webhook
delivery, `verify-certificate`, and `verify-vc`. The multi-agent commands
`orchestrate`, `diff-audit`, and `red-team` still require PostgreSQL.
Cross-backend chain verification uses one canonical content-hash scheme
([docs/reference/schema.md](docs/reference/schema.md)); ledgers written by older versions keep
verifying through the scheme-fallback path.

## Evidence exports

- **`.elc` audit certificates** - self-contained records verified offline by
  the standalone `verify-cert` binary (no Rust, database, or LLM required).
- **W3C Verifiable Credentials** - Ed25519-signed VC-JWT per completed
  session, `did:key:`-anchored, verifiable via CLI or REST.
- **Reports** - JSON, SARIF, HTML, GitHub Actions, GitLab Code Quality.
- **Timestamping** - submit the ledger tip hash to the public
  OpenTimestamps calendars (`anchor-session`, preview); a timestamp is what
  upgrades "tamper-evident" to "provably existed at a point in time". Only
  the hash leaves the machine.
SP1 zero-knowledge proving is unavailable in 0.8 because of an upstream
security advisory. `prove-audit` explains the withdrawal; standard `.elc`
export and verification remain available.

## Receiver binding

Nothing private leaves IronVise valid for whoever finds it ([arXiv 2608.09867](https://arxiv.org/abs/2608.09867) showed why).
- Providers' encrypted reasoning never reaches the ledger; only its SHA-256 does.
- Webhooks are signed for one receiver; the SDK verifiers refuse other receivers' deliveries, stale ones and replays.
- Hook and SDK requests are bound to their token, and a replay is refused (signed into the session where the server holds its key).
- Receipts (`.elc`, VCs) stay public on purpose. See [docs/reference/threat-model.md](docs/reference/threat-model.md).

## Management GUI and SDKs

The Tauri 2 desktop app (`gui/`) bundles the backend with an embedded SQLite
ledger: live dashboard, session browser, cognitive-loop audits, policy editor,
tripwire config, token management, and certificate export. API keys entered
in Settings go to the OS credential store. The semantic guard is off by
default in the app; turn it on in Settings. Screen by screen:
[docs/guides/desktop-app.md](docs/guides/desktop-app.md).

Typed REST SDKs: [`sdk/python`](sdk/python/README.md) (with LangChain and
AutoGen adapters) and [`sdk/typescript`](sdk/typescript/README.md).

## Documentation

The full index is [docs/README.md](docs/README.md): getting started, guides
(integrations, policies, CLI, configuration, desktop app), reference
(architecture, threat model, sandboxing, schema, certificate format, testing)
and compliance mappings. Outside `docs/`:

| Document | Contents |
|---|---|
| [SECURITY.md](SECURITY.md) | Supported versions and how to report a vulnerability privately |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Licence, the local gate, and what is structural |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Running tests

```bash
make test                               # cargo test --workspace
make test-qa                            # workspace tests + workflow/Tauri guards + hook-denial demo
./scripts/test-integration.sh           # Postgres integration tests (Docker)
make test-api                           # black-box HTTP API suite against a fresh server
make test-e2e                           # end to end on this OS with a real model (needs Ollama);
                                        #   Windows: py scripts\qa\run.py
cargo test -p ectoledger --test qa_contracts         # path/seal/scanner/verify contracts
cargo test -p ectoledger --test adversarial_guards   # 124 adversarial tests, 116 or 117 run per OS
cargo test -p ectoledger --test guard_corpus         # guard evaluation corpus (live run: see tests/guard-corpus)
make check-sdk                          # every server route wrapped by both SDKs
cd gui && npm run check                 # GUI type-check
make test-gui-unit                      # GUI unit tests (Vitest 5, jsdom 29: Node 22.13+)
```

What each layer proves, what it has found, and what is not tested:
[docs/reference/testing.md](docs/reference/testing.md).

CI workflows are manual (`workflow_dispatch`) on this repository; what they
run, and the local equivalent before a release cut:
[docs/reference/testing.md#ci](docs/reference/testing.md#ci).

## Security warnings

**macOS network restrictions.** Seatbelt denies network access for sandboxed
`run_command` children. It does not provide per-domain allowances.
`AGENT_ALLOWED_DOMAINS` governs the host's `http_get` action, not arbitrary
child-process traffic. Permissive execution without Seatbelt loses this
restriction. See [docs/reference/sandboxing.md](docs/reference/sandboxing.md).

**Network exposure.** The Observer dashboard binds to `127.0.0.1` by default.
If you set `ECTO_BIND_HOST=0.0.0.0`, the Bearer token becomes the only access
control - front the server with TLS and a reverse proxy.

**The demo image is insecure by design.** `docker-compose.demo.yml` and the
published container run with the semantic guard disabled, dev mode on, and the
dashboard bound to all interfaces. The server logs a `WARN INSECURE DEMO MODE`
banner whenever it is in that state. Before any real use, follow
[docs/getting-started/running-securely.md](docs/getting-started/running-securely.md) - the short version is
`GUARD_REQUIRED=true`, `ECTO_DEV_MODE` unset, `ECTO_BIND_HOST=127.0.0.1`.

## Enterprise and consulting

EctoSpace offers paid help for teams putting IronVise into production:

- Custom policy packs mapped to ISO 42001 controls or SOC 2 criteria
- SIEM integration (forwarding ledger events and verdicts to your existing
  security tooling)
- EU AI Act Article 12 record-keeping setup: retention, export, and an
  evidence process your auditors can follow

Contact [ironvise@ectospace.com](mailto:ironvise@ectospace.com).

## Licensing

Business Source License 1.1.

- **Free for non-production use**: download, inspect, modify, and run locally
  for testing, development, and research.
- **Commercial license required for production** deployments.
- **Open-source conversion**: this version's license automatically converts
  to Apache 2.0 on April 1, 2030.

For commercial licensing or support, contact
[ironvise@ectospace.com](mailto:ironvise@ectospace.com).
