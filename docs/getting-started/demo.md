# IronVise Demo Mode

Evaluating enterprise security tools shouldn't require an afternoon of DevOps.
Demo mode gets you from `git clone` to a running Observer dashboard with zero
configuration.

> **Demo mode is insecure by design.** It deliberately weakens the defaults so
> the stack starts without setup. Never expose a demo instance, and read
> [running-securely.md](running-securely.md) before any real deployment.

There are two demo paths, and they do **not** behave the same. Pick the one
that matches your platform.

## macOS / Linux - `make demo`

```bash
make demo
```

This is a thin wrapper - it is exactly equivalent to:

```bash
ECTO_DEMO_MODE=1 DATABASE_URL=sqlite://ectoledger-demo.db \
  cargo run --release -p ectoledger -- serve
```

What you get:

1. **Zero infrastructure.** A SQLite ledger in a single file (`ectoledger-demo.db`
   in the repository root). No Docker, no PostgreSQL, no embedded database, and
   nothing written outside the repository.
2. **The Observer dashboard** on <http://127.0.0.1:3000>, using the token printed
   at startup.
3. **`/api/admin/reset-demo` enabled.** `ECTO_DEMO_MODE` gates that endpoint and,
   on the PostgreSQL path only, selects the isolated demo database.

What you do **not** get: no LLM is installed or detected, and no sample session is
seeded. `make demo` starts the dashboard over an empty ledger. Running an actual
`audit` needs an LLM backend (in 0.8.0 `audit`, `prove-audit`, and `anchor-session`
all work on SQLite as well as PostgreSQL; only `orchestrate`, `diff-audit`, and
`red-team` require PostgreSQL). See [quickstart.md](quickstart.md) for that path.

## Windows - `.\ironvise-win.ps1 -demo`

```powershell
.\ironvise-win.ps1 -demo
```

The PowerShell launcher does considerably more than `make demo`, because Windows
has no equivalent `make` entry point:

1. **Isolated embedded PostgreSQL.** Starts pg-embed on **port 5433** with its own
   data directory (`%LOCALAPPDATA%\ectoledger\postgres-demo`), fully separate from
   your normal-mode database. `-demo -resetDb` wipes it.
2. **LLM auto-detection and provisioning**, in this order:
   - **Cloud API key** - if `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is already set,
     that provider is used and nothing is downloaded.
   - **Existing Ollama** - reused if installed; the `qwen2.5:0.5b` model is pulled
     if absent.
   - **Auto-install Ollama** - otherwise the script warns and counts down 5 seconds
     before running `winget install Ollama.Ollama` (falling back to a direct `.exe`
     download). Press **Ctrl+C** during the countdown to cancel.
3. **Guard disabled.** `GUARD_REQUIRED=false`, so no separate guard LLM is needed.
   Always enable the guard in production.

Because this path provides both PostgreSQL and an LLM, audits work under it.

### Environment variables set by the Windows launcher

| Variable | Value | Purpose |
|---|---|---|
| `DATABASE_URL` | *(unset)* | Cleared so the backend uses embedded PostgreSQL (pg-embed) for full isolation |
| `ECTO_DEMO_MODE` | `true` | Selects the isolated demo database (port 5433, `postgres-demo` data dir) and enables `/api/admin/reset-demo` |
| `ECTO_DEV_MODE` | `true` | Allows a default database URL when `DATABASE_URL` is unset |
| `GUARD_REQUIRED` | `false` | Disables the semantic guard (no separate guard LLM needed in demo) |
| `LLM_PROVIDER` | `ollama` / `lmstudio` / `llamacpp` / `openai` / `anthropic` / … | LLM provider preset (`LLM_BACKEND` is a deprecated alias) |
| `OLLAMA_MODEL` | `qwen2.5:0.5b` | Lightweight model for fast local inference (only when using Ollama) |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama API endpoint (only when using Ollama) |
| `RUST_LOG` | `info` | Log level (preserved if already set) |

`ECTO_DEMO_MODE` is read as true for either `1` or `true` (case-insensitive).

## Cleaning Up

```bash
# make demo - the SQLite ledger is just a file in the repository root:
rm -f ectoledger-demo.db*
```

```powershell
# Windows launcher - wipe the isolated embedded Postgres data directory:
.\ironvise-win.ps1 -demo -resetDb
# or by hand:
Remove-Item -Recurse "$env:LOCALAPPDATA\ectoledger\postgres-demo"
# optionally remove the pulled model:
ollama rm qwen2.5:0.5b
```

`make reset-db` wipes the *normal-mode* embedded PostgreSQL data directory
(`~/Library/Application Support/ectoledger` on macOS,
`${XDG_DATA_HOME:-$HOME/.local/share}/ectoledger` on Linux). `make demo` never
creates one, so you only need it if you have also run the PostgreSQL path.

Demo mode never modifies your `.env` file - all overrides are process-scoped
environment variables only.

## Idempotency

Both demo paths are safe to run repeatedly:
- `make demo` reuses the existing `ectoledger-demo.db`, so the ledger persists
  between runs; delete the file to start fresh.
- On Windows, Ollama is not re-installed if already present, the `qwen2.5:0.5b`
  model is not re-downloaded if already pulled, and the embedded Postgres data
  persists between runs (use `-resetDb` to start fresh).

## Docker Demo (No Rust or Node Required)

If you prefer a fully containerized experience, you can run the IronVise demo using Docker Compose. This method requires only Docker and Docker Compose - no Rust toolchain, Node.js, or local dependencies are needed.

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/EctoSpace/IronVise.git IronVise
   cd IronVise
   ```
2. **Start the demo stack:**
   ```bash
   docker compose -f docker-compose.demo.yml up
   ```
   This will launch:
   - IronVise backend (connects to the PostgreSQL service below via `DATABASE_URL` - no embedded Postgres in the Docker stack)
   - Ollama LLM backend (for local inference)
   - PostgreSQL 17 (`postgres:17-alpine`, for persistent data)

3. **Access the dashboard:**
   Open [http://localhost:3000](http://localhost:3000) in your browser to use the Observer dashboard.

### Stopping and Cleaning Up

- **Stop the demo:**
  ```bash
  docker compose -f docker-compose.demo.yml down
  ```
- **Remove all containers and volumes (reset demo data):**
  ```bash
  docker compose -f docker-compose.demo.yml down -v
  ```

### Notes
- The Docker demo does **not** include the Tauri desktop GUI. For the full desktop experience, run `make start` (macOS/Linux) or `.\ironvise-win.ps1` (Windows).
- The demo stack auto-provisions all required services and models. No manual setup is needed.
- **This demo is insecure on purpose.** The image turns the semantic guard off, turns dev mode on, and listens on `0.0.0.0`. Do not put it on a shared network. A hardened run is [running-securely.md](running-securely.md): `GUARD_REQUIRED=true`, `ECTO_DEV_MODE=false`, and publish the port only on `127.0.0.1`.
- It pulls a **pre-built image**, which can lag your checkout. Build the current source with `scripts/docker-build.sh --load -t ironvise:local` (provenance and SBOM attestations off, so the manifest does not record the source repository URL).
- You can customize ports and environment variables by editing `docker-compose.demo.yml`.

The stack itself is defined in
[`docker-compose.demo.yml`](../../docker-compose.demo.yml), which documents each
service and the security trade-offs it makes.
