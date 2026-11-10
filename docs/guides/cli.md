# CLI Reference

Full reference for the `ironvise` command-line interface. The `ectoledger`
binary is the same program. Run any command via `cargo run -p ectoledger -- <subcommand>` or the installed binary.

**Support status.** Commands marked *preview* ship and work, but sit outside
the 0.8 support contract: their behaviour and output may change without a
deprecation period, and problems with them are fixed as capacity allows. They
are `orchestrate`, `diff-audit`, `red-team`, `anchor-session` and `verify-vc`.
`prove-audit` is *unavailable in 0.8*. `--help`
shows the same markers. Everything else is supported.

### Global flags

| Flag | Description |
|---|---|
| `--version`, `-V` | Print the build version and exit 0. Reports the workspace version from the root `Cargo.toml` (currently `0.8.0`). |
| `--help`, `-h` | Print usage. Also available per subcommand: `ironvise audit --help`. |

```bash
ironvise --version
# ironvise 0.8.0
```

### `serve` - start the Observer dashboard

```bash
cargo run -- serve
# Observer: http://localhost:3000?token=<printed token> (API calls: Authorization: Bearer <token>;
# ?token= is taken only on /api/stream, session event streams and /metrics)

# Verify the full chain from genesis on startup (default: only the last 1000 events)
cargo run -- serve --verify-full
```

| Endpoint | Description |
|---|---|
| `GET /` | Observer dashboard (real-time SSE, content redacted; `/api/events` redacts for agent tokens only) |
| `GET /metrics` | Prometheus metrics |
| `GET /api/metrics/security` | Security events JSON: injection attempts, denials, aborts, chain failures, plus `total_sessions` and `total_events` (ledger rows) and `guard_denials`, `tripwire_rejections` (this server's counters) |
| `POST /api/tripwire/check` | The tripwire's answer for one proposed action (`{action, params, justification?}`) against the saved rules: `{allowed, reason, rule, matched}`. Records nothing. |
| `GET /api/approvals/<session_id>/pending` | Pending approval gate state |
| `POST /api/approvals/<session_id>` | Submit an approval decision |
| `GET /api/status` | Public liveness. `demo_mode` is `ECTO_DEMO_MODE`. `insecure_demo` is the banner (guard off, or dev mode on). |

### `health` - probe the local Observer

```bash
ironvise health
```

Exits 0 when `GET http://127.0.0.1:$ECTO_BIND_PORT/api/status` (port 3000 if
unset) returns HTTP 200. No database and no curl. The container `HEALTHCHECK`
runs this. A refused connection or any other status exits 1.

### `audit` - run an AI agent audit

```bash
# Basic audit
cargo run -- audit "Read server_config.txt"

# With a compliance policy
cargo run -- audit "Audit Cargo.toml dependencies" \
    --policy crates/host/policies/soc2-audit.toml

# SQLite backend - no infrastructure required
DATABASE_URL=sqlite://ledger.db \
    cargo run -- audit "Quick local audit"

# Cloud credential injection
AGENT_CLOUD_CREDS_FILE=~/.ectoledger/aws-audit.json \
    cargo run -- audit "Audit S3 bucket policy for public exposure" \
    --policy crates/host/policies/soc2-audit.toml

# Interactive approval gates (stdin - no dashboard required)
cargo run -- audit "Run nmap scan" --policy gate_policy.toml --interactive

# Development only - disable guard (requires explicit confirmation flag)
cargo run -- audit "Quick read" --no-guard --no-guard-confirmed

# Verify the full chain from genesis before running (default: last 1000 events)
cargo run -- audit "Full-chain audit" --verify-full

# Read the key-encryption password from a file descriptor (Unix; safer than an env var).
# Without it, audit asks on the terminal; when stdin is not a terminal it asks nothing
# and saves no key file.
cargo run -- audit "..." --key-password-fd 3  3< <(pass show ironvise)
```

### `report` - export session reports

```bash
# Supported formats: json (default), sarif, html, certificate (.elc),
#                   github_actions, gitlab_codequality
cargo run -- report <session_id> --format sarif    --output report.sarif
cargo run -- report <session_id> --format html     --output report.html
cargo run -- report <session_id> --format certificate --output audit.elc
cargo run -- report <session_id> --format github_actions
cargo run -- report <session_id> --format gitlab_codequality --output codequality.json

# Skip OpenTimestamps submission when generating a certificate (offline / air-gapped)
cargo run -- report <session_id> --format certificate --no-ots --output audit.elc

# Sign the certificate with the key `audit` saved for the session
cargo run -- report <session_id> --format certificate --output audit.elc \
    --key-password-fd 3  3< <(pass show ironvise)
```

Exits with code `1` when any finding is `high` or `critical` severity - suitable as a CI gate.

A certificate is signed when the session has a saved signing key (`audit` saves one when given a password) and its password is supplied: by `--key-password-fd`, `ECTO_KEY_PASSWORD`, or the prompt. A blank password writes it unsigned; a wrong one is an error.

### `verify-session` - verify Ed25519 event signatures

```bash
cargo run -- verify-session <session_id>
```

Two checks, composed. Each event's hash is recomputed from its stored payload
(falling back through the pre-0.7.0 schemes, so older ledgers still verify), and
the signature is then verified against the event's own `content_hash`. Together
these bind the payload to the signing key. A failure names the event and what
went wrong - `altered after signing` is a different fact from `signature does
not verify`, and the ledger says which.

Fails non-zero on the first bad event. For a survey that reports instead of
failing, use `verify-ledger`.

**Against a certificate you kept.** Two tampers cannot be seen from the
database alone: events removed behind a rewritten seal, and a session re-signed
with another key. A certificate exported earlier contradicts both:

```bash
cargo run -- verify-session <session_id> --against audit.elc --expected-key <hex from the issuer>
```

The certificate must verify with a signature first. Then the session's key and
every event hash it covers must still match. Events added after it was cut
(anchors, for example) are reported and not failed.

An event without a signature passes only if some legitimate path writes that
kind unsigned: what a client may append (`observation`, `thought`,
`prompt_input`, `chat_message`) and what the server writes without the key
(`cross_ledger_seal`, `anchor`). An unsigned `approval_decision`, which ledgers
from before 0.8 hold beside the signed one, passes only when the session has a
signed decision for the same gate. Those are counted in the
output, since they are covered by the hash chain but not by a signature. Any
other unsigned event fails. A session that records no key and has no
signatures is reported as unsigned, not verified: nothing in it is bound to
anyone. (Before 0.8.0 all of these passed; see F-4 under Fixed in
[CHANGELOG.md](../../CHANGELOG.md).)

### `verify-ledger` - read-only integrity survey of every session

```bash
cargo run -- verify-ledger           # only the failures
cargo run -- verify-ledger --all     # every session
cargo run -- verify-ledger --strict  # exit 1 if any session fails
```

Runs the `verify-session` checks across the whole database and prints a verdict
per session. It never writes, and it is deliberately exempt from the startup
chain check that other commands run, so it can open a ledger that is already
broken.

Use it after upgrading to 0.8.0: verification is stricter than in any previous
release (see the Security section of `CHANGELOG.md`), and this tells you whether
anything you already hold is affected before a stricter check starts refusing it.

**Exit codes.** By default the survey exits 0 whatever it finds - a session that
does not verify is a finding, not a failure of the tool, which is the whole
difference between this command and `verify-session`. That default is wrong for
a script, so `--strict` exits 1 when any session fails. The survey output is the
same either way; `--strict` only decides whether the pipeline stops. A survey
that cannot run at all (no SQLite file, a PostgreSQL database that is missing
or unreachable) exits 2, so a script can tell "nothing to survey" from "a
session does not verify". The survey opens the ledger read-only and never
creates one.

```bash
# In CI: fail the job if anything in the ledger no longer verifies.
ironvise verify-ledger --strict --all
```

Exit 2 is reserved for the command failing to run at all - no ledger schema at
`DATABASE_URL`, an unreadable database - which is a different thing from a
ledger that verifies badly, and `--strict` does not change it.

### `verify-certificate` - offline certificate verification

```bash
cargo run -- verify-certificate audit.elc

# Standalone binary (no Rust, PostgreSQL, or Ollama required - ship to auditors)
./target/release/verify-cert audit.elc
```

Both run the same checks (one implementation, `crates/elc`) and accept the
same flags. So does the browser verifier, `site/verify.html`, which is that
implementation compiled to WebAssembly:

| Flag | Effect |
|---|---|
| `--strict` | Require a signature that verifies. Without it an unsigned certificate is reported as *internally consistent* and exits 0. |
| `--expected-key <hex>` | Require the signature to be by this Ed25519 public key. Implies `--strict`. |
| `--require-anchor` | Require a Bitcoin attestation in the OTS stamp. A freshly taken stamp is a calendar server's promise and does not satisfy this. |
| `--export-ots <FILE>` | Write the certificate's stamp as a standard `.ots` file for `ots upgrade` and `ots verify`. |
| `--ots <FILE>` | Read the stamp from this `.ots` file instead, for example after `ots upgrade`. It must stamp this certificate's tip. Upgrades live beside the certificate: rewriting `ots_proof_hex` would break the signature. |
| `--issuer <hex>` | Require a countersignature by this installation issuer key (see `issuer-key`). On its own it satisfies `--strict`. Not on the browser page yet. |

The default mode **inspects**: it recomputes the hash chain, the Merkle root and
the goal hash from the file's own contents. A certificate forged from scratch
satisfies all three, so internal consistency is not issuer authentication. Only
the signature ties the document to a key, and only a key you obtained away from
the certificate ties that key to anyone - which is why `--expected-key` takes
one rather than reading it from the file.

```bash
verify-cert --strict --expected-key <hex from the issuer> audit.elc
```

See [`examples/verified-session/README.md`](../../examples/verified-session/README.md)
for a signed certificate and the key that signed it.

### `data-receipts` - what a session's tools returned, by hash

```bash
ironvise data-receipts <session_id>                     # list the receipts
ironvise data-receipts <session_id> --file config.ini   # check a file (repeatable)
```

Lists the session's `data_receipt` events (tool, source, SHA-256 of each text
the tool returned) and, with `--file`, checks each file against them: a match
means a tool returned exactly those bytes. Exits 1 when a file matches no
receipt, and refuses a session that does not verify. See
[`docs/guides/integrations.md`](integrations.md#data-receipts-what-the-agent-actually-received).

### `issuer-key` - the installation's certificate issuer key

```bash
ironvise issuer-key init             # create it and print its public key
ironvise issuer-key show             # print the public key
ironvise issuer-key init --replace   # make a new one
```

With an issuer key (`issuer.key` in `ECTO_DATA_DIR`, owner-only), every
certificate this installation exports is countersigned by it, including an
export made after the session's own key is gone. Hand relying parties the
public key once; they check with `verify-cert --issuer <hex>`. Replacing the key
does not invalidate certificates it already signed. Offline, no database.

### `verify-vc` - decode and verify a W3C VC-JWT (preview)

```bash
# Structure + expiry check only
cargo run -- verify-vc "eyJhbGci..."

# Also verify the Ed25519 signature against the issuer's verifying key
cargo run -- verify-vc "eyJhbGci..." --issuer-hex <hex-encoded verifying key>

# A VC issued with ECTO_VC_AUDIENCE carries `aud`: name yourself to accept it
cargo run -- verify-vc "eyJhbGci..." --issuer-hex <key> --audience https://auditor.example
```

Decodes the credential, checks structure and expiry, and (when `--issuer-hex` is supplied) verifies the Ed25519 signature over the VC payload. Runs fully offline - no database required.

### `import-openshell` - signed receipts for NVIDIA OpenShell decisions

```bash
ironvise import-openshell ocsf.log [more.log …] [--out openshell-receipts]
```

Reads OpenShell's OCSF JSON-lines decision log. One sealed session per
sandbox, each record signed with the SHA-256 of its original line, audit-mode
allows recorded as `audit`, and a signed `.elc` receipt per session in `--out`.
Lines that are not JSON objects are reported with `file:line` and skipped.
Needs `DATABASE_URL`. See [docs/guides/integrations.md](integrations.md#nvidia-openshell-signed-receipts-for-its-decisions).

### `mcp-proxy` - check MCP tool calls (enforces)

```bash
ECTOLEDGER_TOKEN=<agent token> ironvise mcp-proxy --name files -- \
  npx -y @modelcontextprotocol/server-filesystem ~/work
```

Runs the MCP server after `--` and relays stdio JSON-RPC between it and the
client. Each `tools/call` is judged by the Observer as `mcp:<name>/<tool>`
(policy, `allowed_mcp_tools`, the command check on `command`-like arguments)
and recorded; a refused call returns to the client as a tool error and never
reaches the server. Fails closed. Exits with the server's exit code. See
[docs/guides/integrations.md](integrations.md#mcp-proxy-any-mcp-client-any-stdio-mcp-server).

### `webhook-key` - one receiver's webhook signing key

```bash
WEBHOOK_HMAC_SECRET=... ironvise webhook-key --url https://siem.example/ironvise
```

Prints the 64-hex key that receiver verifies `X-EctoLedger-Signature-V1` with, derived from `WEBHOOK_HMAC_SECRET` and the URL exactly as configured. Give each receiver only its own key: none of them can then sign a delivery another would accept. Offline, no database.

### `replay` - replay a session

```bash
cargo run -- replay <session_id>
cargo run -- replay <session_id> --to-step 5
cargo run -- replay <session_id> --inject-observation "seq=3:injected content"
```

Useful for debugging and adversarial testing.

### `diff-audit` - compare two sessions (preview)

```bash
cargo run -- diff-audit \
    --baseline <session_id> \
    --current  <session_id> \
    [--output  diff.json]
```

### `orchestrate` - multi-agent security audit (preview)

Runs three sequential sub-agents - **Recon → Analysis → Verify** - each in an independent ledger session. On completion, a `CrossLedgerSeal` event with a length-prefixed SHA-256 commitment is appended to every session, cryptographically binding them together without merging their event chains.

> **Security note:** The cross-ledger seal hash uses length-prefixed encoding (`len(tip) || tip`) for each input to prevent boundary-collision attacks where `sha256("AB" || "C")` would equal `sha256("A" || "BC")` without prefixes.

```bash
cargo run -- orchestrate "Audit the Rust dependency tree for known vulnerabilities"
cargo run -- orchestrate "Audit Nginx config" \
    --policy shared_policy.toml --max-steps 25

# Per-role policy overrides via environment variables:
ECTO_RECON_POLICY=/etc/ectoledger/strict-recon.toml \
ECTO_VERIFY_POLICY=/etc/ectoledger/strict-verify.toml \
    cargo run -- orchestrate "Audit production Kubernetes configuration"
```

**Policy resolution order (highest priority first):**
1. Role-specific env var (`ECTO_RECON_POLICY`, `ECTO_ANALYSIS_POLICY`, `ECTO_VERIFY_POLICY`)
2. Shared `--policy` file (applies to all roles if role-specific var is not set)
3. Built-in hardcoded defaults

| Sub-agent | Allowed actions | Notes |
|---|---|---|
| **Recon** | `read_file`, `run_command` | `http_get` is forbidden |
| **Analysis** | `read_file` | Receives Recon observations as goal context; produces findings |
| **Verify** | `read_file` | Independently confirms each Analysis finding before completing |

### `anchor-session` - OpenTimestamps timestamp (preview)

```bash
cargo run -- anchor-session <session_id>
```

Submits the ledger tip hash to the OpenTimestamps calendar pool and appends an `Anchor` event to the session holding the pending stamp. Only the hash leaves the machine. The stamp is a calendar's promise until it is upgraded after a Bitcoin block confirms it (`ots upgrade`). `--chain bitcoin` is accepted for compatibility and is the only value.

### `red-team` - adversarial defense testing (preview)

```bash
cargo run -- red-team --target-session <session_id>
cargo run -- red-team --target-session <session_id> \
    --attack-budget 100 --output red-team-report.json
```

Generates injection payloads via LLM and tests each against the output scanner and tripwire in isolation. Exit code `1` when any payload passes all checks - integrate directly into CI. For single-payload manual testing, use `replay --inject-observation` instead.

### `prove-audit` - unavailable in 0.8

SP1 proving and the `zk` build feature were withdrawn because their upstream
dependencies contain crypto-bigint 0.5.5 (RUSTSEC-2026-0387). This command
exits 1 before opening a database or loading a signing key. It writes no proof.

The legacy arguments `<session_id>`, `--policy`, `--output` (`-o`), `--no-ots`,
and `--key-password-fd` are still recognized so existing scripts receive the
withdrawal message. For a supported signed certificate, use:

```bash
ironvise report --format certificate --output audit.elc <session_id>
```

Existing certificates retain their optional `zk_proof` field. As before,
`verify-cert` reports that field but does not verify SP1 proofs.

### `hook` - Claude Code PreToolUse client (enforces)

```bash
ironvise hook install [--shared | --user] [--codex | --antigravity] [--project DIR] [--command CMD]
```

`hook install` writes the hook into Claude Code's settings (default
`.claude/settings.local.json` in the current project), keeping the rest of the
file and never adding a second IronVise hook, then checks the Observer and
`ECTOLEDGER_TOKEN`. `--codex` writes Codex's `.codex/hooks.json` instead
(`~/.codex/hooks.json` with `--user`); see [Codex](integrations.md#codex).
`--antigravity` writes Antigravity CLI's `.agents/hooks.json`
(`~/.gemini/config/hooks.json` with `--user`); see
[Antigravity CLI](integrations.md#antigravity-cli). Plain `hook` is what the agent runs:

Reads Claude Code's hook JSON on stdin, asks the Observer to verify the tool call, and writes the decision on stdout. Claude Code honours a deny *before* the tool runs.

This **enforces**. It is not the recording proxy. See [docs/guides/integrations.md](integrations.md) for the coverage matrix.

```bash
# In ~/.claude/settings.json (scope the matcher to tools the hook actually evaluates):
#   Bash → run_command, Read → read_file, WebFetch → http_get,
#   Write / Edit / MultiEdit / NotebookEdit → write_file (checked on the path)
#   Glob / Grep → read_file (checked on the directory the search can reach)
# Everything else returns `ask` (escalates to the human).

# An allow is sent as no decision, so Claude Code's own prompts still apply.
# ECTOLEDGER_HOOK_MODE=approve sends it as "allow" (skips the default prompt).
ECTOLEDGER_TOKEN=<observer-token> \
ECTOLEDGER_URL=http://127.0.0.1:3000 \
  ironvise hook
```

Fail-closed: any error (missing token, unreachable server, malformed stdin, timeout, panic) exits **2**, which is the only Claude Code exit that blocks the tool. Needs a running Observer (`ironvise serve` or the desktop app).

### `proxy` - OpenAI-compatible recording proxy (records only)

Point any agent's base URL at this and every prompt and completion is written to the hash chain. Covers Codex CLI, Cursor, Aider, Continue, and anything else with a configurable endpoint.

This **records only**. It cannot block: it sees text, not actions. For enforcement use `hook`.

```bash
ironvise proxy --bind 127.0.0.1:3100 --upstream https://api.openai.com

# Then point the agent at the proxy:
#   OPENAI_BASE_URL=http://127.0.0.1:3100
```

Needs a running Observer and a configured `DATABASE_URL`. Flagged prompt patterns are recorded as `tripwire_rejection` with `enforced: false`.

The proxy has no authentication, so `--bind` must be a loopback address. A non-loopback one (`0.0.0.0`, a LAN address, or a name that resolves to one) is refused unless `--allow-remote` is passed: anyone who can reach the proxy can write to the ledger through it.

---

