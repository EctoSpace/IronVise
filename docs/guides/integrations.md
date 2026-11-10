# Integrations - what each surface sees, and what it can stop

IronVise's value is that its claims survive checking. That only holds if the
difference between **recording** something and **preventing** it is stated
plainly, everywhere, including where stating it is unflattering.

Five of these surfaces enforce (plus `verify_intent`, when the caller honours
its verdict). The rest observe. They are different products and this document
exists so they are never described as one.

Last verified against the code: **2026-10-26** (0.8.0).

## Coverage matrix

| Integration | Sees | Can block | Records in the ledger | Status |
|---|---|---|---|---|
| **Native cognitive loop** | proposed intents, before execution | **Yes** | full chain: intents, actions, observations, refusals | shipped |
| **Claude Code hook** (`ironvise hook`) | tool calls before execution (`PreToolUse`), and what they returned (`PostToolUse`) | **Yes**, for mapped tools | allowed actions, structured refusals, and data receipts (hashes of what each tool returned) | shipped in 0.8.0 |
| **Codex hook** (`ironvise hook install --codex`) | Codex's `Bash`, `apply_patch` and MCP tool calls, before and after | **Yes**, for mapped tools; an escalation is a deny | as the Claude Code hook | shipped in 0.8.0 |
| **Antigravity CLI hook** (`ironvise hook install --antigravity`) | Antigravity's shell, file, search and URL tool calls, before they run | **Yes**, for mapped tools | allowed actions and structured refusals; no data receipts (Antigravity gives a hook no tool result) | shipped in 0.8.0 |
| **MCP proxy** (`ironvise mcp-proxy`) | every `tools/call` of a stdio MCP server, before it reaches the server, and its answer | **Yes** | allowed calls, structured refusals, and data receipts | shipped in 0.8.0 |
| **NVIDIA OpenShell import** (`ironvise import-openshell`) | OpenShell's OCSF decision log, after the fact | No (OpenShell enforces) | every record, signed, one sealed session and receipt per sandbox | shipped in 0.8.0 |
| **SDK `verify_intent`** | intents the caller submits | Yes - the caller must honour the verdict | **nothing** | shipped in 0.8.0 |
| **Recording proxy** (`ironvise proxy`) | prompts and completions | **No** | prompts, completions, flagged patterns | shipped in 0.8.0 |
| **SDK event append** | whatever the caller sends | No | caller-supplied observations, unsigned | shipped |

"Can block" means the surface returns its answer *before* the action runs and
the action does not happen when the answer is no. By that test the proxy cannot
block, and no amount of positioning changes it: a proxy sees a model saying it
wants to run a command. It never sees the command run, and it is not asked.

## Claude Code hook - the honest detail

`ironvise hook` is a `PreToolUse` client. Claude Code calls it before a tool
executes and honours a `deny`, so a refusal recorded here is a refusal that
happened.

**Where it may work.** Every path check below is against the allowed paths.
With no saved tripwire configuration (`$ECTO_DATA_DIR/tripwire.json`, written
by the app's Tripwire screen or `PUT /api/tripwire`), a hook session's
allowed path is the project it runs in: the `cwd` Claude Code sends with its
first tool call, pinned for the rest of that session. A saved configuration
replaces that for every session. The server's own working directory is used
only when Claude Code sends no `cwd`. (Before this, it was always the server's
directory, which for the desktop app opened from Finder is `/`.)

**Tools it evaluates.** Claude Code has many tools; these map onto IronVise
actions the policy and tripwire understand:

| Claude Code tool | IronVise action | Checked on |
|---|---|---|
| `Bash` | `run_command` | the command |
| `Read` | `read_file` | the path |
| `WebFetch` | `http_get` | the URL |
| `Write`, `Edit`, `MultiEdit` | `write_file` | `file_path` |
| `NotebookEdit` | `write_file` | `notebook_path` |
| `Glob`, `Grep` | `read_file` | the directory the search can reach |

**A chain is checked command by command.** `cd x && cargo test 2>&1 | tail`
is split at its unquoted `&&`, `||`, `;`, `|` and `&`, and each command goes
through policy and tripwire on its own; the first refusal decides and names
the command. Checking a chain whole would let `git status && rm -rf x` pass a
policy that allows `git`, since command rules look at the first program.
Quotes are respected. Command substitution (`$(…)`, backticks) and output
redirects are still refused, with one exception: `$(cat <<'EOF' … EOF)` with
a quoted delimiter, which is how Claude Code writes commit messages, is plain
text and is treated as such.

**Writes are checked on where they land, not on what they say.** A write must
stay inside the allowed paths, may create directories there, and may not
follow a symlink out. Three targets are refused even inside the
workspace, because writing them changes what runs outside the agent's tool
calls: `.claude/settings*.json` (the hook's own configuration: a write there
could switch this check off), `.git/hooks/`, and anything under `.ssh/`. A
policy can narrow writes further with an `allowed_actions` entry for
`write_file` and a `path_pattern`, or forbid them with `forbidden_actions`. The
content is not inspected: the policy has no vocabulary for it yet.

**Searches are checked as a read of the directory they can reach.** That is
`path`, or Claude Code's working directory without one. For `Glob`, the literal
start of the pattern is added: `src/**/*.rs` is checked as `src`, and
`/etc/*.conf` as `/etc`, whatever `path` says. A glob pattern that climbs with
`..` (also inside braces, `{src,..}`) is not resolved and returns `ask`.
Grep's regex and its `glob` filter only narrow what is under the directory, so
they do not change the check. One limit: the directory is checked, not each
file found under it, so a symlink inside the project that points out of it is
not caught here.

**Everything else returns `ask`**, which escalates to the human. An unmapped
tool is never silently allowed, and it is never reported as evaluated either.
`Task` and `WebSearch` are in this category today (MCP tools are evaluated as
`mcp:<server>/<tool>`; see below). A mapped tool
sent without the field its check needs also returns `ask`, and the reason says
which case it was. Scope the
`matcher` in your settings to the tools above unless you want to be prompted.

**What runs.** `crate::verify::evaluate_intent`, in policy → tripwire → guard
order - the same order the cognitive loop applies inline in `agent.rs`. The hook
and the SDK's `verify-intent` share this one function; the loop has its own
implementation of the same sequence, which is worth knowing before reading "the
same pipeline" as "literally the same code everywhere".

**Policy.** The declarative policy comes from `ECTO_POLICY_PATH` and is
evaluated here. An earlier cut of this endpoint built its context with `policy:
None` unconditionally: it shared the evaluator with the loop and none of its
rules. If `ECTO_POLICY_PATH` is unset there is no policy layer, and the response
says so rather than implying one ran.

**The semantic guard.** Deterministic checks - policy rules, banned command
patterns, path and domain restrictions, schema validation - always apply. When
the guard is required (`GUARD_REQUIRED`, on by default), the server also starts
one guard worker, shared by the hook and the SDK's `verify-intent`, and asks it
about every call that passes those checks: one model call per tool call, one
call at a time. A guard refusal is `stage: "guard"` and is recorded as a
`guard_denial`. A worker that cannot start, or fails, gives `deny` at
`stage: "guard_unavailable"`, never an `allow`, and the next call starts a new
one. With `GUARD_REQUIRED=false` no guard runs and `coverage` says so.

**Reported coverage.** Every response carries a `coverage` object:

```json
{ "decision": "allow",
  "coverage": { "evaluated": ["policy", "tripwire"],
                "skipped": ["guard"],
                "policy_hash": "9f86d081…" } }
```

An `allow` from a surface with no policy and no guard is a weaker statement than
one from a surface with both, and the response should not make them look
alike.

**Justification.** A Claude Code tool call carries no justification, and the
tripwire's minimum-length rule would otherwise deny every call for the wrong
reason. The hook substitutes a fixed string that *states the absence* rather
than inventing a rationale, because a fabricated justification in an audit
record is worse than an awkward constant.

**Fail-closed.** Claude Code's contract makes the safe default the unusual one:
exit 2 blocks, but every other non-zero exit - and a hook timeout - lets the
tool run. So the client exits 2 on every failure path: unreachable server,
missing token, malformed payload, unparseable answer, unrecognised decision, and
a Rust panic (which would otherwise exit 101). It also enforces its own 10s
deadline, well inside Claude Code's 600s default, because ours blocks and theirs
does not.

Verified against the built binary: no token, unreachable server, malformed
stdin, and a timeout all exit 2.

**Sessions.** One ledger session per Claude Code or Codex `session_id`,
labelled `llm_backend = "claude-code"` or `"codex"` so hook-mediated events
cannot be mistaken for cognitive-loop ones. The signing key lives in memory for the process lifetime;
a server restart starts a new ledger session for the same conversation. Events
already written stay valid - the conversation is split across two chains.

**If a decision cannot be recorded**, the verdict still stands and the response
carries `recorded: false`, surfaced in the reason text. The audit trail has a
hole and says so, rather than the tool call being allowed through.

### Setup

```bash
ironvise hook install            # .claude/settings.local.json in this project
ironvise hook install --shared   # .claude/settings.json, checked in for the team
ironvise hook install --user     # ~/.claude/settings.json, every project
```

It merges into the existing file, replaces an older IronVise hook rather
than adding a second one (two would send each tool use twice, and the second
is refused as a replay), and then checks that the Observer answers and the
token is accepted. The result is equivalent to:

```jsonc
// .claude/settings.json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|WebFetch|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|apply_patch|mcp__.*",
        "hooks": [{ "type": "command", "command": "ironvise hook", "timeout": 15 }]
      }
    ],
    // The same entry: after each call, a data receipt (below).
    "PostToolUse": [ /* same as PreToolUse */ ]
  }
}
```

```bash
export ECTOLEDGER_URL=http://127.0.0.1:3000   # default
export ECTOLEDGER_TOKEN=<an agent or admin token>
```

The token needs the `agent` or `admin` role; `auditor` is refused, because the
endpoint writes.

### Codex

Codex's hooks take the same input and decision JSON as Claude Code's, so the
same `ironvise hook` serves both:

```bash
ironvise hook install --codex          # .codex/hooks.json in this project
ironvise hook install --codex --user   # ~/.codex/hooks.json, every project
```

Codex runs a project's hooks only once you trust them (`/hooks` in Codex).
Its `Bash` calls are checked as commands, and an `apply_patch` as a write to
every file the patch adds, updates, moves to or deletes; one refused file
refuses the patch. Codex cannot ask a person, and runs the tool when a hook
answers `ask`, so under Codex an escalation is sent as a `deny` that says a
person must approve the call. `.codex/hooks.json` and `.codex/config.toml`
are protected like `.claude/settings.json`. Hosted tools such as Codex's web
search never reach a hook, as OpenAI's documentation says.

### Antigravity CLI

Antigravity CLI, which replaced Gemini CLI in June 2026, has its own hook
input (camelCase, the call under `toolCall`) and decision JSON
(`{"decision", "reason"}`); `ironvise hook` reads and answers both:

```bash
ironvise hook install --antigravity          # .agents/hooks.json in this workspace
ironvise hook install --antigravity --user   # ~/.gemini/config/hooks.json
```

It checks `run_command` as a command, `view_file`, `list_dir`,
`find_by_name` and `grep_search` as reads of their file or directory,
`write_to_file`, `replace_file_content` and `multi_replace_file_content` as
writes to their target, and `read_url_content` as an HTTP GET. Its other
tools are not hooked; its MCP tools can go through the
[MCP proxy](#mcp-proxy-any-mcp-client-any-stdio-mcp-server). An allow is
sent as `allow`, which leaves the call to Antigravity's own rules and
prompts (`ECTOLEDGER_HOOK_MODE=approve` sends `auto_approve`); an escalation
is an `ask`.

Three things differ from the Claude Code hook, because Antigravity's hook
contract does not provide them: no data receipt (a `PostToolUse` hook gets
no tool result to hash), no replay check (there is no tool-use id), and the
session is confined to the first workspace Antigravity names. Its exit-code
contract is not documented, so a failure prints a `deny` and exits 2: either
reading refuses the call. `.agents/hooks.json` and
`~/.gemini/config/hooks.json` are protected paths. The ledger session is
labelled `antigravity`.

### Data receipts: what the agent actually received

A decision records what the agent was allowed to do. A receipt records what it
then got back. After each call, the `PostToolUse` half of the hook hashes the
tool's result where it ran and sends the Observer only the receipt, which it
signs and appends as a `data_receipt`: the tool, what it read (a path, a URL, a
command), SHA-256 of the whole response, and SHA-256 of each text the agent
received (a file's contents, command output, page text). The data never leaves
the agent's machine and is never stored, so a receipt cannot leak what it
covers, and a large result costs the same few hundred bytes as a small one.
The Observer refuses a receipt whose hashes are not SHA-256 digests.

Whoever holds the data can check it later, with nothing but the session id:

```bash
ironvise data-receipts <session> --file config.ini
#   ✓ config.ini: exactly what the tool returned at #12
```

The session is verified first; a receipt in a ledger that does not verify
proves nothing. A file matches when a tool returned all of it; a partial read
(an offset, a line limit) is receipted as the part that came back. A receipt
proves what the agent received, not that it was true. Nothing can be blocked
after the fact, so a receipt that could not be recorded is a hook error Claude
Code shows you (exit 1), not a refusal.

The real Claude Code gate checks this end to end: Claude reads a file, the file
matches its receipt, and its text appears nowhere in the ledger.

### What an `allow` means to Claude Code

IronVise only takes permissions away by default. A `deny` blocks the call; an
`allow` is sent as **no decision** (exit 0, no output), so Claude Code's own
permission rules and prompts decide, exactly as without the hook. Every
decision is recorded in the ledger either way.

That is deliberate. Claude Code treats a hook's `allow` as approval: the call
skips the prompt it would otherwise show (your settings' `deny` and `ask`
rules still apply). Forwarding it would make installing a security hook
remove prompts, file edits included.

Set `ECTOLEDGER_HOOK_MODE=approve` in the hook's environment when the policy is
meant to replace the prompts: an `allow` is then sent as `allow`. Any other
value, or none, is the default (`veto`).

The client also forwards `$CLAUDE_PROJECT_DIR`, which Claude Code sets for hook
commands, so the session is confined to the project root even after the agent
`cd`s elsewhere.

### Verified behaviour

Driven against a live Observer on a SQLite ledger (the Observer's answers; the
route tests `the_hook_judges_*` in `crates/host/tests/routes/hook.rs` and
`make demo-hook` pin them):

```
Bash "rm -rf /"                      -> deny   "banned command: rm -rf / (refused at the tripwire stage)"
Bash "ls -la"                        -> allow  (sent to Claude Code as no decision)
Write <project>/src/new/lib.rs       -> allow
Write <project>/.claude/settings.json -> deny  "protected path: … (the agent's own hook configuration …)"
Edit /etc/passwd                     -> deny
Glob "/etc/*"                        -> deny   (checked on /etc)
Glob "{src,..}/*"                    -> ask    "…a search that stays inside its directory…"
Task                                 -> ask    "…has no equivalent in IronVise's policy vocabulary…"
```

The denial was written to the chain as a structured `tripwire_rejection` with
`enforced: true`, signed, and `verify-session` reported all signatures valid.

## MCP proxy: any MCP client, any stdio MCP server

```bash
ironvise mcp-proxy --name files -- npx -y @modelcontextprotocol/server-filesystem ~/work
```

Put the proxy where the client would start the server. It relays JSON-RPC
unchanged except for `tools/call`: each call is sent to the Observer as the
Claude Code tool `mcp__files__<tool>` and judged like one (below). An allowed
call reaches the server; a refused one never does, and the client gets a tool
result with `isError: true` whose text says why, so the model can adapt. It
fails closed: an unreachable Observer, an unparseable line or a batched
`tools/call` is refused, not forwarded. The server's answer to an allowed call
is passed to the client first and then recorded as a data receipt (above): the
proxy hashes it, per text block, and sends only the hashes. Needs `ECTOLEDGER_TOKEN` (agent role).

**How an MCP call is judged**, for the proxy and for Claude Code's own
`mcp__*` tools alike:

- Its action is `mcp:<server>/<tool>`, so a policy can name one tool:
  `[[forbidden_actions]] action = "mcp:files/write_file"`.
- `allowed_mcp_tools` in `tripwire.json` (`["files/read_text_file", "github/*"]`)
  restricts calls to the listed tools; empty allows any.
- An argument named `command`, `cmd` or `script` gets the shell check: chains
  split, banned commands and substitutions refused.
- Other arguments are not interpreted: a path argument is not checked against
  the allowed paths, since each server means something different by it.

`make demo-mcp` runs the official filesystem server behind the proxy with a
policy forbidding `write_file`, and asserts every step: the read goes through,
the write is refused and never happens, both decisions verify, and the file
that was read matches its receipt while its text is nowhere in the ledger.

## NVIDIA OpenShell: signed receipts for its decisions

OpenShell (NVIDIA's open agent sandbox, Apache-2.0) enforces network and
process policy and logs each decision as an OCSF 1.8.0 JSON line. Its own
documentation calls that log best-effort, not proof of a complete history, and
no record carries a hash, signature or sequence. IronVise adds those:

```bash
openshell settings set my-sandbox --key ocsf_json_enabled --value true
openshell sandbox exec --name my-sandbox -- cat /var/log/openshell-ocsf.2026-09-29.log > ocsf.log
ironvise import-openshell ocsf.log            # receipts in ./openshell-receipts
verify-cert --strict openshell-receipts/*.elc   # or drop one on site/verify.html
```

- One ledger session per sandbox (`container.uid`), sealed after import, with
  a signed `.elc` receipt.
- Every record keeps its full content and the SHA-256 of its original line
  (`params.line_sha256`), so the source log can be checked against the ledger
  byte for byte.
- `Denied` becomes a signed refusal whose stage names OpenShell's engine
  (`openshell:opa`, `openshell:l7`, …) and whose reason carries the rule and
  `status_detail`. `Allowed` becomes an action.
- **Audit mode is not hidden.** OpenShell logs a violating request on an
  `enforcement: audit` endpoint as `Allowed`; only its message says `audit`.
  Those are imported with decision `audit`, and the import summary says what
  that means.
- Re-importing a log adds nothing (`metadata.uid`, or the line hash).
- What it cannot prove: that OpenShell logged every decision. It makes what
  was logged tamper-evident from the moment of import.

## Recording proxy - shipped, and it cannot block

`ironvise proxy` is an OpenAI-compatible server that forwards to a real
upstream and records what passes through. Point any agent's base URL at it:

```bash
ironvise proxy --bind 127.0.0.1:3100 --upstream http://127.0.0.1:1234
export OPENAI_BASE_URL=http://127.0.0.1:3100/v1   # in the agent
```

That covers Codex CLI, Cursor, Aider, Continue, OpenClaw and anything else with
a configurable endpoint, with no per-tool work.

**Its limit is architectural, not a to-do.** It sees *text, not actions*. It
never sees a shell command execute; it sees a model asking to run one, and by
the time the agent acts the proxy is out of the path. Calling it a firewall, a
guard, or protection would be false.

`Tripwire::scan_prompt` runs over each outbound prompt - the only check
available at this layer. A match is recorded as a `tripwire_rejection` with
**`enforced: false`**, and the request is forwarded anyway. That field is the
whole distinction: the hook writes `enforced: true` because the action did not
happen, and the proxy writes `false` because it did.

Recorded per chat call: a `prompt_input`, an `observation` for the completion,
and a `tripwire_rejection` when a pattern matched. The session is labelled
`llm_backend = "proxy"`.

A recording failure logs loudly but does not fail the request. An observer that
can halt the thing it observes is worse than one with a gap - the opposite
trade from the hook, and deliberate.

### Verified behaviour

Driven through a live LM Studio upstream:

```
benign prompt          -> forwarded, prompt_input + observation recorded
prompt with "rm -rf /" -> HTTP 200, still forwarded,
                          tripwire_rejection recorded with enforced=false
```

`verify-session` reported all signatures valid.

## SDK

`verify_intent` ships in 0.8.0. `POST /api/sessions/{id}/verify-intent`
(`server::sdk::verify_intent_handler`) runs the caller's proposed action through
`verify::evaluate_intent` and returns the verdict with the stage that produced
it. Both SDKs expose it - `client.verify_intent` in Python,
`client.verifyIntent` in TypeScript.

**It records nothing.** This document said otherwise until it was checked
against the code, and the code never did: the handler writes no ledger event, and the endpoint is readable by
the `auditor` role, which must not be able to write. If you want the decision in
the chain, append it yourself, or use the hook surface, which records. Every
response now carries `"recorded": false` so the answer states it too.

**What it evaluates.** The server-wide policy from `ECTO_POLICY_PATH` when one
is configured, the tripwire, and, when the guard is required, the same shared
guard worker as the hook, judging the action against the session's goal. A
guard that cannot run gives `deny` at `stage: "guard_unavailable"` rather than
an allow. The `coverage` object on every response names the layers that ran,
the ones that did not, and the SHA-256 of the policy that decided.

**The session is real.** The first implementation echoed the submitted UUID
without looking it up,
so a verdict could name a session that had never existed. It is now loaded: an
unknown session is `404`, a session that is not `running` is `409`, and the
session's own goal is what the evaluation is built from.

Read the "can block" column carefully. The server answers **before** the action
runs, so the *decision* is genuine. But the SDK is a library inside the caller's
process: nothing stops a caller from ignoring a deny and acting anyway. That is
a weaker guarantee than the Claude Code hook, where the runtime - not the
audited code - enforces the answer. The row says "the caller must honour the
verdict" because that is the actual contract, not a caveat.

### Event append, and what a client may assert

`POST /api/sessions/{id}/events` records what a caller *reports*. It accepts
only the event kinds a caller can honestly assert about itself -
`observation`, `thought`, `prompt_input`, `chat_message` - and refuses the rest
with `400`.

The reason is `enforced`. `guard_denial` and `tripwire_rejection` carry a flag
whose entire purpose is to say *the system stopped this*; a client that could
post one could manufacture evidence of an enforcement that never ran,
indistinguishable in the chain from a real one. The same applies to `action`,
`genesis`, `anchor`, `key_rotation` and the rest: they describe things the
server did.

Untagged bodies - everything both SDK READMEs and the quickstart show - are
still wrapped as observations, so no documented client changes.

These events are **unsigned**. The session's Ed25519 key is returned once at
creation and never stored, so the server has nothing to sign a client's event
with; they are hash-chained, and a signature would in any case attest that the
server received a claim, not that the claim is true. The Python SDK's API table
said "sign and append"; it appends.

Two related 0.8.x changes close the older gaps this section used to describe:
the AutoGen and LangChain integrations are fail-closed (a recording failure
stops the call rather than being swallowed), and `LedgerCallbackHandler`
replaced the tool the model could decline to call. A voluntary audit trail is
not an audit trail.

## How to check any of this yourself

Start with the demo - it is the Claude Code hook row of the matrix, executed:

```bash
make demo-hook
```

It denies a real disallowed command through the hook, shows the refusal in the
chain, and then shows verification failing after the record is edited. Every
step asserts, so it fails loudly if any claim here stops being true. See
[`examples/demo/`](../../examples/demo/).

- The matrix rows map to code: `crate::verify::evaluate_intent` (shared
  pipeline), `crate::server::hook` (endpoint), `crate::commands::hook` (client).
- `cargo test -p ectoledger --lib hook::` covers the tool mapping, including
  that unmapped tools do not map.
- Every claim about a refusal being recorded can be checked by running the hook
  against a scratch ledger and reading `agent_events` directly.
