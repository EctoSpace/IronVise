# Threat Model - Adversarial Test Coverage

This document summarizes what IronVise's deterministic guard layers are
tested to catch, what is **known to bypass** them, and how false positives are
controlled. It is generated from the adversarial test suite in
[`crates/host/tests/adversarial_guards.rs`](../../crates/host/tests/adversarial_guards.rs),
124 tests in total (113 run everywhere, plus 4 Linux-only, 3 macOS-only and
4 Windows-only, so 116 run on macOS and 117 on Linux or Windows), most of them hand-crafted adversarial payloads against the
**output scanner** and **tripwire** layers. Every test is deterministic - no
LLM, no database, no network - so the suite runs on every `cargo test`.

Run it directly:

```sh
cargo test -p ectoledger --test adversarial_guards          # all categories
cargo test -p ectoledger --test adversarial_guards tripwire_bypass   # one category
```

## Scope

The suite covers the two deterministic layers of the four-layer pipeline:

| Layer | What it does |
|---|---|
| **Output scanner** | NFKC-normalized regex pass, strict-schema JSON validation, structural JSON/AST extraction, and base64 decoding over every observation before it is appended to the ledger. |
| **Tripwire** | Structural validation of proposed intents: path traversal/symlink checks, domain allowlist + HTTPS, banned command patterns, shell-metacharacter rejection, justification minimums. |

The two LLM-dependent layers - the policy engine's semantic rules and the
dual-LLM guard process - are **not** covered by this deterministic suite; they
are exercised separately (and the guard is disabled by default in the embedded
desktop app - see the Settings panel warning).

## Payload categories

| Category | Tests | Layer tested | Examples |
|---|---|---|---|
| Goal injection | 31 | Output scanner (regex + JSON) | "ignore previous instructions", `<system>`/`[INST]` template tags, markdown-fenced action JSON, role injection |
| Tripwire bypass | 28 | Tripwire (structural) | `..` traversal, symlink escapes, `sudo`/`rm -rf` obfuscation (`r\m -rf`), shell chaining metacharacters, UNC paths / ADS (Windows), `/etc/shadow` (Linux) |
| Output scanner evasion | 30 | Output scanner (all passes) | Unicode homoglyphs, zero-width characters, base64-encoded action JSON (`eyJ…`), embedded `data:`/`javascript:` URIs, prompt-continuation markers |
| Semantic guard | 12 | Output scanner + tripwire | Goal-hijacking keys (`override_goal`, `system_prompt`), strict-schema violations via extra JSON fields |
| Ancillary | 10 | Tripwire (URL, path, allowlist) | HTTPS enforcement, domain allowlist, executable allowlist, justification length |
| Output formatting, injection matrix, regression | 13 | Sandbox output encoding; tripwire; schema | Sandbox output field presence/truncation, a command-injection matrix (`&`, `\|`, backticks), and fixed-bug regressions (e.g. `deny_unknown_fields` against smuggled JSON keys) |

## What is caught

- Direct injection phrases and their common Unicode obfuscations (homoglyphs,
  zero-width characters) after NFKC normalization.
- Action-shaped JSON smuggled into observations - including inside markdown
  fences and base64 (`eyJ…`) blobs - via the structural JSON/AST pass and the
  sealed `StrictAgentOutput` schema (`deny_unknown_fields`).
- Path traversal (component-level `..`), symlink escapes out of the workspace,
  NTFS alternate data streams, and UNC paths.
- Banned commands including quoting/backslash obfuscations that shlex
  tokenization normalizes (e.g. `r\m -rf` → `rm -rf`), plus shell chaining
  operators.
- Non-HTTPS URLs, non-allowlisted domains, internal/metadata hostnames.

## Known bypasses (documented false negatives)

These payloads are **intentionally asserted to evade** the scanner at
`medium` sensitivity. Each has a test that will fail - deliberately - the day
the gap is closed, so this list stays honest:

- **ROT13-encoded instructions** - no ROT13 decode pass.
- **Leetspeak substitution** (`1gn0r3 pr3v10us…`) - digit substitution breaks
  word-pattern regexes.
- **Whitespace / backslash splitting** (`i g n o r e`, `i\gnore`) - breaks
  contiguous-word matching.
- **Soft hyphen (U+00AD) word breaks** - preserved by NFKC and not in the
  zero-width strip list.
- **HTML-comment phrase splits** - split the phrase across a comment boundary.
- **URL-encoded spaces** (`%20`) - prevent `\s+` matching.
- **Right-to-left override (U+202E)** - reversed text defeats forward regexes.
- **Short base64 blobs without a JSON prefix** - below the size threshold and
  missing the `eyJ` prefix (e.g. base64 of `cat /etc/shadow`).
- **Hex-encoded commands in observations** - `scan_observation` has no hex
  pass (the prompt-side tripwire scan does).
- **Pig-latin / semantic reordering** - no semantic pass in the deterministic
  layers.
- **Payloads split across sibling JSON array elements** - the structural pass
  checks each object independently.

Mitigations for this residue: the guard LLM (when enabled) evaluates intent
semantics rather than surface patterns; the executor's program allowlist and
argument blocklist run at execution time regardless of what the scanner
missed; and OS sandboxes (Landlock/Seatbelt/Job Objects, or the
Firecracker/Docker tiers) bound what an executed command can reach. Since
v0.8.0, sandbox setup failure aborts the action instead of degrading
(`ECTO_SANDBOX_PERMISSIVE=false` default).

## False-positive controls

The suite includes control tests asserting that benign content passes:
safe commands (`ls -la`, `grep`), ordinary prose, legitimate JSON without
action shapes, and allowed URLs are accepted by the same tripwire and scanner
configurations that reject the adversarial payloads. `SCANNER_SENSITIVITY`
(`low`/`medium`/`high`) trades recall against false positives; the suite pins
its assertions at `medium`, the default.

## Honest limitations

- No software defence here is absolute; the layers raise the cost of prompt
  injection, they do not eliminate it.
- IronVise governs agents that run **on its own loop** (or call it via the
  SDKs). It cannot constrain processes that never pass through it.
- The ledger is tamper-*evident* (and externally provable once timestamped
  via OpenTimestamps); it does not prevent a host-level attacker with
  database credentials from attempting rewrites - it makes them detectable.
- macOS Seatbelt blocks sockets as a whole (`(deny network*)`) for `run_command`
  children rather than filtering per domain, and Windows Job Objects do not
  isolate network access without `--features sandbox-appcontainer`; see
  [sandboxing.md](sandboxing.md).
