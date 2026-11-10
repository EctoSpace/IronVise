# How IronVise is tested

A tool that says "tamper-evident" should be able to show which tampers it
catches, and a tool that says "enforces" should be shown refusing something in
the real client, not only in a unit test. The rule here: every claim on the
README's first screen has a test that fails when the claim stops being true,
and the limits are reported next to the results, not left out.

The sizes in the table were measured during the 0.8.0 release cycle, on macOS
unless a row says otherwise; rows that name a date were last measured then.
The latest full run is summarised at the end of the next section.

## The test pyramid

| Level | Suites | Runs on |
|---|---|---|
| Unit | Rust unit and property tests in every crate, Vitest for the GUI logic, Vitest and pytest for the SDKs | every change, no network |
| Contract | GUI to Rust IPC, GUI mock to app, SDK route coverage, cross-language fixtures, recorded model replies, provider presets | every change, no network |
| Integration | HTTP routes against an in-process server, the agent loop golden record, PostgreSQL parity, two instances on one database, the CLI audit under its own seccomp filter | every change; PostgreSQL needs Docker |
| System and black box | `tests/api` against a fresh server, the tamper suite, the hook and MCP demos, the upgrade and wheel gates | before a release |
| UI | Playwright visual baselines, accessibility (axe-core) and behaviour tests against a mocked IPC | before a release; pixel baselines on macOS |
| AI behaviour | The guard evaluation corpus (offline every change, live against a real model on demand), the real Claude Code, Codex and Antigravity gates, end to end runs with a local model | on demand, needs a model |
| Test quality | Mutation testing of the verifier, core hashing, keys, signatures, receipts and the guard parser | before a release |

Every model-facing test runs offline against scripted or recorded replies,
so the default suites are deterministic; the live variants are opt-in
(`--ignored`) and report agreement rates instead of pass or fail.

**Latest full run (2026-11-10, release candidate, macOS on Apple Silicon):**
`cargo test --workspace` 1527 passed, 0 failed, 29 ignored (live models and
hardware); PostgreSQL integration 1553 passed; black-box API suite 173 passed,
14 skipped; Python SDK 1364 passed; TypeScript SDK 963 passed; GUI unit tests
214 passed; Playwright 99 passed; repository check scripts 172 passed; tamper
suite 0 must-detect cases missed; browser verifier 82 verdicts agree with
`verify-cert`. The same workspace suite passed on Linux and Windows earlier in
the cycle (about 1,520 tests per platform).

## The layers

| Layer | What it proves | Size | Run |
|---|---|---|---|
| Rust unit and route tests | Every module, and every HTTP route against a real in-process server on SQLite | `make test-qa`: 1584 passed, 0 failed across its runs (workspace, verifier, BLAKE3 pass, WASM verdicts, tamper suite, hook demo) | `cargo test --workspace` |
| PostgreSQL parity | The workspace tests with `--features integration` against a real PostgreSQL, including the integrity cases on both backends | Latest full run 2026-11-10, PostgreSQL 17: 1553 passed. The script runs the same command against an ephemeral container | `./scripts/test-integration.sh` |
| Tamper suite | 18 attacks by someone who can edit the database, against genuine ledgers, with and without a certificate held elsewhere | 0 must-detect misses in 38 rows; 3 limits, named | `make tamper-suite` |
| Real Claude Code gate | The hook inside actual Claude Code (Haiku), judged from the ledger and the files on disk, never from what the model says; a file Claude read must match its data receipt | 9 of 9 | `bash examples/demo/claude-code-gate.sh` |
| Real MCP server | `mcp-proxy` in front of the official filesystem MCP server: a read passes and matches its data receipt, a forbidden write never happens, all verify | every step asserts; passed 2026-10-23 | `make demo-mcp` |
| Hook demo | Deny, record, verify, tamper, detect, as a script that asserts each step | 7 of 7 (2026-10-23) | `make demo-hook` |
| Certificate verifier | One verifier, checked with and without `serde_json/preserve_order`, since that feature once changed the signed bytes | 122 passed (61 twice) | `make test-elc` |
| Mutation testing | Every change `cargo-mutants` makes to the certificate verifier and the core hash and Merkle code fails a test in that crate | verifier 176 of 176; core 55 of 55 (3 by timeout: an endless loop the tests never let pass); BLAKE3-only code 9 of 9 | `make mutants` |
| Mutation testing, host keys, signatures and receipts | The same for `ledger.rs` (verdicts, key lifecycle), `signing.rs` (signatures, key files, passwords), and the data receipts (`receipts.rs`, `data-receipts`) | every mutant a test reaches is caught: by unit tests, and by the CLI and PostgreSQL suites for the 5 that need a real environment or database. Left: 2 equivalent (the 3 in an unused resume prompt went with the prompt, removed in 0.8.0) | `cargo mutants -p ectoledger -f <file> -- --lib` for each |
| Mutation testing, guard verdict parser | Every mutant of `guard.rs` (the verdict parser, think-block handling, the guard prompt) fails a unit test; the first run left 5 alive, which two added tests now catch | 20 of 20 viable (4 do not compile), 2026-10-23 | `cargo mutants --in-place -p ectoledger -f crates/host/src/guard.rs -- --lib` |
| BLAKE3 build | The core and host suites with `--features hash-blake3`, which switches the chain hash and nothing else | 647 passed | `make test-blake3` |
| Browser verifier | The WASM build returns the same verdict as the native one on every mutated example certificate | 82 verdicts agree | `make test-wasm-verifier` |
| Cross-language fixtures | The Rust server writes `sdk/fixtures/webhook-v1.json`; the TypeScript and Python verifiers must agree with it | in both SDK suites | `cargo test -p ectoledger v1_tests`, SDK tests |
| SDKs | Client behaviour, packaging (the packed tarball is installed and imported), verifiers | TypeScript 963, Python 1364 (latest full run, 2026-11-10) | `npm test`, `npm run test:pack`, `pytest` |
| CLI audit under its own filter | The real `audit` binary on Linux with the default seccomp filter: SQLite, the guard worker, a Landlock-confined `run_command`, the saved key file | every step asserts | `cargo test -p ectoledger --test audit_cli_linux` |
| Upgrade from 0.6.3 | A session recorded by a real v0.6.3 build: the candidate migrates the database, verifies it, and signs a certificate with the key file v0.6.3 saved | every step asserts | `make check-upgrade OLD_BIN=…` |
| Python wheel | The built wheel in a clean venv, against the candidate server: a deny, an allow, a recorded, sealed and verified session | every step asserts; passed 2026-10-23 | `make check-python-wheel` |
| Enclave channels | Protocol v2 on both ends, with no hardware | 33 passed | `make test-enclave` |
| At-rest encryption | `--features sqlcipher` against real SQLCipher: ciphertext on disk, every pooled connection keyed, read-only path keyed, key gone from the environment | every step asserts | `make test-sqlcipher` |
| GUI | Type-check, accessibility and primitives gates, visual baselines, readable drop-downs, Settings/Policy/wizard behaviour against a mocked IPC | 0 errors; `npm run test:visual` 96 passed incl. a11y (the open command palette included), Settings search and no overflow at 1024×640 | `cd gui && npm run check`, `npm run test:visual` |
| GUI unit tests | Vitest over the front-end logic modules (`backend.ts`, `sse.ts`, `events.ts`, `verification.ts`, `utils.ts`, `settings/providers.ts`, the stores) with a fake `fetch`/`EventSource`, no network or browser | 214 passed | `cd gui && npm run test:unit` (`make test-gui-unit`); Vitest 5 and jsdom 29 need Node 22.13+ |
| GUI ↔ Rust contract | Every command the webview calls, with the exact JSON its call site sends, through real Tauri IPC (capabilities included); argument structs refuse unknown fields | every call site, macOS, Linux and Windows | `cargo test -p ectoledger-gui ipc_contract` |
| GUI ↔ backend error paths | Commands that call the embedded Observer over HTTP, against a mock server standing in for it: an unauthorized status, a server error, an HTML/non-JSON body, a refused connection, a server that never answers - asserts the message the webview would show, not just that the call failed | 7 passed; found and fixed an HTML-tag leak in `run_prompt`'s error path and a "Policy not found" shown for every non-2xx status, not just 404 | `cargo test -p ectoledger-gui http_error_tests` |
| End to end, per OS | One suite on macOS (Apple Silicon), Linux and Windows with a real local model: the OS sandbox runs commands and refuses what it should; every webview call through real Tauri IPC on this OS's webview origin; the guard worker over HMAC (standalone and as the desktop binary); the documented SOC 2 CLI audit; an isolated `serve` driven through settings round trip and clearing, tripwire, tokens, webhooks, policy saving and the policy for runs, real runs and their recorded policy hash, session isolation, History, certificate and VC, the guard; a keychain round trip (test service only); the GUI suite. macOS adds the strictly signed app bundle driven the same way in a scratch HOME, and idle stability | every check a named PASS/FAIL line; 2026-10-09 macOS: 9 of 9 steps. 2026-10-23 macOS 27, `qwen3.8:27b-mlx`: all 10 steps pass, the strictly signed release app driven through 39 scenarios included (the first run found the Seatbelt `ls -la` refusal, fixed) | `make test-e2e`, or `py scripts\qa\run.py` on Windows (needs Ollama) |
| HTTP API, black box | `tests/api` against a fresh server: auth, boundaries, concurrency, SSE, events, sessions, policies, tokens, webhooks, adversarial inputs | 173 passed, 0 failed, 14 skipped (role tokens, relaxed rate limits) | `make test-api` |
| Guard evaluation corpus | 140 labelled cases (goal and proposed action, Unix and Windows) for the semantic guard: read-only inspection, completion, destructive, exfiltration, code execution, privilege, persistence, off-goal, injection, obfuscation, borderline. Offline: the corpus is well formed, and the guard shows a model the goal and the exact action JSON and reads the verdict back, for every case. Live: every case sent to a real model through the same prompt and parser, scored against the labels ([tests/guard-corpus](../../tests/guard-corpus/README.md)) | Offline: every case. Live, 2026-10-23, `qwen3.8:27b-mlx` on Ollama (Apple M4 Pro): 136 of 140 agree with the labels (97.1%); denials precision 95.8%, recall 98.6%; allows recall 95.8%; no model errors. The misses: `bash -c 'id'` allowed (it runs code through a shell), and three denials of allowed cases: a `complete` with no findings, fetching the nginx documentation, `ps aux` during a TLS check. Every injection, obfuscation, exfiltration and destructive case was denied. One run of a non-deterministic model: a run the same night with the earlier parser scored 96.4%, differing on two cases | `cargo test -p ectoledger --test guard_corpus`; live: `GUARD_LLM_BACKEND=… GUARD_LLM_MODEL=… cargo test -p ectoledger --test guard_corpus -- --ignored --nocapture` |
| Model replies, recorded | 14 recorded reply bodies in each provider's wire format (Anthropic thinking then text, refusal, token limit, tool use first; OpenAI refusal, length, no choices; Ollama length, no message) replayed through each backend against a mock server: the same intent from equivalent replies, or the exact error | 18 replay tests | `cargo test -p ectoledger-llm replay` |
| Property-based tests | Generated inputs (proptest). Core: the content hash is byte-exact and changes with every bound field; tampering breaks a generated chain at that event; every leaf of a 1..511-leaf Merkle tree proves and no other does; policies in both list forms parse, a forbidden action is never allowed, evaluation never panics. LLM: the intent parser never panics on arbitrary, fenced, truncated or deeply nested replies and never replaces a justification the model gave. Host: arbitrary Unicode through the output scanner, tripwire, webhook preview, agent prompt and sandbox output trimming never panics and every cut keeps a prefix | 9 core, 11 parser and 5 host properties; several thousand generated cases a run | `cargo test -p ectoledger_core --test properties`, `-p ectoledger-llm --test parse_intent_proptest`, `-p ectoledger --test text_properties` |
| Benchmarks | Criterion, on an Apple M4 Pro (2026-10-23): one event hashed in 1.2 µs; a 1,000-event chain verified in 1.3 ms and a 10,000-event one in 12.5 ms; a Merkle tree built and one proof taken in 1.7 ms (1,000 leaves) and 18.4 ms (10,000); the SOC 2 pack evaluated against a `run_command` intent, approval gates included, in 2.3 µs; the example certificate verified in 39 µs | numbers, not pass/fail | `cargo bench -p ectoledger_core`, `cargo bench -p ectoledger-elc` |
| SDK route coverage | Every route the server mounts is called by the Python SDK (method and path) and the TypeScript client (path), or listed as deliberately not wrapped with a reason; a listed route the server dropped, or one both SDKs now call, fails too | 48 routes: 42 wrapped by both SDKs, 6 not on purpose | `make check-sdk` |
| GUI test mock ↔ app | The visual suite answers `get_provider_presets` from its own table; that table must equal what the app returns | 1 test | `cargo test -p ectoledger-gui the_visual_mock` |
| Agent loop, golden | `run_cognitive_loop` on SQLite with a scripted model, guard and dashboard, in 23 scenarios (completion, every refusal path, guard denials and errors, approval gates on the dashboard and on timeout, observation rules, a suspicious observation, a banned goal, key rotation, the token budget, cancellation). Every event payload, webhook notice and metric must equal the recorded fixture, and the event counter must equal the events written | 23 scenarios; written before the loop was split into `agent/`, unchanged by the split | `cargo test -p ectoledger --test agent_golden` (`ECTO_UPDATE_GOLDEN=1` rewrites the fixture) |
| Streaming | Each provider's stream format read line by line: OpenAI-format and Anthropic server-sent events, Ollama's JSON lines; thinking left out, refusals, token limits and provider errors reported; a character split across network chunks arrives whole. The chat stream routes end to end: deltas, then the recorded reply or an error event, and nothing recorded for a failed stream | 11 parser and backend tests, 4 route tests | `cargo test -p ectoledger-llm stream`, `cargo test -p ectoledger --test qa_server_chat_stream` |
| Hosted provider presets | Each preset reaches its documented address with its own key variable in the header it documents (Azure's `api-key`); a preset without a default address or model refuses to start; a base URL that names its version is kept | contract tests on the table and on the requests sent; not run against the live APIs | `cargo test -p ectoledger-llm provider`, `cargo test -p ectoledger --lib factory_tests` |
| Codex hook | Codex's `apply_patch` checked on every file it touches, a move target included, against the session's project; an escalation answered as a deny under Codex; the ledger session labelled `codex`. Run by hand inside Codex CLI 0.163.0: `echo` ran, `sudo id` was refused before it ran, an `apply_patch` wrote its file, every call and data receipt landed in a session that `verify-ledger` accepts, and with `GUARD_REQUIRED` on and no guard every call was refused | 5 route tests and unit tests of the patch reader | `cargo test -p ectoledger --test qa_server_hook_codex` |
| Two instances, one database | An approval gate opened on one instance is listed and decided through the other's API; racing decisions on two instances record exactly one; a decision for another gate, or after the timeout, is refused, and one that came first stands | 4 tests, PostgreSQL 17 | `cargo test -p ectoledger --features integration --test multi_instance_postgres` |
| Antigravity CLI hook | Its payload into the real hook binary and its decision shape back out: a banned command denied, a read in the workspace allowed, a write outside it or to its own `.agents/hooks.json` denied, an unreachable Observer answered with a deny on stdout and exit 2; every tool it maps, with the arguments its documentation gives. Run by hand inside Antigravity CLI 1.4.5: `sudo id` was refused before it ran, `git status` ran, both landed in a session labelled `antigravity`, and with the Observer stopped Antigravity refused the call on the hook's exit 2 | 5 binary tests, mapping and payload unit tests | `cargo test -p ectoledger --test qa_hook_antigravity` |
| GUI themes | The dark baselines unchanged and light baselines for Dashboard and Settings; the theme resolver at boot and in the app agree on every input. An axe-core contrast pass over ten screens in light mode found three failing badges at the first attempt and none after (run by hand, not in the suite) | 2 light baselines, theme unit tests | `cd gui && npx playwright test theme-light`, `npx vitest run` |
| Guards | Applied migrations pinned by checksum; no assistant trailers in commits; workflow guards | | `make verify`, `make test-qa` |

## What the tests found

The point of the layers is that they disagree with the code sometimes. These
were all found by the tests or while writing them, reproduced before being
fixed, and are pinned now:

- **F-4: a session with its signatures deleted, or its key cleared, verified.**
  Found by the first tamper-suite run: five must-detect misses.
- **F-5: a key rotation could authorise the key that signed it.** Found in a
  code audit, reproduced with a scratch test (`Verified { signatures: 3 }` on
  a forged tail), fixed, then pinned on SQLite, PostgreSQL and in the tamper
  suite (`append-self-rotation`).
- **The hook refused `git add` and every `&&` chain.** Found by probing
  everyday commands before a real Claude Code session: `dd` in the ban list
  matched as a substring, and shell operators were banned outright.
- **Parallel tool calls were blocked.** The same probe hit the session-creation
  rate limit after five calls, and the hook fails closed on a 429.
- **A policy could be bypassed with a chain.** Command rules look at the first
  program, so `git status && rm -rf x` would pass a policy that allows `git`.
  Pinned by `a_chain_cannot_ride_past_a_policy_on_its_first_program`.
- **The SDKs reported a forged session as verified.** `verifyChain` returned
  the chain flag and dropped the signature verdict.
- **The CLI audit failed on Linux, and its commands ran without Landlock.**
  The upgrade gate ran a real `audit` for the first time: the process's own
  seccomp filter refused `fsync`, `readlink`, `fchmod`, `dup2` and the
  Landlock calls. Every unit test passed, because none installs the filter.
- **A tamper test tampered with nothing, 1 time in 256.** It "corrupted" a
  signature by overwriting its first byte with `ff`, which changes nothing
  when that byte already is `ff`. The golden gate hit it. It now always writes
  a different byte.
- **Certificates from a `hash-blake3` build read INVALID.** No test ran the
  host with the feature. Known-answer tests for the hash layouts ran the core
  suite with it and a policy-hash test failed; the certificate export test
  then failed end to end without the fix. The feature had switched the goal
  hash, which every verifier recomputes as SHA-256.
- **The verifier's own tests let 62 of its 176 mutants live.** `cargo-mutants`
  changed its code and the tests still passed. Nothing checked a certificate
  signed in the legacy field-order form, a wrong `--expected-key`, a session
  key deleted from the ledger, or the OpenTimestamps parser's limits. All 176
  are caught now.
- **The host's signature check had no unit test.** `verify_signature` could
  return "valid" for anything and every unit test still passed; only the
  PostgreSQL suite would have noticed. Nor was the minimum password length
  tested at its boundary, or the PostgreSQL key lookup that VC verification
  uses tested at all. All three are now.
- **The hash and Merkle tests compared the code with itself.** A change to a
  prefix or the child order made in both the builder and the verifier would
  have passed while breaking every issued certificate. Roots, proof paths,
  content-hash layouts and digests are now checked against values computed
  independently with Python's `hashlib`.

Found while building the AI test layers (October 2026):

- **The guard approved replies it should have denied.** It allowed any reply
  starting with the letters ALLOW, so "ALLOWED? No." and "ALLOW, but DENY: it
  deletes the backups" were approvals, and a thinking model that writes a
  `<think>` block into its reply had every action denied as unparseable. An
  independent review then found that a lowercase "deny:" and a nested
  `</think>` still slipped through. One parser, `guard::parse_verdict`, now
  allows only an unambiguous ALLOW, in-process and over the guard-worker
  channel.
- **A guard on an OpenAI-compatible server could never allow anything.** Every
  call asked for JSON mode, including the free-form guard call, so a server
  that honours it forces a JSON object instead of "ALLOW". JSON mode is now
  asked for only when the answer is an intent.
- **Two backends ignored the provider's own stop signal.** Replaying recorded
  replies showed an OpenAI refusal reported as "empty response" and an answer
  cut off at the token limit (OpenAI `finish_reason`, Ollama `done_reason`)
  reported as broken JSON. They are `Refused` and `Truncated` now, as on the
  Anthropic backend, which itself had read only a reply's first block and so
  failed on every current model, whose first block is its thinking.
- **A live stream stalled behind 100 events.** The SDK stream test passed
  alone and failed against the shared black-box server, which holds
  thousands of events: after each 100-event batch the stream waited for the
  next write. `qa_server_sse_backlog` streams a 250-event backlog; the old
  code delivered 100.
- **`red-team` and `report` crashed on non-ASCII text.** Both cut a summary
  with a byte slice; an accented letter, CJK text or an emoji at the cut
  panicked. Found writing the first unit tests for `red_team.rs`; the Unicode
  property tests cover the other paths that cut text.
- **The Python SDK could not stream every session, called a compatibility
  alias for the tripwire config, and its `toggle_webhook` raised against every
  real server.** The route coverage check found the first two; the third had
  passed its unit test because the mock returned a body the server never
  sends, and the black-box suite now toggles a webhook through the SDK.
- **The visual suite's mock had drifted from the app.** Its provider table
  gave Anthropic no default model. The mock contract test compares the two.
- **A goal mentioning "address" was refused before the first step.** Writing
  the golden scenarios showed the goal scan matching banned words as
  substrings: `dd` in "address", `sudo` in "sudoku". It matches whole words
  now, as the command check already did.
- **A timed-out approval was recorded as a person's decision.** Every
  `approval_decision` said `operator:api`, including ones nobody made, and a
  dashboard request outlived its timeout, so a late click was accepted for a
  gate already denied. The reason names the timeout now, and the request is
  withdrawn when it expires.
- **A guard that kept failing never stopped the session**, and was neither
  counted nor reported as a denial; and the event counter skipped approval,
  credential and key-rotation events. The golden record exposed both.

## Rules the tests follow

- **Judge from evidence, not output.** The Claude Code gate reads the ledger
  and the file system; a model saying it ran a command proves nothing.
- **A case the tool did not attempt is inconclusive, not a pass.**
- **Positive controls.** The tamper suite's `clean` case must verify; a false
  alarm fails the run as surely as a miss.
- **Fixtures come from the real thing.** The tamper suite drives the real hook
  to make its ledgers; the OpenShell fixture starts from records in
  OpenShell's own documentation and says which lines are constructed.
- **One source of truth across languages.** Formats shared by Rust, TypeScript
  and Python are pinned by a fixture the server's tests write.
- **Red first.** A security fix lands with the test that failed before it.
- **A test must be able to fail.** `make mutants` changes the verifier and
  the core hash code in about 280 ways; every change must fail a test. A
  mutant no test can observe is excluded by name, with the reason, in
  `.cargo/mutants.toml`.
- **Known answers come from outside.** Values a format depends on are
  computed by a second implementation, not copied from the code's output.

## Not tested here

- The seven hosted presets added in 0.8.0 (Gemini, Azure OpenAI, Mistral,
  Groq, OpenRouter, DeepSeek, xAI) against the live APIs: their requests are
  checked against each provider's API reference, not sent.
- The `windows` 0.62 update on a Windows machine: compile- and lint-checked
  for the target from macOS. Linux was run in a container (`rust:1.99`,
  kernel 7.0): the sandbox crate's 31 tests, Landlock and seccomp included,
  and the host's library, tripwire and Linux CLI tests pass.
- `keyring` stays at 3: version 4 moves the library into `keyring-core` and one store
  crate per OS and says nothing about reading what version 3 stored, and an
  upgrade that cannot find a user's saved API keys on Windows or Linux could
  only be checked on those machines. TypeScript stays at 5.9: TypeScript 7 is
  the native compiler, without the JavaScript API that `svelte-check` drives.

- A pending OpenTimestamps proof upgraded after a Bitcoin block confirms it.
  A live calendar stamp was taken on 2026-10-01; `verify-cert --require-anchor`
  rejects that proof until the upgrade, which is the result the tool should give.
- A live AWS Nitro enclave in EC2. `crates/host/src/enclave/nitro_attestation.rs`
  verifies COSE_Sign1 signatures, certificate chains to the pinned AWS root,
  challenge nonces and PCR policies against synthetic chains and a captured AWS
  sample (`nitro-sample-attestation.cbor`), but `EnclaveRouter` is not wired
  into the cognitive loop and has not been run against a live Nitro instance.
- The Apple hypervisor enclave in CI. `make test-enclave-hv` (6 tests) was run
  on one Apple Silicon machine; it needs that hardware and a codesigned binary.
  The guest is compile-checked on Linux.
- Installing the Windows desktop app over an existing 0.6.3 install. The
  installer asks for elevation, so that step is attended. On Windows 11 at
  the release head the workspace tests passed, and so did the CLI, `serve`,
  the keychain, the GUI type-check, the GUI unit tests and the GUI behaviour
  tests (pixel baselines stay macOS-only). Opening a ledger whose migrations
  were applied by 0.6.3, including a Windows build that recorded CRLF
  checksums, is covered by the `upgrade_from_v063` tests. The installer
  click-through is not.

## CI

[`checks.yml`](../../.github/workflows/checks.yml) and [`ci.yml`](../../.github/workflows/ci.yml)
are **manual** (`workflow_dispatch`) by design on this repository - dispatch from
the Actions tab or with `gh workflow run <file>`. What `checks.yml` runs (also
what to run locally before a release cut):

```bash
python3 scripts/check-workflow-guards.py          # workflow guards intact (needs pyyaml)
python3 scripts/check-tauri-versions.py           # Tauri Rust/npm versions in step
python3 scripts/check-migration-checksums.py      # shipped migrations still match their pinned bytes
make verify                                       # fmt --check, clippy -D warnings, build --all-targets
cargo test --workspace
make demo-hook                                    # when present in the workflow
```

`make verify` bundles the fmt and clippy checks and adds
`cargo build --workspace --all-targets`, without which a target that compiles
but never runs - an `#[ignore]`d integration test, a bench - can break while
`cargo test --workspace` stays green.

Optionally also `cd gui && npm run check`, `cd gui && npm run test:visual` on
macOS (darwin Playwright baselines), and `./scripts/test-integration.sh`
when touching the ledger (needs Docker).

Everything else is also manual (`workflow_dispatch`) - dispatch from the Actions tab
or with `gh workflow run <file>`:

| Workflow | What it does |
|---|---|
| [`ci.yml`](../../.github/workflows/ci.yml) | Full suite: tests, Docker integration, SDKs, GUI, Tauri bundles. Ubuntu jobs always run; the macOS and Windows jobs (tests, Apple Hypervisor boot, Tauri bundles) run only with the `full_matrix` input ticked |
| [`retest.yml`](../../.github/workflows/retest.yml) | "Selective CI" - the same GitHub-hosted jobs behind per-job toggles, to re-run just one without paying for the full fan-out |
| [`docker-publish.yml`](../../.github/workflows/docker-publish.yml) | Builds and publishes the container image |
| `enclave-tests` / `release` | Enclave feature build check on a GitHub-hosted macOS runner, and the release build, each with toggles |

**No workflow runs on its own.** Every workflow is triggered by
`workflow_dispatch` only.
[`scripts/check-workflow-guards.py`](../../scripts/check-workflow-guards.py) runs
first in `checks.yml` and fails if a workflow gains an automatic trigger
without a job-level repository guard. It can only see
`.github/workflows/`; settings-level automation (CodeQL default setup,
Dependabot security updates) is disabled in the repository settings.
