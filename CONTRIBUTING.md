# Contributing

Thank you for looking. A few things are specific to this repository and will
save you time.

## The licence, before anything else

The server is **BUSL-1.1**, not open source in the OSI sense. You may read it,
build it, modify it and use it for anything that is not Production Use, and it
converts to Apache-2.0 on the Change Date in `LICENSE`. There is an Additional
Use Grant stating that **verification is not Production Use** - running
`verify-cert` against a certificate is permitted for any purpose, commercial
included, because evidence nobody may check is not evidence.

The client SDKs under `sdk/typescript` and `sdk/python` are **Apache-2.0**, on
purpose: a client library that talks to a BUSL server should not carry the
server's licence.

By submitting a contribution, you agree that:

- Contributions to `sdk/` (`sdk/typescript`, `sdk/python`) are licensed under
  **Apache-2.0**.
- Contributions to the BUSL-1.1 directories (`crates/`, `gui/`, and root files)
  are licensed by you under **Apache-2.0** to the Licensor (Björn Roman
  Kohlberger / EctoSpace), so the Licensor can distribute them under BUSL-1.1,
  under Apache-2.0 on the Change Date, and under commercial production licences
  without a separate contributor licence agreement.

## Before you open a pull request

```bash
make verify          # fmt --check, clippy -D warnings, build --all-targets, commit trailers
make test            # cargo test --workspace
cd gui && npm run check
make test-e2e        # if you touched the agent, guard, sandbox, policies or the app (needs Ollama)
```

The check scripts in `scripts/` need Python 3.11 or newer. The Python SDK
itself supports 3.10.

Open a pull request against this repository. A maintainer reviews it and merges
it by hand.

**Every workflow is `workflow_dispatch`-only.** Nothing runs automatically on
a push or a pull request, on the public repository or on forks. A maintainer
starts CI by hand. That is a deliberate cost control, so `make verify` locally
is not a formality here; it is the gate.

Only the human maintainer starts GitHub Actions. Coding agents must not dispatch
or rerun workflows through the CLI, API, or UI, and must preserve workflow
triggers, enablement states, and publishing gates. Agents run checks locally.

`cargo test --workspace` alone is not enough. It builds only the targets the
tests need, so a caller that no longer compiles - an `#[ignore]`d integration
test, a bench, an example - passes it and still breaks the tree. `--all-targets`
is what catches that, and `make verify` runs it.

If your change touches PostgreSQL behaviour and you have Docker:

```bash
./scripts/test-integration.sh
```

## Commit messages

`make verify` **fails on AI-assistant attribution trailers** -
`Co-Authored-By: Claude`, `Generated with …`, session URLs. Use an assistant if
you like; leave its footer out. `python3 scripts/check-commit-trailers.py --all`
audits the whole history.

Otherwise: say what changed and why the alternative was rejected. The reason is
the part a reader cannot reconstruct.

## Things that are structural, not preferences

- **`crates/core` has no I/O.** Pure domain logic only. Keep it that way.
- **The hash chain and signing code is a compatibility contract.**
  `crates/core/src/hash.rs`, `crates/host/src/signing.rs` and `crates/host/src/ledger/`
  decide whether existing ledgers still verify. Any change to event
  serialization or hashing breaks verification of every ledger already written.
  Migration fixtures exist for exactly this; they must keep passing.
- **`crates/guest` and `crates/guard_unikernel` are outside the workspace.**
  The retained guest is RISC-V reference source; SP1 proving was withdrawn
  from 0.8. The bare-metal `aarch64` guard is built by the host’s `build.rs`.
  Do not add them to `workspace.members`.
  `crates/elc-wasm` is a workspace member, built for `wasm32-unknown-unknown`
  by `make wasm-verifier`.
- **Recording and preventing are different products.** `docs/guides/integrations.md`
  keeps a matrix of what each surface sees and what it can stop. A change that
  blurs the two is the one change this project cannot accept, whatever else it
  improves.
- **Say what you did not check.** The known limits are
  listed in `docs/reference/threat-model.md`. A pull request that adds an honest
  limit there is as welcome as one that removes it.

## Documents that must stay in sync

The test suite enforces some of these, so a drift is a build failure rather than
a surprise later:

| If you change | Update |
|---|---|
| `crates/core/src/schema.rs`, migrations | `docs/reference/schema.md` |
| `main.rs` arguments | `docs/guides/cli.md` |
| `config.rs`, feature flags | `docs/guides/configuration.md`, `.env.example` |
| the `.elc` format | `docs/reference/elc-spec.md` **and** `examples/verified-session/verify_elc.py` |

The Python verifier is written from the specification rather than from the Rust,
and a test fails if the two disagree. That is what keeps the format genuinely
open rather than declared open - so if you change the format, change the spec
first and let the independent implementation follow it.

## Reporting a vulnerability

Not here. See [SECURITY.md](SECURITY.md).

## Where things are

[docs/reference/architecture.md](docs/reference/architecture.md) maps the crates and the
repository layout; [docs/reference/testing.md](docs/reference/testing.md) covers what is tested,
how to run it, and what the CI workflows do; [docs/guides/configuration.md](docs/guides/configuration.md)
lists the Cargo feature flags and environment variables. Start there for
"what a new contributor needs to know first".
