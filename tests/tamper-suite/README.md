# Tamper suite

Many tools now ship a "tamper-evident" log for AI agents. This asks the
question their READMEs skip: **which tampers does the verifier actually
catch?** The same attacks, run against any log format that has an adapter,
reported case by case.

```bash
cargo build -p ectoledger          # or --release
python3 tests/tamper-suite/suite.py --adapter ironvise-sqlite
make tamper-suite                  # the same, writing RESULTS.md
```

It needs Python 3 with the `cryptography` package, which two attacks use to
sign with a key the attacker holds.

Two IronVise adapters run: `ironvise-sqlite` (the database alone) and
`ironvise-sqlite-cert` (the same, plus a signed certificate the auditor kept,
checked with `verify-session --against`). The second is what turns the two
database-only limits into detections.

Each builds a genuine ledger per run, by driving five
commands through the real Claude Code hook against a real server (two are
refused), then attacks copies of it with plain SQL. Current results:
[`RESULTS.md`](RESULTS.md).

## The attacker

- **Writes anything in the log's storage.** Every row and column, and any
  in-file defence such as a trigger.
- **Knows the hash and signature schemes.** They are published.
- **Does not hold the original signing key.** They may make their own.

## Reading the results

- **detected**: the verifier refused the tampered log.
- **MISSED**: it accepted a tamper it should have caught. The suite exits
  non-zero.
- **missed (limit)**: no verifier holding only the log can catch this, and the
  row names the evidence that would (a certificate, an anchor, a key obtained
  elsewhere). These are reported, not hidden, because a tool that lists only
  what it catches is advertising.
- **false alarm**: the untouched log failed. Worse than useless.

## What it has found

Its first run against IronVise found five must-detect misses: deleting
signature rows, appending an unsigned forged action, and clearing the session's
public key, which switched off every check. All five are fixed and listed
as F-4 under Fixed in [`CHANGELOG.md`](../../CHANGELOG.md) (0.8.0). The three limits
the results still show are in [RESULTS.md](RESULTS.md).

A later case, `append-self-rotation`, was added after a code audit found that
a key rotation could authorise the key that signed it: an attacker could
append a rotation to their own key and then sign anything. It was reproduced
first, then fixed (F-5), and the case now pins it.

## Your tool

Copy [`adapters/TEMPLATE.py`](adapters/TEMPLATE.py). Use the shared case ids so
rows line up across tools. Results for your tool are yours to publish; this
repository publishes only its own. If you run it and something here is wrong,
or a case is unfair to your format, open an issue.

Certificates are covered separately: `make test-wasm-verifier` runs fifteen
mutations of every example `.elc` through `verify-cert` and the browser build.
