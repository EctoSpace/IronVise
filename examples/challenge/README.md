# Break the ledger

Five SQLite ledgers and one certificate. **Three of the ledgers were tampered
with** after the fact, each in a different way, by someone with write access to
the database and no access to the signing key. Two are genuine.

The certificate is the fourth tamper, and it is cut from one of the ledgers that
*does* verify - so "this ledger is clean" and "this certificate describing it is
honest" are two different questions.

Find the clean ledgers. Name what was done to the rest.

```bash
cargo build --release -p ectoledger

for f in examples/challenge/ledger-*.sqlite; do
  echo "== $f"
  DATABASE_URL="sqlite:$f" OBSERVER_TOKEN=x \
    ./target/release/ironvise verify-ledger
done
```

Then the certificate. `ledger-5-certificate.elc` claims to describe the ledger
it sits beside - which is one of the two that verify. Check the claim rather
than the ledger.

```bash
./target/release/verify-cert examples/challenge/ledger-5-certificate.elc
```

## The rules the attacker played by

Worth stating, because a puzzle with an undefined threat model is a guessing
game:

- **They can read and write every table.** Including dropping the append-only
  triggers, which live in the same file they are holding. A defence you can
  `DROP` is a speed bump.
- **They know the hash scheme.** It is published in
  [`docs/reference/elc-spec.md`](../../docs/reference/elc-spec.md) §2, so assuming otherwise would
  be security by obscurity - and they can recompute hashes as competently as we
  can.
- **They do not have the session's Ed25519 private key.** It exists only in
  memory for the life of the session and is never written down. This is the
  single asymmetry the whole design rests on; without it nothing here is
  detectable by anyone.

Each ledger is a real session, produced by driving the Claude Code `PreToolUse`
hook against a running Observer, then sealed. The tampering happened afterwards,
on the file.

## Checking your answer

`ANSWER.sha256` holds the SHA-256 of the canonical answer:

```
ledger-1.sqlite:<kind>
ledger-2.sqlite:<kind>
ledger-3.sqlite:<kind>
ledger-4.sqlite:<kind>
ledger-5.sqlite:<kind>
ledger-5-certificate.elc:merkle-root-mismatch
```

One line per file in that order, newline-separated, no trailing newline, where
`<kind>` is one of `verified`, `payload-hash-mismatch`,
`altered-after-signing`, `truncated-since-sealing`, `bad-signature`,
`unauthorised-key`.

```bash
printf '%s' "$(cat your-answer.txt)" | shasum -a 256
```

**This is a self-check, not a secret.** The kinds come from a six-item
vocabulary across six lines, so the hash is trivially brute-forceable, and
[`generate.py`](generate.py) in this directory states the answer outright. Both
are deliberate: a challenge whose fixtures cannot be regenerated is a challenge
nobody can audit, and "trust me, one of these is clean" is exactly the posture
this project argues against. The hash is there so you can confirm your own
reasoning without reading a spoiler, if you would rather not.

## Two of the four were undetectable a week ago

Not as a boast - as the reason the challenge is worth doing.

Until **2026-08-12**, two of these tampers passed `verify-session` cleanly:

- **The re-chained edit.** Change a payload, then recompute every hash to the
  tip. The chain is internally consistent again, so only a signature can
  object - and signatures were verified against a copy of the hash stored
  beside them, never against the event's own. Both operands moved together for
  the attacker.
- **The truncation.** Deleting events from the end left a shorter but perfectly
  consistent chain, and nothing recorded how long the session was meant to be.

Both are listed under Fixed in
[`CHANGELOG.md`](../../CHANGELOG.md) (0.8.0), with reproductions including [`repro-stale-signature.sh`](repro-stale-signature.sh)
in this directory, which still demonstrates the original behaviour. They were
found by trying to build *this challenge* and discovering two of its four
puzzle pieces were not puzzles.

Assume there are more.

There were. On 2026-09-24 a tamper suite built from this challenge
([`tests/tamper-suite/`](../../tests/tamper-suite/)) found five more that
passed: deleting signature rows, appending an unsigned forged action, and
clearing the session's public key, which switched off every check. Fixed as
F-4. The suite still lists three it cannot catch from the database alone, and
says what would.

## What counts as breaking it

- A tampered ledger that `verify-ledger` reports as verified.
- A mutation of `session.elc` in
  [`../verified-session/`](../verified-session/) that `verify-cert` accepts.
- Any disagreement between `verify-cert` and the independent Python
  implementation in [`../verified-session/verify_elc.py`](../verified-session/verify_elc.py).
- An argument that a check is weaker than the docs claim, even without an
  exploit.

That last one counts. F-2 was not an exploit; it was noticing that "sealed"
implied something the schema did not enforce.

## The limit you should attack next

Signature verification assumes you know the session's public key **out of
band**. Here you do not - you are reading it out of the same database an
attacker controls. Someone who can rewrite `agent_events` can rewrite
`agent_sessions.session_public_key` and re-sign everything with a key of their
own, and every check in this challenge will pass.

That is not a bug in these fixtures, it is the honest boundary of what signing
does. What defends against it is anchoring, or a verifier that already knows
which key to expect. If you want the hardest available target, start there.

## Regenerating

```bash
python3 examples/challenge/generate.py   # ⚠️ spoiler
```

`crates/host/tests/challenge.rs` verifies all five on every test run and checks
the observed outcomes against `ANSWER.sha256`, without naming which file is
which. So the fixtures cannot rot quietly, and a regression in any verification
path shows up as a failing test rather than an easier puzzle.
