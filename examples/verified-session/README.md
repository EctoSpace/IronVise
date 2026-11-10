# Verify a real IronVise certificate - in about two minutes

Two files. One is a genuine audit certificate; the other is the same file with a
single hex character changed. Check both and see the difference yourself.

You do not need Rust, PostgreSQL, a model, or a licence from us to do this. The
BUSL's Additional Use Grant states explicitly that **verification is not
Production Use** - running the verifier against a certificate is permitted for
any purpose, commercial included. Evidence nobody may check is not evidence.

```bash
# genuine
verify-cert examples/verified-session/session.elc          # exit 0
# one hex character changed
verify-cert examples/verified-session/session-tampered.elc # CERTIFICATE INVALID (exit 1)
```

That is the *inspection* mode, and it answers a narrower question than it looks
like: it recomputes the hash chain, the Merkle root and the goal hash from the
file's own contents. A certificate forged from scratch satisfies all three. What
it cannot tell you is who issued this one.

For that you need the signature, checked against a key you did not get from the
certificate:

```bash
verify-cert --strict \
  --expected-key 374ef79f4035fcbb6bd81bdc6e77d937099c80675f4f772c59be57109bc88fd2 \
  examples/verified-session/session.elc                    # exit 0
```

**That key is published here, in this README, and nowhere inside the file.**
That is the whole mechanism: a key read out of a certificate only tells you the
certificate signed itself. `--strict` alone refuses an unsigned certificate;
`--expected-key` implies `--strict` and additionally refuses one signed by
anybody else. Try it with one character of the key changed - it fails, and it
names the key it actually found.

## What is in the certificate

A real session, produced by driving the Claude Code `PreToolUse` hook against a
running Observer. Four tool calls, in this order:

| # | Tool call | What happened |
|---|---|---|
| 1 | `ls -la` | allowed |
| 2 | `cat README.md` | allowed |
| 3 | `rm -rf /` | **denied before it ran** |
| 4 | `pwd` | allowed |

Regenerate it yourself with `generate.py` in this directory - the command list
is at the top of that file, so this table is checkable rather than asserted.

The denial carries `enforced: true`: Claude Code consults the hook before a tool
executes and honours the deny, so that command did not run. Along with the
native loop, the Codex and Antigravity hooks, and `mcp-proxy`, this is a surface
where prevention can honestly be claimed - see
[`docs/guides/integrations.md`](../../docs/guides/integrations.md) for what each surface can
and cannot do.

## What the tampered file changes

One hex character, in the `content_hash` of the third event - the denial:

```
fab981299179e15ca03f…   ->   0ab981299179e15ca03f…
```

(Those hashes change every time the pair is regenerated; the *shape* - one
leading hex digit, third event - is what is fixed, and
`tests/example_certificate.rs` asserts it.)

That is the shape of a real attack, not a random corruption. Substituting an
event hash is how you would make a certificate vouch for an event that never
happened, or stop it vouching for one that did.

## Or verify it without our binary at all

`verify_elc.py` in this directory is a second implementation, written from
[`docs/reference/elc-spec.md`](../../docs/reference/elc-spec.md) rather than from the Rust, in a
different language, with no project imports:

```bash
# from the repository root
python3 examples/verified-session/verify_elc.py \
        examples/verified-session/session.elc           # exit 0
python3 examples/verified-session/verify_elc.py \
        examples/verified-session/session-tampered.elc  # exit 1

# and strictly, against the published key (needs `pip install cryptography`)
python3 examples/verified-session/verify_elc.py \
        examples/verified-session/session.elc \
        --strict --expected-key 374ef79f4035fcbb6bd81bdc6e77d937099c80675f4f772c59be57109bc88fd2
```

It agrees with `verify-cert` on both files, down to the computed Merkle root,
and a test in `crates/host/tests/example_certificate.rs` keeps it that way. That
agreement is the evidence that the format is genuinely open and not just
declared open - if the spec were incomplete, this file could not exist.

## Try to break it yourself

That is the point of shipping these. Some things worth trying:

- Change a different event's hash. Change several.
- Reorder the entries in `events` without changing any of them.
- Delete an event, and adjust `event_count` to match.
- Edit `goal` without editing `goal_hash`.
- Edit `merkle_root` to match your tampered events.

If you find a mutation that the verifier accepts, that is a real finding and we
want it.

**One of these already worked.** Until 2026-08-12, editing any event hash *other
than the last* was accepted: the verifier skipped the Merkle-root comparison
entirely for sessions with no findings, and only the last event was pinned by
the tip hash. It was found while preparing these very files. See the
`verify_cert.rs` regression tests.

## Honest limits of this artifact

- **What the signature does and does not establish.** It binds this document to
  the key `374ef79f4035fcbb…`, which signed it. That the key belongs to anyone in
  particular is something this README asserts and you take on trust - the same
  trust problem every signature has, stated rather than hidden. An anchor or a
  key you obtained from the maintainer through a channel you trust is what
  narrows it further.
- **This certificate could be signed because the server still held the key.**
  The per-session Ed25519 key is generated at session creation, returned once,
  and never written to disk. The hook keeps it in memory for the life of the
  process, so `GET /api/certificates/{id}` can sign an export made while the
  server is up. After a restart the key is gone and an export from the same
  ledger is unsigned - honestly, because there is nothing left to sign with.
  An installation issuer key (`ironvise issuer-key init`) can now countersign
  every exported certificate (`--issuer`), while signed key-rotation successor
  statements and external KMS/HSM custody are not part of 0.8.
- **`verify-cert` proves integrity, not completeness.** It shows this file has
  not been altered since it was produced. It cannot show that everything which
  happened was recorded. A hash chain constrains what can happen *after* an
  event is written; it says nothing about an event that was never written.
- **The OTS timestamp is a calendar's promise, not a Bitcoin attestation.**
  The verifier says so, and `--require-anchor` fails on it, which is the honest
  answer until the proof is upgraded. See "Upgrading the anchor" below.

## Getting `verify-cert`

```bash
cargo build --release --bin verify-cert     # ./target/release/verify-cert
```

It needs no database, no network and no configuration.

## Regenerating these files

```bash
python3 examples/verified-session/generate.py            # takes a Bitcoin anchor
python3 examples/verified-session/generate.py --no-ots   # offline
```

Both files come out of one run, and the run is real: a live server on a
throwaway SQLite database, four tool calls through `ironvise hook` (one of
which the tripwire refuses - a genuine session contains refusals), sealed over
HTTP, then exported over HTTP **while the server was still running** - which is
what makes it signed. The tampered copy is
the genuine one with the first character of `events[2].content_hash` flipped,
which is the smallest edit that breaks the chain without touching anything
else.

The session's goal is a fixed neutral path rather than wherever the script
happened to run, so two people regenerating these get artefacts that differ
only in the session UUID, the timestamps and the anchor - not in whose machine
built them.

`--no-ots` skips the OpenTimestamps submission. With it the certificate has no
`ots_proof_hex`; without it the calendar returns a proof immediately, and that
proof upgrades to a Bitcoin attestation once a block containing it confirms.
`verify-certificate --require-anchor` is the machine check: it distinguishes a
Bitcoin attestation from a calendar's promise and fails on the latter, which is
the correct answer for the committed proof. Without that flag the anchor is
reported and not enforced, so an unanchored example demonstrates everything the
anchored one does except the timestamp itself.

Regenerating produces a new session key, so the `--expected-key` value above
changes with it. `tests/example_certificate.rs` fails if this README stops
publishing the key that actually signed the shipped file, so the instruction
cannot silently go stale. It verifies both files on every test run too. `examples/challenge/ledger-5-certificate.elc` is cut from
`session.elc`, so rerun the challenge generator after regenerating here.

### Upgrading the anchor

A freshly taken OpenTimestamps proof is a calendar's promise, not yet a Bitcoin
attestation. The calendar aggregates submissions and commits them in a later
block, and the proof only gains its Bitcoin path when someone asks for it back.

Upgrade it **beside** the certificate, not inside it. `ots_proof_hex` is covered
by the signature, so writing an upgraded proof back into the certificate would
make it fail as tampered. (This README used to say the opposite.)

```bash
verify-cert --export-ots session.ots session.elc   # the stamp as a .ots file
ots upgrade session.ots                              # once a block has confirmed it
ots verify  session.ots                              # checks the block, needs a node or explorer
verify-cert --require-anchor --ots session.ots session.elc
```

`--export-ots` writes a standard detached `.ots` file (the reference `ots` client
reads it); `--ots` reads an upgraded one, checks that it stamps this
certificate's `ledger_tip_hash`, and reports the block height and the Merkle root
that block must carry. The browser verifier takes the same file.

**The committed proof here is un-upgraded.** It was taken when these files were
regenerated and has not been fetched back since. That is worth knowing before
citing it as a timestamp: it proves the calendar accepted the digest, not yet
that Bitcoin did.
