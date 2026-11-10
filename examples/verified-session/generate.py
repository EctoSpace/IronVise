#!/usr/bin/env python3
"""Rebuild the verified-session example: one genuine certificate, one tampered.

    python3 examples/verified-session/generate.py            # with a Bitcoin anchor
    python3 examples/verified-session/generate.py --no-ots   # offline

These two files are what someone is handed when they ask "show me what a
verified audit trail looks like, and show me that verification actually
catches something". Until now they had no generator - they were the output of
one session on one machine, which is a poor thing to hand a sceptic, and they
carried that machine's home directory in the session goal.

The session is real: driven through `ironvise hook` against a live server,
sealed over HTTP, then exported with `report --format certificate`. The
tampered copy flips the first character of `events[2].content_hash`, which is
the smallest edit that breaks the chain without touching anything else.

`tests/example_certificate.rs` verifies both on every test run, so they cannot
rot unnoticed.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _session_builder import BIN, build_session  # noqa: E402

HERE = Path(__file__).resolve().parent
PORT = 3191

# Four tool calls: three the tripwire permits and one it refuses. A genuine
# session contains refusals - that is the point of the thing - and an example
# made only of allowed calls would not show the ledger doing its job.
COMMANDS = ["ls -la", "cat README.md", "rm -rf /", "pwd"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-ots", action="store_true",
                    help="skip the OpenTimestamps submission (no network)")
    args = ap.parse_args()

    if not BIN.exists():
        print(f"binary not found: {BIN}\n"
              f"build it first, or set ECTOLEDGER_BIN.", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        cert = HERE / "session.elc"
        print("  running a real hook session, exporting a signed certificate …")
        sealed, sid = build_session(work, COMMANDS, PORT,
                                    hook_session_id="verified-example",
                                    certificate_to=cert, ots=not args.no_ots)

    genuine = json.loads(cert.read_text())
    print(f"    session {genuine['session_id']}, {genuine['event_count']} events")
    print(f"    signed by {genuine['session_public_key']}")
    print("    ^ this is the expected key the README publishes; verification is")
    print("      only worth something against a key obtained away from the file.")
    if not args.no_ots and not genuine.get("ots_proof_hex"):
        print("    warning: no OTS proof - the calendar pool did not answer",
              file=sys.stderr)

    # The tamper: flip one hex digit of the third event's content hash. Small
    # on purpose. A verifier that only catches obvious damage is not a verifier.
    tampered = json.loads(json.dumps(genuine))
    old = tampered["events"][2]["content_hash"]
    flipped = ("1" if old[0] == "0" else "0") + old[1:]
    tampered["events"][2]["content_hash"] = flipped
    (HERE / "session-tampered.elc").write_text(json.dumps(tampered, indent=2, sort_keys=True))
    print(f"  tampered copy: events[2].content_hash {old[:8]}… → {flipped[:8]}…")

    print("\n  verify both strictly against the expected key, expecting 0 then 1:")
    for name in ("session.elc", "session-tampered.elc"):
        rc = subprocess.run(
            [str(BIN), "verify-certificate", str(HERE / name),
             "--strict", "--expected-key", genuine["session_public_key"]],
            capture_output=True).returncode
        print(f"    {name} → {rc}")
    print("\n  examples/challenge/ledger-5-certificate.elc is cut from "
          "session.elc - rerun the challenge generator too.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
