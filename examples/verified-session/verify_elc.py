#!/usr/bin/env python3
"""An independent verifier for the .elc audit certificate format.

Written from docs/reference/elc-spec.md alone, in a different language, with no imports
from this project. That is its whole purpose: a format specification is only
open if somebody can implement it without reading the reference source, and the
cheapest way to keep that true is to ship an implementation that would break if
the spec drifted.

    python3 examples/verified-session/verify_elc.py session.elc
    python3 examples/verified-session/verify_elc.py session.elc --strict \
        --expected-key <hex published away from this file>

Exit 0 if every fatal check passes, 1 otherwise - matching verify-cert.

Without `--strict` this *inspects*: it reports what the file contains and
whether the file is internally consistent. That is not the same as knowing who
issued it. The chain structure, Merkle root and goal hash are all recomputed
from the certificate's own contents, so a certificate forged from scratch
satisfies every one of them. Only the signature ties the document to a key, and
only `--expected-key` ties that key to anyone.

Only the standard library is used, except that Ed25519 signature checking needs
`cryptography`. Without it, signatures are reported as unchecked rather than
silently skipped - and `--strict` refuses to pass on an unchecked signature,
because "I could not look" is not "I looked and it was fine".
"""

import hashlib
import json
import sys

# Windows pipes and redirected consoles commonly default to a legacy code page
# such as CP1252. This verifier deliberately uses compact Unicode status marks,
# so make its output encoding explicit instead of crashing after verification.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

GREEN, RED, YELLOW, DIM, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = YELLOW = DIM = OFF = ""

LEAF, NODE = b"\x00", b"\x01"


# ── §3 Merkle ────────────────────────────────────────────────────────────────
def leaf_hash(content_hash_hex: str) -> str:
    """Leaves hash the ASCII of the hex string, NOT the decoded bytes (§3)."""
    return hashlib.sha256(LEAF + content_hash_hex.encode("ascii")).hexdigest()


def combine(left_hex: str, right_hex: str) -> str:
    """Internal nodes hash the DECODED bytes of their children (§3)."""
    return hashlib.sha256(
        NODE + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def merkle_root(content_hashes: list) -> str | None:
    if not content_hashes:
        return None
    layer = [leaf_hash(h) for h in content_hashes]
    while len(layer) > 1:
        # Odd layers duplicate the final node (§3).
        nxt = []
        for i in range(0, len(layer), 2):
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(combine(layer[i], right))
        layer = nxt
    return layer[0]


def check_inclusion(content_hash_hex: str, proof: dict, root: str) -> bool:
    h = leaf_hash(content_hash_hex)
    for node in proof.get("path", []):
        sib = node["hash"]
        # `side` names the side the SIBLING is on (§3).
        h = combine(sib, h) if node["side"] == "left" else combine(h, sib)
    return h == root


# ── §5 canonical JSON ────────────────────────────────────────────────────────
def canonical_signing_bytes(cert: dict) -> bytes:
    """Strip `signature`, `zk_proof` and `issuer`, sort keys at EVERY level, compact.

    Python's dicts preserve insertion order, so the recursion the Rust gets for
    free from BTreeMap has to be explicit here - exactly the trap §5 warns of.
    """
    stripped = {
        k: v for k, v in cert.items() if k not in ("signature", "zk_proof", "issuer")
    }
    return json.dumps(
        stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def check_signature(cert: dict, strict: bool = False,
                    expected_key: str | None = None) -> tuple[bool, str]:
    sig = cert.get("signature")
    if sig is None:
        if strict:
            return False, (
                f"{RED}✗  Signature{OFF} - unsigned, and a signature was required. "
                f"Nothing here identifies an issuer."
            )
        return True, f"{YELLOW}⚠  Signature{OFF} - unsigned (permitted; see spec §5)"
    pk = cert.get("session_public_key")
    if pk is None:
        return False, f"{RED}✗  Signature{OFF} - signed but no session_public_key"
    # Checked before verifying: a signature that verifies against a key nobody
    # vouched for proves only that whoever made the file had a key.
    if expected_key is not None and pk.strip().lower() != expected_key.strip().lower():
        return False, (
            f"{RED}✗  Signature{OFF} - signed by {pk[:16]}…, not by the expected "
            f"key {expected_key[:16]}…"
        )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        if strict:
            return False, (
                f"{RED}✗  Signature{OFF} - present but could NOT be checked "
                f"(pip install cryptography), and --strict was given"
            )
        return True, (
            f"{YELLOW}⚠  Signature{OFF} - present but NOT checked "
            f"(pip install cryptography)"
        )
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(
            bytes.fromhex(sig), canonical_signing_bytes(cert)
        )
    except (InvalidSignature, ValueError) as exc:
        return False, f"{RED}✗  Signature{OFF} - {type(exc).__name__}"
    return True, f"{GREEN}✓  Signature{OFF} - valid Ed25519 over canonical JSON"


# ── §6 procedure ─────────────────────────────────────────────────────────────
def verify(cert: dict, strict: bool = False,
           expected_key: str | None = None) -> bool:
    ok = True
    lines = []

    good, msg = check_signature(cert, strict, expected_key)
    ok &= good
    lines.append(msg)

    # 2. Structure: consecutive sequences, tip, count.
    events = cert.get("events", [])
    hashes = [e["content_hash"] for e in events]
    if not events:
        lines.append(f"{RED}✗  Events{OFF} - empty; nothing to verify")
        return False
    gap = next(
        (
            (events[i - 1]["sequence"], events[i]["sequence"])
            for i in range(1, len(events))
            if events[i]["sequence"] != events[i - 1]["sequence"] + 1
        ),
        None,
    )
    if gap:
        ok = False
        lines.append(f"{RED}✗  Sequence{OFF} - gap after {gap[0]}: got {gap[1]}")
    elif hashes[-1] != cert["ledger_tip_hash"]:
        ok = False
        lines.append(f"{RED}✗  Tip{OFF} - last event hash != ledger_tip_hash")
    elif len(events) != cert["event_count"]:
        ok = False
        lines.append(
            f"{RED}✗  Count{OFF} - {len(events)} events, event_count says "
            f"{cert['event_count']}"
        )
    else:
        lines.append(
            f"{GREEN}✓  Chain structure{OFF} - {len(events)} consecutive events, "
            f"tip {hashes[-1][:8]}…"
        )

    # 3. Merkle root - ALWAYS, findings or not (§3, §8).
    root = merkle_root(hashes)
    if root != cert["merkle_root"]:
        ok = False
        lines.append(
            f"{RED}✗  Merkle root{OFF} - declared {cert['merkle_root'][:16]}…, "
            f"computed {(root or '')[:16]}…"
        )
    else:
        lines.append(f"{GREEN}✓  Merkle root{OFF} - matches the {len(hashes)} events")

        by_seq = {e["sequence"]: e["content_hash"] for e in events}
        n_proofs = 0
        for f in cert.get("findings", []):
            seqs, proofs = f.get("evidence_sequence", []), f.get("merkle_proofs", [])
            if len(seqs) != len(proofs):
                ok = False
                lines.append(
                    f"{RED}✗  Finding{OFF} '{f.get('title')}' - "
                    f"{len(seqs)} evidence seqs but {len(proofs)} proofs"
                )
                continue
            for seq, proof in zip(seqs, proofs):
                n_proofs += 1
                if seq not in by_seq or not check_inclusion(by_seq[seq], proof, root):
                    ok = False
                    lines.append(
                        f"{RED}✗  Inclusion proof{OFF} - finding "
                        f"'{f.get('title')}', event {seq}"
                    )
        if n_proofs:
            lines.append(f"{GREEN}✓  Inclusion proofs{OFF} - {n_proofs} verified")

    # 4. Goal hash.
    if hashlib.sha256(cert["goal"].encode("utf-8")).hexdigest() != cert["goal_hash"]:
        ok = False
        lines.append(f"{RED}✗  Goal hash{OFF} - does not match `goal`")
    else:
        lines.append(f"{GREEN}✓  Goal hash{OFF} - matches the declared goal")

    # 5-6. Warnings only.
    if cert.get("ots_proof_hex"):
        lines.append(
            f"{YELLOW}⚠  OTS{OFF} - stamp present "
            f"({len(cert['ots_proof_hex']) // 2} bytes), not checked here"
        )
    if cert.get("enclave_attestation"):
        lines.append(
            f"{DIM}·  Enclave{OFF} - level "
            f"{cert['enclave_attestation'].get('level')}"
        )

    print("\n".join("  " + ln for ln in lines))
    return ok


def main() -> int:
    args = sys.argv[1:]
    strict = False
    expected_key = None
    path = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--strict":
            strict = True
        elif arg == "--expected-key":
            i += 1
            if i >= len(args):
                print("--expected-key needs a hex public key", file=sys.stderr)
                return 2
            expected_key = args[i]
            strict = True
        elif arg.startswith("-"):
            print(f"unknown option {arg}", file=sys.stderr)
            return 2
        elif path is None:
            path = arg
        else:
            print("more than one certificate given", file=sys.stderr)
            return 2
        i += 1
    if path is None:
        print(__doc__.strip().splitlines()[0])
        print(f"usage: {sys.argv[0]} [--strict] [--expected-key HEX] "
              f"<certificate.elc>", file=sys.stderr)
        return 2
    sys.argv = [sys.argv[0], path]
    # A missing or malformed file is a normal thing for a verifier to be
    # handed; answering with a Python traceback is not. Exit 2 keeps it
    # distinct from exit 1, which means "the certificate does not verify".
    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            _probe = fh.read(1)
    except OSError as exc:
        print(f"cannot read {sys.argv[1]}: {exc.strerror}", file=sys.stderr)
        return 2
    del _probe

    with open(sys.argv[1], encoding="utf-8") as fh:
        cert = json.load(fh)

    print(f"\n  Independent verification of {sys.argv[1]}")
    print(f"  {DIM}session {cert.get('session_id')} · "
          f"format version {cert.get('version')}{OFF}\n")
    ok = verify(cert, strict, expected_key)
    if not ok:
        print(f"\n  {RED}CERTIFICATE INVALID{OFF}\n")
        return 1
    if cert.get("signature"):
        who = ("the expected key" if expected_key else "an unvouched-for key")
        print(f"\n  {GREEN}CERTIFICATE VALID{OFF} - signed by {who} "
              f"{cert['session_public_key'][:16]}…\n")
    else:
        print(f"\n  {YELLOW}CERTIFICATE INTERNALLY CONSISTENT{OFF} - unsigned: "
              f"every check above is computed from the file's own contents, so "
              f"none of them says who issued it.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
