#!/usr/bin/env python3
"""Fail when an applied migration file no longer matches its pinned bytes.

sqlx records a SHA-384 of each migration the first time it runs, and on every
later start refuses to open the database if that file has changed
(``migration ... was previously applied but has been modified``). A comment,
a rename, or a CRLF checkout is enough. The failure shows up only for people
who already have a ledger, so review of a fresh database does not catch it.

Two pins:

* ``crates/host/migrations/CHECKSUMS.json`` is SHA-256 of every ``.sql`` file
  that exists now. A new migration is added to this file in the same commit.
* ``crates/host/migrations/V063_CHECKSUMS.json`` is the sqlx SHA-384 of every
  migration that shipped in public v0.6.3 (commit
  cf7d29df91738d983fcef0635539b02aac6a847d). Those bytes stay. A later schema
  change is a new migration file. Do not update this manifest to match an edit.

``.gitattributes`` keeps ``*.sql`` on LF. This script also rejects a CR byte,
which is what a Windows ``core.autocrlf`` checkout would introduce.

USAGE
-----
    python3 scripts/check-migration-checksums.py

Exit codes: 0 = both manifests match the files on disk.
            1 = at least one migration was edited, added unpinned, or deleted.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def _sql_files(directory: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(directory.rglob("*.sql")):
        if path.is_file():
            rel = path.relative_to(directory).as_posix()
            files[rel] = path.read_bytes()
    return files


def _load_map(path: Path) -> dict[str, str]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name} is missing or is not a JSON object: {exc}") from exc
    if not isinstance(loaded, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in loaded.items()
    ):
        raise ValueError(f"{path.name} must be an object of filename to hex digest")
    return loaded


def check(root: Path) -> list[str]:
    """Return one error string per problem. Empty means the pins hold."""
    migrations = root / "crates" / "host" / "migrations"
    if not migrations.is_dir():
        return [f"missing {migrations}"]

    errors: list[str] = []
    try:
        pinned = _load_map(migrations / "CHECKSUMS.json")
        shipped = _load_map(migrations / "V063_CHECKSUMS.json")
    except ValueError as exc:
        return [str(exc)]

    files = _sql_files(migrations)
    sha256 = {rel: hashlib.sha256(data).hexdigest() for rel, data in files.items()}
    sha384 = {rel: hashlib.sha384(data).hexdigest() for rel, data in files.items()}

    for rel, data in files.items():
        if b"\r" in data:
            errors.append(
                f"{rel} contains CR. Migrations are LF "
                "(.gitattributes sets *.sql text eol=lf)."
            )

    for rel, want in sorted(pinned.items()):
        got = sha256.get(rel)
        if got is None:
            errors.append(
                f"{rel} is pinned in CHECKSUMS.json but the file is gone. "
                "Deleting an applied migration strands every database that ran it."
            )
        elif got != want:
            errors.append(
                f"{rel} changed after it was pinned.\n"
                f"  pinned {want}\n"
                f"  found  {got}\n"
                "  Restore the file. If the schema must change, add a new migration."
            )

    for rel in sorted(set(files) - set(pinned)):
        errors.append(
            f"{rel} is not pinned in CHECKSUMS.json. "
            "Add its SHA-256 in the same commit that adds the migration."
        )

    for rel, want in sorted(shipped.items()):
        got = sha384.get(rel)
        if got is None:
            errors.append(
                f"{rel} shipped in v0.6.3 and is missing. "
                "Every database that applied it will fail to open."
            )
        elif got != want:
            errors.append(
                f"{rel} no longer matches the bytes that shipped in v0.6.3.\n"
                f"  v0.6.3 {want}\n"
                f"  found  {got}\n"
                "  sqlx will refuse every database that already applied it "
                "(VersionMismatch), including a change that is only a comment.\n"
                "  Restore the v0.6.3 bytes. Put the change in a new migration.\n"
                "  Do not update V063_CHECKSUMS.json to match the edit."
            )

    return errors


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    errors = check(root)
    if errors:
        print(
            f"check-migration-checksums: {len(errors)} problem(s).\n",
            file=sys.stderr,
        )
        print("\n".join(errors), file=sys.stderr)
        return 1
    migrations = root / "crates" / "host" / "migrations"
    sql_count = len(list(migrations.rglob("*.sql")))
    shipped = json.loads((migrations / "V063_CHECKSUMS.json").read_text(encoding="utf-8"))
    print(
        f"check-migration-checksums: {sql_count} migration(s) match CHECKSUMS.json; "
        f"{len(shipped)} match the v0.6.3 sqlx checksums."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
