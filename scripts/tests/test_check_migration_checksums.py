"""An edited migration must fail the checksum guard, even inside a comment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "check-migration-checksums.py"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _sha384(text: str) -> str:
    return hashlib.sha384(text.encode()).hexdigest()


def _write(root: Path, files: dict[str, str], *, v063: dict[str, str] | None = None) -> None:
    migrations = root / "crates" / "host" / "migrations"
    migrations.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        path = migrations / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
    pins = {rel: _sha256(text) for rel, text in files.items()}
    (migrations / "CHECKSUMS.json").write_text(json.dumps(pins, indent=2) + "\n")
    shipped = v063 if v063 is not None else {rel: _sha384(text) for rel, text in files.items()}
    (migrations / "V063_CHECKSUMS.json").write_text(json.dumps(shipped, indent=2) + "\n")


def test_real_repository_matches_both_manifests(run_script):
    result = run_script(SCRIPT)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "v0.6.3 sqlx checksums" in result.stdout


def test_a_comment_edit_of_a_shipped_migration_fails_even_if_the_current_pin_is_updated(
    tmp_path: Path, install_script, run_script
):
    original = "-- shipped\nCREATE TABLE t (id INTEGER);\n"
    edited = "-- shipped, then edited\nCREATE TABLE t (id INTEGER);\n"
    files = {"20260222000011_add_compensating_actions.sql": edited}
    _write(
        tmp_path,
        files,
        v063={"20260222000011_add_compensating_actions.sql": _sha384(original)},
    )
    result = run_script(install_script("check-migration-checksums.py"), cwd=tmp_path)
    assert result.returncode == 1
    assert "20260222000011_add_compensating_actions.sql" in result.stderr
    assert "Do not update V063_CHECKSUMS.json" in result.stderr


def test_crlf_bytes_fail(tmp_path: Path, install_script, run_script):
    text = "CREATE TABLE t (id INTEGER);\r\n"
    _write(tmp_path, {"001_create.sql": text})
    result = run_script(install_script("check-migration-checksums.py"), cwd=tmp_path)
    assert result.returncode == 1
    assert "contains CR" in result.stderr


def test_a_new_unpinned_migration_fails(tmp_path: Path, install_script, run_script):
    text = "CREATE TABLE t (id INTEGER);\n"
    _write(tmp_path, {"001_create.sql": text})
    extra = tmp_path / "crates" / "host" / "migrations" / "002_more.sql"
    extra.write_text("ALTER TABLE t ADD COLUMN x TEXT;\n")
    result = run_script(install_script("check-migration-checksums.py"), cwd=tmp_path)
    assert result.returncode == 1
    assert "002_more.sql" in result.stderr
    assert "not pinned" in result.stderr


def test_matching_files_pass(tmp_path: Path, install_script, run_script):
    _write(tmp_path, {"001_create.sql": "CREATE TABLE t (id INTEGER);\n"})
    result = run_script(install_script("check-migration-checksums.py"), cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
