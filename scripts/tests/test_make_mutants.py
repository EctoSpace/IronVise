"""`make mutants` runs from a fresh checkout.

cargo-mutants creates the directory named by `-o` but not its parent, and a
fresh checkout has no `target/`, so the recipe failed with "create output
parent directory" before it mutated anything. Found by the WSL session.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Stands in for cargo: like cargo-mutants, it refuses an -o whose parent does not exist.
FAKE_CARGO = """#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    parent=$(dirname "$2")
    [ -d "$parent" ] || { echo "Error: create output parent directory \\"$2\\"" >&2; exit 1; }
    mkdir -p "$2"
  fi
  shift
done
"""


@pytest.mark.skipif(shutil.which("make") is None, reason="needs make")
def test_mutants_recipe_works_without_a_target_directory(tmp_path: Path) -> None:
    shutil.copy(ROOT / "Makefile", tmp_path / "Makefile")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("cargo", FAKE_CARGO), ("cargo-mutants", "#!/bin/sh\n")):
        tool = bin_dir / name
        tool.write_text(body, encoding="utf-8")
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}

    result = subprocess.run(["make", "mutants", f"CARGO={bin_dir / 'cargo'}"], cwd=tmp_path, env=env,
                            capture_output=True, text=True, encoding="utf-8", errors="replace")

    assert result.returncode == 0, result.stdout + result.stderr
    for out in ("mutants-elc", "mutants-core", "mutants-core-blake3"):
        assert (tmp_path / "target" / out).is_dir()
