"""Shared helpers for the repository check script tests.

The check scripts locate the repository from their own path
(``Path(__file__).resolve().parent.parent``), so the tests copy a script into
``<tmp>/scripts/`` and build a fixture repository around it. Running the copy
as a subprocess exercises the real entry point, exit code included, without
touching the actual checkout.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent

# The check scripts print non-ASCII (an em-dash in every summary line). On
# Windows a piped child writes in the ANSI code page, so the UTF-8 decode in
# subprocess.run failed in its reader thread and left stdout as None. Every
# script run by these tests, directly or through git, inherits this.
os.environ.setdefault("PYTHONIOENCODING", "utf-8")


def _run_script(script: Path, *args: str, cwd: Path | None = None,
                env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )


@pytest.fixture
def run_script():
    """Run a script with the current interpreter; returns the CompletedProcess."""
    return _run_script


@pytest.fixture
def install_script(tmp_path: Path):
    """Copy ``scripts/<name>`` into ``<tmp_path>/scripts/`` and return the copy."""

    def install(name: str) -> Path:
        target = tmp_path / "scripts" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SCRIPTS_DIR / name, target)
        return target

    return install


@pytest.fixture
def git_env(tmp_path: Path) -> dict[str, str]:
    """An environment in which git ignores every user and system config."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        HOME=str(home),
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CEILING_DIRECTORIES=str(tmp_path),
        GIT_AUTHOR_NAME="Fixture Author",
        GIT_AUTHOR_EMAIL="author@example.invalid",
        GIT_COMMITTER_NAME="Fixture Author",
        GIT_COMMITTER_EMAIL="author@example.invalid",
        LC_ALL="C.UTF-8",
    )
    return env
