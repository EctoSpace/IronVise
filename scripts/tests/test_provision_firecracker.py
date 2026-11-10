"""Argument parsing of scripts/provision-firecracker.sh.

Every invocation carries ``--print-prefix``, which makes the script exit right
after parsing, so nothing here downloads, needs root, or touches /dev/kvm. The
error cases put it first so that even a parser that silently ignored the bad
argument would still stop before provisioning.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "provision-firecracker.sh"

# Firecracker is Linux-only, and on Windows `bash` is usually WSL's, which
# cannot open a Windows path to the script.
pytestmark = [
    pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed"),
    pytest.mark.skipif(sys.platform == "win32", reason="a Linux-only provisioning script"),
]


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )


@pytest.mark.parametrize(
    "args, prefix",
    [
        (("--print-prefix",), "/opt/ectoledger"),
        (("--print-prefix", "--prefix", "/srv/ecto"), "/srv/ecto"),
        (("--prefix", "/srv/ecto", "--print-prefix"), "/srv/ecto"),
        (("--print-prefix", "--prefix=/srv/ecto"), "/srv/ecto"),
        (("--print-prefix", "/srv/legacy"), "/srv/legacy"),
    ],
)
def test_prefix_is_resolved(args, prefix):
    result = run(*args)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{prefix}\n"


@pytest.mark.parametrize(
    "args, message",
    [
        (("--print-prefix", "--bogus"), "unknown option: --bogus"),
        (("--print-prefix", "--prefix"), "--prefix needs a directory"),
        (("--print-prefix", "--prefix="), "must not be empty"),
        (("--print-prefix", "/a", "/b"), "given more than once"),
        (("--print-prefix", "--prefix", "/a", "/b"), "given more than once"),
    ],
)
def test_bad_arguments_exit_2_with_usage(args, message):
    result = run(*args)
    assert result.returncode == 2
    assert result.stdout == ""
    assert message in result.stderr
    assert "Usage:" in result.stderr


def test_help_exits_0():
    result = run("--print-prefix", "--help")
    assert result.returncode == 0
    assert "Usage:" in result.stdout
