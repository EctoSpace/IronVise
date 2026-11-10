"""Every published PowerShell script parses under Windows PowerShell 5.1.

Windows PowerShell 5.1, the version Windows 10 and 11 ship with, reads a
script without a byte-order mark as Windows-1252. An em-dash in UTF-8
(E2 80 94) then decodes to three characters ending in a right double
quotation mark, which PowerShell treats as a string delimiter, so
ironvise-win.ps1 failed to parse at all ("Unexpected token '}'").
Plain ASCII, or a UTF-8 byte-order mark, keeps it readable on every version.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _scripts() -> list[Path]:
    listed = subprocess.run(["git", "ls-files", "*.ps1", "*.psm1", "*.psd1"], cwd=ROOT,
                            capture_output=True, text=True, encoding="utf-8", check=True).stdout.split()
    return [ROOT / name for name in listed if not name.startswith("doNotPublish/")]


def test_there_is_a_launcher_to_check() -> None:
    assert ROOT / "ironvise-win.ps1" in _scripts()


def test_every_script_is_ascii_or_has_a_bom() -> None:
    offenders = []
    for path in _scripts():
        data = path.read_bytes()
        if data.startswith(b"\xef\xbb\xbf"):
            continue
        for number, line in enumerate(data.splitlines(), 1):
            if any(byte > 0x7F for byte in line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, "non-ASCII bytes without a UTF-8 BOM (breaks PowerShell 5.1): " + ", ".join(offenders)
