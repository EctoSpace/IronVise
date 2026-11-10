"""Every text-mode child process in scripts/qa must decode as UTF-8.

Without an explicit ``encoding=``, ``text=True`` decodes with the locale code
page (cp1252 on Windows), and the first non-ASCII byte a child prints kills
the reader with a UnicodeDecodeError.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

QA = Path(__file__).resolve().parent
SUBPROCESS_CALLS = {"run", "Popen", "call", "check_call", "check_output"}
TEXT_FLAGS = {"text", "universal_newlines"}


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _text_mode_calls_without_encoding(source: str) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name not in SUBPROCESS_CALLS:
            continue
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        if any(_is_true(keywords[f]) for f in TEXT_FLAGS if f in keywords) and "encoding" not in keywords:
            lines.append(node.lineno)
    return lines


def test_scan_catches_a_call_without_encoding():
    assert _text_mode_calls_without_encoding("subprocess.run(cmd, text=True)\n") == [1]
    assert _text_mode_calls_without_encoding("Popen(cmd, universal_newlines=True)\n") == [1]
    assert _text_mode_calls_without_encoding("subprocess.run(cmd, text=True, encoding='utf-8')\n") == []


def test_every_text_mode_subprocess_call_sets_an_encoding():
    offenders = [
        f"{path.name}:{line}"
        for path in sorted(QA.glob("*.py"))
        for line in _text_mode_calls_without_encoding(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], "text=True without encoding= at " + ", ".join(offenders)


def test_utf8_and_invalid_bytes_from_a_child_decode_without_error():
    child = "import sys; sys.stdout.buffer.write(b'\\xe2\\x9c\\x94 ok \\xff\\n')"
    result = subprocess.run([sys.executable, "-c", child], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=30)
    assert result.stdout == "✔ ok �\n"
