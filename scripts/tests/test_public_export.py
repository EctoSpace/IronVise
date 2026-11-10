"""The published archive keeps its doc links and drops maintainer-only material."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_public_export_links_and_leak_grep() -> None:
    script = ROOT / "scripts" / "check-public-export.py"
    result = subprocess.run([sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def _load_checker():
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_public_export", ROOT / "scripts" / "check-public-export.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_stray_notes_are_refused(tmp_path: Path) -> None:
    checker = _load_checker()
    (tmp_path / "docs" / "guides").mkdir(parents=True)
    (tmp_path / "docs" / "README.md").write_text("[CLI](guides/cli.md)\n", encoding="utf-8")
    (tmp_path / "docs" / "guides" / "cli.md").write_text("# CLI\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# x\n", encoding="utf-8")
    assert checker.unindexed_docs(tmp_path) == []
    (tmp_path / "docs" / "idea-notes.md").write_text("# idea\n", encoding="utf-8")
    (tmp_path / "NOTES.md").write_text("# notes\n", encoding="utf-8")
    problems = checker.unindexed_docs(tmp_path)
    assert "unexpected root Markdown file NOTES.md" in problems
    assert "docs page not in docs/README.md: docs/idea-notes.md" in problems


def test_plans_stay_private(tmp_path: Path) -> None:
    checker = _load_checker()
    word = checker.PLANS_WORD
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# x\n", encoding="utf-8")
    assert checker.leak_hits(tmp_path) == []
    (tmp_path / f"{word.upper()}.md").write_text("# plans\n", encoding="utf-8")
    (tmp_path / "docs" / "README.md").write_text(f"Plans: see the {word.title()}.\n", encoding="utf-8")
    hits = checker.leak_hits(tmp_path)
    assert f"export contains {word.upper()}.md" in hits
    assert "plans mentioned in docs/README.md" in hits
