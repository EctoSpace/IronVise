#!/usr/bin/env python3
"""Check the `git archive` export: relative links, and strings that must not ship.

`git archive` is how this tree is published. export-ignore in .gitattributes
drops maintainer-only paths. This script materialises that archive and checks
the result, so a broken doc link fails before a publish.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Split so this file does not contain the contiguous needle it searches for.
LEAK_SUBSTRINGS = (
    "Ai" "Test",
    "bjorn" "@",
    "zv" "eht",
    "/Users/" "bkohlberger",
)
PRIVATE_REPO = "private " "repo"
# Plans stay out of the export (split so this file does not match itself).
PLANS_WORD = "road" "map"

ABSENT_PATHS = (
    "doNotPublish",
    "CLAUDE.md",
    "AGENTS.md",
    "BeforeYouPublishZeroEight.md",
    "docs/security",
    "docs/private-export-prep",
    "docs/ironvise-handoff.md",
    "docs/ironvise-private-validation.md",
    "docs/ironvise-public-export.md",
    "docs/release-readiness.md",
    "crates/host/tests/private_docs_location.rs",
    ".github/workflows/macLocal.yml",
    ".github/workflows/ubuntuLocal.yml",
    ".github/workflows/winLocal.yml",
    # Moved out of the published tree in 0.8.0 (wiki or maintainer-only).
    "SANDBOX_CROSS_PLATFORM.md",
    "docs/writeups",
    "docs/sandbox-verification-report.md",
    "docs/security-findings-open.md",
    PLANS_WORD.upper() + ".md",
)

# The only Markdown files allowed at the root of the export. A new root note
# has to be added here on purpose, or it fails the check.
ROOT_MARKDOWN = {
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
}


def extract_archive(dest: Path) -> None:
    """Archive HEAD plus the working tree, using a temporary index."""
    with tempfile.TemporaryDirectory(prefix="ironvise-index-") as index_dir:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(Path(index_dir) / "index")
        subprocess.run(["git", "read-tree", "HEAD"], cwd=ROOT, env=env, check=True)
        subprocess.run(["git", "add", "-A"], cwd=ROOT, env=env, check=True)
        tree = subprocess.run(
            ["git", "write-tree"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        archive = subprocess.run(
            ["git", "archive", "--format=tar", tree],
            cwd=ROOT,
            env=env,
            capture_output=True,
            check=True,
        )
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive.stdout, check=True)


def collect_markdown(directory: Path, out: list[Path]) -> None:
    if not directory.is_dir():
        return
    for path in sorted(directory.iterdir()):
        name = path.name
        if path.is_dir():
            if name not in {"node_modules", "dist", ".venv"}:
                collect_markdown(path, out)
        elif name.endswith(".md"):
            out.append(path)


def broken_links(root: Path) -> list[str]:
    files = [root / name for name in sorted(ROOT_MARKDOWN)]
    for directory in ("docs", "examples", "sdk", "tests", "crates"):
        collect_markdown(root / directory, files)
    broken: list[str] = []
    if len(files) <= 20:
        broken.append(f"found too few Markdown files: {len(files)}")
    for file in files:
        if not file.is_file():
            broken.append(f"missing {file.relative_to(root)}")
            continue
        prose = "\n".join(file.read_text(encoding="utf-8").split("```")[::2])
        for chunk in prose.split("](")[1:]:
            target = chunk.split(")", 1)[0]
            path = target.split("#", 1)[0]
            if not path or "://" in path or path.startswith("mailto:") or " " in path:
                continue
            if not (file.parent / path).exists():
                broken.append(f"{file.relative_to(root)} -> {target}")
    return broken


def unindexed_docs(root: Path) -> list[str]:
    """Every page under docs/ is linked from docs/README.md; no stray notes."""
    problems: list[str] = []
    for path in sorted(root.glob("*.md")):
        if path.name not in ROOT_MARKDOWN:
            problems.append(f"unexpected root Markdown file {path.name}")
    docs = root / "docs"
    index = docs / "README.md"
    if not index.is_file():
        return problems + ["docs/README.md is missing"]
    linked = set()
    prose = index.read_text(encoding="utf-8")
    for chunk in prose.split("](")[1:]:
        target = chunk.split(")", 1)[0].split("#", 1)[0]
        if target and "://" not in target:
            linked.add((docs / target).resolve())
    for path in sorted(docs.rglob("*.md")):
        if path == index or "assets" in path.relative_to(docs).parts:
            continue
        if path.resolve() not in linked:
            problems.append(f"docs page not in docs/README.md: {path.relative_to(root)}")
    return problems


def leak_hits(root: Path) -> list[str]:
    hits: list[str] = []
    for relative in ABSENT_PATHS:
        if (root / relative).exists():
            hits.append(f"export contains {relative}")
    prose_files = [root / name for name in sorted(ROOT_MARKDOWN)]
    for directory in ("docs", "site", "examples", "sdk"):
        if (root / directory).is_dir():
            prose_files += [p for p in (root / directory).rglob("*") if p.suffix in {".md", ".html"}]
    for path in prose_files:
        if not path.is_file():
            continue
        prose = path.read_text(encoding="utf-8", errors="replace")
        if "doNotPublish" in prose:
            hits.append(f"doNotPublish mentioned in {path.relative_to(root)}")
        if PLANS_WORD in prose.lower():
            hits.append(f"plans mentioned in {path.relative_to(root)}")
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if "gen/schemas" in path.as_posix():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if PRIVATE_REPO in text.lower():
            hits.append(f"disallowed phrase in {path.relative_to(root)}")
        for needle in LEAK_SUBSTRINGS:
            if needle in text:
                hits.append(f"disallowed token in {path.relative_to(root)}")
                break
    return hits


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ironvise-export-") as tmp:
        dest = Path(tmp)
        extract_archive(dest)
        broken = broken_links(dest)
        leaks = leak_hits(dest) + unindexed_docs(dest)
    if broken or leaks:
        print("check-public-export: FAILED")
        for item in broken:
            print(f"  link  {item}")
        for item in leaks:
            print(f"  leak  {item}")
        return 1
    print("check-public-export: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
