#!/usr/bin/env python3
"""Refuse commit messages carrying AI-assistant attribution trailers.

    python3 scripts/check-commit-trailers.py            # commits not yet pushed
    python3 scripts/check-commit-trailers.py --all      # audit the whole history
    python3 scripts/check-commit-trailers.py <range>    # any git rev range

Tools that write commits sometimes append a footer naming themselves - a
`Co-Authored-By:` line, a session URL, a "generated with" credit. They are
harmless individually and they accumulate silently, and this repository's
history is intended to be merged into a public one, where the footers say
nothing a reader wants and quite a lot they did not ask about.

Scoped to unpushed commits by default rather than the whole history, because a
gate that is red on arrival gets switched off. `--all` is there for auditing
what is already in the tree.

Exit codes: 0 clean, 1 a trailer was found, 2 the check could not run.
"""

import subprocess
import sys

# Substrings, case-insensitive: these appear as message *footers*, and matching
# loosely is right - the point is that no variant slips through, and a false
# positive costs one reworded commit message.
FORBIDDEN = [
    "co-authored-by: claude",
    "co-authored-by: chatgpt",
    "co-authored-by: copilot",
    "claude.ai/code/session",
    "generated with [claude",
    "generated with claude",
    "🤖 generated",
    "noreply@anthropic.com",
]

# Not a NUL: it has to survive being passed to git as an argv string.
SEPARATOR = "@@ectoledger-commit-boundary@@"


def fail(message: str) -> None:
    print(f"check-commit-trailers: {message}", file=sys.stderr)
    sys.exit(2)


def git_succeeds(*args: str) -> bool:
    return subprocess.run(["git", *args], capture_output=True).returncode == 0


def default_range() -> str | None:
    """Commits on HEAD that the upstream branch does not have.

    None means there is nothing to check: the repository has no commits yet.
    """
    try:
        upstream = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        # No upstream (a fresh branch, a detached head): check the tip only,
        # which is the commit someone is most likely to have just written.
        if git_succeeds("rev-parse", "--verify", "-q", "HEAD~1^{commit}"):
            return "HEAD~1..HEAD"
        if git_succeeds("rev-parse", "--verify", "-q", "HEAD^{commit}"):
            # A root commit has no HEAD~1, so the range would make git log
            # fail; a bare HEAD lists exactly that one commit.
            return "HEAD"
        if git_succeeds("rev-parse", "--git-dir"):
            return None
        # Outside a repository: keep the range so git log reports why.
        return "HEAD~1..HEAD"
    except FileNotFoundError:
        fail("git is not on PATH")
    return f"{upstream}..HEAD"


def main() -> int:
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg in ("-h", "--help"):
        print(__doc__)
        return 0
    rev_range = "--all" if arg == "--all" else (arg or default_range())
    if rev_range is None:
        print("check-commit-trailers: OK - no commits yet, nothing to check")
        return 0

    cmd = ["git", "log", f"--format=%H%n%B{SEPARATOR}", rev_range]
    try:
        # git writes messages as UTF-8. Decoding with the locale instead (the
        # ANSI code page on Windows) mangled the robot emoji, so a
        # "\N{ROBOT FACE} Generated with ..." trailer passed the check there.
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", check=True).stdout
    except subprocess.CalledProcessError as e:
        fail(f"git log {rev_range} failed: {e.stderr.strip()}")
    except FileNotFoundError:
        fail("git is not on PATH")

    offenders = []
    for chunk in out.split(SEPARATOR):
        chunk = chunk.strip("\n")
        if not chunk:
            continue
        sha, _, body = chunk.partition("\n")
        lowered = body.lower()
        hits = sorted({p for p in FORBIDDEN if p in lowered})
        if hits:
            subject = body.splitlines()[0] if body.splitlines() else ""
            offenders.append((sha[:9], subject[:60], hits))

    scanned = len([c for c in out.split(SEPARATOR) if c.strip()])
    if not offenders:
        print(f"check-commit-trailers: OK - {scanned} commit(s) in {rev_range}, no "
              f"assistant attribution trailers")
        return 0

    print("check-commit-trailers: FAILED\n", file=sys.stderr)
    for sha, subject, hits in offenders:
        print(f"  {sha}  {subject}", file=sys.stderr)
        for h in hits:
            print(f"             ↳ {h}", file=sys.stderr)
    print(
        f"\n{len(offenders)} commit(s) in {rev_range} carry an attribution trailer.\n"
        "Reword the message - `git commit --amend` for the tip, an interactive\n"
        "rebase for anything older - and drop the footer.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
