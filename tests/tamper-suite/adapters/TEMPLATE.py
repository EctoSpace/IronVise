"""Template: run the tamper suite against another tool's agent log.

Copy to adapters/<your_tool>.py, fill in the four methods, then:

    python3 tests/tamper-suite/suite.py --adapter <your-tool>

Rules that keep results comparable:

- make_clean() should drive the real tool to produce a genuine log. A
  hand-written fixture tests your fixture, not your tool.
- Each case edits the log the way someone holding its storage could, using
  only what is public about the format. No private keys.
- Use the ids in suite.CASE_IDS. Skip a case that does not apply to your
  format, rather than bending it into something else.
- Mark a case "limit" only when no verifier holding just the log could catch
  it, and name what would.

Results for your tool are yours to publish. This repository publishes only
IronVise's.
"""

from pathlib import Path

from suite import Case  # noqa: F401  (resolved when suite.py loads the adapter)


class _Adapter:
    name = "Your tool, `your-verify-command`"

    def version(self) -> str:
        return "your-tool x.y.z"

    def make_clean(self, workdir: Path) -> Path:
        raise NotImplementedError("produce a genuine log in workdir and return its path")

    def verify(self, path: Path) -> tuple[bool, str]:
        raise NotImplementedError("run the tool's verifier; return (passed, what it said)")

    def cases(self) -> list:
        return []  # [Case("edit-payload", apply_fn), ...]


ADAPTER = _Adapter()
