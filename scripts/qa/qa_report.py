"""PASS/FAIL reporting shared by the QA scenario scripts."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    passed: int = 0

    def check(self, name: str, ok: bool, detail: object = "") -> bool:
        line = ("PASS " if ok else "FAIL ") + name
        if detail != "":
            line += f"  [{str(detail)[:200]}]"
        print(line, flush=True)
        if ok:
            self.passed += 1
        else:
            self.failures.append(name)
        return ok

    def summary(self) -> int:
        """Print the totals; the process exit status (0 when all passed)."""
        tail = f": {self.failures}" if self.failures else ""
        print(f"\n{self.passed} passed, {len(self.failures)} failed{tail}")
        return 0 if not self.failures else 1
