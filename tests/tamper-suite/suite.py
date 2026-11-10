#!/usr/bin/env python3
"""A vendor-neutral tamper suite for agent audit logs.

    python3 tests/tamper-suite/suite.py --adapter ironvise-sqlite
    python3 tests/tamper-suite/suite.py --adapter ironvise-sqlite-cert --markdown RESULTS.md

Many projects now ship a "tamper-evident" log for AI agents. Few say which
tampers their verifier catches. This runs the same attacks against any log
format that has an adapter, and reports detected and missed, case by case.

## The attacker

Stated first, because a result without a threat model is a guess:

- **Writes anything in the log's storage.** Every row, every column, every
  sidecar table, and any in-file defence such as a trigger.
- **Knows the hash and signature schemes.** They are published.
- **Does not hold the original signing key.** They may make their own key.

Some cases are expected to be missed by *any* verifier that only has the log:
an attacker who rewrites everything, including the key, produces a
self-consistent log. Those rows say so (`limit`), and name the out-of-band
evidence that would catch them. Reporting them as misses, rather than leaving
them out, is the point.

## Adding a tool

Write `adapters/<name>.py` exposing `ADAPTER`, an object with:

- `name`, `version()` (str)
- `make_clean(workdir) -> Path`: produce a genuine log, ideally by driving the
  real tool, not by hand
- `verify(path) -> (ok: bool, detail: str)`: run the tool's own verifier
- `cases() -> list[Case]`: the attacks it can express in its format. Reuse the
  ids in `CASE_IDS` so results line up across tools; skip what does not apply.

See `adapters/TEMPLATE.py`. Results for other tools are theirs to publish;
this repository publishes only its own.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent

# Shared vocabulary, so a row means the same thing for every adapter.
CASE_IDS = {
    "clean": "No change. Must verify: a verifier that fails this is useless.",
    "edit-payload": "Change one event's content, touch nothing else.",
    "edit-payload-rehash": "Change one event's content and recompute every hash after it.",
    "swap-events": "Exchange two events' contents.",
    "delete-interior": "Remove an event from the middle.",
    "delete-interior-rehash": "Remove an event from the middle and re-link the chain.",
    "truncate-tail": "Remove the last event.",
    "truncate-tail-reseal": "Remove the last event and update any stored length or tip.",
    "append-unsigned": "Add a forged event at the end with a correct hash and no signature.",
    "append-unsigned-by-design": "Forge an event of a kind the tool itself stores unsigned.",
    "forge-approval": "Add a human approval the operator never gave.",
    "strip-signatures": "Delete every signature, change nothing else.",
    "strip-signatures-edit": "Delete every signature, then edit and rehash freely.",
    "null-key": "Remove the session's recorded public key.",
    "null-key-edit": "Remove the recorded key, then edit a payload without rehashing.",
    "downgrade-unsigned": "Remove the key and every signature, then edit and rehash: pass it off as unsigned.",
    "timestamp-rewrite": "Change one event's time and recompute hashes.",
    "resign-own-key": "Rewrite everything and sign it with the attacker's own key.",
    "append-self-rotation": "Append a key rotation signed by the attacker's own new key, then forged events signed with it.",
}


@dataclass
class Case:
    id: str
    apply: Callable[[Path], None]
    # "must": a verifier with only the log should catch it.
    # "limit": no log-only verifier can; `beyond` names what would.
    expectation: str = "must"
    beyond: str = ""
    note: str = ""


@dataclass
class Result:
    case: str
    description: str
    expectation: str
    detected: bool
    detail: str
    beyond: str = ""
    note: str = ""
    passed: bool = field(init=False)

    def __post_init__(self):
        if self.case == "clean":
            self.passed = not self.detected
        elif self.expectation == "limit":
            self.passed = True  # reported either way; a catch is a bonus
        else:
            self.passed = self.detected


def load_adapter(name: str):
    path = HERE / "adapters" / f"{name.replace('-', '_')}.py"
    if not path.exists():
        sys.exit(f"no adapter {name!r} ({path})")
    spec = importlib.util.spec_from_file_location(f"adapter_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ADAPTER


def run(adapter) -> list[Result]:
    results = []
    with tempfile.TemporaryDirectory(prefix="tamper-suite-") as tmp:
        tmp = Path(tmp)
        clean = adapter.make_clean(tmp)
        for case in [Case("clean", lambda p: None)] + adapter.cases():
            if case.id not in CASE_IDS:
                sys.exit(f"adapter case {case.id!r} is not in CASE_IDS")
            work = tmp / f"case-{case.id}{clean.suffix}"
            shutil.copy(clean, work)
            case.apply(work)
            ok, detail = adapter.verify(work)
            results.append(Result(case.id, CASE_IDS[case.id], case.expectation,
                                  detected=not ok, detail=detail,
                                  beyond=case.beyond, note=case.note))
    return results


# Each run signs with fresh keys, so their short ids differ every time. The
# record names them generically to stay the same when the verdicts do.
KEY_ID = re.compile(r"\b[0-9a-f]{16}…")


def markdown(adapter, results: list[Result]) -> str:
    today = dt.date.today().isoformat()
    lines = [
        f"### {adapter.name}",
        "",
        f"{adapter.version()}, run {today}.",
        "",
        "| Case | Attack | Verdict | Verifier said |",
        "|---|---|---|---|",
    ]
    for r in results:
        if r.case == "clean":
            verdict = "verifies" if not r.detected else "**false alarm**"
        elif r.detected:
            verdict = "detected"
        elif r.expectation == "limit":
            verdict = f"missed (limit: {r.beyond})"
        else:
            verdict = "**MISSED**"
        said = KEY_ID.sub("[key id]…", r.detail).replace("|", "\\|")
        if r.note:
            said += f" ({r.note})"
        lines.append(f"| `{r.case}` | {r.description} | {verdict} | {said} |")
    missed = [r.case for r in results if not r.passed]
    lines += ["", f"Must-detect cases missed: {len(missed)}"
              + (f" ({', '.join(missed)})" if missed else "") + "."]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--adapter", required=True, action="append",
                    help="repeat to run several adapters into one report")
    ap.add_argument("--markdown", type=Path, help="write the results table here")
    ap.add_argument("--json", type=Path, help="write machine-readable results here")
    args = ap.parse_args()

    header = ("# Tamper suite results\n\nGenerated by `make tamper-suite`; do not edit by "
              "hand. What the verdicts mean, and the attacker they assume: "
              "[README.md](README.md).\n\n")
    sections, everything, ok = [], {}, True
    for name in args.adapter:
        adapter = load_adapter(name)
        results = run(adapter)
        sections.append(markdown(adapter, results))
        everything[name] = [r.__dict__ for r in results]
        ok &= all(r.passed for r in results)
    report = header + "\n".join(sections)
    print(report)
    if args.markdown:
        args.markdown.write_text(report)
    if args.json:
        args.json.write_text(json.dumps(everything, indent=2))
    # Non-zero only for a must-detect miss or a false alarm, so the suite can
    # gate CI without pretending the documented limits are fixed.
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
