#!/usr/bin/env python3
"""Enforce the repository guard on every automatically-triggered workflow job.

THE INVARIANT
-------------
The files in ``.github/workflows/`` live verbatim in the public repository and
in any private mirror or fork:

    private mirror or fork       : any other repository          <- Actions may be billed
    public                       : EctoSpace/IronVise          <- Actions are free

Any workflow that can start without a human (push, pull_request, schedule, a
``v*`` tag, ...) would therefore run on a mirror or fork as well. To
prevent that, **every job** in such a workflow must carry this exact job-level
condition::

    if: github.repository == 'EctoSpace/IronVise' || github.event_name == 'workflow_dispatch'

which makes the job run automatically on the public repo, run on manual
dispatch anywhere, and *skip* on any mirror or fork. A job skipped by an
``if:`` condition is never assigned a runner and bills zero minutes.

Workflows whose only trigger is ``workflow_dispatch`` need no guard: they
cannot start without a human.

This script fails (exit 1) the moment that invariant is broken, so a missing
guard can never slip in silently.

USAGE
-----
    python3 scripts/check-workflow-guards.py

Exit codes: 0 = every automatically-triggered job is correctly guarded.
            1 = at least one violation (details printed).
            2 = the script could not run (bad YAML, missing PyYAML, ...).

Dependencies: Python 3 standard library plus PyYAML.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not a policy failure
    print(
        "check-workflow-guards: PyYAML is required.\n"
        "  install with: python3 -m pip install --quiet pyyaml",
        file=sys.stderr,
    )
    sys.exit(2)

# The only repository on which automatic runs are free.
PUBLIC_REPO = "EctoSpace/IronVise"

# The one trigger that always involves a human pressing a button.
MANUAL_TRIGGER = "workflow_dispatch"

# Everything else can fire on its own. Listed explicitly rather than inferred
# so that a newly-invented GitHub event is treated as automatic by default
# (see classify_triggers: anything not workflow_dispatch counts as automatic).
KNOWN_AUTOMATIC_TRIGGERS = {
    "branch_protection_rule", "check_run", "check_suite", "create", "delete",
    "deployment", "deployment_status", "discussion", "discussion_comment",
    "fork", "gollum", "issue_comment", "issues", "label", "merge_group",
    "milestone", "page_build", "project", "project_card", "project_column",
    "public", "pull_request", "pull_request_review",
    "pull_request_review_comment", "pull_request_target", "push",
    "registry_package", "release", "repository_dispatch", "schedule", "status",
    "watch", "workflow_call", "workflow_run",
}

# Expressions that can resurrect a job whose dependency was skipped, which
# would defeat skip-propagation. Presence is a warning for human review.
SKIP_OVERRIDE_FUNCTIONS = ("always()", "success()", "failure()", "cancelled()")

# The two clauses the guard must contain, in either order.
CLAUSE_REPO = f"github.repository == '{PUBLIC_REPO}'"
CLAUSE_EVENT = f"github.event_name == '{MANUAL_TRIGGER}'"

ACCEPTED_GUARDS = (
    f"{CLAUSE_REPO} || {CLAUSE_EVENT}",
    f"{CLAUSE_EVENT} || {CLAUSE_REPO}",
)


def normalize(expression: object) -> str:
    """Collapse whitespace and strip a wrapping ``${{ ... }}``.

    GitHub accepts a job-level ``if:`` with or without the expression braces,
    and YAML folding can introduce arbitrary internal whitespace; neither
    changes the meaning, so neither should change the verdict.
    """
    text = " ".join(str(expression).split())
    if text.startswith("${{") and text.endswith("}}"):
        text = " ".join(text[3:-2].split())
    return text


def load_workflow(path: Path) -> dict:
    """Parse a workflow file, tolerating YAML 1.1's ``on:`` -> ``True`` quirk."""
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def classify_triggers(document: dict) -> tuple[list[str], list[str]]:
    """Return (automatic_triggers, all_triggers) for a parsed workflow.

    PyYAML resolves the bare key ``on:`` to the boolean ``True`` under YAML
    1.1, so the raw string key is checked as a fallback. Any trigger that is
    not ``workflow_dispatch`` is treated as automatic - including events this
    script has never heard of, which is the fail-safe direction.
    """
    raw = document.get(True, document.get("on"))
    if raw is None:
        triggers: list[str] = []
    elif isinstance(raw, str):
        triggers = [raw]
    elif isinstance(raw, list):
        triggers = [str(item) for item in raw]
    elif isinstance(raw, dict):
        triggers = [str(key) for key in raw]
    else:
        triggers = []

    automatic = sorted(t for t in triggers if t != MANUAL_TRIGGER)
    return automatic, sorted(triggers)


def check_workflow(path: Path, display: Path | None = None) -> tuple[list[str], list[str]]:
    """Audit one workflow. Returns (errors, warnings).

    ``path`` is opened; ``display`` is what appears in messages. They differ so
    the check works from any working directory while still reporting the short
    repo-relative name.
    """
    name = display if display is not None else path

    try:
        document = load_workflow(path)
    except yaml.YAMLError as exc:
        return [f"{name}: not valid YAML: {exc}"], []

    return check_document(document, name)


def check_document(document: object, name: Path) -> tuple[list[str], list[str]]:
    """Audit one already-parsed workflow. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(document, dict):
        return [f"{name}: top level is not a mapping"], []

    automatic, _all_triggers = classify_triggers(document)
    if not automatic:
        # Manual-only (or trigger-less): cannot start without a human.
        return [], []

    unknown = [t for t in automatic if t not in KNOWN_AUTOMATIC_TRIGGERS]
    if unknown:
        warnings.append(
            f"{name}: unrecognized trigger(s) {unknown} treated as automatic "
            f"(fail-safe); confirm this is intended"
        )

    jobs = document.get("jobs") or {}
    if not jobs:
        warnings.append(f"{name}: automatic trigger {automatic} but no jobs defined")
        return errors, warnings

    for job_name, job in jobs.items():
        job = job or {}
        location = f"{name}::{job_name}"

        if "if" not in job:
            errors.append(
                f"{location}: MISSING job-level `if:` guard "
                f"(workflow has automatic trigger(s) {automatic})"
            )
            continue

        condition = normalize(job["if"])

        if condition in ACCEPTED_GUARDS:
            # Correct. Still surface skip-override functions for review.
            if any(fn in condition for fn in SKIP_OVERRIDE_FUNCTIONS):
                warnings.append(
                    f"{location}: guard also uses a skip-override function; "
                    f"verify it cannot run when the guard is false"
                )
            continue

        # Wrong in some way - diagnose precisely rather than just "mismatch".
        has_repo_clause = CLAUSE_REPO in condition
        has_event_clause = CLAUSE_EVENT in condition

        if not has_repo_clause and "github.repository" in condition:
            errors.append(
                f"{location}: wrong repository string; expected "
                f"{CLAUSE_REPO}\n      found: {condition}"
            )
        elif not has_repo_clause:
            errors.append(
                f"{location}: guard has no repository check; expected "
                f"{CLAUSE_REPO}\n      found: {condition}"
            )
        elif not has_event_clause:
            errors.append(
                f"{location}: guard has no workflow_dispatch escape; expected "
                f"{CLAUSE_EVENT}\n      found: {condition}"
            )
        else:
            # Both clauses present but the expression is larger than the two
            # accepted forms - cannot mechanically prove it is safe.
            warnings.append(
                f"{location}: `if:` contains both guard clauses inside a larger "
                f"expression that this script cannot verify - review by hand\n"
                f"      found: {condition}"
            )
            if any(fn in condition for fn in SKIP_OVERRIDE_FUNCTIONS):
                warnings.append(
                    f"{location}: that expression also uses a skip-override "
                    f"function (always/success/failure/cancelled)"
                )

    return errors, warnings


def main() -> int:
    workflows_dir = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    if not workflows_dir.is_dir():
        print(f"check-workflow-guards: no such directory: {workflows_dir}", file=sys.stderr)
        return 2

    paths = sorted(
        p for p in workflows_dir.iterdir()
        if p.is_file() and p.suffix in (".yml", ".yaml")
    )
    if not paths:
        print(f"check-workflow-guards: no workflow files in {workflows_dir}", file=sys.stderr)
        return 2

    all_errors: list[str] = []
    all_warnings: list[str] = []
    guarded_jobs = 0
    manual_only = 0

    for path in paths:
        # Open by absolute path; report by relative one. Passing the relative
        # path to the loaders made every message tidy and every invocation
        # from outside the repository root die with a FileNotFoundError
        # traceback and exit 1, where the contract at the top of this file
        # promises exit 2 for "could not run".
        # as_posix: the same message on Windows as everywhere else.
        rel = path.relative_to(workflows_dir.parent.parent).as_posix()
        try:
            document = load_workflow(path)
        except yaml.YAMLError as exc:
            # A file that does not parse cannot be audited at all, so this is
            # "could not run" (exit 2), not a guard violation (exit 1).
            print(f"check-workflow-guards: {rel}: not valid YAML: {exc}", file=sys.stderr)
            return 2
        errors, warnings = check_document(document, rel)
        all_errors.extend(errors)
        all_warnings.extend(warnings)

        automatic, _ = classify_triggers(document if isinstance(document, dict) else {})
        if automatic:
            guarded_jobs += len((document.get("jobs") or {}))
        else:
            manual_only += 1

    for warning in all_warnings:
        print(f"WARNING  {warning}")

    if all_errors:
        print()
        print("check-workflow-guards: FAILED - unguarded automatic workflow job(s).")
        print(
            "Every job in a workflow with an automatic trigger must carry:\n"
            f"    if: {ACCEPTED_GUARDS[0]}\n"
            "Without it the job runs automatically on any mirror or fork.\n"
        )
        for error in all_errors:
            print(f"  ERROR  {error}")
        print(f"\n{len(all_errors)} violation(s).")
        return 1

    print(
        f"check-workflow-guards: OK - {len(paths)} workflow(s) checked; "
        f"{manual_only} manual-only (no guard needed), "
        f"{guarded_jobs} automatically-triggered job(s) correctly guarded."
    )
    if all_warnings:
        print(f"({len(all_warnings)} warning(s) above are advisory, not failures.)")
    print(
        "NOTE: this check only sees files in .github/workflows/. It CANNOT see "
        "settings-level automation such as CodeQL default setup or Dependabot "
        "security updates, which run without any file in the repo. Disable those "
        "in the repository's settings - a green result here is necessary but "
        "not sufficient."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
