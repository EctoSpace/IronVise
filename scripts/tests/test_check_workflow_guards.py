"""Tests for scripts/check-workflow-guards.py against fixture workflow trees."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("yaml")

GUARD = "github.repository == 'EctoSpace/EctoLedger' || github.event_name == 'workflow_dispatch'"
GUARD_REVERSED = "github.event_name == 'workflow_dispatch' || github.repository == 'EctoSpace/EctoLedger'"


@pytest.fixture
def repo(tmp_path: Path, install_script, run_script):
    """A fixture repository: returns a writer for workflow files and a runner."""
    script = install_script("check-workflow-guards.py")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)

    class Repo:
        root = tmp_path

        @staticmethod
        def workflow(name: str, text: str, *, newline: str = "\n") -> Path:
            path = workflows / name
            path.write_bytes(text.replace("\n", newline).encode("utf-8"))
            return path

        @staticmethod
        def run():
            # Run from an unrelated directory: the script must find the tree
            # from its own location, not the working directory.
            return run_script(script, cwd=tmp_path / "scripts")

    return Repo


def job(guard: str | None = None, name: str = "build") -> str:
    lines = [f"  {name}:", "    runs-on: ubuntu-latest"]
    if guard is not None:
        lines.append(f'    if: "{guard}"')
    lines += ["    steps:", "      - run: echo hi"]
    return "\n".join(lines) + "\n"


def workflow(on: str, *jobs: str) -> str:
    return f"name: fixture\n{on}\njobs:\n" + "".join(jobs)


# --- passing trees -----------------------------------------------------------


@pytest.mark.parametrize(
    "on",
    [
        "on: workflow_dispatch",
        "on: [workflow_dispatch]",
        "on:\n  workflow_dispatch:\n    inputs:\n      x:\n        type: string",
    ],
    ids=["string", "list", "map"],
)
def test_manual_only_workflow_needs_no_guard(repo, on):
    repo.workflow("manual.yml", workflow(on, job()))
    result = repo.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 manual-only (no guard needed)" in result.stdout
    assert "0 automatically-triggered job(s)" in result.stdout


@pytest.mark.parametrize(
    "on",
    [
        "on: push",
        "on: [push, pull_request]",
        "on:\n  push:\n    branches: [main]\n  schedule:\n    - cron: '0 0 * * *'",
        '"on": push',
        "'on': [push]",
    ],
    ids=["string", "list", "map", "double-quoted-key", "single-quoted-key"],
)
def test_guarded_automatic_workflow_passes(repo, on):
    repo.workflow("ci.yml", workflow(on, job(GUARD, "a"), job(GUARD_REVERSED, "b")))
    result = repo.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "check-workflow-guards: OK" in result.stdout
    assert "2 automatically-triggered job(s) correctly guarded" in result.stdout


@pytest.mark.parametrize(
    "guard",
    [
        "${{ " + GUARD + " }}",
        "${{" + GUARD + "}}",
        GUARD.replace(" || ", "   ||\t "),
    ],
    ids=["braced", "braced-tight", "extra-whitespace"],
)
def test_guard_spelling_variants_are_accepted(repo, guard):
    repo.workflow("ci.yml", workflow("on: push", job(guard)))
    assert repo.run().returncode == 0


def test_folded_multiline_guard_is_accepted(repo):
    text = (
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    if: >-\n"
        "      github.repository == 'EctoSpace/EctoLedger' ||\n"
        "      github.event_name == 'workflow_dispatch'\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    repo.workflow("ci.yml", text)
    assert repo.run().returncode == 0


def test_comments_and_crlf_line_endings_are_handled(repo):
    text = (
        "# leading comment\n"
        "on:  # triggers\n"
        "  push:  # every push\n"
        "jobs:\n"
        "  build:  # the only job\n"
        "    runs-on: ubuntu-latest\n"
        f'    if: "{GUARD}"  # the guard\n'
        "    steps:\n"
        "      - run: echo hi\n"
    )
    repo.workflow("ci.yml", text, newline="\r\n")
    result = repo.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 automatically-triggered job(s) correctly guarded" in result.stdout


def test_crlf_unguarded_workflow_still_fails(repo):
    repo.workflow("ci.yml", workflow("on: push", job()), newline="\r\n")
    assert repo.run().returncode == 1


def test_empty_and_comment_only_files_are_treated_as_manual(repo):
    repo.workflow("empty.yml", "")
    repo.workflow("comments.yaml", "# nothing here yet\n")
    result = repo.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 workflow(s) checked; 2 manual-only" in result.stdout


def test_non_workflow_files_are_ignored(repo):
    repo.workflow("README.md", "on: push\njobs:\n  x: {}\n")
    repo.workflow("ok.yml", workflow("on: workflow_dispatch", job()))
    result = repo.run()
    assert result.returncode == 0
    assert "1 workflow(s) checked" in result.stdout


def test_both_yml_and_yaml_extensions_are_checked(repo):
    repo.workflow("a.yml", workflow("on: workflow_dispatch", job()))
    repo.workflow("b.yaml", workflow("on: push", job()))
    result = repo.run()
    assert result.returncode == 1
    assert ".github/workflows/b.yaml::build: MISSING" in result.stdout


def test_ok_output_notes_settings_level_automation_is_out_of_scope(repo):
    repo.workflow("ci.yml", workflow("on: push", job(GUARD)))
    result = repo.run()
    assert "NOTE: this check only sees files in .github/workflows/" in result.stdout


# --- failing trees -----------------------------------------------------------


def test_unguarded_automatic_job_fails_with_clear_message(repo):
    repo.workflow("ci.yml", workflow("on: push", job()))
    result = repo.run()
    assert result.returncode == 1
    assert "check-workflow-guards: FAILED" in result.stdout
    assert (
        "ERROR  .github/workflows/ci.yml::build: MISSING job-level `if:` guard "
        "(workflow has automatic trigger(s) ['push'])"
    ) in result.stdout
    assert f"if: {GUARD}" in result.stdout
    assert "1 violation(s)." in result.stdout


@pytest.mark.parametrize(
    "on, expected",
    [
        ("on: [workflow_dispatch, push]", "['push']"),
        ("on:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 3 * * 1'", "['schedule']"),
        ("on:\n  workflow_dispatch:\n  pull_request:\n  push:", "['pull_request', 'push']"),
    ],
    ids=["list", "map-schedule", "map-two-automatic"],
)
def test_mixed_triggers_require_the_guard(repo, on, expected):
    repo.workflow("mixed.yml", workflow(on, job()))
    result = repo.run()
    assert result.returncode == 1
    assert f"automatic trigger(s) {expected}" in result.stdout


def test_every_job_must_carry_the_guard(repo):
    repo.workflow("ci.yml", workflow("on: push", job(GUARD, "good"), job(None, "bad"), job(None, "worse")))
    result = repo.run()
    assert result.returncode == 1
    assert "ci.yml::good" not in result.stdout
    assert "ci.yml::bad: MISSING" in result.stdout
    assert "ci.yml::worse: MISSING" in result.stdout
    assert "2 violation(s)." in result.stdout


def test_job_with_empty_body_is_reported_missing(repo):
    repo.workflow("ci.yml", "on: push\njobs:\n  placeholder:\n")
    result = repo.run()
    assert result.returncode == 1
    assert "ci.yml::placeholder: MISSING" in result.stdout


def test_violations_in_one_file_fail_the_whole_run(repo):
    repo.workflow("a.yml", workflow("on: push", job(GUARD)))
    repo.workflow("b.yml", workflow("on: release", job()))
    result = repo.run()
    assert result.returncode == 1
    assert "a.yml::" not in result.stdout
    assert "b.yml::build: MISSING" in result.stdout


@pytest.mark.parametrize(
    "guard, diagnosis",
    [
        (
            "github.repository == 'Someone/EctoLedger' || github.event_name == 'workflow_dispatch'",
            "wrong repository string; expected github.repository == 'EctoSpace/EctoLedger'",
        ),
        (
            "github.event_name == 'workflow_dispatch'",
            "guard has no repository check",
        ),
        (
            "github.repository == 'EctoSpace/EctoLedger'",
            "guard has no workflow_dispatch escape",
        ),
        (
            "always()",
            "guard has no repository check",
        ),
    ],
    ids=["wrong-repo", "no-repo-clause", "no-dispatch-clause", "unrelated"],
)
def test_wrong_guards_are_diagnosed_precisely(repo, guard, diagnosis):
    repo.workflow("ci.yml", workflow("on: push", job(guard)))
    result = repo.run()
    assert result.returncode == 1
    assert f"ci.yml::build: {diagnosis}" in result.stdout
    assert f"found: {guard}" in result.stdout


# --- warnings (advisory, exit 0) ---------------------------------------------


def test_guard_inside_larger_expression_is_a_warning_not_an_error(repo):
    guard = f"({GUARD}) && github.ref == 'refs/heads/main'"
    repo.workflow("ci.yml", workflow("on: push", job(guard)))
    result = repo.run()
    assert result.returncode == 0, result.stdout
    assert "WARNING  .github/workflows/ci.yml::build: `if:` contains both guard clauses" in result.stdout
    assert "skip-override" not in result.stdout
    assert "(1 warning(s) above are advisory, not failures.)" in result.stdout


def test_skip_override_in_larger_expression_adds_a_second_warning(repo):
    guard = f"always() && ({GUARD})"
    repo.workflow("ci.yml", workflow("on: push", job(guard)))
    result = repo.run()
    assert result.returncode == 0
    assert "also uses a skip-override function (always/success/failure/cancelled)" in result.stdout
    assert "(2 warning(s)" in result.stdout


def test_unknown_trigger_is_treated_as_automatic_and_warned(repo):
    repo.workflow("future.yml", workflow("on: some_future_event", job()))
    result = repo.run()
    assert result.returncode == 1
    assert "unrecognized trigger(s) ['some_future_event'] treated as automatic" in result.stdout
    assert "future.yml::build: MISSING" in result.stdout


def test_automatic_workflow_without_jobs_warns(repo):
    repo.workflow("ci.yml", "on: push\n")
    result = repo.run()
    assert result.returncode == 0
    assert "automatic trigger ['push'] but no jobs defined" in result.stdout


# --- could not run -----------------------------------------------------------


def test_missing_workflows_directory_exits_2(tmp_path, install_script, run_script):
    script = install_script("check-workflow-guards.py")
    result = run_script(script, cwd=tmp_path)
    assert result.returncode == 2
    assert "no such directory" in result.stderr


def test_empty_workflows_directory_exits_2(repo):
    result = repo.run()
    assert result.returncode == 2
    assert "no workflow files in" in result.stderr


def test_top_level_list_is_an_error(repo):
    repo.workflow("odd.yml", "- just\n- a list\n")
    result = repo.run()
    assert result.returncode == 1
    assert "odd.yml: top level is not a mapping" in result.stdout


def test_invalid_yaml_is_reported_without_a_traceback(repo):
    repo.workflow("broken.yml", "on: push\njobs:\n  build: [unclosed\n")
    result = repo.run()
    assert "Traceback" not in result.stderr
    assert "broken.yml: not valid YAML" in result.stdout + result.stderr
    assert result.returncode == 2
