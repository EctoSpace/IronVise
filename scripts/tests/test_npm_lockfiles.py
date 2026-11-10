"""Every committed npm lockfile installs on every platform.

`npm audit fix` once left two version-less stubs for an optional, Linux-only
package in gui/package-lock.json. macOS and Windows skip that package, so
`npm ci` passed there; on Linux x64 it died with "Invalid Version:".
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _lockfiles() -> list[Path]:
    listed = subprocess.run(["git", "ls-files", "*package-lock.json"], cwd=ROOT, capture_output=True,
                            text=True, encoding="utf-8", check=True).stdout.split()
    return [ROOT / name for name in listed]


def _incomplete_entries(lock: dict) -> list[str]:
    # Local security backports are committed source directories, referenced by
    # a lockfile link rather than a registry tarball. They still need a version.
    local_targets = {
        entry["resolved"] for entry in lock.get("packages", {}).values()
        if entry.get("link") and "resolved" in entry
    }
    return [
        path for path, entry in lock.get("packages", {}).items()
        if path and not entry.get("link") and (
            "version" not in entry
            # A bundled dependency ships inside its parent's tarball.
            or path not in local_targets and not entry.get("inBundle")
            and not ("resolved" in entry and "integrity" in entry)
        )
    ]


def test_the_scan_catches_a_version_less_stub():
    lock = {"packages": {
        "": {"name": "app"},
        "node_modules/ok": {"version": "1.0.0", "resolved": "https://r/ok.tgz", "integrity": "sha512-x"},
        "node_modules/a/node_modules/stub": {"dev": True, "optional": True},
        "node_modules/local": {"link": True, "resolved": "../local"},
        "node_modules/b/node_modules/bundled": {"version": "2.0.0", "inBundle": True},
        "node_modules/no-hash": {"version": "1.0.0", "resolved": "https://r/no-hash.tgz"},
    }}
    assert _incomplete_entries(lock) == ["node_modules/a/node_modules/stub", "node_modules/no-hash"]


def test_the_repository_has_lockfiles_to_check():
    assert any(path.parent.name == "gui" for path in _lockfiles())


# Direct optional deps, not only transitive ones. `npm ci` on another OS skips
# a platform binding that the lockfile lists only under rolldown (npm/cli#4828).
REQUIRED_GUI_BINDINGS = (
    "@rolldown/binding-darwin-arm64",
    "@rolldown/binding-linux-x64-gnu",
    "@rolldown/binding-win32-x64-msvc",
)


def test_gui_lockfile_installs_native_bindings_on_every_desktop():
    lock = json.loads((ROOT / "gui" / "package-lock.json").read_text(encoding="utf-8"))
    root = lock["packages"][""]
    direct = root.get("optionalDependencies", {})
    missing = [name for name in REQUIRED_GUI_BINDINGS if name not in direct]
    assert missing == [], missing
    for name in REQUIRED_GUI_BINDINGS:
        entry = lock["packages"][f"node_modules/{name}"]
        assert entry["version"]
        assert entry["resolved"].startswith("https://registry.npmjs.org/")
        assert entry["integrity"].startswith("sha512-")
        assert entry.get("optional") is True


def test_every_lockfile_entry_pins_a_version_tarball_and_hash():
    offenders = {
        str(path.relative_to(ROOT)): bad
        for path in _lockfiles()
        if (bad := _incomplete_entries(json.loads(path.read_text(encoding="utf-8"))))
    }
    assert offenders == {}, f"entries npm ci cannot install on every platform: {offenders}"


def test_local_backports_require_a_version_and_an_explicit_link():
    lock = {"packages": {
        "node_modules/dep": {"link": True, "resolved": "security-dep"},
        "security-dep": {"version": "1.0.0-local.1"},
        "unlinked-source": {"version": "1.0.0"},
    }}
    assert _incomplete_entries(lock) == ["unlinked-source"]
    del lock["packages"]["security-dep"]["version"]
    assert _incomplete_entries(lock) == ["security-dep", "unlinked-source"]
