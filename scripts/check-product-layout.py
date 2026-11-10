#!/usr/bin/env python3
"""Reject obsolete executable/SDK namespaces in source and built packages."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OBSOLETE = (
    "sdk/python/ectoledger_sdk", "ectoledger-win.ps1",
    "crates/host/src/bin/ironvise.rs", "assets/ectoLedger-Logo.webp",
    "site/images/ectoLedger.webp", "site/images/ectoledger-logo.png",
    "assets/el-logo.webp", "site/images/el-logo.webp", "site/images/el-Logo.webp",
)
REQUIRED = (
    "assets/ironvise-logo.webp", "assets/ironvise-mark.webp",
    "site/images/ironvise-logo.webp", "site/images/ironvise-hero.webp",
    "site/images/ironvise-mark.webp",
)


def check_source(root: Path) -> list[str]:
    errors = [f"obsolete path remains: {name}" for name in OBSOLETE if (root / name).exists()]
    errors += [f"required logo missing: {name}" for name in REQUIRED if not (root / name).exists()]
    cargo = tomllib.loads((root / "crates/host/Cargo.toml").read_text())
    bins = cargo.get("bin", [])
    if sorted(b["name"] for b in bins) != ["guard-worker", "ironvise", "verify-cert"]:
        errors.append("CLI targets must be ironvise, guard-worker and verify-cert only")
    if cargo["package"].get("autobins") is not False:
        errors.append("automatic binary discovery must be disabled")
    python = tomllib.loads((root / "sdk/python/pyproject.toml").read_text())
    if python["project"]["name"] != "ironvise":
        errors.append("Python distribution must be named ironvise")
    if python["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] != ["ironvise_sdk"]:
        errors.append("Python wheel must contain only ironvise_sdk")
    if json.loads((root / "sdk/typescript/package.json").read_text())["name"] != "ironvise":
        errors.append("npm package must be named ironvise")
    for name in ("Dockerfile", ".github/workflows/release.yml"):
        text = (root / name).read_text()
        if "/release/ectoledger" in text or "\\release\\ectoledger" in text:
            errors.append(f"legacy executable is packaged by {name}")
    return errors


def check_python_archive(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = [n for n in archive.namelist() if not n.endswith("/")]
        relative = names
    else:
        with tarfile.open(path) as archive:
            names = [m.name for m in archive.getmembers() if m.isfile()]
        relative = [n.split("/", 1)[-1] for n in names]
    errors = []
    for name in relative:
        parts = PurePosixPath(name).parts
        if any(p in {"ectoledger_sdk", "__pycache__", ".DS_Store"} for p in parts):
            errors.append(f"obsolete/cache file in {path.name}: {name}")
        if name.endswith(".py") and not name.startswith("ironvise_sdk/"):
            errors.append(f"extra Python implementation in {path.name}: {name}")
    if "ironvise_sdk/client.py" not in relative or "ironvise_sdk/py.typed" not in relative:
        errors.append(f"incomplete IronVise SDK: {path.name}")
    if not path.name.startswith("ironvise-"):
        errors.append(f"old distribution name: {path.name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-dist", type=Path, help="inspect built wheel and source archive")
    args = parser.parse_args()
    errors = check_source(ROOT)
    if args.python_dist:
        wheels = list(args.python_dist.glob("*.whl"))
        sources = list(args.python_dist.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sources) != 1:
            errors.append("dist must contain exactly one wheel and one source archive")
        for path in [*wheels, *sources]:
            errors.extend(check_python_archive(path))
    for error in errors:
        print(f"check-product-layout: {error}")
    if errors:
        return 1
    print("check-product-layout: OK - one CLI and one SDK namespace per language")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
