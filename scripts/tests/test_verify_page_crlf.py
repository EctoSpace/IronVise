"""The verifier page's freshness check holds on a Windows checkout.

Git for Windows defaults to core.autocrlf=true, which gave the Rust sources
and the sample certificates CRLF line endings. check-wasm-verifier.mjs then
reported the bundle as stale and every embedded sample as changed, although
nothing had changed but the line endings.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _source_hash(root: Path) -> str:
    script = (
        "import(process.argv[1]).then(m => process.stdout.write(m.sourceHash(process.argv[2])))"
    )
    module = (ROOT / "scripts" / "build-verify-page.mjs").as_uri()
    return subprocess.run(["node", "-e", script, module, str(root)], capture_output=True,
                          text=True, check=True).stdout


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node")
def test_crlf_sources_hash_like_lf_sources(tmp_path: Path) -> None:
    lf, crlf = tmp_path / "lf", tmp_path / "crlf"
    for root, eol in ((lf, "\n"), (crlf, "\r\n")):
        for d in ("crates/elc", "crates/elc-wasm", "crates/core"):
            (root / d / "src").mkdir(parents=True)
            (root / d / "Cargo.toml").write_bytes(f"[package]{eol}name = \"x\"{eol}".encode())
            (root / d / "src" / "lib.rs").write_bytes(f"fn a() {{}}{eol}// end{eol}".encode())
    assert _source_hash(lf) == _source_hash(crlf)


def test_certificates_and_the_bundle_check_out_with_lf() -> None:
    paths = ["examples/verified-session/session.elc", "examples/challenge/ledger-5-certificate.elc",
             "site/verify-bundle.js"]
    out = subprocess.run(["git", "check-attr", "eol", "--", *paths], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    assert out.count("eol: lf") == len(paths), out
