"""Delivery guards reject legacy shims, extra implementations and bytecode."""
import importlib.util
from pathlib import Path
import zipfile

import pytest

spec = importlib.util.spec_from_file_location(
    "product_layout", Path(__file__).resolve().parents[1] / "check-product-layout.py"
)
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)


@pytest.mark.parametrize("extra", [
    "ectoledger_sdk/__init__.py", "other_sdk/client.py",
    "ironvise_sdk/__pycache__/client.pyc", "ironvise_sdk/.DS_Store",
])
def test_a_built_wheel_rejects_unwanted_delivered_files(tmp_path, extra):
    wheel = tmp_path / "ironvise-0.8.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("ironvise_sdk/client.py", "")
        archive.writestr("ironvise_sdk/py.typed", "")
        archive.writestr(extra, "")
    assert layout.check_python_archive(wheel)


def test_a_complete_single_namespace_wheel_passes(tmp_path):
    wheel = tmp_path / "ironvise-0.8.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("ironvise_sdk/client.py", "")
        archive.writestr("ironvise_sdk/py.typed", "")
        archive.writestr("ironvise-0.8.0.dist-info/METADATA", "")
    assert layout.check_python_archive(wheel) == []
