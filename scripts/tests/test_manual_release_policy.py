"""The private candidate never starts Actions without a human dispatch."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_all_workflows_are_manual_and_publication_is_opt_in():
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        doc = yaml.safe_load(path.read_text())
        trigger = doc.get("on", doc.get(True))
        assert isinstance(trigger, dict), path
        assert set(trigger) == {"workflow_dispatch"}, path
        for name, spec in (trigger["workflow_dispatch"] or {}).get("inputs", {}).items():
            if name in {"publish_release", "publish_image"}:
                assert spec["type"] == "boolean", path
                assert spec["default"] is False, path
