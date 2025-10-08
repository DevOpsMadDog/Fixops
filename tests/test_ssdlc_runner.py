from __future__ import annotations

import json
from pathlib import Path

import pytest

from simulations.ssdlc import run


@pytest.mark.parametrize(
    "stage, expected",
    [
        ("design", "design_crosswalk.json"),
        ("requirements", "policy_plan.json"),
        ("build", "component_index.json"),
        ("test", "normalized_findings.json"),
        ("deploy", "iac_posture.json"),
        ("operate", "exploitability.json"),
    ],
)
def test_ssdlc_runner_generates_artifacts(tmp_path: Path, stage: str, expected: str) -> None:
    output_dir = tmp_path / stage
    rc = run.main(["--stage", stage, "--out", str(output_dir)])
    assert rc == 0
    output_file = output_dir / expected
    assert output_file.exists()
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert payload
