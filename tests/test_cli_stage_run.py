from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest


APP_ID = "life-claims-portal"
SIM_DIR = Path("simulations/demo_pack")
EXPECTED_OUTPUTS = {
    "requirements": "requirements.json",
    "design": "design.manifest.json",
    "build": "build.report.json",
    "test": "test.report.json",
    "deploy": "deploy.manifest.json",
    "operate": "operate.snapshot.json",
    "decision": "decision.json",
}


def _stage_inputs() -> list[tuple[str, Path | None]]:
    return [
        ("requirements", SIM_DIR / "requirements-input.csv"),
        ("design", SIM_DIR / "design-input.json"),
        ("build", SIM_DIR / "sbom.json"),
        ("test", SIM_DIR / "scanner.sarif"),
        ("deploy", SIM_DIR / "tfplan.json"),
        ("operate", SIM_DIR / "ops-telemetry.json"),
        ("decision", None),
    ]


@pytest.fixture(autouse=True)
def clean_run_registry(tmp_path_factory: pytest.TempPathFactory) -> None:
    artefacts_root = Path("artefacts") / APP_ID
    if artefacts_root.exists():
        for run_dir in artefacts_root.iterdir():
            if run_dir.is_dir():
                for child in run_dir.rglob("*"):
                    if child.is_file():
                        child.unlink()
                for child in sorted(run_dir.rglob("*"), reverse=True):
                    if child.is_dir():
                        child.rmdir()
                run_dir.rmdir()


def _invoke_stage(stage: str, input_path: Path | None) -> tuple[str, Path]:
    cmd = [
        sys.executable,
        "-m",
        "core.cli",
        "stage-run",
        "--stage",
        stage,
        "--app",
        APP_ID,
    ]
    if input_path is not None:
        cmd.extend(["--input", str(input_path)])
    completed = subprocess.run(cmd, capture_output=True, text=True, check=True)
    match = re.search(r"run ([0-9T:-]+)", completed.stdout)
    assert match, f"unable to parse run identifier from output: {completed.stdout}"
    run_id = match.group(1)
    outputs_dir = Path("artefacts") / APP_ID / run_id / "outputs"
    assert outputs_dir.exists(), f"outputs directory missing for {stage}"
    return run_id, outputs_dir


def test_stage_run_pipeline_generates_outputs(signing_env: None) -> None:
    for stage, input_file in _stage_inputs():
        run_id, outputs_dir = _invoke_stage(stage, input_file)
        expected = outputs_dir / EXPECTED_OUTPUTS[stage]
        assert expected.exists(), f"missing canonical output for {stage}"
        if stage == "design":
            payload = json.loads(expected.read_text())
            assert payload.get("app_id") == APP_ID
        if stage == "decision":
            decision_payload = json.loads(expected.read_text())
            assert len(decision_payload.get("top_factors", [])) >= 2
            assert "compliance_rollup" in decision_payload
