from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SIM_ROOT = REPO_ROOT / "simulations" / "demo_pack"

STAGE_INPUTS = [
    ("requirements", "requirements-input.csv"),
    ("design", "design-input.json"),
    ("build", "sbom.json"),
    ("test", "scanner.sarif"),
    ("deploy", "tfplan.json"),
    ("operate", "ops-telemetry.json"),
    ("decision", None),
]

CANONICAL_OUTPUTS = {
    "requirements": "requirements.json",
    "design": "design.manifest.json",
    "build": "build.report.json",
    "test": "test.report.json",
    "deploy": "deploy.manifest.json",
    "operate": "operate.snapshot.json",
    "decision": "decision.json",
}


def _pythonpath_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    entries = [str(REPO_ROOT), str(REPO_ROOT / "fixops-enterprise")]
    existing = env.get("PYTHONPATH")
    if existing:
        entries.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(entries)
    env["FIXOPS_ARTEFACTS_ROOT"] = str(tmp_path)
    return env


def _invoke_stage(stage: str, input_file: Path | None, env: dict[str, str]) -> None:
    cmd = [
        sys.executable,
        "-m",
        "apps.fixops_cli",
        "stage-run",
        "--stage",
        stage,
        "--app",
        "life-claims-portal",
    ]
    if input_file is not None:
        cmd.extend(["--input", str(input_file)])
    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"stage {stage} failed: {result.stdout}\n{result.stderr}"


def _latest_run(tmp_path: Path) -> tuple[str, str, Path]:
    app_dirs = [entry for entry in tmp_path.iterdir() if entry.is_dir() and entry.name.startswith("APP-")]
    assert app_dirs, f"expected artefact directory under {tmp_path}"
    app_root = app_dirs[0]
    latest = json.loads((app_root / "LATEST").read_text(encoding="utf-8"))
    run_id = latest["run_id"]
    outputs_dir = app_root / run_id / "outputs"
    return app_root.name, run_id, outputs_dir


@pytest.mark.integration
def test_stage_run_materialises_canonical_outputs(tmp_path: Path) -> None:
    env = _pythonpath_env(tmp_path)
    for stage, filename in STAGE_INPUTS:
        input_path = SIM_ROOT / filename if filename else None
        _invoke_stage(stage, input_path, env)
        app_id, run_id, outputs_dir = _latest_run(tmp_path)
        canonical_name = CANONICAL_OUTPUTS[stage]
        target = outputs_dir / canonical_name
        assert target.exists(), f"missing {canonical_name} for {stage}"
        if target.suffix == ".json":
            payload = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                if stage != "decision":
                    assert payload.get("app_id", "").startswith("APP-"), payload
                    assert payload.get("run_id") == run_id, payload
                if stage == "requirements":
                    requirements = payload.get("requirements", [])
                    assert requirements, "requirements array missing"
                    for item in requirements:
                        assert item["requirement_id"].startswith("REQ-"), item
                        assert item.get("Requirement_ID", "").startswith("REQ-"), item
        if stage == "decision":
            assert payload.get("app_id") == app_id
            assert payload.get("run_id") == run_id
            bundle = outputs_dir / "evidence_bundle.zip"
            manifest = outputs_dir / "manifest.json"
            assert bundle.exists()
            assert manifest.exists()
            json.loads(manifest.read_text(encoding="utf-8"))


def test_requirements_stage_starts_new_run(tmp_path: Path) -> None:
    env = _pythonpath_env(tmp_path)
    requirements_path = SIM_ROOT / "requirements-input.csv"

    _invoke_stage("requirements", requirements_path, env)
    _app_id, first_run_id, _ = _latest_run(tmp_path)

    _invoke_stage("requirements", requirements_path, env)
    _app_id, second_run_id, _ = _latest_run(tmp_path)

    assert second_run_id != first_run_id


def test_design_stage_reuses_current_run(tmp_path: Path) -> None:
    env = _pythonpath_env(tmp_path)
    requirements_path = SIM_ROOT / "requirements-input.csv"
    design_path = SIM_ROOT / "design-input.json"

    _invoke_stage("requirements", requirements_path, env)
    _app_id, first_run_id, _ = _latest_run(tmp_path)

    _invoke_stage("design", design_path, env)
    _app_id, second_run_id, _ = _latest_run(tmp_path)

    assert second_run_id == first_run_id

