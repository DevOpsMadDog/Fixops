from __future__ import annotations

from pathlib import Path

import pytest

from simulations.ssdlc import run


def test_overlay_merge(tmp_path: Path) -> None:
    overlay_file = tmp_path / "overlay.json"
    overlay_file.write_text(
        '{"global": true, "stages": {"design": {"risk_summary": {"critical": 99}}}}',
        encoding="utf-8",
    )
    overlay = run._load_overlay(overlay_file)
    merged = run._overlay_for_stage(overlay, "design")
    assert merged["risk_summary"]["critical"] == 99
    merged_all = run._overlay_for_stage(overlay, "build")
    assert merged_all["global"] is True


def test_overlay_requires_mapping(tmp_path: Path) -> None:
    bad = tmp_path / "overlay.json"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(run.StageValidationError):
        run._load_overlay(bad)


def test_ensure_inputs_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run, "BASE_DIR", tmp_path)
    with pytest.raises(run.StageValidationError):
        run._ensure_inputs("design", ["design_context.csv"])


STAGE_OUTPUTS = {
    "design": "design_crosswalk.json",
    "requirements": "policy_plan.json",
    "build": "component_index.json",
    "test": "normalized_findings.json",
    "deploy": "iac_posture.json",
    "operate": "exploitability.json",
}


@pytest.mark.parametrize("stage", sorted(STAGE_OUTPUTS.keys()))
def test_individual_stage_outputs(tmp_path: Path, stage: str) -> None:
    out_dir = tmp_path / stage
    out_dir.mkdir()
    exit_code = run.main(["--stage", stage, "--out", str(out_dir)])
    assert exit_code == 0
    assert (out_dir / STAGE_OUTPUTS[stage]).exists()


def test_run_all_generates_everything(tmp_path: Path) -> None:
    out_dir = tmp_path / "all"
    exit_code = run.main(["--stage", "all", "--out", str(out_dir)])
    assert exit_code == 0
    for filename in STAGE_OUTPUTS.values():
        assert (out_dir / filename).exists()
