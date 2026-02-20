import json
import zipfile
from pathlib import Path

import pytest
from apps.api.normalizers import InputNormalizer
from core.services.enterprise import id_allocator, signing
from core.services.enterprise.run_registry import RunRegistry
from core.stage_runner import StageRunner

REPO_ROOT = Path(__file__).resolve().parents[1]
INPUT_ROOT = REPO_ROOT / "fixtures" / "sample_inputs"
EXPECTED_ROOT = REPO_ROOT / "fixtures" / "expected_outputs"

STAGES = [
    ("requirements", "requirements/requirements-input.csv", "requirements.json"),
    ("design", "design/design-input.json", "design.manifest.json"),
    ("build", "build/sbom.json", "build.report.json"),
    ("test", "test/scanner.sarif", "test.report.json"),
    ("deploy", "deploy/tfplan.json", "deploy.manifest.json"),
    ("operate", "operate/ops-telemetry.json", "operate.snapshot.json"),
    ("decision", "decision/decision-input.json", "decision.json"),
]


def test_sample_stage_outputs_match_expected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FIXOPS_RUN_ID_SEED", "SAMPLE-RUN")
    monkeypatch.setenv("FIXOPS_FAKE_NOW", "2024-01-01T00:00:00Z")

    registry_root = tmp_path / "artefacts"
    registry = RunRegistry(root=registry_root)
    runner = StageRunner(registry, id_allocator, signing, normalizer=InputNormalizer())

    decision_summary = None

    for stage, relative_path, filename in STAGES:
        input_path = INPUT_ROOT / relative_path if relative_path else None
        summary = runner.run_stage(
            stage,
            input_path,
            app_name="life-claims-portal",
            mode="demo",
        )
        actual_payload = json.loads(summary.output_file.read_text(encoding="utf-8"))
        expected_payload = json.loads(
            (EXPECTED_ROOT / stage / filename).read_text(encoding="utf-8")
        )
        assert actual_payload == expected_payload
        if stage == "decision":
            decision_summary = summary

    assert decision_summary is not None

    actual_manifest = json.loads(
        (decision_summary.outputs_dir / "manifest.json").read_text(encoding="utf-8")
    )
    expected_manifest = json.loads(
        (EXPECTED_ROOT / "decision" / "manifest.json").read_text(encoding="utf-8")
    )
    assert actual_manifest == expected_manifest

    assert decision_summary.bundle is not None
    actual_bundle_path = decision_summary.bundle
    expected_bundle_dir = EXPECTED_ROOT / "decision" / "evidence_bundle"

    with zipfile.ZipFile(actual_bundle_path, "r") as actual_zip:
        actual_documents = {
            info.filename: actual_zip.read(info).decode("utf-8")
            for info in actual_zip.infolist()
        }

    expected_documents = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(expected_bundle_dir.glob("*"))
        if path.is_file()
    }
    assert actual_documents == expected_documents
