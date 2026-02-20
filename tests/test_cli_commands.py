import argparse
import json
from pathlib import Path

import pytest
from core import cli
from core.configuration import OverlayConfig


@pytest.fixture
def parser() -> argparse.ArgumentParser:
    return cli.build_parser()


def _create_required_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    sbom = tmp_path / "sbom.json"
    sarif = tmp_path / "snyk.sarif"
    cve = tmp_path / "cve.json"
    sbom.write_text("{}", encoding="utf-8")
    sarif.write_text("{}", encoding="utf-8")
    cve.write_text("[]", encoding="utf-8")
    return sbom, sarif, cve


def test_ingest_command_writes_output_and_copies_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parser: argparse.ArgumentParser
) -> None:
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}", encoding="utf-8")

    result_payload = {"evidence_bundle": {"files": {"bundle": str(bundle)}}}
    monkeypatch.setattr(cli, "_build_pipeline_result", lambda args: result_payload)

    sbom, sarif, cve = _create_required_files(tmp_path)
    output_path = tmp_path / "result.json"
    evidence_dir = tmp_path / "evidence"

    args = parser.parse_args(
        [
            "ingest",
            "--sbom",
            str(sbom),
            "--sarif",
            str(sarif),
            "--cve",
            str(cve),
            "--output",
            str(output_path),
            "--pretty",
            "--evidence-dir",
            str(evidence_dir),
        ]
    )

    exit_code = args.func(args)
    assert exit_code == 0
    assert output_path.exists()
    copied_bundle = evidence_dir / bundle.name
    assert copied_bundle.exists()


def test_make_decision_command_returns_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    parser: argparse.ArgumentParser,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}", encoding="utf-8")

    result_payload = {
        "enhanced_decision": {"final_decision": "allow", "consensus_confidence": 0.91},
        "severity_overview": {"highest": "medium"},
        "guardrail_evaluation": {"status": "pass"},
        "evidence_bundle": {"files": {"bundle": str(bundle)}},
    }
    monkeypatch.setattr(cli, "_build_pipeline_result", lambda args: result_payload)

    sbom, sarif, cve = _create_required_files(tmp_path)
    output_path = tmp_path / "decision.json"
    evidence_dir = tmp_path / "evidence"

    args = parser.parse_args(
        [
            "make-decision",
            "--sbom",
            str(sbom),
            "--sarif",
            str(sarif),
            "--cve",
            str(cve),
            "--output",
            str(output_path),
            "--pretty",
            "--evidence-dir",
            str(evidence_dir),
        ]
    )

    exit_code = args.func(args)
    assert exit_code == 0
    stdout = capsys.readouterr().out.strip()
    summary = json.loads(stdout)
    assert summary["decision"] == "allow"
    assert output_path.exists()
    assert (evidence_dir / bundle.name).exists()


def test_get_evidence_command_copies_bundle(
    tmp_path: Path, parser: argparse.ArgumentParser, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}", encoding="utf-8")
    result_payload = {"evidence_bundle": {"files": {"bundle": str(bundle)}}}
    result_path = tmp_path / "pipeline.json"
    result_path.write_text(json.dumps(result_payload), encoding="utf-8")

    destination = tmp_path / "copies"
    args = parser.parse_args(
        [
            "get-evidence",
            "--result",
            str(result_path),
            "--destination",
            str(destination),
            "--pretty",
        ]
    )

    exit_code = args.func(args)
    assert exit_code == 0
    copied = destination / bundle.name
    assert copied.exists()
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "ok"


def test_health_command_reports_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    parser: argparse.ArgumentParser,
    capsys: pytest.CaptureFixture[str],
) -> None:
    overlay = OverlayConfig(
        mode="enterprise",
        data={"evidence_dir": str(tmp_path / "evidence")},
        limits={
            "evidence": {"bundle_max_bytes": 2048, "compress": False, "encrypt": False}
        },
    )
    overlay.allowed_data_roots = (tmp_path,)

    monkeypatch.setattr(cli, "load_overlay", lambda path=None: overlay)

    args = parser.parse_args(["health", "--pretty"])
    exit_code = args.func(args)
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert "pgmpy_available" in payload["checks"]
