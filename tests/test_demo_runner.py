import os
from pathlib import Path

import pytest

from core.demo_runner import run_demo_pipeline
from core.evidence import Fernet


def test_run_demo_pipeline_demo_mode(tmp_path: Path) -> None:
    output_path = tmp_path / "demo.json"
    result, summary = run_demo_pipeline(
        mode="demo", output_path=output_path, include_summary=False
    )
    assert output_path.exists()
    assert "FixOps Demo mode summary:" == summary[0]
    assert result.get("severity_overview")
    bundle = result.get("evidence_bundle", {})
    assert bundle.get("bundle_id")
    bundle_path = Path(bundle["files"]["bundle"])
    assert bundle_path.exists()
    if Fernet is None or not os.getenv("FIXOPS_EVIDENCE_KEY"):
        assert bundle.get("encrypted") is False


def test_run_demo_pipeline_enterprise_mode(tmp_path: Path) -> None:
    output_path = tmp_path / "enterprise.json"
    result, summary = run_demo_pipeline(
        mode="enterprise",
        output_path=output_path,
        include_summary=False,
    )
    assert output_path.exists()
    assert "FixOps Enterprise mode summary:" == summary[0]
    assert result.get("pricing_summary")
    bundle = result.get("evidence_bundle", {})
    assert bundle.get("bundle_id")
    files = bundle.get("files", {})
    bundle_path = Path(files["bundle"])
    manifest_path = Path(files["manifest"])
    assert bundle_path.exists()
    assert manifest_path.exists()
    if Fernet is None or not os.getenv("FIXOPS_EVIDENCE_KEY"):
        assert bundle.get("encrypted") is False


def test_run_demo_pipeline_reports_runtime_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")
    monkeypatch.delenv("FIXOPS_JIRA_TOKEN", raising=False)
    monkeypatch.delenv("FIXOPS_CONFLUENCE_TOKEN", raising=False)
    monkeypatch.setattr("core.demo_runner._ensure_env_defaults", lambda: None)

    result, summary = run_demo_pipeline(mode="enterprise", include_summary=False)

    warnings = result.get("runtime_warnings", [])
    assert warnings, "runtime warnings should be present when automation tokens missing"
    assert any(line.strip().startswith("Runtime warnings:") for line in summary)
    assert any("automation token" in line for line in summary)
