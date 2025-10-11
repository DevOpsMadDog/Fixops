import json
import os
from pathlib import Path

import pytest

import core.cli as cli


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_cli_run_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")
    monkeypatch.delenv("SIGNING_PROVIDER", raising=False)
    monkeypatch.delenv("KEY_ID", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AZURE_VAULT_URL", raising=False)
    monkeypatch.delenv("SIGNING_ROTATION_SLA_DAYS", raising=False)

    design_csv = (
        "component,owner,criticality,notes\n"
        "payment-service,app-team,high,Handles card processing\n"
        "notification-service,platform,medium,Sends emails\n"
        "ai-orchestrator,ml-team,high,LangChain agent orchestrator for support bots\n"
    )
    design_path = tmp_path / "design.csv"
    design_path.write_text(design_csv, encoding="utf-8")

    sbom_document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "payment-service",
                "version": "1.0.0",
                "purl": "pkg:pypi/payment-service@1.0.0",
                "licenses": [{"license": "MIT"}],
            },
            {
                "type": "application",
                "name": "ai-orchestrator",
                "version": "0.4.0",
                "purl": "pkg:npm/langchain-agent@0.4.0",
                "licenses": [{"license": "Apache-2.0"}],
            },
        ],
    }
    sbom_path = tmp_path / "sbom.json"
    _write_json(sbom_path, sbom_document)

    cve_feed = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "title": "Example vulnerability in payment-service",
                "knownExploited": True,
                "severity": "high",
            }
        ]
    }
    cve_path = tmp_path / "cve.json"
    _write_json(cve_path, cve_feed)

    sarif_document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "DemoScanner"}},
                "results": [
                    {
                        "ruleId": "DEMO001",
                        "level": "error",
                        "message": {"text": "SQL injection risk"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "services/payment-service/app.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    sarif_path = tmp_path / "scan.sarif"
    _write_json(sarif_path, sarif_document)

    output_path = tmp_path / "result.json"
    evidence_dir = tmp_path / "evidence"

    exit_code = cli.main(
        [
            "run",
            "--overlay",
            str(Path("config/fixops.overlay.yml")),
            "--design",
            str(design_path),
            "--sbom",
            str(sbom_path),
            "--sarif",
            str(sarif_path),
            "--cve",
            str(cve_path),
            "--output",
            str(output_path),
            "--pretty",
            "--include-overlay",
            "--offline",
            "--signing-provider",
            "env",
            "--signing-key-id",
            "alias/demo",
            "--signing-region",
            "us-east-1",
            "--rotation-sla-days",
            "60",
            "--opa-url",
            "https://opa.internal",
            "--opa-token",
            "demo-token",
            "--opa-package",
            "core.security",
            "--opa-health-path",
            "/healthz",
            "--opa-bundle-status-path",
            "/bundles/core/status",
            "--opa-timeout",
            "9",
            "--evidence-dir",
            str(evidence_dir),
        ]
    )

    assert exit_code == 0
    assert os.getenv("SIGNING_PROVIDER") == "env"
    assert os.getenv("KEY_ID") == "alias/demo"
    assert os.getenv("AWS_REGION") == "us-east-1"
    assert os.getenv("SIGNING_ROTATION_SLA_DAYS") == "60"
    assert os.getenv("OPA_SERVER_URL") == "https://opa.internal"
    assert os.getenv("OPA_AUTH_TOKEN") == "demo-token"
    assert os.getenv("OPA_POLICY_PACKAGE") == "core.security"
    assert os.getenv("OPA_HEALTH_PATH") == "/healthz"
    assert os.getenv("OPA_BUNDLE_STATUS_PATH") == "/bundles/core/status"
    assert os.getenv("OPA_REQUEST_TIMEOUT") == "9"
    result_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert result_payload["status"] == "ok"
    assert result_payload["modules"]["executed"]
    archive_info = result_payload.get("artifact_archive")
    assert archive_info and "cve" in archive_info
    copied_files = list(evidence_dir.iterdir())
    assert copied_files, "evidence bundle was not copied"

    summary_output = capsys.readouterr().out
    assert "FixOps pipeline summary" in summary_output
    assert "Highest severity" in summary_output
    assert "Estimated ROI" in summary_output
    assert "Performance status" in summary_output
    assert "Tenants tracked" in summary_output


def test_cli_show_overlay(monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")
    monkeypatch.delenv("FIXOPS_JIRA_TOKEN", raising=False)
    monkeypatch.delenv("FIXOPS_CONFLUENCE_TOKEN", raising=False)
    monkeypatch.setattr("core.overlay_runtime.Fernet", None)

    exit_code = cli.main(
        [
            "show-overlay",
            "--overlay",
            str(Path("config/fixops.overlay.yml")),
            "--pretty",
        ]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    overlay_payload = json.loads(captured.out)
    assert overlay_payload["mode"] in {"demo", "enterprise"}
    assert "guardrails" in overlay_payload
    assert overlay_payload.get("limits", {}).get("evidence", {}).get("encrypt") is False
    metadata = overlay_payload.get("metadata", {})
    warnings = metadata.get("runtime_warnings", [])
    assert warnings, "runtime warnings should be surfaced when automation tokens missing"
    assert metadata.get("automation_ready") is False
    assert "automation token" in captured.err


def test_cli_train_forecast(tmp_path: Path, capsys):
    incidents = [
        {
            "timeline": ["low", "medium", "high"],
            "final_severity": "high",
        }
    ]
    incidents_path = tmp_path / "incidents.json"
    _write_json(incidents_path, incidents)

    output_path = tmp_path / "calibrated.json"
    exit_code = cli.main(
        [
            "train-forecast",
            "--incidents",
            str(incidents_path),
            "--output",
            str(output_path),
            "--pretty",
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["metrics"]["incidents"] == 1
    assert payload["bayesian_prior"]["high"] > payload["bayesian_prior"]["low"]
    summary = capsys.readouterr().out
    assert "Probabilistic calibration complete" in summary


def test_cli_demo_command(tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")

    output_path = tmp_path / "demo.json"
    exit_code = cli.main(
        [
            "demo",
            "--mode",
            "enterprise",
            "--output",
            str(output_path),
            "--pretty",
        ]
    )

    assert exit_code == 0
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload.get("pricing_summary", {}).get("active_plan", {}).get("name")

    summary = capsys.readouterr().out
    assert "FixOps Enterprise mode summary:" in summary
