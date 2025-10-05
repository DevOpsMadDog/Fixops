import json
from pathlib import Path

import pytest

import fixops.cli as cli


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_cli_run_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")

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
            "--evidence-dir",
            str(evidence_dir),
        ]
    )

    assert exit_code == 0
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

    exit_code = cli.main(
        [
            "show-overlay",
            "--overlay",
            str(Path("config/fixops.overlay.yml")),
            "--pretty",
        ]
    )
    assert exit_code == 0
    output = capsys.readouterr().out
    overlay_payload = json.loads(output)
    assert overlay_payload["mode"] in {"demo", "enterprise"}
    assert "guardrails" in overlay_payload


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
