from __future__ import annotations

import json
from pathlib import Path

from simulations.cve_scenario import run_simulation


def _build_overlay(tmp_path: Path) -> Path:
    overlay_path = tmp_path / "overlay.json"
    overlay_content = {
        "mode": "demo",
        "data": {
            "design_context_dir": str(tmp_path / "design-demo"),
            "evidence_dir": str(tmp_path / "evidence-demo"),
        },
        "guardrails": {
            "maturity": "foundational",
            "profiles": {
                "foundational": {"fail_on": "critical", "warn_on": "high"},
                "advanced": {"fail_on": "medium", "warn_on": "medium"},
            },
        },
        "profiles": {
            "enterprise": {
                "mode": "enterprise",
                "data": {
                    "design_context_dir": str(tmp_path / "design-enterprise"),
                    "evidence_dir": str(tmp_path / "evidence-enterprise"),
                },
                "guardrails": {"maturity": "advanced"},
            }
        },
    }
    overlay_path.write_text(json.dumps(overlay_content), encoding="utf-8")
    return overlay_path


def test_demo_mode_downgrades_severity(tmp_path: Path) -> None:
    overlay_path = _build_overlay(tmp_path)
    result = run_simulation(mode="demo", overlay_path=overlay_path)

    assert result.adjusted_severity == "MEDIUM"
    assert result.risk_adjustment == -1
    assert result.guardrail_status == "warn"
    assert result.score_path.exists()
    payload = json.loads(result.score_path.read_text(encoding="utf-8"))
    assert payload["contextualised"]["fixops_severity"] == "MEDIUM"
    assert payload["scanner_severity"] == "HIGH"
    assert payload["raw_feed_severity"] == "HIGH"
    assert payload["guardrail_evaluation"]["status"] == "warn"


def test_enterprise_mode_escalates_severity(tmp_path: Path) -> None:
    overlay_path = _build_overlay(tmp_path)
    result = run_simulation(mode="enterprise", overlay_path=overlay_path)

    assert result.adjusted_severity == "HIGH"
    assert result.risk_adjustment == 1
    assert result.guardrail_status == "fail"
    assert result.evidence_path.exists()
    evidence = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    assert evidence["sarif_findings"]
    assert evidence["cve_record"][0]["cve_id"] == "CVE-2021-44228"
    assert evidence["guardrail_evaluation"]["status"] == "fail"
