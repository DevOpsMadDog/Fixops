from __future__ import annotations

import json
import os
from pathlib import Path

from simulations.cve_scenario import run_simulation


def _build_overlay(tmp_path: Path) -> Path:
    repo_data = Path(__file__).resolve().parents[1] / "data"
    allowlist = [str(tmp_path), str(repo_data)]
    os.environ["FIXOPS_DATA_ROOT_ALLOWLIST"] = os.pathsep.join(allowlist)
    overlay_path = tmp_path / "overlay.json"
    overlay_content = {
        "mode": "enterprise",
        "data": {
            "design_context_dir": str(tmp_path / "design-context"),
            "evidence_dir": str(tmp_path / "evidence"),
        },
        "guardrails": {
            "maturity": "foundational",
            "profiles": {
                "foundational": {"fail_on": "critical", "warn_on": "high"},
                "advanced": {"fail_on": "medium", "warn_on": "medium"},
            },
        },
        "compliance": {
            "frameworks": [
                {
                    "name": "SOC 2",
                    "controls": [
                        {
                            "id": "CC8.1",
                            "requires": ["design", "guardrails", "evidence"],
                        }
                    ],
                }
            ],
            "profiles": {
                "enterprise": {
                    "frameworks": [
                        {
                            "name": "PCI DSS",
                            "controls": [
                                {
                                    "id": "6.5",
                                    "requires": ["cve", "context", "guardrails"],
                                }
                            ],
                        }
                    ]
                }
            },
        },
        "policy_automation": {
            "actions": [{"trigger": "guardrail:fail", "type": "jira_issue"}],
            "profiles": {
                "enterprise": {
                    "actions": [
                        {"trigger": "compliance:gap", "type": "confluence_page"}
                    ]
                }
            },
        },
        "ssdlc": {
            "stages": [
                {"id": "plan", "requirements": ["design"]},
                {"id": "deploy", "requirements": ["compliance"]},
            ]
        },
        "exploit_signals": {
            "signals": {
                "kev": {
                    "mode": "boolean",
                    "fields": ["knownExploited", "kev"],
                    "escalate_to": "critical",
                },
                "epss": {"mode": "probability", "fields": ["epss"], "threshold": 0.4},
            }
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


def test_enterprise_mode_downgrades_severity(tmp_path: Path) -> None:
    overlay_path = _build_overlay(tmp_path)
    result = run_simulation(mode="enterprise", overlay_path=overlay_path)

    assert result.adjusted_severity == "MEDIUM"
    assert result.risk_adjustment == -1
    assert result.guardrail_status == "warn"
    assert result.score_path.exists()
    payload = json.loads(result.score_path.read_text(encoding="utf-8"))
    assert payload["contextualised"]["fixops_severity"] == "MEDIUM"
    assert payload["scanner_severity"] == "HIGH"
    assert payload["raw_feed_severity"] == "HIGH"
    assert payload["guardrail_evaluation"]["status"] == "warn"
    assert payload["context_summary"]["summary"]["components_evaluated"] == 1
    assert payload["policy_automation"]["actions"] == []
    assert payload["ssdlc_assessment"]["summary"]["total_stages"] >= 1
    assert payload["exploitability_insights"]["overview"]["matched_records"] >= 1


def test_enterprise_mode_escalates_severity(tmp_path: Path) -> None:
    overlay_path = _build_overlay(tmp_path)
    result = run_simulation(mode="enterprise", overlay_path=overlay_path)

    assert result.adjusted_severity == "HIGH"
    assert result.risk_adjustment == 1
    assert result.guardrail_status == "fail"
    assert result.evidence_path.exists()
    evidence = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    assert evidence["sarif_summary"]["finding_count"] == 1
    assert evidence["context_summary"]["summary"]["highest_component"]["score"] >= 7
    assert evidence["compliance_status"]["frameworks"]
    assert evidence["policy_automation"]["actions"]
    assert evidence["guardrail_evaluation"]["status"] == "fail"
    assert evidence["ssdlc_assessment"]["summary"]["total_stages"] >= 1
    assert evidence["exploitability_insights"]["overview"]["signals_configured"] >= 1
