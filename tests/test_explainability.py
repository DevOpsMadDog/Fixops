from __future__ import annotations

from src.services.compliance import ComplianceEngine
from src.services.decision_engine import DecisionEngine
from src.services.evidence import EvidenceStore


def test_top_factors_deterministic(signing_env: None) -> None:
    engine = DecisionEngine(EvidenceStore(), ComplianceEngine())
    payload = {
        "findings": [
            {"id": "A", "severity": "high"},
            {"id": "B", "severity": "medium"},
            {"id": "C", "severity": "low"},
        ],
        "controls": [
            {"id": "CM-1", "framework": "nist_ssdf", "status": "fail"},
            {"id": "AC-1", "framework": "iso_27001", "status": "pass"},
        ],
        "frameworks": ["nist_ssdf", "iso_27001"],
    }
    outcome = engine.evaluate(payload)
    weights = [factor["weight"] for factor in outcome.top_factors]
    assert weights == sorted(weights, reverse=True)
    names = [factor["name"] for factor in outcome.top_factors]
    assert names[0].startswith("High")
    # Re-running with the same payload should not change ordering
    outcome_again = engine.evaluate(payload)
    assert [factor["name"] for factor in outcome_again.top_factors] == names


def test_decision_engine_compliance_rollup_and_marketplace(signing_env: None) -> None:
    engine = DecisionEngine(EvidenceStore(), ComplianceEngine())
    submission = {
        "findings": [{"id": "Z", "severity": "critical"}],
        "controls": [
            {"id": "ISO27001:AC-2", "framework": "iso_27001", "status": "fail"},
            {"id": "ISO27001:AC-1", "framework": "iso_27001", "status": "partial"},
        ],
        "frameworks": ["iso_27001"],
        "deploy": {
            "control_evidence": [
                {"control": "ISO27001:AC-2", "result": "fail"},
                {"control": "ISO27001:AC-1", "result": "partial"},
            ]
        },
        "test": {"summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}},
        "operate": {
            "kev_hits": ["CVE-2021-44228"],
            "pressure_by_service": [{"service": "life-claims-portal", "pressure": 0.65}],
        },
    }
    outcome = engine.evaluate(submission)
    assert outcome.compliance_rollup["controls"], "Compliance rollup should include control coverage"
    assert any(factor["name"] == "Compliance gaps" for factor in outcome.top_factors)
    assert outcome.marketplace_recommendations, "Marketplace packs should surface for failing controls"

