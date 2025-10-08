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

