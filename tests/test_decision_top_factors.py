from __future__ import annotations

from src.services.decision_engine import DecisionEngine


def test_top_factors_and_marketplace_recommendations(signing_env: None) -> None:
    engine = DecisionEngine()
    submission = {
        "findings": [
            {"id": "CVE-2021-44228", "severity": "critical"},
            {"id": "TLS", "severity": "high"},
        ],
        "controls": [
            {"id": "ISO27001:AC-2", "framework": "ISO27001", "status": "fail"},
        ],
    }
    outcome = engine.evaluate(submission)
    assert len(outcome.top_factors) >= 2
    assert outcome.marketplace_recommendations
