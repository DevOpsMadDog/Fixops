from __future__ import annotations

import pytest
from core.services.enterprise.explainability import ExplainabilityService


def test_explainability_service_generates_contributions() -> None:
    service = ExplainabilityService()
    service.prime_baseline([{"epss": 0.1, "cvss": 7.0}])

    vector = {"epss": 0.5, "cvss": 7.0}
    contributions = service.explain(vector)
    assert pytest.approx(contributions["epss"], rel=0.01) == 0.4
    assert contributions["cvss"] == 0.0

    findings = service.enrich_findings(
        [{"epss": 0.5, "cvss": 7.0, "id": "f-1"}], feature_keys=["epss", "cvss"]
    )

    assert (
        findings[0]["explainability"]["contributions"]["epss"] == contributions["epss"]
    )
    assert "narrative" in findings[0]["explainability"]
