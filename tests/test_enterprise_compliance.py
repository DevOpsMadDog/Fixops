from __future__ import annotations

from core.services.enterprise.compliance_engine import ComplianceEngine


def test_compliance_engine_evaluates_frameworks() -> None:
    engine = ComplianceEngine()

    critical_findings = [
        {"id": "CVE-001", "scanner_severity": "high", "fixops_severity": "critical"},
    ]
    results = engine.evaluate(["PCI_DSS"], critical_findings)
    assert results["PCI_DSS"]["status"] == "non_compliant"
    assert results["PCI_DSS"]["highest_fixops_severity"] == "CRITICAL"

    moderate_findings = [
        {"id": "CVE-010", "scanner_severity": "medium", "fixops_severity": "low"},
    ]
    review_results = engine.evaluate(["NIST"], moderate_findings)
    assert review_results["NIST"]["status"] == "needs_review"
    assert review_results["NIST"]["highest_fixops_severity"] == "LOW"
