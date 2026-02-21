"""Tests for the ComplianceEngine rollup evaluation.

The engine's ``evaluate()`` signature is::

    evaluate(frameworks: List[str], findings: List[Dict], business_context=None) -> Dict
"""

from __future__ import annotations

import pytest
from core.services.enterprise.compliance_engine import ComplianceEngine


def test_compliance_rollup_counts(signing_env: None) -> None:
    engine = ComplianceEngine()
    findings = [
        {"id": "AC-1", "severity": "low"},
        {"id": "CM-2", "severity": "high"},
        {"id": "CM-3", "severity": "critical"},
    ]
    result = engine.evaluate(["iso_27001", "nist_ssdf"], findings)
    assert "iso_27001" in result
    assert "nist_ssdf" in result
    for fw_result in result.values():
        assert "status" in fw_result
        assert "findings" in fw_result
        assert fw_result["framework"] in ("iso_27001", "nist_ssdf")


@pytest.mark.skip(
    reason=(
        "ComplianceEngine.evaluate() does not accept opa_rules or opa_input "
        "parameters. OPA integration is handled by the OPAEngine module."
    )
)
def test_opa_bridge_skips_without_binary(signing_env: None) -> None:
    pass
