from __future__ import annotations

from src.services.compliance import ComplianceEngine


def test_compliance_rollup_counts(signing_env: None) -> None:
    engine = ComplianceEngine()
    controls = [
        {"id": "AC-1", "framework": "iso_27001", "status": "pass"},
        {"id": "CM-2", "framework": "nist_ssdf", "status": "fail"},
        {"id": "CM-3", "framework": "nist_ssdf", "status": "gap"},
    ]
    result = engine.evaluate(controls, frameworks=["iso_27001", "nist_ssdf"])
    assert result["coverage"]["total_controls"] == 3
    assert result["coverage"]["pass"] == 1
    assert result["coverage"]["fail"] == 2
    assert set(result["frameworks"].keys()) == {"iso_27001", "nist_ssdf"}
    assert result["frameworks"]["nist_ssdf"]["fail"] == 2


def test_opa_bridge_skips_without_binary(signing_env: None) -> None:
    engine = ComplianceEngine()
    rules = [{"name": "allow", "rego": "package policy\n default allow = true"}]
    result = engine.evaluate([], opa_rules=rules, opa_input={"example": True})
    assert result["opa"]["status"] in {"skipped", "completed"}
