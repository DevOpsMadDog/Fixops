"""Tests for PolicyEngine — enums, dataclasses, and rule evaluation."""

from core.services.enterprise.policy_engine import (
    PolicyDecision,
    PolicyContext,
    PolicyEvaluationResult,
)


class TestPolicyDecision:
    def test_all_values(self):
        assert PolicyDecision.BLOCK.value == "block"
        assert PolicyDecision.ALLOW.value == "allow"
        assert PolicyDecision.DEFER.value == "defer"
        assert PolicyDecision.FIX.value == "fix"
        assert PolicyDecision.MITIGATE.value == "mitigate"
        assert PolicyDecision.ESCALATE.value == "escalate"

    def test_count(self):
        assert len(PolicyDecision) == 6

    def test_string_enum(self):
        assert isinstance(PolicyDecision.BLOCK, str)
        assert PolicyDecision.BLOCK == "block"


class TestPolicyContext:
    def test_defaults(self):
        ctx = PolicyContext()
        assert ctx.finding_id is None
        assert ctx.service_id is None
        assert ctx.severity is None
        assert ctx.internet_facing is False
        assert ctx.pci_scope is False
        assert ctx.data_classification == []
        assert ctx.custom_attributes == {}

    def test_custom_values(self):
        ctx = PolicyContext(
            finding_id="f-001",
            service_id="svc-1",
            severity="CRITICAL",
            scanner_type="trivy",
            environment="production",
            data_classification=["pci", "pii"],
            internet_facing=True,
            pci_scope=True,
            cvss_score=9.8,
            cve_id="CVE-2024-001",
            business_impact="high",
            custom_attributes={"team": "platform"},
        )
        assert ctx.finding_id == "f-001"
        assert ctx.severity == "CRITICAL"
        assert ctx.internet_facing is True
        assert ctx.cvss_score == 9.8
        assert "pci" in ctx.data_classification

    def test_post_init_none_to_empty(self):
        # __post_init__ replaces None with empty list/dict
        ctx = PolicyContext(data_classification=None, custom_attributes=None)
        assert ctx.data_classification == []
        assert ctx.custom_attributes == {}


class TestPolicyEvaluationResult:
    def test_create(self):
        result = PolicyEvaluationResult(
            decision=PolicyDecision.BLOCK,
            confidence=0.95,
            rationale="Critical vuln in PCI scope",
            policy_rules_applied=["block_critical_pci", "require_fix"],
            execution_time_ms=0.45,
            nist_ssdf_controls=["PO.1.1", "PS.1.1"],
        )
        assert result.decision == PolicyDecision.BLOCK
        assert result.confidence == 0.95
        assert len(result.policy_rules_applied) == 2
        assert result.escalation_required is False

    def test_escalation(self):
        result = PolicyEvaluationResult(
            decision=PolicyDecision.ESCALATE,
            confidence=0.6,
            rationale="Needs human review",
            policy_rules_applied=[],
            execution_time_ms=1.2,
            nist_ssdf_controls=[],
            escalation_required=True,
        )
        assert result.escalation_required is True
        assert result.decision == PolicyDecision.ESCALATE
