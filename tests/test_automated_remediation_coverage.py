"""Tests for core.automated_remediation — remediation types, priorities, and suggestions."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.automated_remediation import (  # noqa: E402
    RemediationPriority,
    RemediationStatus,
    RemediationSuggestion,
    RemediationType,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestRemediationType:
    def test_all_types(self):
        assert RemediationType.CODE_PATCH.value == "code_patch"
        assert RemediationType.CONFIGURATION_CHANGE.value == "configuration_change"
        assert RemediationType.DEPENDENCY_UPDATE.value == "dependency_update"
        assert RemediationType.WAF_RULE.value == "waf_rule"
        assert RemediationType.NETWORK_CONTROL.value == "network_control"
        assert RemediationType.ACCESS_CONTROL.value == "access_control"
        assert RemediationType.INPUT_VALIDATION.value == "input_validation"
        assert RemediationType.OUTPUT_ENCODING.value == "output_encoding"
        assert len(RemediationType) == 8


class TestRemediationPriority:
    def test_all_priorities(self):
        assert RemediationPriority.CRITICAL.value == "critical"
        assert RemediationPriority.HIGH.value == "high"
        assert RemediationPriority.MEDIUM.value == "medium"
        assert RemediationPriority.LOW.value == "low"
        assert len(RemediationPriority) == 4


class TestRemediationStatus:
    def test_all_statuses(self):
        assert RemediationStatus.SUGGESTED.value == "suggested"
        assert RemediationStatus.IN_PROGRESS.value == "in_progress"
        assert RemediationStatus.APPLIED.value == "applied"
        assert RemediationStatus.VERIFIED.value == "verified"
        assert RemediationStatus.FAILED.value == "failed"
        assert RemediationStatus.REJECTED.value == "rejected"
        assert len(RemediationStatus) == 6


# ---------------------------------------------------------------------------
# RemediationSuggestion
# ---------------------------------------------------------------------------


class TestRemediationSuggestion:
    def test_create_with_defaults(self):
        s = RemediationSuggestion(
            id="rem-001",
            finding_id="F-001",
            remediation_type=RemediationType.CODE_PATCH,
            priority=RemediationPriority.HIGH,
            title="Fix SQL Injection",
            description="Use parameterized queries",
        )
        assert s.id == "rem-001"
        assert s.status == RemediationStatus.SUGGESTED
        assert s.success_probability == 0.8
        assert s.code_changes == []
        assert s.config_changes == []
        assert s.testing_guidance == ""

    def test_create_with_all_fields(self):
        s = RemediationSuggestion(
            id="rem-002",
            finding_id="F-002",
            remediation_type=RemediationType.DEPENDENCY_UPDATE,
            priority=RemediationPriority.CRITICAL,
            title="Upgrade lodash",
            description="Upgrade lodash to 4.17.21",
            code_changes=[{"file": "package.json", "action": "update_dependency"}],
            config_changes=[{"key": "lockfile", "action": "regenerate"}],
            testing_guidance="Run npm test after upgrade",
            risk_assessment="Low risk — minor version upgrade",
            effort_estimate="15 minutes",
            success_probability=0.95,
            ai_confidence=0.88,
            status=RemediationStatus.IN_PROGRESS,
            metadata={"package": "lodash", "from": "4.17.20", "to": "4.17.21"},
        )
        assert s.priority == RemediationPriority.CRITICAL
        assert s.success_probability == 0.95
        assert s.ai_confidence == 0.88
        assert s.status == RemediationStatus.IN_PROGRESS

    def test_to_dict(self):
        s = RemediationSuggestion(
            id="rem-003",
            finding_id="F-003",
            remediation_type=RemediationType.WAF_RULE,
            priority=RemediationPriority.MEDIUM,
            title="Add WAF Rule",
            description="Block XSS patterns",
        )
        d = s.to_dict()
        assert d["id"] == "rem-003"
        assert d["remediation_type"] == "waf_rule"
        assert d["priority"] == "medium"
        assert d["status"] == "suggested"
        assert "title" in d
        assert "description" in d

    def test_to_dict_keys(self):
        s = RemediationSuggestion(
            id="rem-004",
            finding_id="F-004",
            remediation_type=RemediationType.NETWORK_CONTROL,
            priority=RemediationPriority.LOW,
            title="T",
            description="D",
        )
        d = s.to_dict()
        expected_keys = {
            "id", "finding_id", "remediation_type", "priority", "title",
            "description", "code_changes", "config_changes", "testing_guidance",
            "risk_assessment", "effort_estimate", "success_probability",
            "ai_confidence", "status",
        }
        # At least these keys should be present
        assert expected_keys <= set(d.keys())

    def test_all_type_combinations(self):
        """Every remediation type can be used in a suggestion."""
        for rtype in RemediationType:
            s = RemediationSuggestion(
                id=f"rem-{rtype.value}",
                finding_id="F-X",
                remediation_type=rtype,
                priority=RemediationPriority.MEDIUM,
                title=f"Test {rtype.value}",
                description="Test",
            )
            d = s.to_dict()
            assert d["remediation_type"] == rtype.value
