"""Tests for core.analytics_models — finding, decision, and metric data models."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.analytics_models import (  # noqa: E402
    Decision,
    DecisionOutcome,
    Finding,
    FindingSeverity,
    FindingStatus,
    Metric,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestFindingSeverity:
    def test_all(self):
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"
        assert len(FindingSeverity) == 5


class TestFindingStatus:
    def test_all(self):
        assert FindingStatus.OPEN.value == "open"
        assert FindingStatus.IN_PROGRESS.value == "in_progress"
        assert FindingStatus.RESOLVED.value == "resolved"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"
        assert FindingStatus.ACCEPTED_RISK.value == "accepted_risk"


class TestDecisionOutcome:
    def test_all(self):
        assert DecisionOutcome.BLOCK.value == "block"
        assert DecisionOutcome.ALERT.value == "alert"
        assert DecisionOutcome.ALLOW.value == "allow"
        assert DecisionOutcome.REVIEW.value == "review"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def test_create_minimal(self):
        f = Finding(
            id="F-001", application_id="app1", service_id=None,
            rule_id="CWE-89", severity=FindingSeverity.HIGH,
            status=FindingStatus.OPEN, title="SQL Injection",
            description="Found in login.py", source="sast",
        )
        assert f.id == "F-001"
        assert f.exploitable is False
        assert f.cve_id is None

    def test_create_full(self):
        f = Finding(
            id="F-002", application_id="app2", service_id="svc-1",
            rule_id="CWE-79", severity=FindingSeverity.CRITICAL,
            status=FindingStatus.IN_PROGRESS, title="XSS",
            description="Reflected XSS", source="dast",
            cve_id="CVE-2024-1234", cvss_score=9.8, epss_score=0.95,
            exploitable=True, metadata={"scanner": "ZAP"},
        )
        assert f.exploitable is True
        assert f.cvss_score == 9.8

    def test_to_dict(self):
        f = Finding(
            id="F-003", application_id="app3", service_id=None,
            rule_id="R1", severity=FindingSeverity.LOW,
            status=FindingStatus.FALSE_POSITIVE, title="T",
            description="D", source="manual",
        )
        d = f.to_dict()
        assert d["severity"] == "low"
        assert d["status"] == "false_positive"
        assert d["resolved_at"] is None
        assert "created_at" in d


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


class TestDecision:
    def test_create(self):
        d = Decision(
            id="D-001", finding_id="F-001",
            outcome=DecisionOutcome.BLOCK, confidence=0.92,
            reasoning="High severity with active exploit",
            llm_votes={"gpt-4": "block", "claude": "block"},
        )
        assert d.confidence == 0.92
        assert d.policy_matched is None

    def test_to_dict(self):
        d = Decision(
            id="D-002", finding_id="F-002",
            outcome=DecisionOutcome.REVIEW, confidence=0.6,
            reasoning="Uncertain severity", policy_matched="policy-v2",
        )
        dd = d.to_dict()
        assert dd["outcome"] == "review"
        assert dd["policy_matched"] == "policy-v2"


# ---------------------------------------------------------------------------
# Metric
# ---------------------------------------------------------------------------


class TestMetric:
    def test_create(self):
        m = Metric(
            id="M-001", metric_type="security", metric_name="mttr",
            value=4.5, unit="hours",
        )
        assert m.value == 4.5
        assert m.unit == "hours"

    def test_to_dict(self):
        m = Metric(
            id="M-002", metric_type="compliance", metric_name="score",
            value=85.0, unit="percent", metadata={"framework": "SOC2"},
        )
        d = m.to_dict()
        assert d["value"] == 85.0
        assert d["metadata"]["framework"] == "SOC2"
