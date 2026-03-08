"""Tests for core.audit_models — audit logging, compliance frameworks, and controls."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.audit_models import (  # noqa: E402
    AuditEventType,
    AuditLog,
    AuditSeverity,
    ComplianceControl,
    ComplianceFramework,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestAuditEventType:
    def test_all_events(self):
        assert AuditEventType.USER_LOGIN.value == "user_login"
        assert AuditEventType.DECISION_MADE.value == "decision_made"
        assert AuditEventType.API_ACCESS.value == "api_access"
        assert len(AuditEventType) == 13

    def test_all_are_strings(self):
        for evt in AuditEventType:
            assert isinstance(evt.value, str)


class TestAuditSeverity:
    def test_all_severities(self):
        assert AuditSeverity.INFO.value == "info"
        assert AuditSeverity.WARNING.value == "warning"
        assert AuditSeverity.ERROR.value == "error"
        assert AuditSeverity.CRITICAL.value == "critical"
        assert len(AuditSeverity) == 4


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class TestAuditLog:
    def test_create_minimal(self):
        log = AuditLog(
            id="audit-001",
            event_type=AuditEventType.USER_LOGIN,
            severity=AuditSeverity.INFO,
            user_id="user-1",
            resource_type=None,
            resource_id=None,
            action="login",
        )
        assert log.id == "audit-001"
        assert log.details == {}
        assert log.ip_address is None
        assert log.user_agent is None

    def test_create_full(self):
        log = AuditLog(
            id="audit-002",
            event_type=AuditEventType.DECISION_MADE,
            severity=AuditSeverity.WARNING,
            user_id="user-2",
            resource_type="finding",
            resource_id="F-123",
            action="suppress_finding",
            details={"reason": "false positive", "confidence": 0.95},
            ip_address="10.0.0.1",
            user_agent="Mozilla/5.0",
        )
        assert log.details["reason"] == "false positive"

    def test_to_dict(self):
        log = AuditLog(
            id="audit-003",
            event_type=AuditEventType.CONFIG_CHANGED,
            severity=AuditSeverity.CRITICAL,
            user_id="admin",
            resource_type="config",
            resource_id="auth",
            action="change",
        )
        d = log.to_dict()
        assert d["id"] == "audit-003"
        assert d["event_type"] == "config_changed"
        assert d["severity"] == "critical"
        assert "timestamp" in d

    def test_to_dict_all_event_types(self):
        for evt in AuditEventType:
            log = AuditLog(
                id=f"a-{evt.value}",
                event_type=evt,
                severity=AuditSeverity.INFO,
                user_id="u",
                resource_type=None,
                resource_id=None,
                action="test",
            )
            d = log.to_dict()
            assert d["event_type"] == evt.value


# ---------------------------------------------------------------------------
# ComplianceFramework
# ---------------------------------------------------------------------------


class TestComplianceFramework:
    def test_create(self):
        fw = ComplianceFramework(
            id="fw-1", name="SOC 2", version="2017",
            description="SOC 2 Type II",
            controls=["CC1.1", "CC1.2", "CC2.1"],
        )
        assert fw.name == "SOC 2"
        assert len(fw.controls) == 3

    def test_to_dict(self):
        fw = ComplianceFramework(
            id="fw-2", name="PCI DSS", version="4.0",
            description="Payment Card Industry",
            metadata={"scope": "payment"},
        )
        d = fw.to_dict()
        assert d["name"] == "PCI DSS"
        assert d["version"] == "4.0"
        assert d["metadata"]["scope"] == "payment"
        assert "created_at" in d


# ---------------------------------------------------------------------------
# ComplianceControl
# ---------------------------------------------------------------------------


class TestComplianceControl:
    def test_create(self):
        ctrl = ComplianceControl(
            id="ctrl-1", framework_id="fw-1",
            control_id="CC1.1", name="Security Monitoring",
            description="Monitor security events",
            category="monitoring",
            requirements=["SIEM", "alerting"],
        )
        assert ctrl.control_id == "CC1.1"
        assert len(ctrl.requirements) == 2

    def test_to_dict(self):
        ctrl = ComplianceControl(
            id="ctrl-2", framework_id="fw-1",
            control_id="CC2.1", name="Access Control",
            description="Implement RBAC",
            category="access",
        )
        d = ctrl.to_dict()
        assert d["control_id"] == "CC2.1"
        assert d["framework_id"] == "fw-1"
        assert d["category"] == "access"
