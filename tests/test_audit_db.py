"""Tests for AuditDB — audit and compliance database manager."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.audit_models import (
    AuditEventType,
    AuditLog,
    AuditSeverity,
    ComplianceControl,
    ComplianceFramework,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------
class TestAuditModels:
    def test_audit_event_type_enum(self):
        assert AuditEventType.USER_LOGIN == "user_login"
        assert AuditEventType.DECISION_MADE == "decision_made"
        assert AuditEventType.CONFIG_CHANGED == "config_changed"
        assert AuditEventType.API_ACCESS == "api_access"

    def test_audit_severity_enum(self):
        assert AuditSeverity.INFO == "info"
        assert AuditSeverity.WARNING == "warning"
        assert AuditSeverity.ERROR == "error"
        assert AuditSeverity.CRITICAL == "critical"

    def test_audit_log_to_dict(self):
        log = AuditLog(
            id="al-1",
            event_type=AuditEventType.USER_LOGIN,
            severity=AuditSeverity.INFO,
            user_id="u1",
            resource_type="session",
            resource_id="s1",
            action="login",
            details={"method": "sso"},
            ip_address="10.0.0.1",
        )
        d = log.to_dict()
        assert d["id"] == "al-1"
        assert d["event_type"] == "user_login"
        assert d["severity"] == "info"
        assert d["user_id"] == "u1"
        assert d["details"]["method"] == "sso"

    def test_compliance_framework_to_dict(self):
        fw = ComplianceFramework(
            id="fw-1",
            name="SOC2",
            version="2.0",
            description="SOC2 Type II",
            controls=["CC6.1", "CC7.1"],
        )
        d = fw.to_dict()
        assert d["name"] == "SOC2"
        assert len(d["controls"]) == 2

    def test_compliance_control_to_dict(self):
        ctrl = ComplianceControl(
            id="c-1",
            framework_id="fw-1",
            control_id="CC6.1",
            name="Logical Access",
            description="Ensure access control",
            category="access",
            requirements=["RBAC", "MFA"],
        )
        d = ctrl.to_dict()
        assert d["control_id"] == "CC6.1"
        assert len(d["requirements"]) == 2


# ---------------------------------------------------------------------------
# AuditDB tests
# ---------------------------------------------------------------------------
class TestAuditDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.audit_db import AuditDB
        return AuditDB(db_path=str(tmp_path / "test_audit.db"))

    @pytest.fixture
    def sample_log(self, db):
        log = AuditLog(
            id="",
            event_type=AuditEventType.USER_LOGIN,
            severity=AuditSeverity.INFO,
            user_id="user-1",
            resource_type="session",
            resource_id="sess-1",
            action="login",
            details={"ip": "10.0.0.1"},
        )
        return db.create_audit_log(log)

    def test_create_audit_log(self, db):
        log = AuditLog(
            id="",
            event_type=AuditEventType.CONFIG_CHANGED,
            severity=AuditSeverity.WARNING,
            user_id="admin-1",
            resource_type="config",
            resource_id="cfg-1",
            action="update_setting",
        )
        created = db.create_audit_log(log)
        assert created.id != ""

    def test_list_audit_logs(self, db, sample_log):
        logs = db.list_audit_logs()
        assert len(logs) >= 1

    def test_list_audit_logs_by_event_type(self, db, sample_log):
        logs = db.list_audit_logs(event_type="user_login")
        assert len(logs) >= 1
        assert all(entry.event_type == AuditEventType.USER_LOGIN for entry in logs)

    def test_list_audit_logs_by_user_id(self, db, sample_log):
        logs = db.list_audit_logs(user_id="user-1")
        assert len(logs) >= 1
        assert all(entry.user_id == "user-1" for entry in logs)

    def test_list_audit_logs_by_both(self, db, sample_log):
        logs = db.list_audit_logs(event_type="user_login", user_id="user-1")
        assert len(logs) >= 1

    def test_list_audit_logs_empty(self, db):
        logs = db.list_audit_logs(event_type="decision_made")
        assert len(logs) == 0

    def test_list_audit_logs_pagination(self, db):
        for i in range(5):
            db.create_audit_log(AuditLog(
                id="",
                event_type=AuditEventType.API_ACCESS,
                severity=AuditSeverity.INFO,
                user_id=f"user-{i}",
                resource_type="api",
                resource_id=f"req-{i}",
                action="GET /health",
            ))
        page = db.list_audit_logs(limit=3)
        assert len(page) == 3


# ---------------------------------------------------------------------------
# Compliance Framework tests
# ---------------------------------------------------------------------------
class TestComplianceFrameworkDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.audit_db import AuditDB
        return AuditDB(db_path=str(tmp_path / "test_compliance.db"))

    def test_create_framework(self, db):
        fw = ComplianceFramework(
            id="",
            name="ISO27001",
            version="2022",
            description="Information Security Management",
            controls=["A.5", "A.6", "A.7"],
        )
        created = db.create_framework(fw)
        assert created.id != ""

    def test_get_framework(self, db):
        fw = db.create_framework(ComplianceFramework(
            id="",
            name="NIST CSF",
            version="2.0",
            description="Cybersecurity Framework",
        ))
        retrieved = db.get_framework(fw.id)
        assert retrieved is not None
        assert retrieved.name == "NIST CSF"

    def test_get_framework_not_found(self, db):
        assert db.get_framework("nonexistent") is None

    def test_list_frameworks(self, db):
        db.create_framework(ComplianceFramework(
            id="", name="PCI DSS", version="4.0", description="Payment Card",
        ))
        frameworks = db.list_frameworks()
        assert len(frameworks) >= 1


# ---------------------------------------------------------------------------
# Compliance Control tests
# ---------------------------------------------------------------------------
class TestComplianceControlDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.audit_db import AuditDB
        return AuditDB(db_path=str(tmp_path / "test_controls.db"))

    @pytest.fixture
    def framework(self, db):
        return db.create_framework(ComplianceFramework(
            id="",
            name="SOC2 Test",
            version="1.0",
            description="Test framework",
        ))

    def test_create_control(self, db, framework):
        ctrl = ComplianceControl(
            id="",
            framework_id=framework.id,
            control_id="CC6.1",
            name="Logical Access",
            description="Access controls",
            category="access",
            requirements=["RBAC", "MFA"],
        )
        created = db.create_control(ctrl)
        assert created.id != ""

    def test_list_controls(self, db, framework):
        db.create_control(ComplianceControl(
            id="",
            framework_id=framework.id,
            control_id="CC7.1",
            name="Change Detection",
            description="Detect changes",
            category="operations",
        ))
        controls = db.list_controls()
        assert len(controls) >= 1

    def test_list_controls_by_framework(self, db, framework):
        db.create_control(ComplianceControl(
            id="",
            framework_id=framework.id,
            control_id="CC8.1",
            name="Change Mgmt",
            description="Change management",
            category="change",
        ))
        controls = db.list_controls(framework_id=framework.id)
        assert len(controls) >= 1
        assert all(c.framework_id == framework.id for c in controls)
