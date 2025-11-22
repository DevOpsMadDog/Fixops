"""
Tests for audit and compliance API endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app
from core.audit_db import AuditDB
from core.audit_models import (
    AuditEventType,
    AuditLog,
    AuditSeverity,
    ComplianceControl,
    ComplianceFramework,
)


@pytest.fixture
def client():
    """Create test client."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def db():
    """Create test database."""
    return AuditDB(db_path="data/test_audit.db")


@pytest.fixture(autouse=True)
def cleanup_db(db):
    """Clean up test database after each test."""
    yield
    import os

    if os.path.exists("data/test_audit.db"):
        os.remove("data/test_audit.db")


def test_list_audit_logs_empty(client):
    """Test listing audit logs when none exist."""
    response = client.get("/api/v1/audit/logs", headers={"X-API-Key": "test-key"})
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert isinstance(data["items"], list)


def test_list_audit_logs_with_filter(client, db):
    """Test listing audit logs with event type filter."""
    log1 = AuditLog(
        id="",
        event_type=AuditEventType.USER_LOGIN,
        severity=AuditSeverity.INFO,
        action="User logged in",
        user_id="user1",
    )
    log2 = AuditLog(
        id="",
        event_type=AuditEventType.POLICY_UPDATED,
        severity=AuditSeverity.WARNING,
        action="Policy updated",
        user_id="user2",
    )
    db.create_audit_log(log1)
    db.create_audit_log(log2)

    response = client.get(
        "/api/v1/audit/logs?event_type=user_login", headers={"X-API-Key": "test-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1
    assert all(item["event_type"] == "user_login" for item in data["items"])


def test_get_audit_log(client, db):
    """Test getting audit log entry."""
    log = AuditLog(
        id="",
        event_type=AuditEventType.USER_LOGIN,
        severity=AuditSeverity.INFO,
        action="User logged in",
    )
    created = db.create_audit_log(log)

    response = client.get(
        f"/api/v1/audit/logs/{created.id}", headers={"X-API-Key": "test-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created.id


def test_get_audit_log_not_found(client):
    """Test getting non-existent audit log."""
    response = client.get(
        "/api/v1/audit/logs/nonexistent", headers={"X-API-Key": "test-key"}
    )
    assert response.status_code == 404


def test_get_user_activity(client, db):
    """Test getting user activity logs."""
    log = AuditLog(
        id="",
        event_type=AuditEventType.USER_LOGIN,
        severity=AuditSeverity.INFO,
        action="User logged in",
        user_id="test-user",
    )
    db.create_audit_log(log)

    response = client.get(
        "/api/v1/audit/user-activity?user_id=test-user",
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "test-user"
    assert "activities" in data


def test_get_policy_changes(client):
    """Test getting policy change history."""
    response = client.get(
        "/api/v1/audit/policy-changes", headers={"X-API-Key": "test-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "changes" in data


def test_get_decision_trail(client):
    """Test getting decision audit trail."""
    response = client.get(
        "/api/v1/audit/decision-trail", headers={"X-API-Key": "test-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "decisions" in data


def test_list_frameworks(client, db):
    """Test listing compliance frameworks."""
    framework = ComplianceFramework(
        id="",
        name="NIST 800-53",
        version="Rev 5",
        description="NIST security controls",
        controls=[],
    )
    db.create_framework(framework)

    response = client.get(
        "/api/v1/audit/compliance/frameworks", headers={"X-API-Key": "test-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1


def test_get_framework_status(client, db):
    """Test getting framework compliance status."""
    framework = ComplianceFramework(
        id="",
        name="NIST 800-53",
        version="Rev 5",
        description="NIST security controls",
        controls=["AC-1", "AC-2"],
    )
    created = db.create_framework(framework)

    response = client.get(
        f"/api/v1/audit/compliance/frameworks/{created.id}/status",
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["framework_id"] == created.id
    assert "compliance_percentage" in data


def test_get_framework_status_not_found(client):
    """Test getting status for non-existent framework."""
    response = client.get(
        "/api/v1/audit/compliance/frameworks/nonexistent/status",
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 404


def test_get_compliance_gaps(client, db):
    """Test getting compliance gaps."""
    framework = ComplianceFramework(
        id="",
        name="NIST 800-53",
        version="Rev 5",
        description="NIST security controls",
        controls=["AC-1", "AC-2"],
    )
    created = db.create_framework(framework)

    response = client.get(
        f"/api/v1/audit/compliance/frameworks/{created.id}/gaps",
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["framework_id"] == created.id
    assert "gaps" in data


def test_generate_compliance_report(client, db):
    """Test generating compliance report."""
    framework = ComplianceFramework(
        id="",
        name="NIST 800-53",
        version="Rev 5",
        description="NIST security controls",
        controls=[],
    )
    created = db.create_framework(framework)

    response = client.post(
        f"/api/v1/audit/compliance/frameworks/{created.id}/report",
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["framework_id"] == created.id
    assert "report_id" in data


def test_list_controls(client, db):
    """Test listing compliance controls."""
    framework = ComplianceFramework(
        id="",
        name="NIST 800-53",
        version="Rev 5",
        description="NIST security controls",
        controls=[],
    )
    created_framework = db.create_framework(framework)

    control = ComplianceControl(
        id="",
        framework_id=created_framework.id,
        control_id="AC-1",
        name="Access Control Policy",
        description="Develop access control policy",
        category="Access Control",
    )
    db.create_control(control)

    response = client.get(
        "/api/v1/audit/compliance/controls", headers={"X-API-Key": "test-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1


def test_list_controls_with_framework_filter(client, db):
    """Test listing controls filtered by framework."""
    framework = ComplianceFramework(
        id="",
        name="NIST 800-53",
        version="Rev 5",
        description="NIST security controls",
        controls=[],
    )
    created_framework = db.create_framework(framework)

    response = client.get(
        f"/api/v1/audit/compliance/controls?framework_id={created_framework.id}",
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data


def test_audit_logs_pagination(client):
    """Test audit log pagination."""
    response = client.get(
        "/api/v1/audit/logs?limit=10&offset=0", headers={"X-API-Key": "test-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["limit"] == 10
    assert data["offset"] == 0
