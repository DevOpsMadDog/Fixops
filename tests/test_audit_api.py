"""
Tests for audit and compliance API endpoints.
"""
import os

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

# Use the API token from environment or default (matches Docker image default)
API_TOKEN = os.getenv("FIXOPS_API_TOKEN", "demo-token-12345")


@pytest.fixture
def client(monkeypatch):
    """Create test client with proper environment variables."""
    monkeypatch.setenv(
        "FIXOPS_API_TOKEN", os.getenv("FIXOPS_API_TOKEN", "demo-token-12345")
    )
    monkeypatch.setenv("FIXOPS_MODE", os.getenv("FIXOPS_MODE", "demo"))
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Return headers with API key for authenticated requests."""
    return {"X-API-Key": API_TOKEN}


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


def test_list_audit_logs_empty(client, auth_headers):
    """Test listing audit logs when none exist."""
    response = client.get("/api/v1/audit/logs", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert isinstance(data["items"], list)


def test_list_audit_logs_with_filter(client, db, auth_headers):
    """Test listing audit logs with event type filter."""
    log1 = AuditLog(
        id="",
        event_type=AuditEventType.USER_LOGIN,
        severity=AuditSeverity.INFO,
        user_id="user1",
        resource_type="user",
        resource_id="user1",
        action="User logged in",
    )
    log2 = AuditLog(
        id="",
        event_type=AuditEventType.POLICY_UPDATED,
        severity=AuditSeverity.WARNING,
        user_id="user2",
        resource_type="policy",
        resource_id="policy1",
        action="Policy updated",
    )
    db.create_audit_log(log1)
    db.create_audit_log(log2)

    response = client.get(
        "/api/v1/audit/logs?event_type=user_login", headers=auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1
    assert all(item["event_type"] == "user_login" for item in data["items"])


def test_get_audit_log(client, db, auth_headers):
    """Test getting audit log entry."""
    log = AuditLog(
        id="",
        event_type=AuditEventType.USER_LOGIN,
        severity=AuditSeverity.INFO,
        user_id="test-user",
        resource_type="user",
        resource_id="test-user",
        action="User logged in",
    )
    created = db.create_audit_log(log)

    response = client.get(f"/api/v1/audit/logs/{created.id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created.id


def test_get_audit_log_not_found(client, auth_headers):
    """Test getting non-existent audit log."""
    response = client.get("/api/v1/audit/logs/nonexistent", headers=auth_headers)
    assert response.status_code == 404


def test_get_user_activity(client, db, auth_headers):
    """Test getting user activity logs."""
    log = AuditLog(
        id="",
        event_type=AuditEventType.USER_LOGIN,
        severity=AuditSeverity.INFO,
        user_id="test-user",
        resource_type="user",
        resource_id="test-user",
        action="User logged in",
    )
    db.create_audit_log(log)

    response = client.get(
        "/api/v1/audit/user-activity?user_id=test-user",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "test-user"
    assert "activities" in data


def test_get_policy_changes(client, auth_headers):
    """Test getting policy change history."""
    response = client.get("/api/v1/audit/policy-changes", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "changes" in data


def test_get_decision_trail(client, auth_headers):
    """Test getting decision audit trail."""
    response = client.get("/api/v1/audit/decision-trail", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "decisions" in data


def test_list_frameworks(client, db, auth_headers):
    """Test listing compliance frameworks."""
    framework = ComplianceFramework(
        id="",
        name="NIST 800-53",
        version="Rev 5",
        description="NIST security controls",
        controls=[],
    )
    db.create_framework(framework)

    response = client.get("/api/v1/audit/compliance/frameworks", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1


def test_get_framework_status(client, db, auth_headers):
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
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["framework_id"] == created.id
    assert "compliance_percentage" in data


def test_get_framework_status_not_found(client, auth_headers):
    """Test getting status for non-existent framework."""
    response = client.get(
        "/api/v1/audit/compliance/frameworks/nonexistent/status",
        headers=auth_headers,
    )
    assert response.status_code == 404


def test_get_compliance_gaps(client, db, auth_headers):
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
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["framework_id"] == created.id
    assert "gaps" in data


def test_generate_compliance_report(client, db, auth_headers):
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
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["framework_id"] == created.id
    assert "report_id" in data


def test_list_controls(client, db, auth_headers):
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

    response = client.get("/api/v1/audit/compliance/controls", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1


def test_list_controls_with_framework_filter(client, db, auth_headers):
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
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data


def test_audit_logs_pagination(client, auth_headers):
    """Test audit log pagination."""
    response = client.get("/api/v1/audit/logs?limit=10&offset=0", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["limit"] == 10
    assert data["offset"] == 0
