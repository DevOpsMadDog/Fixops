"""Tests for Pentagi pen testing API endpoints."""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app
from core.pentagi_db import PentagiDB


@pytest.fixture
def client():
    """Create test client."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def db():
    """Create test database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = PentagiDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_pen_test_requests(client, db, monkeypatch):
    """Test listing pen test requests."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    response = client.get("/api/v1/pentagi/requests")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_create_pen_test_request(client, db, monkeypatch):
    """Test creating pen test request."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    response = client.post(
        "/api/v1/pentagi/requests",
        json={
            "finding_id": "finding-123",
            "target_url": "https://test.example.com/api/users",
            "vulnerability_type": "sql_injection",
            "test_case": "Test SQL injection via username parameter",
            "priority": "high",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["finding_id"] == "finding-123"
    assert data["status"] == "pending"


def test_get_pen_test_request(client, db, monkeypatch):
    """Test getting pen test request."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    create_response = client.post(
        "/api/v1/pentagi/requests",
        json={
            "finding_id": "finding-456",
            "target_url": "https://test.example.com",
            "vulnerability_type": "xss",
            "test_case": "Test XSS",
            "priority": "medium",
        },
    )
    request_id = create_response.json()["id"]

    response = client.get(f"/api/v1/pentagi/requests/{request_id}")
    assert response.status_code == 200
    assert response.json()["id"] == request_id


def test_update_pen_test_request(client, db, monkeypatch):
    """Test updating pen test request."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    create_response = client.post(
        "/api/v1/pentagi/requests",
        json={
            "finding_id": "finding-789",
            "target_url": "https://test.example.com",
            "vulnerability_type": "csrf",
            "test_case": "Test CSRF",
            "priority": "low",
        },
    )
    request_id = create_response.json()["id"]

    response = client.put(
        f"/api/v1/pentagi/requests/{request_id}",
        json={"status": "running", "pentagi_job_id": "job-123"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_start_pen_test(client, db, monkeypatch):
    """Test starting pen test."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    create_response = client.post(
        "/api/v1/pentagi/requests",
        json={
            "finding_id": "finding-start",
            "target_url": "https://test.example.com",
            "vulnerability_type": "sqli",
            "test_case": "Test",
            "priority": "high",
        },
    )
    request_id = create_response.json()["id"]

    response = client.post(f"/api/v1/pentagi/requests/{request_id}/start")
    assert response.status_code == 200
    assert response.json()["status"] == "started"


def test_cancel_pen_test(client, db, monkeypatch):
    """Test cancelling pen test."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    create_response = client.post(
        "/api/v1/pentagi/requests",
        json={
            "finding_id": "finding-cancel",
            "target_url": "https://test.example.com",
            "vulnerability_type": "xss",
            "test_case": "Test",
            "priority": "medium",
        },
    )
    request_id = create_response.json()["id"]

    response = client.post(f"/api/v1/pentagi/requests/{request_id}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"


def test_list_pen_test_results(client, db, monkeypatch):
    """Test listing pen test results."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    response = client.get("/api/v1/pentagi/results")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_create_pen_test_result(client, db, monkeypatch):
    """Test creating pen test result."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    req_response = client.post(
        "/api/v1/pentagi/requests",
        json={
            "finding_id": "finding-result",
            "target_url": "https://test.example.com",
            "vulnerability_type": "sqli",
            "test_case": "Test",
            "priority": "high",
        },
    )
    request_id = req_response.json()["id"]

    response = client.post(
        "/api/v1/pentagi/results",
        json={
            "request_id": request_id,
            "finding_id": "finding-result",
            "exploitability": "confirmed_exploitable",
            "exploit_successful": True,
            "evidence": "SQL injection successful, extracted user data",
            "steps_taken": ["Attempted payload", "Confirmed injection"],
            "confidence_score": 0.95,
            "execution_time_seconds": 12.5,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["exploitability"] == "confirmed_exploitable"
    assert data["exploit_successful"] is True


def test_get_pen_test_result_by_request(client, db, monkeypatch):
    """Test getting pen test result by request ID."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    req_response = client.post(
        "/api/v1/pentagi/requests",
        json={
            "finding_id": "finding-get-result",
            "target_url": "https://test.example.com",
            "vulnerability_type": "xss",
            "test_case": "Test",
            "priority": "medium",
        },
    )
    request_id = req_response.json()["id"]

    client.post(
        "/api/v1/pentagi/results",
        json={
            "request_id": request_id,
            "finding_id": "finding-get-result",
            "exploitability": "unexploitable",
            "exploit_successful": False,
            "evidence": "No XSS vector found",
        },
    )

    response = client.get(f"/api/v1/pentagi/results/by-request/{request_id}")
    assert response.status_code == 200
    assert response.json()["request_id"] == request_id


def test_list_pen_test_configs(client, db, monkeypatch):
    """Test listing Pentagi configurations."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    response = client.get("/api/v1/pentagi/configs")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_create_pen_test_config(client, db, monkeypatch):
    """Test creating Pentagi configuration."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    response = client.post(
        "/api/v1/pentagi/configs",
        json={
            "name": "Production Pentagi",
            "pentagi_url": "https://pentagi.example.com",
            "api_key": "secret-key-123",
            "enabled": True,
            "max_concurrent_tests": 10,
            "timeout_seconds": 600,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Production Pentagi"
    assert data["api_key"] == "***"


def test_get_pen_test_config(client, db, monkeypatch):
    """Test getting Pentagi configuration."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    create_response = client.post(
        "/api/v1/pentagi/configs",
        json={"name": "Test Config", "pentagi_url": "https://pentagi.test.com"},
    )
    config_id = create_response.json()["id"]

    response = client.get(f"/api/v1/pentagi/configs/{config_id}")
    assert response.status_code == 200
    assert response.json()["id"] == config_id


def test_update_pen_test_config(client, db, monkeypatch):
    """Test updating Pentagi configuration."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    create_response = client.post(
        "/api/v1/pentagi/configs",
        json={"name": "Update Test", "pentagi_url": "https://pentagi.test.com"},
    )
    config_id = create_response.json()["id"]

    response = client.put(
        f"/api/v1/pentagi/configs/{config_id}",
        json={"enabled": False, "max_concurrent_tests": 20},
    )
    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert response.json()["max_concurrent_tests"] == 20


def test_delete_pen_test_config(client, db, monkeypatch):
    """Test deleting Pentagi configuration."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    create_response = client.post(
        "/api/v1/pentagi/configs",
        json={"name": "Delete Test", "pentagi_url": "https://pentagi.test.com"},
    )
    config_id = create_response.json()["id"]

    response = client.delete(f"/api/v1/pentagi/configs/{config_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "deleted"


def test_micro_test_playbook_crud(client, db, monkeypatch):
    """Test micro test playbook lifecycle."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    create_response = client.post(
        "/api/v1/pentagi/micro-tests",
        json={
            "name": "SQLI Micro Probe",
            "description": "Focused SQLi verification for API endpoints",
            "category": "api",
            "lifecycle": "approved",
            "severity_focus": ["high", "critical"],
            "target_types": ["api_gateway", "web_service"],
            "tooling_profile": ["sqlmap", "curl"],
            "controls_required": ["allowlisted_ip"],
            "estimated_runtime_seconds": 180,
            "max_execution_seconds": 240,
            "version": "1.2.0",
            "owner": "security-team@fixops.io",
            "enabled": True,
            "compliance_tags": ["pci", "soc2"],
            "guardrails": {"rate_limit": "5rps"},
        },
    )
    assert create_response.status_code == 201
    playbook_id = create_response.json()["id"]

    list_response = client.get("/api/v1/pentagi/micro-tests")
    assert list_response.status_code == 200
    assert list_response.json()["total"] == 1

    get_response = client.get(f"/api/v1/pentagi/micro-tests/{playbook_id}")
    assert get_response.status_code == 200
    assert get_response.json()["name"] == "SQLI Micro Probe"

    update_response = client.put(
        f"/api/v1/pentagi/micro-tests/{playbook_id}",
        json={"enabled": False, "lifecycle": "disabled"},
    )
    assert update_response.status_code == 200
    assert update_response.json()["enabled"] is False
    assert update_response.json()["lifecycle"] == "disabled"

    delete_response = client.delete(f"/api/v1/pentagi/micro-tests/{playbook_id}")
    assert delete_response.status_code == 200
    assert delete_response.json()["status"] == "deleted"


def test_micro_test_run_flow(client, db, monkeypatch):
    """Test micro test run creation and updates."""
    monkeypatch.setattr("apps.api.pentagi_router.db", db)

    playbook_resp = client.post(
        "/api/v1/pentagi/micro-tests",
        json={
            "name": "Auth Bypass Probe",
            "description": "Checks for weak auth paths",
            "category": "web_application",
            "lifecycle": "approved",
        },
    )
    playbook_id = playbook_resp.json()["id"]

    request_resp = client.post(
        "/api/v1/pentagi/requests",
        json={
            "finding_id": "finding-micro",
            "target_url": "https://auth.fixops.com",
            "vulnerability_type": "auth_bypass",
            "test_case": "Validate bypass via session fixation",
            "priority": "high",
        },
    )
    request_id = request_resp.json()["id"]

    run_resp = client.post(
        "/api/v1/pentagi/micro-test-runs",
        json={
            "playbook_id": playbook_id,
            "request_id": request_id,
            "priority": "high",
            "approval_state": "pending",
            "commands": ["nuclei -t auth-bypass"],
            "policy_blockers": [],
            "telemetry": {"expected_runtime": 120},
            "risk_score": 0.87,
        },
    )
    assert run_resp.status_code == 201
    run_id = run_resp.json()["id"]
    assert run_resp.json()["status"] == "queued"

    list_resp = client.get("/api/v1/pentagi/micro-test-runs")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] == 1

    update_resp = client.put(
        f"/api/v1/pentagi/micro-test-runs/{run_id}",
        json={
            "status": "running",
            "approval_state": "approved",
            "runner_label": "runner-us-east-1",
            "runner_location": "us-east-1",
            "artifacts": ["s3://evidence/run1/log.txt"],
        },
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "running"
    assert update_resp.json()["approval_state"] == "approved"
