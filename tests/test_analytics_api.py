"""
Tests for analytics API endpoints.
"""
import os
import tempfile

import pytest

from core.analytics_db import AnalyticsDB
from core.analytics_models import (
    Decision,
    DecisionOutcome,
    Finding,
    FindingSeverity,
    FindingStatus,
)


@pytest.fixture
def client(authenticated_client):
    """Create test client using shared authenticated_client fixture.

    This ensures all requests include the X-API-Key header for authentication.
    """
    return authenticated_client


@pytest.fixture
def db():
    """Create test database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = AnalyticsDB(db_path=path)
    yield db

    os.unlink(path)


def test_dashboard_overview_empty(client, db, monkeypatch):
    """Test dashboard overview with empty database."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    response = client.get("/api/v1/analytics/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 0
    assert data["open_findings"] == 0


def test_create_finding(client, db, monkeypatch):
    """Test creating a new finding."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    finding_data = {
        "rule_id": "SAST-001",
        "severity": "high",
        "status": "open",
        "title": "SQL Injection Vulnerability",
        "description": "Potential SQL injection in user input",
        "source": "SAST",
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.5,
        "exploitable": True,
    }

    response = client.post("/api/v1/analytics/findings", json=finding_data)
    assert response.status_code == 201
    data = response.json()
    assert data["rule_id"] == "SAST-001"
    assert data["severity"] == "high"
    assert data["title"] == "SQL Injection Vulnerability"


def test_list_findings(client, db, monkeypatch):
    """Test listing findings."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="Test Finding",
        description="Test description",
        source="SAST",
    )
    db.create_finding(finding)

    response = client.get("/api/v1/analytics/findings")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Test Finding"


def test_get_finding(client, db, monkeypatch):
    """Test getting finding by ID."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="Test Finding",
        description="Test description",
        source="SAST",
    )
    created = db.create_finding(finding)

    response = client.get(f"/api/v1/analytics/findings/{created.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created.id
    assert data["title"] == "Test Finding"


def test_get_finding_not_found(client, db, monkeypatch):
    """Test getting non-existent finding."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    response = client.get("/api/v1/analytics/findings/nonexistent-id")
    assert response.status_code == 404


def test_update_finding(client, db, monkeypatch):
    """Test updating finding status."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="Test Finding",
        description="Test description",
        source="SAST",
    )
    created = db.create_finding(finding)

    update_data = {"status": "resolved"}

    response = client.put(f"/api/v1/analytics/findings/{created.id}", json=update_data)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "resolved"
    assert data["resolved_at"] is not None


def test_create_decision(client, db, monkeypatch):
    """Test creating a decision."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="Test Finding",
        description="Test description",
        source="SAST",
    )
    created_finding = db.create_finding(finding)

    decision_data = {
        "finding_id": created_finding.id,
        "outcome": "block",
        "confidence": 0.95,
        "reasoning": "High severity with active exploitation",
        "llm_votes": {"gpt4": "block", "claude": "block"},
    }

    response = client.post("/api/v1/analytics/decisions", json=decision_data)
    assert response.status_code == 201
    data = response.json()
    assert data["outcome"] == "block"
    assert data["confidence"] == 0.95


def test_list_decisions(client, db, monkeypatch):
    """Test listing decisions."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="Test Finding",
        description="Test description",
        source="SAST",
    )
    created_finding = db.create_finding(finding)

    decision = Decision(
        id="",
        finding_id=created_finding.id,
        outcome=DecisionOutcome.BLOCK,
        confidence=0.95,
        reasoning="Test reasoning",
    )
    db.create_decision(decision)

    response = client.get("/api/v1/analytics/decisions")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["outcome"] == "block"


def test_get_top_risks(client, db, monkeypatch):
    """Test getting top risks."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    for i in range(5):
        finding = Finding(
            id="",
            application_id="app-1",
            service_id="svc-1",
            rule_id=f"SAST-{i:03d}",
            severity=FindingSeverity.CRITICAL if i < 2 else FindingSeverity.HIGH,
            status=FindingStatus.OPEN,
            title=f"Finding {i}",
            description="Test description",
            source="SAST",
            exploitable=i < 3,
        )
        db.create_finding(finding)

    response = client.get("/api/v1/analytics/dashboard/top-risks?limit=3")
    assert response.status_code == 200
    data = response.json()
    assert len(data["risks"]) == 3


def test_get_mttr(client, db, monkeypatch):
    """Test getting MTTR metrics."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    response = client.get("/api/v1/analytics/mttr")
    assert response.status_code == 200
    data = response.json()
    assert data["mttr_hours"] is None


def test_get_coverage(client, db, monkeypatch):
    """Test getting coverage metrics."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    finding = Finding(
        id="",
        application_id="app-1",
        service_id="svc-1",
        rule_id="SAST-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="Test Finding",
        description="Test description",
        source="SAST",
    )
    db.create_finding(finding)

    response = client.get("/api/v1/analytics/coverage")
    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 1
    assert data["scanned_applications"] == 1


def test_get_roi(client, db, monkeypatch):
    """Test getting ROI calculations."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    response = client.get("/api/v1/analytics/roi")
    assert response.status_code == 200
    data = response.json()
    assert "total_findings" in data
    assert "estimated_prevented_cost" in data


def test_get_noise_reduction(client, db, monkeypatch):
    """Test getting noise reduction metrics."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    response = client.get("/api/v1/analytics/noise-reduction")
    assert response.status_code == 200
    data = response.json()
    assert "noise_reduction_percentage" in data


def test_custom_query_findings(client, db, monkeypatch):
    """Test custom query for findings."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    query = {"type": "findings", "filters": {"severity": "high", "limit": 10}}

    response = client.post("/api/v1/analytics/custom-query", json=query)
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert "count" in data


def test_export_analytics(client, db, monkeypatch):
    """Test exporting analytics data."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    response = client.get("/api/v1/analytics/export?format=json&data_type=findings")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["format"] == "json"


def test_findings_deduplicate_by_fingerprint_within_window(client, db, monkeypatch):
    """Creating the same finding twice should deduplicate within the default window."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    finding_data = {
        "rule_id": "SAST-001",
        "severity": "high",
        "status": "open",
        "title": "SQL Injection Vulnerability",
        "description": "Potential SQL injection in user input",
        "source": "SAST",
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.5,
        "exploitable": True,
        "metadata": {"file_path": "/workspace/app/api/users.py:10"},
    }

    first = client.post("/api/v1/analytics/findings", json=finding_data)
    assert first.status_code == 201
    second = client.post("/api/v1/analytics/findings", json=finding_data)
    assert second.status_code == 201

    assert first.json()["id"] == second.json()["id"]


def test_list_cases_groups_findings(client, db, monkeypatch):
    """Cases endpoint should group findings by correlation key."""
    monkeypatch.setattr("apps.api.analytics_router.db", db)

    a = client.post(
        "/api/v1/analytics/findings",
        json={
            "rule_id": "SAST-001",
            "severity": "high",
            "status": "open",
            "title": "SQL Injection Vulnerability",
            "description": "Potential SQL injection in user input",
            "source": "SAST",
            "metadata": {"file_path": "services/users.py:10"},
        },
    )
    assert a.status_code == 201

    b = client.post(
        "/api/v1/analytics/findings",
        json={
            "rule_id": "SAST-001",
            "severity": "high",
            "status": "open",
            "title": "SQL Injection Vulnerability",
            "description": "Potential SQL injection in user input",
            "source": "SAST",
            "metadata": {"file_path": "services/users.py:11"},
        },
    )
    assert b.status_code == 201

    response = client.get("/api/v1/analytics/cases")
    assert response.status_code == 200
    cases = response.json()
    assert isinstance(cases, list)
    assert cases
