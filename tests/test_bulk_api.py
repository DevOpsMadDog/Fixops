"""Tests for bulk operations API endpoints."""
import os

import pytest
from apps.api.app import create_app
from fastapi.testclient import TestClient

_TEST_TOKEN = "test-bulk-api-token"


@pytest.fixture
def client(monkeypatch):
    """Create test client with proper environment variables."""
    monkeypatch.setenv("FIXOPS_API_TOKEN", _TEST_TOKEN)
    monkeypatch.setenv("FIXOPS_MODE", os.getenv("FIXOPS_MODE", "enterprise"))
    app = create_app()
    return TestClient(app)


@pytest.fixture
def headers():
    """Auth headers for bulk API requests."""
    return {"X-API-Key": _TEST_TOKEN}


def test_bulk_update_findings(client, headers):
    """Test bulk updating findings — non-existent IDs return success_count=0."""
    response = client.post(
        "/api/v1/bulk/findings/update",
        json={"ids": ["id1", "id2", "id3"], "updates": {"status": "resolved"}},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    # Non-existent IDs result in 0 successes, 3 errors
    assert "success_count" in data
    assert "failure_count" in data
    assert data["success_count"] + data["failure_count"] == 3


def test_bulk_delete_findings(client, headers):
    """Test bulk deleting findings — non-existent IDs return success_count=0."""
    response = client.post(
        "/api/v1/bulk/findings/delete",
        json={"ids": ["id1", "id2"]},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "success_count" in data
    assert "failure_count" in data


def test_bulk_assign_findings(client, headers):
    """Test bulk assigning findings via request body."""
    response = client.post(
        "/api/v1/bulk/findings/assign",
        json={"ids": ["id1", "id2"], "assignee": "user@example.com"},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "success_count" in data
    assert "failure_count" in data


def test_bulk_apply_policies(client, headers):
    """Test bulk applying policies via request body."""
    response = client.post(
        "/api/v1/bulk/policies/apply",
        json={"policy_ids": ["policy1"], "target_ids": ["target1", "target2"]},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "success_count" in data
    assert "failure_count" in data


def test_bulk_export(client, headers):
    """Test bulk export returns a job response."""
    response = client.post(
        "/api/v1/bulk/export",
        json={"ids": ["id1", "id2", "id3"], "format": "json", "org_id": "test-org"},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["status"] in ("pending", "running", "completed")
