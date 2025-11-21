"""Tests for bulk operations API endpoints."""
from fastapi.testclient import TestClient


def test_bulk_update_findings(client: TestClient, api_key: str):
    """Test bulk updating findings."""
    response = client.post(
        "/api/v1/bulk/findings/update",
        headers={"X-API-Key": api_key},
        json={"ids": ["id1", "id2", "id3"], "updates": {"status": "resolved"}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success_count"] == 3
    assert data["failure_count"] == 0


def test_bulk_delete_findings(client: TestClient, api_key: str):
    """Test bulk deleting findings."""
    response = client.post(
        "/api/v1/bulk/findings/delete",
        headers={"X-API-Key": api_key},
        json={"ids": ["id1", "id2"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success_count"] == 2


def test_bulk_assign_findings(client: TestClient, api_key: str):
    """Test bulk assigning findings."""
    response = client.post(
        "/api/v1/bulk/findings/assign",
        headers={"X-API-Key": api_key},
        params={"ids": ["id1", "id2"], "assignee": "user@example.com"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success_count"] == 2


def test_bulk_apply_policies(client: TestClient, api_key: str):
    """Test bulk applying policies."""
    response = client.post(
        "/api/v1/bulk/policies/apply",
        headers={"X-API-Key": api_key},
        params={"policy_ids": ["policy1"], "target_ids": ["target1", "target2"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success_count"] == 2


def test_bulk_export(client: TestClient, api_key: str):
    """Test bulk export."""
    response = client.post(
        "/api/v1/bulk/export",
        headers={"X-API-Key": api_key},
        params={"ids": ["id1", "id2", "id3"], "format": "json"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "export_id" in data
    assert data["format"] == "json"
    assert data["item_count"] == 3
