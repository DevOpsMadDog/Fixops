"""Tests for secrets detection API endpoints."""
from fastapi.testclient import TestClient


def test_list_secret_findings(client: TestClient, api_key: str):
    """Test listing secret findings."""
    response = client.get("/api/v1/secrets", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


def test_create_secret_finding(client: TestClient, api_key: str):
    """Test creating secret finding."""
    response = client.post(
        "/api/v1/secrets",
        headers={"X-API-Key": api_key},
        json={
            "secret_type": "api_key",
            "file_path": "config/secrets.yml",
            "line_number": 42,
            "repository": "myapp",
            "branch": "main",
            "entropy_score": 4.5,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["secret_type"] == "api_key"
    assert data["status"] == "active"


def test_get_secret_finding(client: TestClient, api_key: str):
    """Test getting secret finding."""
    create_response = client.post(
        "/api/v1/secrets",
        headers={"X-API-Key": api_key},
        json={
            "secret_type": "password",
            "file_path": "app.py",
            "line_number": 10,
            "repository": "test-repo",
            "branch": "dev",
        },
    )
    finding_id = create_response.json()["id"]

    response = client.get(
        f"/api/v1/secrets/{finding_id}", headers={"X-API-Key": api_key}
    )
    assert response.status_code == 200
    assert response.json()["id"] == finding_id


def test_resolve_secret_finding(client: TestClient, api_key: str):
    """Test resolving secret finding."""
    create_response = client.post(
        "/api/v1/secrets",
        headers={"X-API-Key": api_key},
        json={
            "secret_type": "token",
            "file_path": "config.py",
            "line_number": 5,
            "repository": "app",
            "branch": "main",
        },
    )
    finding_id = create_response.json()["id"]

    response = client.post(
        f"/api/v1/secrets/{finding_id}/resolve", headers={"X-API-Key": api_key}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_scan_repository(client: TestClient, api_key: str):
    """Test triggering repository scan."""
    response = client.post(
        "/api/v1/secrets/scan",
        headers={"X-API-Key": api_key},
        params={"repository": "myapp", "branch": "main"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "scanning"
