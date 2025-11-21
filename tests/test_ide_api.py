"""Tests for IDE extension support API endpoints."""
from fastapi.testclient import TestClient


def test_get_ide_config(client: TestClient, api_key: str):
    """Test getting IDE configuration."""
    response = client.get("/api/v1/ide/config", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert "api_endpoint" in data
    assert "supported_languages" in data
    assert "features" in data
    assert isinstance(data["supported_languages"], list)


def test_analyze_code(client: TestClient, api_key: str):
    """Test analyzing code."""
    response = client.post(
        "/api/v1/ide/analyze",
        headers={"X-API-Key": api_key},
        json={
            "file_path": "app.py",
            "content": "import os\npassword = 'secret123'\n",
            "language": "python",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert "suggestions" in data
    assert "metrics" in data


def test_get_suggestions(client: TestClient, api_key: str):
    """Test getting code suggestions."""
    response = client.get(
        "/api/v1/ide/suggestions",
        headers={"X-API-Key": api_key},
        params={"file_path": "app.py", "line": 10, "column": 5},
    )
    assert response.status_code == 200
    data = response.json()
    assert "suggestions" in data
    assert "context" in data
