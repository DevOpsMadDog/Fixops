"""Tests for IDE extension support API endpoints."""
import os

import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app


@pytest.fixture
def client(monkeypatch):
    """Create test client with proper environment variables."""
    monkeypatch.setenv(
        "FIXOPS_API_TOKEN", os.getenv("FIXOPS_API_TOKEN", "demo-token-12345")
    )
    monkeypatch.setenv("FIXOPS_MODE", os.getenv("FIXOPS_MODE", "demo"))
    app = create_app()
    return TestClient(app)


def test_get_ide_config(client):
    """Test getting IDE configuration."""
    response = client.get("/api/v1/ide/config")
    assert response.status_code == 200
    data = response.json()
    assert "api_endpoint" in data
    assert "supported_languages" in data
    assert "features" in data
    assert isinstance(data["supported_languages"], list)


def test_analyze_code(client):
    """Test analyzing code."""
    response = client.post(
        "/api/v1/ide/analyze",
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


def test_get_suggestions(client):
    """Test getting code suggestions."""
    response = client.get(
        "/api/v1/ide/suggestions",
        params={"file_path": "app.py", "line": 10, "column": 5},
    )
    assert response.status_code == 200
    data = response.json()
    assert "suggestions" in data
    assert "context" in data
