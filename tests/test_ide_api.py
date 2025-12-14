"""Tests for IDE extension support API endpoints."""
import pytest


@pytest.fixture
def client(authenticated_client):
    """Create test client using shared authenticated_client fixture.

    This ensures all requests include the X-API-Key header for authentication.
    """
    return authenticated_client


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
