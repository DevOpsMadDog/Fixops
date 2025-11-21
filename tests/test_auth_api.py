"""Tests for SSO/SAML authentication API endpoints."""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app
from core.auth_db import AuthDB


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

    db = AuthDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_sso_configs(client, db, monkeypatch):
    """Test listing SSO configurations."""
    monkeypatch.setattr("apps.api.auth_router.db", db)

    response = client.get("/api/v1/auth/sso")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


def test_create_sso_config(client, db, monkeypatch):
    """Test creating SSO configuration."""
    monkeypatch.setattr("apps.api.auth_router.db", db)

    response = client.post(
        "/api/v1/auth/sso",
        json={
            "name": "Test SAML",
            "provider": "saml",
            "entity_id": "https://test.example.com",
            "sso_url": "https://test.example.com/sso",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test SAML"
    assert data["provider"] == "saml"
    assert data["entity_id"] == "https://test.example.com"


def test_get_sso_config(client, db, monkeypatch):
    """Test getting SSO configuration."""
    monkeypatch.setattr("apps.api.auth_router.db", db)

    create_response = client.post(
        "/api/v1/auth/sso",
        json={"name": "Test SSO", "provider": "oauth2"},
    )
    config_id = create_response.json()["id"]

    response = client.get(f"/api/v1/auth/sso/{config_id}")
    assert response.status_code == 200
    assert response.json()["id"] == config_id


def test_update_sso_config(client, db, monkeypatch):
    """Test updating SSO configuration."""
    monkeypatch.setattr("apps.api.auth_router.db", db)

    create_response = client.post(
        "/api/v1/auth/sso",
        json={"name": "Test SSO", "provider": "ldap"},
    )
    config_id = create_response.json()["id"]

    response = client.put(
        f"/api/v1/auth/sso/{config_id}",
        json={"status": "active"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "active"


def test_get_nonexistent_sso_config(client, db, monkeypatch):
    """Test getting non-existent SSO configuration."""
    monkeypatch.setattr("apps.api.auth_router.db", db)

    response = client.get("/api/v1/auth/sso/nonexistent")
    assert response.status_code == 404
