"""Tests for SSO/SAML authentication API endpoints."""
from fastapi.testclient import TestClient


def test_list_sso_configs(client: TestClient, api_key: str):
    """Test listing SSO configurations."""
    response = client.get("/api/v1/auth/sso", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


def test_create_sso_config(client: TestClient, api_key: str):
    """Test creating SSO configuration."""
    response = client.post(
        "/api/v1/auth/sso",
        headers={"X-API-Key": api_key},
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


def test_get_sso_config(client: TestClient, api_key: str):
    """Test getting SSO configuration."""
    create_response = client.post(
        "/api/v1/auth/sso",
        headers={"X-API-Key": api_key},
        json={"name": "Test SSO", "provider": "oauth2"},
    )
    config_id = create_response.json()["id"]

    response = client.get(
        f"/api/v1/auth/sso/{config_id}", headers={"X-API-Key": api_key}
    )
    assert response.status_code == 200
    assert response.json()["id"] == config_id


def test_update_sso_config(client: TestClient, api_key: str):
    """Test updating SSO configuration."""
    create_response = client.post(
        "/api/v1/auth/sso",
        headers={"X-API-Key": api_key},
        json={"name": "Test SSO", "provider": "ldap"},
    )
    config_id = create_response.json()["id"]

    response = client.put(
        f"/api/v1/auth/sso/{config_id}",
        headers={"X-API-Key": api_key},
        json={"status": "active"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "active"


def test_get_nonexistent_sso_config(client: TestClient, api_key: str):
    """Test getting non-existent SSO configuration."""
    response = client.get(
        "/api/v1/auth/sso/nonexistent", headers={"X-API-Key": api_key}
    )
    assert response.status_code == 404
