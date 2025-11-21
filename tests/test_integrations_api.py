"""
Tests for integration management API endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app
from core.integration_db import IntegrationDB
from core.integration_models import Integration, IntegrationStatus, IntegrationType


@pytest.fixture
def client():
    """Create test client."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def db():
    """Create test database."""
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = IntegrationDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_integrations_empty(client, db, monkeypatch):
    """Test listing integrations when database is empty."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    response = client.get("/api/v1/integrations")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 0


def test_create_integration(client, db, monkeypatch):
    """Test creating a new integration."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration_data = {
        "name": "Test Jira",
        "integration_type": "jira",
        "status": "active",
        "config": {
            "base_url": "https://test.atlassian.net",
            "project_key": "TEST",
        },
    }

    response = client.post("/api/v1/integrations", json=integration_data)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Jira"
    assert data["integration_type"] == "jira"
    assert data["status"] == "active"


def test_get_integration(client, db, monkeypatch):
    """Test getting integration by ID."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={"base_url": "https://test.atlassian.net"},
    )
    created = db.create_integration(integration)

    response = client.get(f"/api/v1/integrations/{created.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created.id
    assert data["name"] == "Test Jira"


def test_get_integration_not_found(client, db, monkeypatch):
    """Test getting non-existent integration."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    response = client.get("/api/v1/integrations/nonexistent-id")
    assert response.status_code == 404


def test_update_integration(client, db, monkeypatch):
    """Test updating integration."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    update_data = {"name": "Updated Jira", "status": "inactive"}

    response = client.put(f"/api/v1/integrations/{created.id}", json=update_data)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Jira"
    assert data["status"] == "inactive"


def test_delete_integration(client, db, monkeypatch):
    """Test deleting integration."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    response = client.delete(f"/api/v1/integrations/{created.id}")
    assert response.status_code == 204

    get_response = client.get(f"/api/v1/integrations/{created.id}")
    assert get_response.status_code == 404


def test_test_integration_jira(client, db, monkeypatch):
    """Test testing Jira integration connection."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={
            "base_url": "https://test.atlassian.net",
            "project_key": "TEST",
            "token": "test-token",
        },
    )
    created = db.create_integration(integration)

    response = client.post(f"/api/v1/integrations/{created.id}/test")
    assert response.status_code == 200
    data = response.json()
    assert data["integration_id"] == created.id
    assert "success" in data


def test_test_integration_inactive(client, db, monkeypatch):
    """Test testing inactive integration."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.INACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    response = client.post(f"/api/v1/integrations/{created.id}/test")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is False
    assert "not active" in data["message"]


def test_get_sync_status(client, db, monkeypatch):
    """Test getting integration sync status."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    response = client.get(f"/api/v1/integrations/{created.id}/sync-status")
    assert response.status_code == 200
    data = response.json()
    assert data["integration_id"] == created.id
    assert data["status"] == "active"


def test_trigger_sync(client, db, monkeypatch):
    """Test triggering manual sync."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    response = client.post(f"/api/v1/integrations/{created.id}/sync")
    assert response.status_code == 200
    data = response.json()
    assert data["sync_triggered"] is True
    assert "sync_time" in data


def test_trigger_sync_inactive(client, db, monkeypatch):
    """Test triggering sync on inactive integration."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.INACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    response = client.post(f"/api/v1/integrations/{created.id}/sync")
    assert response.status_code == 400


def test_list_integrations_with_filter(client, db, monkeypatch):
    """Test listing integrations with type filter."""
    monkeypatch.setattr("apps.api.integrations_router.db", db)

    jira_integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    db.create_integration(jira_integration)

    slack_integration = Integration(
        id="",
        name="Test Slack",
        integration_type=IntegrationType.SLACK,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    db.create_integration(slack_integration)

    response = client.get("/api/v1/integrations?integration_type=jira")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["integration_type"] == "jira"
