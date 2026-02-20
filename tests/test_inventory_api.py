"""
Tests for inventory management APIs.
"""
import os
import shutil
import tempfile

import pytest
from apps.api.app import create_app
from core.inventory_db import InventoryDB
from fastapi.testclient import TestClient


@pytest.fixture
def test_db_path():
    """Create temporary database path."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_inventory.db")
    yield db_path
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def client(test_db_path, monkeypatch):
    """Create test client with temporary database."""
    monkeypatch.setenv("FIXOPS_API_TOKEN", "test-token")

    original_init = InventoryDB.__init__

    def mock_init(self, db_path=None):
        original_init(self, db_path=test_db_path)

    monkeypatch.setattr(InventoryDB, "__init__", mock_init)

    app = create_app()
    return TestClient(app)


class TestInventoryAPIs:
    """Test inventory API endpoints."""

    def test_list_applications_empty(self, client):
        """Test listing applications when empty."""
        response = client.get(
            "/api/v1/inventory/applications", headers={"X-API-Key": "test-token"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)

    def test_create_application(self, client):
        """Test creating a new application."""
        app_data = {
            "name": "Test App",
            "description": "Test application",
            "criticality": "high",
            "status": "active",
            "environment": "production",
        }
        response = client.post(
            "/api/v1/inventory/applications",
            json=app_data,
            headers={"X-API-Key": "test-token"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test App"
        assert "id" in data
        assert data["criticality"] == "high"

    def test_create_application_validation(self, client):
        """Test application creation validation."""
        app_data = {"description": "Test application"}
        response = client.post(
            "/api/v1/inventory/applications",
            json=app_data,
            headers={"X-API-Key": "test-token"},
        )
        assert response.status_code == 422

    def test_get_application(self, client):
        """Test getting application by ID."""
        app_data = {"name": "Test App", "description": "Test", "criticality": "medium"}
        create_response = client.post(
            "/api/v1/inventory/applications",
            json=app_data,
            headers={"X-API-Key": "test-token"},
        )
        app_id = create_response.json()["id"]

        response = client.get(
            f"/api/v1/inventory/applications/{app_id}",
            headers={"X-API-Key": "test-token"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == app_id
        assert data["name"] == "Test App"

    def test_get_nonexistent_application(self, client):
        """Test getting application that doesn't exist."""
        response = client.get(
            "/api/v1/inventory/applications/nonexistent-id",
            headers={"X-API-Key": "test-token"},
        )
        assert response.status_code == 404

    def test_update_application(self, client):
        """Test updating application."""
        app_data = {"name": "Test App", "description": "Original", "criticality": "low"}
        create_response = client.post(
            "/api/v1/inventory/applications",
            json=app_data,
            headers={"X-API-Key": "test-token"},
        )
        app_id = create_response.json()["id"]

        update_data = {"description": "Updated", "criticality": "high"}
        response = client.put(
            f"/api/v1/inventory/applications/{app_id}",
            json=update_data,
            headers={"X-API-Key": "test-token"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "Updated"
        assert data["criticality"] == "high"

    def test_delete_application(self, client):
        """Test deleting application."""
        app_data = {
            "name": "Test App",
            "description": "To be deleted",
            "criticality": "low",
        }
        create_response = client.post(
            "/api/v1/inventory/applications",
            json=app_data,
            headers={"X-API-Key": "test-token"},
        )
        app_id = create_response.json()["id"]

        response = client.delete(
            f"/api/v1/inventory/applications/{app_id}",
            headers={"X-API-Key": "test-token"},
        )
        assert response.status_code == 204

        get_response = client.get(
            f"/api/v1/inventory/applications/{app_id}",
            headers={"X-API-Key": "test-token"},
        )
        assert get_response.status_code == 404

    def test_search_inventory(self, client):
        """Test inventory search."""
        app_data = {
            "name": "SearchTest App",
            "description": "Searchable application",
            "criticality": "high",
        }
        client.post(
            "/api/v1/inventory/applications",
            json=app_data,
            headers={"X-API-Key": "test-token"},
        )

        response = client.get(
            "/api/v1/inventory/search?q=SearchTest", headers={"X-API-Key": "test-token"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "applications" in data
        assert len(data["applications"]) > 0

    def test_pagination(self, client):
        """Test pagination parameters."""
        for i in range(5):
            app_data = {
                "name": f"App {i}",
                "description": f"Application {i}",
                "criticality": "medium",
            }
            client.post(
                "/api/v1/inventory/applications",
                json=app_data,
                headers={"X-API-Key": "test-token"},
            )

        response = client.get(
            "/api/v1/inventory/applications?limit=2&offset=0",
            headers={"X-API-Key": "test-token"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 2
        assert data["offset"] == 0
        assert len(data["items"]) <= 2

    def test_unauthorized_access(self, client):
        """Test accessing API without authentication."""
        response = client.get("/api/v1/inventory/applications")
        assert response.status_code == 401
