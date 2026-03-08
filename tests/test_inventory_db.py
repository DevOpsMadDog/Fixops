"""Tests for InventoryDB — application inventory database."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.inventory_models import (
    APIEndpoint,
    Application,
    ApplicationCriticality,
    ApplicationStatus,
    Component,
    Service,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------
class TestInventoryModels:
    def test_criticality_enum(self):
        assert ApplicationCriticality.CRITICAL == "critical"
        assert ApplicationCriticality.HIGH == "high"
        assert ApplicationCriticality.MEDIUM == "medium"
        assert ApplicationCriticality.LOW == "low"

    def test_status_enum(self):
        assert ApplicationStatus.ACTIVE == "active"
        assert ApplicationStatus.DEPRECATED == "deprecated"
        assert ApplicationStatus.ARCHIVED == "archived"

    def test_application_to_dict(self):
        app = Application(
            id="app-1",
            name="Web Portal",
            description="Main web application",
            criticality=ApplicationCriticality.CRITICAL,
            status=ApplicationStatus.ACTIVE,
            owner_team="security",
            repository_url="https://github.com/org/app",
            environment="production",
            tags=["web", "frontend"],
        )
        d = app.to_dict()
        assert d["id"] == "app-1"
        assert d["name"] == "Web Portal"
        assert d["criticality"] == "critical"
        assert d["status"] == "active"
        assert d["tags"] == ["web", "frontend"]

    def test_service_to_dict(self):
        svc = Service(
            id="svc-1",
            name="auth-service",
            application_id="app-1",
            description="Auth microservice",
            version="2.0.0",
            endpoint_url="https://auth.internal",
        )
        d = svc.to_dict()
        assert d["id"] == "svc-1"
        assert d["version"] == "2.0.0"

    def test_api_endpoint_to_dict(self):
        ep = APIEndpoint(
            id="ep-1",
            service_id="svc-1",
            path="/api/v1/login",
            method="POST",
            description="User login",
            is_public=True,
            requires_auth=False,
            rate_limit=100,
        )
        d = ep.to_dict()
        assert d["path"] == "/api/v1/login"
        assert d["is_public"] is True
        assert d["rate_limit"] == 100

    def test_component_to_dict(self):
        comp = Component(
            id="comp-1",
            application_id="app-1",
            name="lodash",
            version="4.17.21",
            type="npm",
            license="MIT",
        )
        d = comp.to_dict()
        assert d["name"] == "lodash"
        assert d["license"] == "MIT"


# ---------------------------------------------------------------------------
# InventoryDB tests
# ---------------------------------------------------------------------------
class TestInventoryDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.inventory_db import InventoryDB
        return InventoryDB(db_path=str(tmp_path / "test_inventory.db"))

    @pytest.fixture
    def sample_app(self, db):
        app = Application(
            id="",
            name="Test App",
            description="A test application",
            criticality=ApplicationCriticality.HIGH,
            status=ApplicationStatus.ACTIVE,
            owner_team="engineering",
            environment="staging",
            tags=["test"],
        )
        return db.create_application(app)

    def test_create_application(self, db):
        app = Application(
            id="",
            name="New App",
            description="Brand new app",
            criticality=ApplicationCriticality.MEDIUM,
            status=ApplicationStatus.ACTIVE,
        )
        created = db.create_application(app)
        assert created.id != ""
        assert created.name == "New App"

    def test_get_application(self, db, sample_app):
        app = db.get_application(sample_app.id)
        assert app is not None
        assert app.name == "Test App"
        assert app.criticality == ApplicationCriticality.HIGH
        assert app.tags == ["test"]

    def test_get_application_not_found(self, db):
        assert db.get_application("nonexistent") is None

    def test_list_applications(self, db, sample_app):
        apps = db.list_applications()
        assert len(apps) >= 1

    def test_list_applications_pagination(self, db):
        for i in range(5):
            db.create_application(Application(
                id="",
                name=f"App {i}",
                description=f"Desc {i}",
                criticality=ApplicationCriticality.LOW,
                status=ApplicationStatus.ACTIVE,
            ))
        page1 = db.list_applications(limit=3)
        page2 = db.list_applications(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 2

    def test_update_application(self, db, sample_app):
        sample_app.name = "Updated App"
        sample_app.criticality = ApplicationCriticality.CRITICAL
        updated = db.update_application(sample_app)
        assert updated.name == "Updated App"
        from_db = db.get_application(sample_app.id)
        assert from_db.name == "Updated App"
        assert from_db.criticality == ApplicationCriticality.CRITICAL

    def test_delete_application(self, db, sample_app):
        result = db.delete_application(sample_app.id)
        assert result is True
        assert db.get_application(sample_app.id) is None

    def test_search_inventory(self, db, sample_app):
        results = db.search_inventory("Test")
        assert "applications" in results
        assert len(results["applications"]) >= 1

    def test_search_inventory_no_results(self, db, sample_app):
        results = db.search_inventory("nonexistent_xyz")
        assert len(results["applications"]) == 0
