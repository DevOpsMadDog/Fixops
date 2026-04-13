"""Comprehensive tests for the Integration Marketplace.

Tests cover:
- Marketplace core class: catalog seeding, list/get, install/uninstall,
  update_config, list_installed, get_app_health, rate_app, register_custom_app
- IntegrationCategory enum values
- MarketplaceApp and InstalledApp Pydantic models
- Integration Marketplace REST API endpoints (10 endpoints)

All tests use a temp SQLite DB — no external dependencies.
35+ tests, all passing.
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import patch

import pytest

# Environment setup before any app imports
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-marketplace")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-that-is-at-least-32-chars-long")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# Add suite paths
sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.marketplace import (
    AppStatus,
    HealthStatus,
    InstalledApp,
    IntegrationCategory,
    Marketplace,
    MarketplaceApp,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmpdb(tmp_path):
    """Temp SQLite path for an isolated Marketplace instance."""
    return str(tmp_path / "test_marketplace.db")


@pytest.fixture
def market(tmpdb):
    """Fresh Marketplace with built-in catalog."""
    return Marketplace(db_path=tmpdb)


@pytest.fixture
def installed_market(market):
    """Marketplace with one app already installed."""
    market.install_app(
        app_id="slack",
        org_id="org-test",
        config={"webhook_url": "https://hooks.slack.com/test"},
        installed_by="user-alice",
    )
    return market


# ---------------------------------------------------------------------------
# IntegrationCategory enum
# ---------------------------------------------------------------------------


class TestIntegrationCategory:
    def test_all_categories_exist(self):
        expected = {
            "SCANNER", "TICKETING", "NOTIFICATION", "CLOUD",
            "CI_CD", "SIEM", "COMPLIANCE", "CUSTOM",
        }
        actual = {c.name for c in IntegrationCategory}
        assert expected == actual

    def test_category_values_are_lowercase(self):
        for cat in IntegrationCategory:
            assert cat.value == cat.value.lower()

    def test_category_is_string_enum(self):
        assert isinstance(IntegrationCategory.SCANNER, str)


# ---------------------------------------------------------------------------
# MarketplaceApp model
# ---------------------------------------------------------------------------


class TestMarketplaceApp:
    def test_create_minimal(self):
        app = MarketplaceApp(
            id="test-app",
            name="Test App",
            description="A test integration",
            category=IntegrationCategory.CUSTOM,
            version="1.0",
            author="ACME",
        )
        assert app.id == "test-app"
        assert app.install_count == 0
        assert app.rating == 0.0
        assert app.org_id is None

    def test_rating_bounds(self):
        with pytest.raises(Exception):
            MarketplaceApp(
                id="x", name="x", description="x",
                category=IntegrationCategory.CUSTOM,
                version="1.0", author="x", rating=6.0,
            )

    def test_rating_min_bound(self):
        with pytest.raises(Exception):
            MarketplaceApp(
                id="x", name="x", description="x",
                category=IntegrationCategory.CUSTOM,
                version="1.0", author="x", rating=-1.0,
            )

    def test_install_count_non_negative(self):
        with pytest.raises(Exception):
            MarketplaceApp(
                id="x", name="x", description="x",
                category=IntegrationCategory.CUSTOM,
                version="1.0", author="x", install_count=-1,
            )


# ---------------------------------------------------------------------------
# InstalledApp model
# ---------------------------------------------------------------------------


class TestInstalledApp:
    def test_create_installed_app(self):
        app = InstalledApp(
            app_id="slack",
            org_id="org-1",
            config={"webhook_url": "https://example.com"},
            installed_by="alice",
        )
        assert app.app_id == "slack"
        assert app.status == AppStatus.ACTIVE
        assert isinstance(app.installed_at, datetime)

    def test_disabled_status(self):
        app = InstalledApp(
            app_id="jira",
            org_id="org-1",
            config={},
            installed_by="bob",
            status=AppStatus.DISABLED,
        )
        assert app.status == AppStatus.DISABLED


# ---------------------------------------------------------------------------
# Marketplace.list_apps
# ---------------------------------------------------------------------------


class TestListApps:
    def test_returns_builtin_catalog(self, market):
        apps = market.list_apps()
        assert len(apps) >= 20

    def test_filter_by_category_scanner(self, market):
        apps = market.list_apps(category=IntegrationCategory.SCANNER)
        assert all(a.category == IntegrationCategory.SCANNER for a in apps)
        assert len(apps) >= 3

    def test_filter_by_category_ticketing(self, market):
        apps = market.list_apps(category=IntegrationCategory.TICKETING)
        assert all(a.category == IntegrationCategory.TICKETING for a in apps)

    def test_search_by_name(self, market):
        apps = market.list_apps(search="slack")
        assert any(a.id == "slack" for a in apps)

    def test_search_case_insensitive(self, market):
        apps = market.list_apps(search="SLACK")
        assert any(a.id == "slack" for a in apps)

    def test_search_by_description(self, market):
        apps = market.list_apps(search="container")
        assert len(apps) >= 1

    def test_search_no_match_returns_empty(self, market):
        apps = market.list_apps(search="xyznonexistent999abc")
        assert apps == []

    def test_ordered_by_install_count_desc(self, market):
        apps = market.list_apps()
        counts = [a.install_count for a in apps]
        assert counts == sorted(counts, reverse=True)

    def test_private_app_visible_to_owner_org(self, market):
        market.register_custom_app(
            MarketplaceApp(
                id="my-private-tool",
                name="Private Tool",
                description="Internal scanner",
                category=IntegrationCategory.CUSTOM,
                version="1.0",
                author="Acme",
                org_id="org-secret",
            )
        )
        apps_for_owner = market.list_apps(org_id="org-secret")
        assert any(a.id == "my-private-tool" for a in apps_for_owner)

    def test_private_app_not_visible_to_other_org(self, market):
        market.register_custom_app(
            MarketplaceApp(
                id="my-private-tool-2",
                name="Private Tool 2",
                description="Internal scanner",
                category=IntegrationCategory.CUSTOM,
                version="1.0",
                author="Acme",
                org_id="org-secret",
            )
        )
        apps_for_other = market.list_apps(org_id="org-other")
        assert not any(a.id == "my-private-tool-2" for a in apps_for_other)


# ---------------------------------------------------------------------------
# Marketplace.get_app
# ---------------------------------------------------------------------------


class TestGetApp:
    def test_get_existing_app(self, market):
        app = market.get_app("trivy")
        assert app is not None
        assert app.id == "trivy"
        assert app.category == IntegrationCategory.SCANNER

    def test_get_nonexistent_app_returns_none(self, market):
        assert market.get_app("does-not-exist") is None

    def test_get_app_has_config_schema(self, market):
        app = market.get_app("jira")
        assert isinstance(app.config_schema, dict)
        assert "properties" in app.config_schema

    def test_get_app_has_required_scopes(self, market):
        app = market.get_app("slack")
        assert isinstance(app.required_scopes, list)
        assert len(app.required_scopes) > 0


# ---------------------------------------------------------------------------
# Marketplace.install_app
# ---------------------------------------------------------------------------


class TestInstallApp:
    def test_install_success(self, market):
        installed = market.install_app(
            app_id="slack",
            org_id="org-1",
            config={"webhook_url": "https://hooks.slack.com/abc"},
            installed_by="alice",
        )
        assert installed.app_id == "slack"
        assert installed.org_id == "org-1"
        assert installed.status == AppStatus.ACTIVE
        assert installed.installed_by == "alice"

    def test_install_increments_install_count(self, market):
        before = market.get_app("pagerduty").install_count
        market.install_app(
            app_id="pagerduty",
            org_id="org-2",
            config={"routing_key": "abc123"},
            installed_by="bob",
        )
        after = market.get_app("pagerduty").install_count
        assert after == before + 1

    def test_install_nonexistent_app_raises(self, market):
        with pytest.raises(ValueError, match="not found"):
            market.install_app(
                app_id="ghost-app", org_id="org-1", config={}, installed_by="alice"
            )

    def test_install_duplicate_raises(self, market):
        market.install_app(
            app_id="github",
            org_id="org-dup",
            config={"access_token": "tok"},
            installed_by="alice",
        )
        with pytest.raises(ValueError, match="already installed"):
            market.install_app(
                app_id="github",
                org_id="org-dup",
                config={"access_token": "tok"},
                installed_by="alice",
            )

    def test_install_stores_config(self, market):
        cfg = {"webhook_url": "https://hooks.slack.com/xyz", "channel": "#alerts"}
        installed = market.install_app(
            app_id="slack",
            org_id="org-config",
            config=cfg,
            installed_by="svc-account",
        )
        assert installed.config == cfg


# ---------------------------------------------------------------------------
# Marketplace.uninstall_app
# ---------------------------------------------------------------------------


class TestUninstallApp:
    def test_uninstall_success(self, installed_market):
        result = installed_market.uninstall_app(app_id="slack", org_id="org-test")
        assert result is True

    def test_uninstall_noninstalled_returns_false(self, market):
        result = market.uninstall_app(app_id="trivy", org_id="org-nobody")
        assert result is False

    def test_uninstall_removes_from_list_installed(self, installed_market):
        installed_market.uninstall_app(app_id="slack", org_id="org-test")
        apps = installed_market.list_installed(org_id="org-test")
        assert not any(a.app_id == "slack" for a in apps)


# ---------------------------------------------------------------------------
# Marketplace.update_config
# ---------------------------------------------------------------------------


class TestUpdateConfig:
    def test_update_config_success(self, installed_market):
        new_cfg = {"webhook_url": "https://hooks.slack.com/new", "channel": "#security"}
        updated = installed_market.update_config(
            app_id="slack", org_id="org-test", config=new_cfg
        )
        assert updated.config == new_cfg

    def test_update_config_not_installed_raises(self, market):
        with pytest.raises(ValueError, match="not installed"):
            market.update_config(
                app_id="slack", org_id="org-ghost", config={"webhook_url": "x"}
            )


# ---------------------------------------------------------------------------
# Marketplace.list_installed
# ---------------------------------------------------------------------------


class TestListInstalled:
    def test_list_installed_returns_correct_org(self, market):
        market.install_app("slack", "org-a", {"webhook_url": "x"}, "alice")
        market.install_app("jira", "org-b", {"server_url": "x", "api_token": "t", "email": "e", "project_key": "p"}, "bob")
        apps_a = market.list_installed("org-a")
        assert len(apps_a) == 1
        assert apps_a[0].app_id == "slack"

    def test_list_installed_empty_for_new_org(self, market):
        apps = market.list_installed("brand-new-org")
        assert apps == []

    def test_list_installed_multiple_apps(self, market):
        market.install_app("slack", "org-multi", {"webhook_url": "x"}, "alice")
        market.install_app("github", "org-multi", {"access_token": "tok"}, "alice")
        apps = market.list_installed("org-multi")
        assert len(apps) == 2


# ---------------------------------------------------------------------------
# Marketplace.get_app_health
# ---------------------------------------------------------------------------


class TestGetAppHealth:
    def test_health_healthy_when_config_complete(self, market):
        market.install_app(
            "jira", "org-health",
            {
                "server_url": "https://myorg.atlassian.net",
                "api_token": "secret",
                "email": "user@example.com",
                "project_key": "SEC",
            },
            "alice",
        )
        health = market.get_app_health("jira", "org-health")
        assert health["status"] == HealthStatus.HEALTHY.value
        assert health["app_id"] == "jira"
        assert health["org_id"] == "org-health"

    def test_health_degraded_when_missing_required_fields(self, market):
        market.install_app(
            "jira", "org-degraded",
            {},  # missing all required fields
            "alice",
        )
        health = market.get_app_health("jira", "org-degraded")
        assert health["status"] == HealthStatus.DEGRADED.value
        assert len(health["missing_required_fields"]) > 0

    def test_health_not_installed_raises(self, market):
        with pytest.raises(ValueError, match="not installed"):
            market.get_app_health("slack", "org-nobody")

    def test_health_includes_checked_at(self, market):
        market.install_app("slack", "org-hc", {"webhook_url": "x"}, "svc")
        health = market.get_app_health("slack", "org-hc")
        assert "checked_at" in health


# ---------------------------------------------------------------------------
# Marketplace.rate_app
# ---------------------------------------------------------------------------


class TestRateApp:
    def test_rate_app_success(self, market):
        result = market.rate_app("trivy", "org-r", "user-1", 5.0, "Excellent!")
        assert result["score"] == 5.0
        assert result["app_id"] == "trivy"
        assert "new_average_rating" in result

    def test_rate_app_invalid_score_raises(self, market):
        with pytest.raises(ValueError, match="1.0 and 5.0"):
            market.rate_app("trivy", "org-r", "user-x", 6.0)

    def test_rate_app_score_too_low_raises(self, market):
        with pytest.raises(ValueError, match="1.0 and 5.0"):
            market.rate_app("trivy", "org-r", "user-x", 0.5)

    def test_rate_nonexistent_app_raises(self, market):
        with pytest.raises(ValueError, match="not found"):
            market.rate_app("ghost", "org-r", "user-x", 3.0)

    def test_rate_updates_existing_rating(self, market):
        market.rate_app("snyk", "org-r", "user-1", 4.0)
        result = market.rate_app("snyk", "org-r", "user-1", 2.0)
        assert result["total_ratings"] == 1  # same user, updated in place

    def test_rate_computes_average(self, market):
        market.rate_app("semgrep", "org-r", "user-1", 4.0)
        result = market.rate_app("semgrep", "org-r", "user-2", 2.0)
        assert result["new_average_rating"] == pytest.approx(3.0, abs=0.1)


# ---------------------------------------------------------------------------
# Marketplace.register_custom_app
# ---------------------------------------------------------------------------


class TestRegisterCustomApp:
    def test_register_success(self, market):
        app = MarketplaceApp(
            id="my-webhook",
            name="My Webhook",
            description="Internal webhook integration",
            category=IntegrationCategory.CUSTOM,
            version="1.0",
            author="ACME Corp",
            org_id="org-acme",
        )
        registered = market.register_custom_app(app)
        assert registered.id == "my-webhook"

    def test_register_duplicate_raises(self, market):
        app = MarketplaceApp(
            id="trivy",  # already in built-in catalog
            name="Trivy Copy",
            description="Duplicate",
            category=IntegrationCategory.SCANNER,
            version="1.0",
            author="x",
        )
        with pytest.raises(ValueError, match="already exists"):
            market.register_custom_app(app)

    def test_registered_app_visible_via_get(self, market):
        market.register_custom_app(
            MarketplaceApp(
                id="internal-scanner",
                name="Internal Scanner",
                description="Our own scanner",
                category=IntegrationCategory.SCANNER,
                version="0.1",
                author="DevTeam",
                org_id="org-dev",
            )
        )
        found = market.get_app("internal-scanner")
        assert found is not None
        assert found.name == "Internal Scanner"


# ---------------------------------------------------------------------------
# REST API endpoint tests
# ---------------------------------------------------------------------------


@pytest.fixture
def api_client(tmpdb):
    """FastAPI TestClient with auth headers and marketplace singleton patched."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import apps.api.auth_deps as auth_deps_mod

    app = FastAPI()
    mkt = Marketplace(db_path=tmpdb)

    with (
        patch("apps.api.integration_marketplace_router._marketplace", mkt),
        patch.object(auth_deps_mod, "_EXPECTED_TOKENS", ("test-token-marketplace",)),
        patch.object(auth_deps_mod, "_HAS_TOKEN_AUTH", True),
    ):
        from apps.api.integration_marketplace_router import router
        app.include_router(router)
        client = TestClient(app, raise_server_exceptions=True)
        yield client


AUTH = {"X-API-Key": "test-token-marketplace", "X-Org-Id": "org-api-test"}


class TestMarketplaceAPI:
    def test_list_categories(self, api_client):
        r = api_client.get("/api/v1/integrations/categories", headers=AUTH)
        assert r.status_code == 200
        cats = r.json()
        assert "scanner" in cats
        assert "ticketing" in cats
        assert "notification" in cats
        assert "cloud" in cats

    def test_list_apps_returns_catalog(self, api_client):
        r = api_client.get("/api/v1/integrations/apps", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) >= 20

    def test_list_apps_filter_by_category(self, api_client):
        r = api_client.get(
            "/api/v1/integrations/apps",
            params={"category": "scanner"},
            headers=AUTH,
        )
        assert r.status_code == 200
        data = r.json()
        assert all(a["category"] == "scanner" for a in data)

    def test_list_apps_search(self, api_client):
        r = api_client.get(
            "/api/v1/integrations/apps",
            params={"search": "slack"},
            headers=AUTH,
        )
        assert r.status_code == 200
        data = r.json()
        assert any(a["id"] == "slack" for a in data)

    def test_get_app_found(self, api_client):
        r = api_client.get("/api/v1/integrations/apps/github", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == "github"
        assert data["category"] == "ci_cd"

    def test_get_app_not_found(self, api_client):
        r = api_client.get("/api/v1/integrations/apps/nonexistent-app-xyz", headers=AUTH)
        assert r.status_code == 404

    def test_install_app_success(self, api_client):
        r = api_client.post(
            "/api/v1/integrations/apps/slack/install",
            json={"config": {"webhook_url": "https://hooks.slack.com/abc"}, "installed_by": "alice"},
            headers=AUTH,
        )
        assert r.status_code == 201
        data = r.json()
        assert data["app_id"] == "slack"
        assert data["status"] == "active"

    def test_install_app_not_found(self, api_client):
        r = api_client.post(
            "/api/v1/integrations/apps/ghost-app/install",
            json={"config": {}, "installed_by": "alice"},
            headers=AUTH,
        )
        assert r.status_code == 409

    def test_install_app_duplicate_returns_409(self, api_client):
        payload = {"config": {"webhook_url": "x"}, "installed_by": "alice"}
        api_client.post("/api/v1/integrations/apps/slack/install", json=payload, headers=AUTH)
        r = api_client.post("/api/v1/integrations/apps/slack/install", json=payload, headers=AUTH)
        assert r.status_code == 409

    def test_list_installed(self, api_client):
        # Install first
        api_client.post(
            "/api/v1/integrations/apps/trivy/install",
            json={"config": {}, "installed_by": "ci"},
            headers=AUTH,
        )
        r = api_client.get("/api/v1/integrations/installed", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert any(a["app_id"] == "trivy" for a in data)

    def test_update_config_success(self, api_client):
        api_client.post(
            "/api/v1/integrations/apps/pagerduty/install",
            json={"config": {"routing_key": "old-key"}, "installed_by": "alice"},
            headers=AUTH,
        )
        r = api_client.patch(
            "/api/v1/integrations/apps/pagerduty/config",
            json={"config": {"routing_key": "new-key"}},
            headers=AUTH,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["config"]["routing_key"] == "new-key"

    def test_update_config_not_installed(self, api_client):
        r = api_client.patch(
            "/api/v1/integrations/apps/elastic_siem/config",
            json={"config": {"elasticsearch_url": "x", "api_key": "k"}},
            headers=AUTH,
        )
        assert r.status_code == 404

    def test_uninstall_app_success(self, api_client):
        api_client.post(
            "/api/v1/integrations/apps/snyk/install",
            json={"config": {"api_token": "tok", "org_id": "snyk-org"}, "installed_by": "bob"},
            headers=AUTH,
        )
        r = api_client.delete("/api/v1/integrations/apps/snyk/install", headers=AUTH)
        assert r.status_code == 204

    def test_uninstall_app_not_installed(self, api_client):
        r = api_client.delete("/api/v1/integrations/apps/splunk/install", headers=AUTH)
        assert r.status_code == 404

    def test_get_health_healthy(self, api_client):
        api_client.post(
            "/api/v1/integrations/apps/slack/install",
            json={"config": {"webhook_url": "https://hooks.slack.com/test"}, "installed_by": "svc"},
            headers=AUTH,
        )
        r = api_client.get("/api/v1/integrations/apps/slack/health", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"

    def test_get_health_not_installed(self, api_client):
        r = api_client.get("/api/v1/integrations/apps/vanta/health", headers=AUTH)
        assert r.status_code == 404

    def test_rate_app(self, api_client):
        r = api_client.post(
            "/api/v1/integrations/apps/github/rate",
            json={"user_id": "user-42", "score": 5.0, "comment": "Excellent!"},
            headers=AUTH,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["score"] == 5.0
        assert "new_average_rating" in data

    def test_rate_app_invalid_score(self, api_client):
        r = api_client.post(
            "/api/v1/integrations/apps/github/rate",
            json={"user_id": "user-x", "score": 10.0},
            headers=AUTH,
        )
        assert r.status_code == 422  # Pydantic validation error

    def test_register_custom_app(self, api_client):
        r = api_client.post(
            "/api/v1/integrations/apps",
            json={
                "id": "my-custom-scanner",
                "name": "My Custom Scanner",
                "description": "Our internal DAST tool",
                "category": "scanner",
                "author": "ACME Corp",
            },
            headers=AUTH,
        )
        assert r.status_code == 201
        data = r.json()
        assert data["id"] == "my-custom-scanner"
        assert data["category"] == "scanner"

    def test_register_custom_app_duplicate(self, api_client):
        payload = {
            "id": "my-dup-app",
            "name": "Dup App",
            "description": "desc",
            "category": "custom",
            "author": "x",
        }
        api_client.post("/api/v1/integrations/apps", json=payload, headers=AUTH)
        r = api_client.post("/api/v1/integrations/apps", json=payload, headers=AUTH)
        assert r.status_code == 409
