"""Tests for GET /api/v1/integrations/catalog/stats and Marketplace.get_catalog_stats().

6 targeted tests — no mocks, real SQLite via tmp_path.
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-catalog-stats")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-that-is-at-least-32-chars-long")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.marketplace import IntegrationCategory, Marketplace, MarketplaceApp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def market(tmp_path):
    return Marketplace(db_path=str(tmp_path / "stats_test.db"))


@pytest.fixture
def api_client(tmp_path):
    from unittest.mock import patch
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.auth_deps import api_key_auth
    from apps.api.dependencies import get_org_id

    mkt = Marketplace(db_path=str(tmp_path / "stats_api_test.db"))
    app = FastAPI()

    with patch("apps.api.integration_marketplace_router._marketplace", mkt):
        from apps.api.integration_marketplace_router import router
        app.include_router(router)

    # Bypass auth and supply a fixed org_id
    app.dependency_overrides[api_key_auth] = lambda: None
    app.dependency_overrides[get_org_id] = lambda: "org-stats-test"

    yield TestClient(app, raise_server_exceptions=True), mkt


# ---------------------------------------------------------------------------
# Engine-level tests
# ---------------------------------------------------------------------------


class TestGetCatalogStatsEngine:
    def test_total_apps_matches_builtin_catalog(self, market):
        stats = market.get_catalog_stats()
        assert stats["total_apps"] >= 20

    def test_category_breakdown_covers_all_categories(self, market):
        stats = market.get_catalog_stats()
        breakdown = stats["category_breakdown"]
        for cat in ("scanner", "ticketing", "notification", "cloud", "ci_cd", "siem", "compliance", "custom"):
            assert cat in breakdown, f"Category '{cat}' missing from breakdown"
            assert breakdown[cat] >= 1

    def test_most_installed_app_is_github(self, market):
        stats = market.get_catalog_stats()
        assert stats["most_installed_app"] == "github"
        assert stats["most_installed_count"] == 7241

    def test_private_app_counted_for_owner_org_only(self, market):
        market.register_custom_app(
            MarketplaceApp(
                id="priv-scanner",
                name="Private Scanner",
                description="Internal tool",
                category=IntegrationCategory.CUSTOM,
                version="1.0",
                author="ACME",
                org_id="org-owner",
            )
        )
        stats_owner = market.get_catalog_stats(org_id="org-owner")
        stats_other = market.get_catalog_stats(org_id="org-other")
        assert stats_owner["total_apps"] == stats_other["total_apps"] + 1

    def test_average_rating_is_positive_and_bounded(self, market):
        stats = market.get_catalog_stats()
        avg = stats["average_rating"]
        assert 0.0 <= avg <= 5.0
        assert avg > 4.0  # builtin catalog is well-rated


# ---------------------------------------------------------------------------
# REST API test
# ---------------------------------------------------------------------------


class TestCatalogStatsEndpoint:
    def test_catalog_stats_endpoint_200_with_expected_keys(self, api_client):
        client, _ = api_client
        r = client.get("/api/v1/integrations/catalog/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total_apps" in data
        assert "category_breakdown" in data
        assert "total_installs_across_catalog" in data
        assert "average_rating" in data
        assert "most_installed_app" in data
        assert data["total_apps"] >= 20
        assert data["most_installed_app"] == "github"
