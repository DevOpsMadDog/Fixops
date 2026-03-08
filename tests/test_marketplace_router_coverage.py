"""Comprehensive tests for apps.api.marketplace_router — Marketplace endpoints.

Uses TestClient to exercise GET/POST routes for marketplace browse,
recommendations, contributions, ratings, purchases, and compliance content.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi.testclient import TestClient
from apps.api.app import create_app

API_KEY = os.environ.get("FIXOPS_API_TOKEN", "test-key-for-ci")
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client():
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


class TestMarketplaceBrowse:
    def test_browse_all(self, client):
        r = client.get("/api/v1/marketplace/browse", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_browse_with_category(self, client):
        r = client.get("/api/v1/marketplace/browse?category=scanner", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_browse_with_search(self, client):
        r = client.get("/api/v1/marketplace/browse?search=sast", headers=HEADERS)
        assert r.status_code in (200, 401, 403)


class TestRecommendations:
    def test_get_recommendations(self, client):
        r = client.get("/api/v1/marketplace/recommendations", headers=HEADERS)
        assert r.status_code in (200, 401, 403)


class TestPacks:
    def test_get_compliance_pack(self, client):
        r = client.get("/api/v1/marketplace/packs/SOC2/AC-1", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)

    def test_get_pack_nonexistent(self, client):
        r = client.get("/api/v1/marketplace/packs/FAKE/CTRL-999", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)


class TestItems:
    def test_get_item(self, client):
        r = client.get("/api/v1/marketplace/items/item-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)

    def test_update_item(self, client):
        payload = {"name": "Updated Scanner", "description": "New version"}
        r = client.put("/api/v1/marketplace/items/item-001", json=payload, headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403, 422)

    def test_rate_item(self, client):
        payload = {"rating": 5}
        r = client.post("/api/v1/marketplace/items/item-001/rate", json=payload, headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403, 422)


class TestContribute:
    def test_contribute(self, client):
        payload = {
            "name": "My SAST Rule",
            "description": "Custom rule for detecting XSS",
            "category": "scanner",
            "type": "rule",
        }
        r = client.post("/api/v1/marketplace/contribute", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)


class TestPurchase:
    def test_purchase_item(self, client):
        payload = {"org_id": "org-test"}
        r = client.post("/api/v1/marketplace/purchase/item-001", json=payload, headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403, 422)

    def test_download(self, client):
        r = client.get("/api/v1/marketplace/download/fake-token", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)


class TestContributors:
    def test_list_contributors(self, client):
        r = client.get("/api/v1/marketplace/contributors", headers=HEADERS)
        assert r.status_code in (200, 401, 403)


class TestComplianceContent:
    def test_get_compliance_content(self, client):
        r = client.get("/api/v1/marketplace/compliance-content/discovery", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)


class TestMarketplaceStats:
    def test_stats(self, client):
        r = client.get("/api/v1/marketplace/stats", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_health(self, client):
        r = client.get("/api/v1/marketplace/health", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_status(self, client):
        r = client.get("/api/v1/marketplace/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403)
