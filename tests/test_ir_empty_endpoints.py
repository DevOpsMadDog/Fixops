"""Tests for IR/response domain GET / root endpoints — incidents domain batch."""
from __future__ import annotations

import os
import sys
import pytest

sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-api")

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_app():
    from apps.api.auth_deps import api_key_auth
    from apps.api.incident_comms_router import router as comms_router
    from apps.api.incident_cost_router import router as cost_router
    from apps.api.incident_kb_router import router as kb_router
    from apps.api.incident_lessons_router import router as lessons_router

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: None  # bypass auth in tests
    app.include_router(comms_router)
    app.include_router(cost_router)
    app.include_router(kb_router)
    app.include_router(lessons_router)
    return app


@pytest.fixture(scope="module")
def client():
    app = _make_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# incident-comms GET /
# ---------------------------------------------------------------------------

class TestIncidentCommsRoot:
    def test_returns_200(self, client):
        r = client.get("/api/v1/incident-comms/")
        assert r.status_code == 200

    def test_envelope_keys(self, client):
        data = client.get("/api/v1/incident-comms/").json()
        for key in ("items", "total", "org_id", "service", "filters_applied"):
            assert key in data, f"Missing key: {key}"

    def test_service_field(self, client):
        data = client.get("/api/v1/incident-comms/").json()
        assert data["service"] == "incident-comms"

    def test_items_nonempty(self, client):
        data = client.get("/api/v1/incident-comms/").json()
        assert len(data["items"]) > 0

    def test_hint_when_empty(self, client):
        data = client.get("/api/v1/incident-comms/?org_id=brand-new-org").json()
        assert "hint" in data

    def test_channels_present(self, client):
        data = client.get("/api/v1/incident-comms/").json()
        keys = [i["key"] for i in data["items"]]
        assert "channels" in keys

    def test_no_mock_signatures(self, client):
        text = client.get("/api/v1/incident-comms/").text
        for sig in ("MOCK_", "lorem ipsum", "Acme Corp", "John Doe"):
            assert sig not in text


# ---------------------------------------------------------------------------
# incident-costs GET /
# ---------------------------------------------------------------------------

class TestIncidentCostRoot:
    def test_returns_200(self, client):
        r = client.get("/api/v1/incident-costs/")
        assert r.status_code == 200

    def test_envelope_keys(self, client):
        data = client.get("/api/v1/incident-costs/").json()
        for key in ("items", "total", "org_id", "service", "filters_applied"):
            assert key in data

    def test_service_field(self, client):
        data = client.get("/api/v1/incident-costs/").json()
        assert data["service"] == "incident-costs"

    def test_items_nonempty(self, client):
        data = client.get("/api/v1/incident-costs/").json()
        assert len(data["items"]) > 0

    def test_hint_when_empty(self, client):
        data = client.get("/api/v1/incident-costs/?org_id=fresh-org-cost").json()
        assert "hint" in data

    def test_analytics_key_present(self, client):
        data = client.get("/api/v1/incident-costs/").json()
        keys = [i["key"] for i in data["items"]]
        assert "analytics" in keys

    def test_no_mock_signatures(self, client):
        text = client.get("/api/v1/incident-costs/").text
        for sig in ("MOCK_", "lorem ipsum", "Acme Corp"):
            assert sig not in text


# ---------------------------------------------------------------------------
# incident-kb GET /
# ---------------------------------------------------------------------------

class TestIncidentKBRoot:
    def test_returns_200(self, client):
        r = client.get("/api/v1/incident-kb/")
        assert r.status_code == 200

    def test_envelope_keys(self, client):
        data = client.get("/api/v1/incident-kb/").json()
        for key in ("items", "total", "org_id", "service", "filters_applied"):
            assert key in data

    def test_service_field(self, client):
        data = client.get("/api/v1/incident-kb/").json()
        assert data["service"] == "incident-kb"

    def test_items_nonempty(self, client):
        data = client.get("/api/v1/incident-kb/").json()
        assert len(data["items"]) > 0

    def test_hint_when_empty(self, client):
        data = client.get("/api/v1/incident-kb/?org_id=fresh-org-kb").json()
        assert "hint" in data

    def test_article_types_present(self, client):
        data = client.get("/api/v1/incident-kb/").json()
        keys = [i["key"] for i in data["items"]]
        assert "article_types" in keys

    def test_incident_types_present(self, client):
        data = client.get("/api/v1/incident-kb/").json()
        keys = [i["key"] for i in data["items"]]
        assert "incident_types" in keys

    def test_no_mock_signatures(self, client):
        text = client.get("/api/v1/incident-kb/").text
        for sig in ("MOCK_", "lorem ipsum", "Acme Corp"):
            assert sig not in text


# ---------------------------------------------------------------------------
# incident-lessons GET /
# ---------------------------------------------------------------------------

class TestIncidentLessonsRoot:
    def test_returns_200(self, client):
        r = client.get("/api/v1/incident-lessons/")
        assert r.status_code == 200

    def test_envelope_keys(self, client):
        data = client.get("/api/v1/incident-lessons/").json()
        for key in ("items", "total", "org_id", "service", "filters_applied"):
            assert key in data

    def test_service_field(self, client):
        data = client.get("/api/v1/incident-lessons/").json()
        assert data["service"] == "incident-lessons"

    def test_items_nonempty(self, client):
        data = client.get("/api/v1/incident-lessons/").json()
        assert len(data["items"]) > 0

    def test_hint_when_empty(self, client):
        data = client.get("/api/v1/incident-lessons/?org_id=fresh-org-lessons").json()
        assert "hint" in data

    def test_implementation_rate_present(self, client):
        data = client.get("/api/v1/incident-lessons/").json()
        keys = [i["key"] for i in data["items"]]
        assert "implementation_rate" in keys

    def test_overdue_count_present(self, client):
        data = client.get("/api/v1/incident-lessons/").json()
        keys = [i["key"] for i in data["items"]]
        assert "overdue_actions_count" in keys

    def test_no_mock_signatures(self, client):
        text = client.get("/api/v1/incident-lessons/").text
        for sig in ("MOCK_", "lorem ipsum", "Acme Corp"):
            assert sig not in text
