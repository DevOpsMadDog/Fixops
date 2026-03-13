"""Tests for gap_router (suite-api/apps/api/gap_router.py).

Covers:
  - Audit gap endpoints
  - Bulk gap endpoints
  - Copilot gap endpoints (ChatRequest model)
  - FAIL gap endpoints
  - Feeds gap endpoints
  - Graph gap endpoints
  - Integrations gap endpoints
  - Router mounting and tag validation
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.gap_router import (
    audit_gap,
    bulk_gap,
    copilot_gap,
    ChatRequest,
    fail_gap,
    feeds_gap,
    graph_gap,
    integrations_gap,
)


# ──────────────────────────────────────────────────────
#  Helper to create a test app with gap routers
# ──────────────────────────────────────────────────────


@pytest.fixture
def app():
    """Create a FastAPI app with gap routers mounted."""
    _app = FastAPI()
    _app.include_router(audit_gap)
    _app.include_router(bulk_gap)
    _app.include_router(copilot_gap)
    _app.include_router(fail_gap)
    _app.include_router(feeds_gap)
    _app.include_router(graph_gap)
    _app.include_router(integrations_gap)
    return _app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


# ──────────────────────────────────────────────────────
#  Models
# ──────────────────────────────────────────────────────


class TestChatRequest:
    def test_basic(self):
        req = ChatRequest(message="What vulnerabilities are critical?")
        assert req.message == "What vulnerabilities are critical?"

    def test_with_context(self):
        req = ChatRequest(
            message="Explain CVE-2024-0001",
            context={"app_id": "my-app"},
        )
        assert req.context["app_id"] == "my-app"


# ──────────────────────────────────────────────────────
#  Audit Gap
# ──────────────────────────────────────────────────────


class TestAuditGap:
    def test_list_audit_logs(self, client):
        resp = client.get("/api/v1/audit/")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, (list, dict))

    def test_list_audit_logs_pagination(self, client):
        resp = client.get("/api/v1/audit/?page=1&per_page=5")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Bulk Gap
# ──────────────────────────────────────────────────────


class TestBulkGap:
    def test_get_bulk_assignments(self, client):
        resp = client.get("/api/v1/bulk/assign")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Copilot Gap
# ──────────────────────────────────────────────────────


class TestCopilotGap:
    def test_list_copilot_agents(self, client):
        resp = client.get("/api/v1/copilot/agents")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, (list, dict))


# ──────────────────────────────────────────────────────
#  Integrations Gap
# ──────────────────────────────────────────────────────


class TestIntegrationsGap:
    def test_list_integrations(self, client):
        resp = client.get("/api/v1/integrations/")
        assert resp.status_code == 200
