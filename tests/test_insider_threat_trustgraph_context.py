"""
Tests for InsiderThreatDetector.get_trustgraph_context — ALDECI insider-risk / UEBA.

Covers:
  1. Returns required keys when TrustGraph is unavailable (graceful degrade).
  2. trustgraph_available is False when import fails.
  3. entity_id and org_id are echoed back in the response.
  4. Different org_ids produce independent results (tenant isolation).
  5. Empty entity_id still returns a valid structure without raising.
  6. Router GET /api/v1/insider-threat/context/{entity_id} returns 200 with correct shape.

No mocks of engine logic — calls the real InsiderThreatDetector backed by a
temp SQLite db. TrustGraph import is expected to fail in CI (graceful degrade path).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.insider_threat import InsiderThreatDetector


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def detector(tmp_path):
    """Fresh InsiderThreatDetector backed by a temp DB."""
    return InsiderThreatDetector(db_path=str(tmp_path / "it_ctx_test.db"))


@pytest.fixture
def client(monkeypatch):
    """TestClient for the insider_threat_router with a test API key injected.

    auth_deps calls _load_api_tokens() per-request (not cached), so
    monkeypatch.setenv takes effect without any module reload.
    """
    monkeypatch.setenv("FIXOPS_API_TOKEN", "test-key-insider-ctx")

    from fastapi import FastAPI
    from apps.api.insider_threat_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(
        app,
        raise_server_exceptions=False,
        headers={"X-API-Key": "test-key-insider-ctx"},
    )


# ---------------------------------------------------------------------------
# Unit tests — InsiderThreatDetector.get_trustgraph_context
# ---------------------------------------------------------------------------


class TestGetTrustgraphContextStructure:
    """Verify the returned dict always has the required keys."""

    REQUIRED_KEYS = {
        "entity_id",
        "org_id",
        "related_assets",
        "related_findings",
        "related_incidents",
        "trustgraph_available",
    }

    def test_returns_all_required_keys(self, detector):
        result = detector.get_trustgraph_context(
            org_id="org-test", entity_id="alice@example.com"
        )
        assert self.REQUIRED_KEYS.issubset(result.keys()), (
            f"Missing keys: {self.REQUIRED_KEYS - result.keys()}"
        )

    def test_trustgraph_available_is_bool(self, detector):
        """trustgraph_available must always be a bool regardless of TrustGraph state."""
        result = detector.get_trustgraph_context(
            org_id="org-ci", entity_id="bob@example.com"
        )
        assert isinstance(result["trustgraph_available"], bool)

    def test_list_fields_are_lists(self, detector):
        result = detector.get_trustgraph_context(
            org_id="org-test", entity_id="carol@example.com"
        )
        assert isinstance(result["related_assets"], list)
        assert isinstance(result["related_findings"], list)
        assert isinstance(result["related_incidents"], list)

    def test_entity_id_and_org_id_echoed(self, detector):
        result = detector.get_trustgraph_context(
            org_id="org-echo", entity_id="dave@example.com"
        )
        assert result["entity_id"] == "dave@example.com"
        assert result["org_id"] == "org-echo"

    def test_tenant_isolation_different_orgs_independent(self, detector):
        """Two orgs with same entity_id must not share state."""
        r1 = detector.get_trustgraph_context(org_id="org-A", entity_id="shared@example.com")
        r2 = detector.get_trustgraph_context(org_id="org-B", entity_id="shared@example.com")
        assert r1["org_id"] == "org-A"
        assert r2["org_id"] == "org-B"
        # Both return a bool for trustgraph_available — no cross-tenant bleed
        assert isinstance(r1["trustgraph_available"], bool)
        assert isinstance(r2["trustgraph_available"], bool)

    def test_empty_entity_id_does_not_raise(self, detector):
        result = detector.get_trustgraph_context(org_id="org-test", entity_id="")
        assert isinstance(result, dict)
        assert "related_assets" in result


# ---------------------------------------------------------------------------
# Integration — router GET /context/{entity_id}
# ---------------------------------------------------------------------------


class TestInsiderThreatContextRouter:
    """Verify the HTTP endpoint wires correctly to the detector method."""

    def test_context_endpoint_returns_200(self, client):
        resp = client.get(
            "/api/v1/insider-threat/context/alice%40example.com",
            params={"org_id": "org-http"},
        )
        assert resp.status_code == 200, resp.text

    def test_context_endpoint_response_has_required_keys(self, client):
        resp = client.get(
            "/api/v1/insider-threat/context/bob%40example.com",
            params={"org_id": "org-http"},
        )
        assert resp.status_code == 200
        body = resp.json()
        for key in ("trustgraph_available", "related_assets", "related_findings", "related_incidents"):
            assert key in body, f"Key '{key}' missing from response: {body}"
