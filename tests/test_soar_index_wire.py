"""Tests: soar_index GET / returns real playbook items, not hardcoded [].

Covers empty-endpoint #12 fix: soar_router.soar_index now serialises
SOAREngine.list_playbooks() into the response instead of always returning [].
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_app():
    """Build test app with auth dependency overridden to a no-op."""
    from apps.api.soar_router import router

    app = FastAPI()

    # Override any auth dependencies so tests don't need a real API key
    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: "test-key"
    except ImportError:
        pass

    app.include_router(router)
    return app


@pytest.fixture()
def client():
    app = _make_app()
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Test 1: when engine returns playbooks, items must be non-empty
# ---------------------------------------------------------------------------

def test_soar_index_returns_real_playbooks(client):
    """soar_index must forward engine.list_playbooks() into items."""
    from core.soar_engine import SOARPlaybook, PlaybookTrigger

    fake_pb = SOARPlaybook(
        id="pb-001",
        name="Test Playbook",
        trigger=PlaybookTrigger.FINDING_CRITICAL,
        conditions={},
        actions=[],
        org_id="default",
        enabled=True,
    )

    mock_engine = MagicMock()
    mock_engine.list_playbooks.return_value = [fake_pb]

    with patch("apps.api.soar_router._get_engine", return_value=mock_engine):
        resp = client.get("/api/v1/soar/")

    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["id"] == "pb-001"
    assert body["items"][0]["name"] == "Test Playbook"


# ---------------------------------------------------------------------------
# Test 2: when engine raises, index degrades gracefully (count=0, items=[])
# ---------------------------------------------------------------------------

def test_soar_index_degrades_on_engine_error(client):
    """soar_index must return empty items (not 500) when engine errors."""
    mock_engine = MagicMock()
    mock_engine.list_playbooks.side_effect = RuntimeError("db locked")

    with patch("apps.api.soar_router._get_engine", return_value=mock_engine):
        resp = client.get("/api/v1/soar/")

    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 0
    assert body["items"] == []
