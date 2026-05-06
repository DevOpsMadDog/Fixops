"""Tests for Multica #4032: openclaw GET / now returns real campaigns list.

Previously the endpoint fetched campaigns from the engine but hardcoded
`"items": []` in the response — discarding the data. This verifies the fix.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))


def _make_app():
    from apps.api.openclaw_router import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # Override auth so tests don't need a real API key
    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: "test-key"
    except Exception:
        pass

    return app


FAKE_CAMPAIGN = {
    "id": "c-001",
    "org_id": "test-org",
    "name": "Red Team Alpha",
    "status": "staged",
    "campaign_type": "full_kill_chain",
}


def test_openclaw_index_returns_campaigns():
    """GET /api/v1/openclaw/ must include real campaigns in items, not []."""
    from fastapi.testclient import TestClient

    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)

    mock_engine = MagicMock()
    mock_engine.list_campaigns.return_value = [FAKE_CAMPAIGN]

    with patch("apps.api.openclaw_router._get_engine", return_value=mock_engine):
        resp = client.get("/api/v1/openclaw/", params={"org_id": "test-org"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["name"] == "Red Team Alpha"


def test_openclaw_index_empty_on_engine_error():
    """GET /api/v1/openclaw/ must return empty items (not crash) when engine raises."""
    from fastapi.testclient import TestClient

    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.openclaw_router._get_engine", side_effect=RuntimeError("db gone")):
        resp = client.get("/api/v1/openclaw/", params={"org_id": "test-org"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["count"] == 0
