"""Tests for empty-endpoint #22 — GET /api/v1/dca/ wired to DeepCodeAnalysisEngine."""
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient


def _make_app():
    from fastapi import FastAPI
    from apps.api.deep_code_analysis_router import router
    from apps.api.auth_deps import api_key_auth
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return app


@pytest.fixture()
def client():
    return TestClient(_make_app(), raise_server_exceptions=False)


def test_dca_index_calls_engine(client):
    """dca_index must call engine.stats() and engine.list_analyses(), not return hardcoded []."""
    mock_engine = MagicMock()
    mock_engine.stats.return_value = {"total_analyses": 3, "total_symbols": 42}
    mock_engine.list_analyses.return_value = [
        {"id": "a1", "repo_ref": "github.com/org/repo", "org_id": "test-org"},
        {"id": "a2", "repo_ref": "github.com/org/repo2", "org_id": "test-org"},
    ]
    with patch("apps.api.deep_code_analysis_router._get_engine", return_value=mock_engine):
        resp = client.get("/api/v1/dca/?org_id=test-org")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert len(body["items"]) == 2
    assert body["stats"]["total_analyses"] == 3
    mock_engine.list_analyses.assert_called_once_with(org_id="test-org")
    mock_engine.stats.assert_called_once_with(org_id="test-org")


def test_dca_index_engine_unavailable_graceful(client):
    """When engine is unavailable, index returns degraded response (not 500)."""
    with patch(
        "apps.api.deep_code_analysis_router._get_engine",
        side_effect=Exception("engine down"),
    ):
        resp = client.get("/api/v1/dca/?org_id=default")
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["count"] == 0
    assert body["stats"] == {}
