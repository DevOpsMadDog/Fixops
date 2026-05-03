"""Tests for OSV poll_feed_status — GET /api/v1/osv/poll.

Covers:
1. poll returns correct structure for all ecosystems (no network)
2. needs_update=True when remote size differs from cached size
3. needs_update=False on second poll with same size
4. error field populated when HEAD request fails
5. invalid ecosystem name raises ValueError
6. GET /api/v1/osv/poll via FastAPI TestClient returns 200
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — same convention as test_osv_importer.py
# ---------------------------------------------------------------------------

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
_SUITE_API = os.path.join(os.path.dirname(__file__), "..", "suite-api")
_SUITE_CORE = os.path.join(os.path.dirname(__file__), "..", "suite-core")
for _p in (_SUITE_FEEDS, _SUITE_API, _SUITE_CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# In-memory store fixture (shared with test_osv_importer pattern)
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    def persist(self, key):  # noqa: D401
        pass


@pytest.fixture(autouse=True)
def _mock_store(monkeypatch):
    from feeds.osv import importer as imp
    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# ---------------------------------------------------------------------------
# Helper — build a fake httpx response for HEAD requests
# ---------------------------------------------------------------------------

def _make_head_response(content_length: int = 5_000_000, last_modified: str = "Mon, 01 Jan 2024 00:00:00 GMT"):
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {
        "content-length": str(content_length),
        "last-modified": last_modified,
    }
    resp.raise_for_status = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# Test 1: poll returns correct top-level structure for all ecosystems
# ---------------------------------------------------------------------------

def test_poll_returns_correct_structure(monkeypatch):
    from feeds.osv import importer as imp
    from feeds.osv.importer import SUPPORTED_ECOSYSTEMS, poll_feed_status

    fake_client = MagicMock()
    fake_client.__enter__ = lambda s: s
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_client.head.return_value = _make_head_response()

    with patch("feeds.osv.importer.httpx.Client", return_value=fake_client):
        result = poll_feed_status()

    assert "polled_at" in result
    assert result["ecosystems_checked"] == len(SUPPORTED_ECOSYSTEMS)
    assert "any_needs_update" in result
    assert "results" in result
    assert len(result["results"]) == len(SUPPORTED_ECOSYSTEMS)

    first = result["results"][0]
    assert "ecosystem" in first
    assert "remote_size" in first
    assert "remote_last_modified" in first
    assert "local_count" in first
    assert "needs_update" in first
    assert first["error"] is None


# ---------------------------------------------------------------------------
# Test 2: needs_update=True when remote size differs from cached
# ---------------------------------------------------------------------------

def test_needs_update_true_on_size_change(monkeypatch, _mock_store):
    from feeds.osv.importer import poll_feed_status

    # Seed cached size for PyPI
    _mock_store["__poll_size__PyPI"] = 1_000

    fake_client = MagicMock()
    fake_client.__enter__ = lambda s: s
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_client.head.return_value = _make_head_response(content_length=5_000_000)

    with patch("feeds.osv.importer.httpx.Client", return_value=fake_client):
        result = poll_feed_status(ecosystems=["PyPI"])

    pypi_row = result["results"][0]
    assert pypi_row["ecosystem"] == "PyPI"
    assert pypi_row["needs_update"] is True
    assert pypi_row["remote_size"] == 5_000_000
    assert result["any_needs_update"] is True


# ---------------------------------------------------------------------------
# Test 3: needs_update=False on second poll with same size
# ---------------------------------------------------------------------------

def test_needs_update_false_when_size_unchanged(monkeypatch, _mock_store):
    from feeds.osv.importer import poll_feed_status

    SIZE = 5_000_000
    # Pre-cache the same size
    _mock_store["__poll_size__PyPI"] = SIZE

    fake_client = MagicMock()
    fake_client.__enter__ = lambda s: s
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_client.head.return_value = _make_head_response(content_length=SIZE)

    with patch("feeds.osv.importer.httpx.Client", return_value=fake_client):
        result = poll_feed_status(ecosystems=["PyPI"])

    pypi_row = result["results"][0]
    assert pypi_row["needs_update"] is False
    assert result["any_needs_update"] is False


# ---------------------------------------------------------------------------
# Test 4: error field populated when HEAD request fails
# ---------------------------------------------------------------------------

def test_poll_captures_error_on_network_failure(monkeypatch):
    from feeds.osv.importer import poll_feed_status

    fake_client = MagicMock()
    fake_client.__enter__ = lambda s: s
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_client.head.side_effect = Exception("connection refused")

    with patch("feeds.osv.importer.httpx.Client", return_value=fake_client):
        result = poll_feed_status(ecosystems=["PyPI"])

    pypi_row = result["results"][0]
    assert pypi_row["error"] is not None
    assert "connection refused" in pypi_row["error"]
    assert pypi_row["needs_update"] is False


# ---------------------------------------------------------------------------
# Test 5: invalid ecosystem name raises ValueError
# ---------------------------------------------------------------------------

def test_poll_rejects_invalid_ecosystem():
    from feeds.osv.importer import poll_feed_status

    with pytest.raises(ValueError, match="Unsupported ecosystem"):
        poll_feed_status(ecosystems=["NotReal"])


# ---------------------------------------------------------------------------
# Test 6: GET /api/v1/osv/poll via FastAPI TestClient returns 200
# ---------------------------------------------------------------------------

def test_osv_poll_http_endpoint(monkeypatch):
    """FastAPI TestClient smoke-test — verifies route is registered and returns 200."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.osv_router import router
    from apps.api.auth_deps import api_key_auth

    SIZE = 9_999_999
    fake_client = MagicMock()
    fake_client.__enter__ = lambda s: s
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_client.head.return_value = _make_head_response(content_length=SIZE)

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None

    http_client = TestClient(app, raise_server_exceptions=True)

    with patch("feeds.osv.importer.httpx.Client", return_value=fake_client):
        resp = http_client.get("/api/v1/osv/poll?ecosystem=PyPI")

    assert resp.status_code == 200
    body: Dict[str, Any] = resp.json()
    assert "results" in body
    assert body["ecosystems_checked"] == 1
    assert body["results"][0]["ecosystem"] == "PyPI"
    assert body["results"][0]["remote_size"] == SIZE
