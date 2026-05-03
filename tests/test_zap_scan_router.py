"""Tests for ZAP DAST scan router (real engine, no mocks).

Uses a tmp_path SQLite to keep tests hermetic. The engine is constructed
through ``get_zap_scan_engine(db_path=...)`` which returns a fresh, non-
singleton instance per call when ``db_path`` is provided, then we monkey-
patch the singleton lookup so the router shares that instance.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def zap_app(tmp_path, monkeypatch):
    """Build a tiny FastAPI app mounting only the ZAP router with an isolated DB."""
    db_path = tmp_path / "zap_scans.db"

    # Import engine + router fresh, then point the singleton at our tmp DB.
    engine_module = importlib.import_module("core.zap_scan_engine")
    importlib.reload(engine_module)

    isolated_engine = engine_module.ZapScanEngine(db_path=str(db_path))

    def _get_engine(*_a, **_k):
        return isolated_engine

    monkeypatch.setattr(engine_module, "get_zap_scan_engine", _get_engine)

    router_module = importlib.import_module("apps.api.zap_scan_router")
    importlib.reload(router_module)
    monkeypatch.setattr(router_module, "get_zap_scan_engine", _get_engine)

    app = FastAPI()
    app.include_router(router_module.router)
    client = TestClient(app)
    return client, isolated_engine, db_path


def test_capability_summary_empty(zap_app):
    client, engine, _db = zap_app
    resp = client.get("/api/v1/zap/")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["engine"] == "zap_scan_engine"
    # No scans yet → status is "empty" if zap client available, else "degraded".
    assert body["status"] in ("empty", "degraded")
    assert "baseline" in body["profiles"]
    assert "active" in body["profiles"]
    assert "api" in body["profiles"]
    assert body["scan_count"] == 0
    assert body["supported_scan_types"] == body["profiles"]


def test_queue_scan_returns_queued_envelope(zap_app):
    client, _engine, _db = zap_app
    resp = client.post(
        "/api/v1/zap/scans",
        json={
            "target_url": "https://example.com",
            "profile": "baseline",
            "depth": 3,
            "contexts": ["public-web"],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["scan_id"].startswith("zap-")
    assert body["target"] == "https://example.com"
    assert body["profile"] == "baseline"
    assert body["status"] == "queued"
    assert body["started_at"]
    assert body["finding_summary"] == {}
    assert body["scan_metadata"]["depth"] == 3
    assert body["scan_metadata"]["contexts"] == ["public-web"]


def test_queue_scan_rejects_invalid_profile(zap_app):
    client, _engine, _db = zap_app
    resp = client.post(
        "/api/v1/zap/scans",
        json={"target_url": "https://example.com", "profile": "nonsense"},
    )
    # Pydantic v2 validation → 422
    assert resp.status_code in (400, 422), resp.text


def test_queue_scan_blocks_ssrf_localhost(zap_app):
    client, _engine, _db = zap_app
    resp = client.post(
        "/api/v1/zap/scans",
        json={"target_url": "http://127.0.0.1/admin", "profile": "active"},
    )
    assert resp.status_code in (400, 422), resp.text
    detail = resp.json().get("detail", "")
    # detail can be string or pydantic error list
    if isinstance(detail, str):
        assert "blocked" in detail.lower() or "private" in detail.lower()
    else:
        # FastAPI 422 — at least one entry mentions blocked/private
        joined = " ".join(str(e) for e in detail).lower()
        assert "blocked" in joined or "private" in joined


def test_queue_scan_rejects_non_http_scheme(zap_app):
    client, _engine, _db = zap_app
    resp = client.post(
        "/api/v1/zap/scans",
        json={"target_url": "file:///etc/passwd", "profile": "baseline"},
    )
    assert resp.status_code in (400, 422), resp.text


def test_get_scan_roundtrip_with_status_update(zap_app):
    client, engine, _db = zap_app
    create = client.post(
        "/api/v1/zap/scans",
        json={"target_url": "https://example.org", "profile": "active", "depth": 5},
    )
    assert create.status_code == 201, create.text
    scan_id = create.json()["scan_id"]

    # Engine-side update (mirrors what the worker would do)
    engine.update_status(
        scan_id,
        "completed",
        finding_summary={"high": 2, "medium": 5, "low": 12, "info": 3},
        scan_metadata={"duration_seconds": 47.3},
    )

    fetch = client.get(f"/api/v1/zap/scans/{scan_id}")
    assert fetch.status_code == 200, fetch.text
    body = fetch.json()
    assert body["scan_id"] == scan_id
    assert body["status"] == "completed"
    assert body["completed_at"]
    assert body["finding_summary"]["high"] == 2
    assert body["finding_summary"]["medium"] == 5
    assert body["finding_summary"]["low"] == 12
    assert body["finding_summary"]["info"] == 3
    assert body["scan_metadata"]["duration_seconds"] == 47.3


def test_get_scan_unknown_returns_404(zap_app):
    client, _engine, _db = zap_app
    resp = client.get("/api/v1/zap/scans/zap-does-not-exist")
    assert resp.status_code == 404


def test_capability_summary_after_scan_is_ok(zap_app):
    client, engine, _db = zap_app
    # Queue + complete one scan so scan_count > 0.
    create = client.post(
        "/api/v1/zap/scans",
        json={"target_url": "https://example.com", "profile": "api"},
    )
    assert create.status_code == 201
    engine.update_status(
        create.json()["scan_id"],
        "completed",
        finding_summary={"high": 0, "medium": 1, "low": 0},
    )

    resp = client.get("/api/v1/zap/")
    body = resp.json()
    assert body["scan_count"] == 1
    # Without a real ZAP client present, status will be "degraded";
    # if the zaproxy package is installed (rare in CI), it will be "ok".
    assert body["status"] in ("ok", "degraded")
