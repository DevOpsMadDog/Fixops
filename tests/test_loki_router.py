"""
Router-level HTTP tests for Grafana Loki integration API.

Covers /api/v1/loki/* via FastAPI TestClient. The upstream Loki HTTP API
is replaced with a small in-process httpx MockTransport, so no real
Loki server is required.

NO MOCKS in product code — these stubs only replace the *external*
HTTP boundary; everything inside the engine + router runs for real.

Tests:
  1. GET /                     — capability summary (LOKI_URL set)
  2. GET /                     — capability summary (LOKI_URL unset → unavailable)
  3. GET /labels               — proxied label-name list
  4. GET /label/{name}/values  — proxied label-value list
  5. POST /push                — forwards stream payload, returns 204
  6. POST /query               — instant LogQL query
  7. POST /query_range         — range LogQL query
  8. GET /series               — series matching selectors
  9. Unavailable upstream → 503 (LOKI_URL unset)
 10. Validation errors (empty query, bad direction, missing match[])
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import core.loki_integration_engine as _engine_mod
from core.loki_integration_engine import LokiIntegrationEngine
import apps.api.loki_router as _router_mod
from apps.api.loki_router import router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    _engine_mod._engine_singleton = None
    yield
    _engine_mod._engine_singleton = None


def _build_mock_transport():
    """
    httpx.MockTransport that mimics a minimal Loki upstream:
      GET  /loki/api/v1/labels                   → {status:success, data:[...]}
      GET  /loki/api/v1/label/{name}/values      → {status:success, data:[...]}
      POST /loki/api/v1/push                     → 204
      GET  /loki/api/v1/query                    → {status:success, data:{resultType,result}}
      GET  /loki/api/v1/query_range              → {status:success, data:{resultType,result}}
      GET  /loki/api/v1/series                   → {status:success, data:[{...labels}]}
    """
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["last"] = {
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "body": request.content.decode("utf-8") if request.content else "",
        }
        path = request.url.path
        if path == "/loki/api/v1/labels" and request.method == "GET":
            return httpx.Response(200, json={"status": "success", "data": ["job", "level", "service"]})
        if path.startswith("/loki/api/v1/label/") and path.endswith("/values") and request.method == "GET":
            return httpx.Response(200, json={"status": "success", "data": ["aldeci-api", "aldeci-brain"]})
        if path == "/loki/api/v1/push" and request.method == "POST":
            return httpx.Response(204)
        if path == "/loki/api/v1/query" and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "streams",
                        "result": [
                            {"stream": {"job": "aldeci-api"}, "values": [["1714780800000000000", "log line"]]}
                        ],
                    },
                },
            )
        if path == "/loki/api/v1/query_range" and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "matrix",
                        "result": [
                            {"metric": {"job": "aldeci-api"}, "values": [[1714780800, "5"]]}
                        ],
                    },
                },
            )
        if path == "/loki/api/v1/series" and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": [{"job": "aldeci-api", "level": "error"}],
                },
            )
        return httpx.Response(404, json={"status": "error", "error": f"unmocked path: {path}"})

    transport = httpx.MockTransport(handler)
    return transport, captured


@pytest.fixture
def loki_env(monkeypatch):
    """Set LOKI_URL to a sentinel value so the engine treats upstream as configured."""
    monkeypatch.setenv("LOKI_URL", "http://test-loki:3100")
    monkeypatch.delenv("LOKI_TENANT_ID", raising=False)
    monkeypatch.delenv("LOKI_AUTH_TOKEN", raising=False)
    yield


@pytest.fixture
def patched_engine(loki_env, monkeypatch):
    """Engine with an httpx.Client whose transport is a MockTransport."""
    transport, captured = _build_mock_transport()

    eng = LokiIntegrationEngine()
    # Override _client_or_new so every call uses our MockTransport.
    monkeypatch.setattr(eng, "_client_or_new", lambda: httpx.Client(transport=transport, timeout=5.0))
    monkeypatch.setattr(_router_mod, "_get_engine", lambda: eng)
    return eng, captured


@pytest.fixture
def client(patched_engine):
    app = FastAPI()
    app.include_router(router)
    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def client_no_loki(monkeypatch):
    """Client where LOKI_URL is unset — engine returns unavailable / proxies 503."""
    monkeypatch.delenv("LOKI_URL", raising=False)
    eng = LokiIntegrationEngine()
    monkeypatch.setattr(_router_mod, "_get_engine", lambda: eng)

    app = FastAPI()
    app.include_router(router)
    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. Capability summary — LOKI_URL set
# ---------------------------------------------------------------------------


def test_capability_ok(client):
    resp = client.get("/api/v1/loki/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Grafana Loki"
    assert body["loki_url_present"] is True
    assert body["status"] == "ok"
    assert "/labels" in body["endpoints"]
    assert "/push" in body["endpoints"]
    assert "/query" in body["endpoints"]
    assert "/query_range" in body["endpoints"]
    assert "/series" in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — LOKI_URL unset
# ---------------------------------------------------------------------------


def test_capability_unavailable_when_env_unset(client_no_loki):
    resp = client_no_loki.get("/api/v1/loki/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["loki_url_present"] is False
    assert body["status"] == "unavailable"


# ---------------------------------------------------------------------------
# 3. GET /labels — proxied label-name list
# ---------------------------------------------------------------------------


def test_labels_proxied(client, patched_engine):
    _eng, captured = patched_engine
    resp = client.get("/api/v1/loki/labels")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["data"] == ["job", "level", "service"]
    assert captured["last"]["method"] == "GET"
    assert captured["last"]["url"].endswith("/loki/api/v1/labels")


# ---------------------------------------------------------------------------
# 4. GET /label/{name}/values — proxied label values
# ---------------------------------------------------------------------------


def test_label_values_proxied(client, patched_engine):
    _eng, captured = patched_engine
    resp = client.get("/api/v1/loki/label/job/values")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert "aldeci-api" in body["data"]
    assert captured["last"]["url"].endswith("/loki/api/v1/label/job/values")

    bad = client.get("/api/v1/loki/label/bad@name/values")
    assert bad.status_code == 400


# ---------------------------------------------------------------------------
# 5. POST /push — forwards payload, returns 204
# ---------------------------------------------------------------------------


def test_push_streams(client, patched_engine):
    _eng, captured = patched_engine
    payload = {
        "streams": [
            {
                "stream": {"job": "aldeci-api", "level": "info"},
                "values": [["1714780800000000000", "hello from loki test"]],
            }
        ]
    }
    resp = client.post("/api/v1/loki/push", json=payload)
    assert resp.status_code == 204
    last = captured["last"]
    assert last["method"] == "POST"
    assert last["url"].endswith("/loki/api/v1/push")
    sent = json.loads(last["body"])
    assert sent["streams"][0]["stream"]["job"] == "aldeci-api"
    assert sent["streams"][0]["values"][0][1] == "hello from loki test"

    # Empty streams → 400
    bad = client.post("/api/v1/loki/push", json={"streams": []})
    assert bad.status_code == 400


# ---------------------------------------------------------------------------
# 6. POST /query — instant LogQL query
# ---------------------------------------------------------------------------


def test_query_instant(client, patched_engine):
    _eng, captured = patched_engine
    payload = {"query": '{job="aldeci-api"}', "limit": 100, "direction": "backward"}
    resp = client.post("/api/v1/loki/query", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["data"]["resultType"] == "streams"
    assert body["data"]["result"][0]["stream"]["job"] == "aldeci-api"
    assert "/loki/api/v1/query" in captured["last"]["url"]
    # Query params propagated.
    assert "query=" in captured["last"]["url"]
    assert "limit=100" in captured["last"]["url"]
    assert "direction=backward" in captured["last"]["url"]


# ---------------------------------------------------------------------------
# 7. POST /query_range — range LogQL query
# ---------------------------------------------------------------------------


def test_query_range(client, patched_engine):
    _eng, captured = patched_engine
    payload = {
        "query": 'count_over_time({job="aldeci-api"}[5m])',
        "start": "1714780500000000000",
        "end": "1714780800000000000",
        "step": "60s",
        "limit": 1000,
    }
    resp = client.post("/api/v1/loki/query_range", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["data"]["resultType"] == "matrix"
    assert "step=60s" in captured["last"]["url"]
    assert "start=1714780500000000000" in captured["last"]["url"]
    assert "end=1714780800000000000" in captured["last"]["url"]


# ---------------------------------------------------------------------------
# 8. GET /series — selector list
# ---------------------------------------------------------------------------


def test_series_selectors(client, patched_engine):
    _eng, captured = patched_engine
    resp = client.get(
        "/api/v1/loki/series",
        params=[("match[]", '{job="aldeci-api"}'), ("start", "1714780500"), ("end", "1714780800")],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["data"]["result"][0]["job"] == "aldeci-api"
    assert "/loki/api/v1/series" in captured["last"]["url"]
    assert "match%5B%5D=" in captured["last"]["url"] or "match[]=" in captured["last"]["url"]

    # Missing match[] → 400
    bad = client.get("/api/v1/loki/series")
    assert bad.status_code == 400


# ---------------------------------------------------------------------------
# 9. Unavailable upstream → 503 across proxied endpoints
# ---------------------------------------------------------------------------


def test_proxied_endpoints_503_when_loki_url_unset(client_no_loki):
    # /labels
    r = client_no_loki.get("/api/v1/loki/labels")
    assert r.status_code == 503
    # /label/{name}/values
    r = client_no_loki.get("/api/v1/loki/label/job/values")
    assert r.status_code == 503
    # /push
    r = client_no_loki.post(
        "/api/v1/loki/push",
        json={"streams": [{"stream": {"job": "x"}, "values": [["1", "y"]]}]},
    )
    assert r.status_code == 503
    # /query
    r = client_no_loki.post("/api/v1/loki/query", json={"query": '{job="x"}'})
    assert r.status_code == 503
    # /query_range
    r = client_no_loki.post(
        "/api/v1/loki/query_range",
        json={"query": '{job="x"}', "start": "1", "end": "2"},
    )
    assert r.status_code == 503
    # /series
    r = client_no_loki.get("/api/v1/loki/series", params=[("match[]", '{job="x"}')])
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# 10. Input validation
# ---------------------------------------------------------------------------


def test_validation_errors(client):
    # Empty query
    r = client.post("/api/v1/loki/query", json={"query": "   "})
    assert r.status_code == 400
    # Bad direction
    r = client.post(
        "/api/v1/loki/query",
        json={"query": '{job="x"}', "direction": "sideways"},
    )
    assert r.status_code == 400
    # Range missing start/end → handled by Pydantic (422) since fields are required
    r = client.post("/api/v1/loki/query_range", json={"query": '{job="x"}'})
    assert r.status_code == 422
