"""Tests for fastly_router — ALDECI.

NO MOCKS rule:
  * Endpoints return HTTP 503 when FASTLY_API_TOKEN is unset.
  * Capability summary reports ``status="unavailable"`` when token is missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we exercise the real httpx call -> normalize -> Pydantic path.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL substring."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> Any:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(self, url, headers=None, params=None):  # noqa: D401
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "params": params or {},
            }
        )
        return self._match(url)

    def post(self, url, headers=None, params=None, data=None):  # noqa: D401
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "data": data or {},
            }
        )
        return self._match(url)

    def request(self, method, url, headers=None, params=None):
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "headers": headers or {},
                "params": params or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(*, api_token: Optional[str], stub_responses: Dict[str, Any]):
    from core import fastly_edge_engine as engine_mod

    engine_mod.reset_fastly_edge_engine()
    stub_client = _StubClient(stub_responses)
    engine_mod.get_fastly_edge_engine(api_token=api_token, client=stub_client)

    from apps.api.fastly_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import fastly_edge_engine as engine_mod

    engine_mod.reset_fastly_edge_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_token(monkeypatch):
    monkeypatch.delenv("FASTLY_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/fastly/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Fastly"
    assert "/service" in body["endpoints"]
    assert "/purge" in body["endpoints"]
    assert body["fastly_api_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    app, _ = _build_app(api_token="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/fastly/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["fastly_api_token_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no token
# ---------------------------------------------------------------------------


def test_list_services_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("FASTLY_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/fastly/service", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "FASTLY_API_TOKEN" in r.json()["detail"]
    _reset()


def test_purge_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("FASTLY_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post("/api/v1/fastly/purge/example.com/foo", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_stats_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("FASTLY_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/fastly/stats",
        params={
            "from": "2026-05-01T00:00:00Z",
            "to": "2026-05-04T00:00:00Z",
            "by": "hour",
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_services_happy_path(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    raw = [
        {
            "id": "SU1Z0isxPaozGVKXdv0eY",
            "name": "marketing-site",
            "comment": "edge for marketing",
            "customer_id": "x4xCwxxJxGCSAEDtxxxxx",
            "type": "vcl",
            "deleted_at": None,
            "created_at": "2026-04-01T12:00:00Z",
            "updated_at": "2026-05-01T12:00:00Z",
            "publish_key": "abcdef",
            "versions": [
                {
                    "number": 7,
                    "active": True,
                    "locked": True,
                    "staging": False,
                    "deployed": True,
                    "comment": "v7",
                }
            ],
        }
    ]
    app, stub = _build_app(
        api_token="test-token",
        stub_responses={"/service": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/fastly/service",
        params={"page": 1, "per_page": 20, "direction": "ascend", "sort": "created"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["id"] == "SU1Z0isxPaozGVKXdv0eY"
    assert body[0]["type"] == "vcl"
    assert body[0]["versions"][0]["number"] == 7
    assert body[0]["versions"][0]["active"] is True

    # Verify the upstream call carried the Fastly-Key header.
    get_calls = [c for c in stub.calls if c["method"] == "GET"]
    assert len(get_calls) >= 1
    assert get_calls[0]["headers"].get("Fastly-Key") == "test-token"
    _reset()


def test_get_service_happy_path(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    raw = {
        "id": "SVCID1",
        "name": "api-edge",
        "comment": "API gateway in front of origin",
        "customer_id": "CUSTID1",
        "type": "wasm",
        "created_at": "2026-04-15T08:00:00Z",
        "updated_at": "2026-05-03T08:00:00Z",
        "publish_key": "key1",
        "versions": [],
    }
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={"/service/SVCID1": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/fastly/service/SVCID1", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "SVCID1"
    assert body["type"] == "wasm"
    assert body["customer_id"] == "CUSTID1"
    _reset()


def test_list_versions_happy_path(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    raw = [
        {
            "number": 1,
            "active": False,
            "locked": True,
            "staging": False,
            "deployed": False,
            "comment": "initial",
            "created_at": "2026-04-01T00:00:00Z",
        },
        {
            "number": 2,
            "active": True,
            "locked": True,
            "staging": False,
            "deployed": True,
            "comment": "rollout",
            "deployed_at": "2026-04-15T00:00:00Z",
        },
    ]
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={"/service/SVCID1/version": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/fastly/service/SVCID1/version", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list)
    assert len(body) == 2
    assert body[1]["active"] is True
    assert body[1]["deployed_at"] == "2026-04-15T00:00:00Z"
    _reset()


def test_purge_key_or_url_with_soft_header(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    raw = {"status": "ok", "id": "abc123"}
    app, stub = _build_app(
        api_token="test-token",
        stub_responses={"/purge/": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/fastly/purge/example.com/foo",
        headers={**HEADERS, "fastly-soft-purge": "1"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["id"] == "abc123"

    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert len(posts) == 1
    assert posts[0]["headers"].get("Fastly-Soft-Purge") == "1"
    _reset()


def test_purge_all_happy_path(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    raw = {"status": "ok"}
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={"/service/SVCID1/purge_all": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/fastly/service/SVCID1/purge_all", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ok"
    _reset()


def test_stats_happy_path(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    raw = {
        "data": [
            {
                "service_id": "SVCID1",
                "hits": 1234,
                "miss": 56,
                "status_2xx": 1200,
                "status_4xx": 30,
                "status_5xx": 4,
                "bandwidth": 9876543,
                "requests": 1290,
                "status_200": 1180,
                "status_204": 20,
                "status_301": 0,
                "status_404": 25,
                "status_503": 4,
                "ipv6_bandwidth": 1234567,
            }
        ]
    }
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={"/stats": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/fastly/stats",
        params={
            "from": "2026-05-01T00:00:00Z",
            "to": "2026-05-04T00:00:00Z",
            "by": "hour",
            "region": "usa",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "data" in body and "meta" in body
    assert len(body["data"]) == 1
    assert body["data"][0]["service_id"] == "SVCID1"
    assert body["data"][0]["hits"] == 1234
    assert body["data"][0]["status_503"] == 4
    assert body["meta"]["from"] == "2026-05-01T00:00:00Z"
    assert body["meta"]["by"] == "hour"
    assert body["meta"]["region"] == "usa"
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths + input validation
# ---------------------------------------------------------------------------


def test_list_services_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={
            "/service": _StubResponse(
                429, {"errors": [{"detail": "Too Many Requests"}]}, text="rate"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/fastly/service", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"].lower()
    assert "rate-limit" in detail or "429" in detail
    _reset()


def test_get_service_returns_503_on_upstream_404(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={
            "/service/MISSING": _StubResponse(404, {"msg": "not found"}, text="nf")
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/fastly/service/MISSING", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_stats_validation_rejects_bad_by(monkeypatch):
    monkeypatch.setenv("FASTLY_API_TOKEN", "test-token")
    app, _ = _build_app(api_token="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/fastly/stats",
        params={
            "from": "2026-05-01T00:00:00Z",
            "to": "2026-05-04T00:00:00Z",
            "by": "second",  # invalid
        },
        headers=HEADERS,
    )
    # Pydantic / FastAPI Query pattern enforces 422 before the engine runs.
    assert r.status_code == 422, r.text
    _reset()
