"""Tests for helicone_router — ALDECI.

Spins up a minimal FastAPI app with the Helicone router mounted. Each test
gets an isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * Endpoints return HTTP 503 when HELICONE_API_KEY is unset.
  * Capability summary reports ``status="unavailable"`` when creds missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real auth-header + parsing code paths.
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
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, url: str) -> _StubResponse:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
            }
        )
        return self._resolve(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "content": content,
            }
        )
        return self._resolve(url)

    def put(self, *args, **kwargs):  # not used today
        return self.post(*args, **kwargs)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    api_key: Optional[str],
    stub_responses: Dict[str, Any],
    base_url: Optional[str] = None,
):
    """Construct an isolated app+engine."""
    from core import helicone_engine as engine_mod

    engine_mod.reset_helicone_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_helicone_engine(
        api_key=api_key,
        base_url=base_url,
        client=stub_client,
    )

    from apps.api.helicone_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import helicone_engine as engine_mod

    engine_mod.reset_helicone_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in ("HELICONE_API_KEY", "HELICONE_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


_OK_KEY = "sk-helicone-test-key-value"


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_key():
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/helicone/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Helicone"
    assert body["endpoints"] == [
        "/v1/request/query",
        "/v1/property",
        "/v1/user/metrics",
        "/v1/cost-by-time",
        "/v1/dataset",
        "/v1/feedback",
    ]
    assert body["helicone_api_key_present"] is False
    assert body["helicone_base_url"] == "https://api.helicone.ai"
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_key_present():
    app, _ = _build_app(api_key=_OK_KEY, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/helicone/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["helicone_api_key_present"] is True
    assert body["helicone_base_url"] == "https://api.helicone.ai"
    assert body["status"] == "ok"


def test_capability_summary_respects_custom_base_url():
    app, _ = _build_app(
        api_key=_OK_KEY,
        stub_responses={},
        base_url="https://helicone.internal.example.com",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/helicone/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["helicone_base_url"] == "https://helicone.internal.example.com"
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when key missing
# ---------------------------------------------------------------------------


def test_request_query_503_when_key_missing():
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/helicone/v1/request/query",
        json={"filter": {}, "limit": 10, "offset": 0},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "HELICONE" in r.json()["detail"]


def test_property_values_503_when_key_missing():
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/helicone/v1/property",
        params={"propertyName": "feature", "offset": 0, "limit": 50},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_user_metrics_503_when_key_missing():
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/helicone/v1/user/metrics",
        params={"userId": "user-123"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_cost_by_time_503_when_key_missing():
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/helicone/v1/cost-by-time",
        json={
            "timeframe": {
                "start": "2026-05-01T00:00:00Z",
                "end": "2026-05-04T00:00:00Z",
            },
            "dbIncrement": "day",
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_dataset_list_503_when_key_missing():
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/helicone/v1/dataset", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_feedback_503_when_key_missing():
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/helicone/v1/feedback",
        json={"helicone-id": "req-001", "rating": True},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# Validation 422
# ---------------------------------------------------------------------------


def test_property_values_422_on_missing_property_name():
    app, _ = _build_app(api_key=_OK_KEY, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get("/api/v1/helicone/v1/property", headers=HEADERS)
    assert r.status_code == 422, r.text


def test_user_metrics_422_on_missing_user_id():
    app, _ = _build_app(api_key=_OK_KEY, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get("/api/v1/helicone/v1/user/metrics", headers=HEADERS)
    assert r.status_code == 422, r.text


def test_cost_by_time_422_on_missing_timeframe():
    app, _ = _build_app(api_key=_OK_KEY, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/helicone/v1/cost-by-time",
        json={"dbIncrement": "day"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_cost_by_time_422_on_bad_increment():
    app, _ = _build_app(api_key=_OK_KEY, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/helicone/v1/cost-by-time",
        json={
            "timeframe": {
                "start": "2026-05-01T00:00:00Z",
                "end": "2026-05-04T00:00:00Z",
            },
            "dbIncrement": "decade",
        },
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_feedback_422_on_missing_helicone_id():
    app, _ = _build_app(api_key=_OK_KEY, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/helicone/v1/feedback",
        json={"rating": True},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_feedback_422_on_non_bool_rating():
    app, _ = _build_app(api_key=_OK_KEY, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/helicone/v1/feedback",
        json={"helicone-id": "req-001", "rating": "yes"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_request_query_happy_path_passes_filter_and_pagination():
    raw = {
        "data": [
            {
                "request_id": "req-001",
                "request_created_at": "2026-05-04T01:23:45Z",
                "request_user_id": "user-123",
                "request_properties": {"feature": "checkout"},
                "request_path": "/v1/chat/completions",
                "request_body": {"messages": [{"role": "user", "content": "hi"}]},
                "response_id": "resp-001",
                "response_created_at": "2026-05-04T01:23:46Z",
                "response_body": {"choices": [{"message": {"content": "hello"}}]},
                "response_status": 200,
                "model": "claude-opus-4-7",
                "latency": 850,
                "total_tokens": 42,
                "prompt_tokens": 12,
                "completion_tokens": 30,
                "cost_usd": 0.000945,
                "cached": False,
                "scores": {"helpfulness": 4.5},
                "threat": False,
                "time_to_first_token": 230,
                "helicone_org_id": "org-1",
            }
        ],
        "error": None,
        "count": 1,
    }
    app, stub = _build_app(
        api_key=_OK_KEY,
        stub_responses={"/v1/request/query": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    body = {
        "filter": {
            "request": {
                "user_id": "user-123",
                "model": "claude-opus-4-7",
                "latency": {"gte": 100, "lte": 5000},
            }
        },
        "sort": {"created_at": "desc"},
        "limit": 10,
        "offset": 0,
        "isCached": False,
        "includeInputs": True,
    }
    r = client.post(
        "/api/v1/helicone/v1/request/query",
        json=body,
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["count"] == 1
    assert payload["error"] is None
    assert len(payload["data"]) == 1
    row = payload["data"][0]
    assert row["request_id"] == "req-001"
    assert row["model"] == "claude-opus-4-7"
    assert row["cost_usd"] == 0.000945
    assert row["request_properties"] == {"feature": "checkout"}

    # Ensure Bearer auth was set + body forwarded.
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "POST"
    assert call["headers"].get("Authorization") == f"Bearer {_OK_KEY}"
    assert call["headers"].get("Content-Type") == "application/json"
    assert call["content"] is not None
    forwarded = json.loads(call["content"].decode("utf-8"))
    assert forwarded["filter"]["request"]["user_id"] == "user-123"
    assert forwarded["limit"] == 10
    assert forwarded["sort"] == {"created_at": "desc"}


def test_property_values_happy_path():
    raw = {
        "data": [
            {"value": "checkout", "count": 132},
            {"value": "auth", "count": 87},
        ]
    }
    app, stub = _build_app(
        api_key=_OK_KEY,
        stub_responses={"/v1/property": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/helicone/v1/property",
        params={"propertyName": "feature", "offset": 0, "limit": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 2
    assert body["data"][0]["value"] == "checkout"

    # Verify GET params forwarded
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "GET"
    assert call["headers"].get("Authorization") == f"Bearer {_OK_KEY}"
    assert call["params"] == {
        "propertyName": "feature",
        "offset": 0,
        "limit": 50,
    }


def test_user_metrics_happy_path():
    raw = {
        "totalRequests": 245,
        "totalTokens": 18420,
        "totalCost": 0.4287,
        "averageLatency": 743.5,
        "lastUseTime": "2026-05-04T01:23:45Z",
    }
    app, stub = _build_app(
        api_key=_OK_KEY,
        stub_responses={"/v1/user/metrics": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/helicone/v1/user/metrics",
        params={
            "userId": "user-123",
            "startTime": "2026-05-01T00:00:00Z",
            "endTime": "2026-05-04T23:59:59Z",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalRequests"] == 245
    assert body["totalCost"] == 0.4287
    assert body["lastUseTime"] == "2026-05-04T01:23:45Z"

    assert len(stub.calls) == 1
    assert stub.calls[0]["params"]["userId"] == "user-123"
    assert stub.calls[0]["params"]["startTime"] == "2026-05-01T00:00:00Z"
    assert stub.calls[0]["params"]["endTime"] == "2026-05-04T23:59:59Z"


def test_cost_by_time_happy_path():
    raw = {
        "data": [
            {"time": "2026-05-01T00:00:00Z", "cost_usd": 1.23, "request_count": 412},
            {"time": "2026-05-02T00:00:00Z", "cost_usd": 0.87, "request_count": 305},
        ]
    }
    app, stub = _build_app(
        api_key=_OK_KEY,
        stub_responses={"/v1/cost-by-time": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    body = {
        "timeframe": {
            "start": "2026-05-01T00:00:00Z",
            "end": "2026-05-04T00:00:00Z",
        },
        "model": "claude-opus-4-7",
        "dbIncrement": "day",
    }
    r = client.post(
        "/api/v1/helicone/v1/cost-by-time",
        json=body,
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert len(payload["data"]) == 2
    assert payload["data"][0]["cost_usd"] == 1.23
    assert payload["data"][1]["request_count"] == 305

    forwarded = json.loads(stub.calls[0]["content"].decode("utf-8"))
    assert forwarded["dbIncrement"] == "day"
    assert forwarded["timeframe"]["start"] == "2026-05-01T00:00:00Z"


def test_dataset_list_happy_path():
    raw = {
        "data": [
            {"id": "ds-1", "name": "checkout-eval", "row_count": 412},
            {"id": "ds-2", "name": "auth-eval", "row_count": 91},
        ]
    }
    app, stub = _build_app(
        api_key=_OK_KEY,
        stub_responses={"/v1/dataset": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/helicone/v1/dataset", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 2
    assert body["data"][0]["name"] == "checkout-eval"
    assert stub.calls[0]["method"] == "GET"
    assert stub.calls[0]["headers"].get("Authorization") == f"Bearer {_OK_KEY}"


def test_feedback_happy_path():
    raw = {"ok": True, "helicone-id": "req-001"}
    app, stub = _build_app(
        api_key=_OK_KEY,
        stub_responses={"/v1/feedback": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/helicone/v1/feedback",
        json={
            "helicone-id": "req-001",
            "rating": True,
            "scores": {"helpfulness": 4.5, "accuracy": 5.0},
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["helicone-id"] == "req-001"

    forwarded = json.loads(stub.calls[0]["content"].decode("utf-8"))
    assert forwarded["helicone-id"] == "req-001"
    assert forwarded["rating"] is True
    assert forwarded["scores"]["helpfulness"] == 4.5


def test_feedback_normalises_snake_case_id():
    """Accept ``helicone_id`` from clients and forward as ``helicone-id``."""
    raw = {"ok": True}
    app, stub = _build_app(
        api_key=_OK_KEY,
        stub_responses={"/v1/feedback": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/helicone/v1/feedback",
        json={"helicone_id": "req-002", "rating": False},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text

    forwarded = json.loads(stub.calls[0]["content"].decode("utf-8"))
    assert forwarded["helicone-id"] == "req-002"
    assert "helicone_id" not in forwarded
    assert forwarded["rating"] is False


# ---------------------------------------------------------------------------
# Engine error mapping
# ---------------------------------------------------------------------------


def test_upstream_401_surfaces_503():
    app, _ = _build_app(
        api_key=_OK_KEY,
        stub_responses={
            "/v1/dataset": _StubResponse(401, {"error": "bad key"}, text="bad key")
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/helicone/v1/dataset", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "HTTP 401" in r.json()["detail"] or "rejected" in r.json()["detail"]


def test_upstream_429_surfaces_503():
    app, _ = _build_app(
        api_key=_OK_KEY,
        stub_responses={
            "/v1/dataset": _StubResponse(429, {"error": "rate limited"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/helicone/v1/dataset", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower()
