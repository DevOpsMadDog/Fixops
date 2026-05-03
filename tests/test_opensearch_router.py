"""Tests for opensearch_router — ALDECI.

Spins up a minimal FastAPI app with the OpenSearch AD router mounted. Each
test resets the engine singleton so state doesn't bleed between tests.

NO MOCKS rule:
  * When OPENSEARCH_URL is unset the capability summary reports
    ``status="unavailable"`` and every detector endpoint returns 503.
  * The happy-path tests inject a stub httpx.Client (not a fake response
    payload baked into the engine) so we still exercise the real
    networking + parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import httpx
import pytest

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for httpx.Response with .json() + .status_code."""

    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per (method, url-suffix)."""

    def __init__(self, responses: Dict[tuple, Any]):
        # keys: ("GET", "/path/suffix") or ("POST", "/path/suffix")
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        json: Optional[Any] = None,  # noqa: A002 - matches httpx signature
        params: Optional[Dict[str, Any]] = None,
        auth: Optional[Any] = None,
    ):
        self.calls.append({
            "method": method,
            "url": url,
            "json": json,
            "params": params or {},
            "auth": auth,
        })
        for (m, suffix), resp in self._responses.items():
            if method.upper() == m.upper() and url.endswith(suffix):
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


def _build_app(
    *,
    base_url: Optional[str],
    stub_responses: Dict[tuple, Any],
    username: Optional[str] = None,
    password: Optional[str] = None,
):
    from core import opensearch_detection_engine as engine_mod

    engine_mod.reset_opensearch_detection_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_opensearch_detection_engine(
        base_url=base_url,
        username=username,
        password=password,
        client=stub_client,
    )

    from apps.api.opensearch_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_url(monkeypatch):
    monkeypatch.delenv("OPENSEARCH_URL", raising=False)
    app, _ = _build_app(base_url=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/opensearch/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "OpenSearch Anomaly Detection"
    assert set(body["endpoints"]) == {
        "/detectors",
        "/detectors/{id}",
        "/detectors/{id}/_start",
        "/detectors/{id}/_stop",
        "/detectors/{id}/results",
    }
    assert body["opensearch_url_present"] is False
    assert body["status"] == "unavailable"

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_capability_summary_ok_when_url_present(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    app, _ = _build_app(
        base_url="https://opensearch.local:9200",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/opensearch/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["opensearch_url_present"] is True
    assert body["status"] == "ok"

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


# ---------------------------------------------------------------------------
# Live calls — unavailable path (no URL) returns 503
# ---------------------------------------------------------------------------


def test_list_detectors_returns_503_when_no_url(monkeypatch):
    monkeypatch.delenv("OPENSEARCH_URL", raising=False)
    app, _ = _build_app(base_url=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/opensearch/detectors", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "OPENSEARCH_URL" in r.json()["detail"]

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_get_detector_returns_503_when_no_url(monkeypatch):
    monkeypatch.delenv("OPENSEARCH_URL", raising=False)
    app, _ = _build_app(base_url=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/opensearch/detectors/abc123", headers=HEADERS
    )
    assert r.status_code == 503

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_start_detector_returns_503_when_no_url(monkeypatch):
    monkeypatch.delenv("OPENSEARCH_URL", raising=False)
    app, _ = _build_app(base_url=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/opensearch/detectors/abc123/_start", headers=HEADERS
    )
    assert r.status_code == 503

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_detectors_happy_path(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    raw = {
        "hits": {
            "total": {"value": 2},
            "hits": [
                {
                    "_id": "det-1",
                    "_source": {
                        "name": "cpu-anomaly",
                        "description": "CPU usage detector",
                        "time_field": "@timestamp",
                        "indices": ["metrics-*"],
                        "feature_attributes": [
                            {
                                "feature_name": "cpu_avg",
                                "feature_enabled": True,
                                "aggregation_query": {
                                    "cpu_avg": {"avg": {"field": "cpu"}}
                                },
                            }
                        ],
                        "detection_interval": {
                            "period": {"interval": 10, "unit": "Minutes"}
                        },
                        "window_delay": {
                            "period": {"interval": 1, "unit": "Minutes"}
                        },
                    },
                },
                {
                    "_id": "det-2",
                    "_source": {
                        "name": "mem-anomaly",
                        "indices": ["metrics-*"],
                    },
                },
            ],
        }
    }
    app, stub = _build_app(
        base_url="https://opensearch.local:9200",
        stub_responses={
            ("POST", "/_plugins/_anomaly_detection/detectors/_search"): _StubResponse(
                200, raw
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/opensearch/detectors", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalDetectors"] == 2
    assert len(body["detectors"]) == 2
    assert body["detectors"][0]["detector_id"] == "det-1"
    assert body["detectors"][0]["name"] == "cpu-anomaly"
    assert body["detectors"][0]["indices"] == ["metrics-*"]
    assert body["detectors"][0]["feature_attributes"][0]["feature_name"] == "cpu_avg"
    assert len(stub.calls) == 1
    assert stub.calls[0]["method"] == "POST"

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_create_detector_happy_path(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    raw = {
        "_id": "new-detector-id",
        "_version": 1,
        "anomaly_detector": {
            "name": "new-detector",
            "indices": ["logs-*"],
        },
    }
    app, stub = _build_app(
        base_url="https://opensearch.local:9200",
        stub_responses={
            ("POST", "/_plugins/_anomaly_detection/detectors"): _StubResponse(
                201, raw
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    payload = {
        "name": "new-detector",
        "description": "Test detector",
        "time_field": "@timestamp",
        "indices": ["logs-*"],
        "feature_attributes": [
            {
                "feature_name": "request_count",
                "feature_enabled": True,
                "aggregation_query": {
                    "request_count": {"value_count": {"field": "request_id"}}
                },
            }
        ],
        "detection_interval": {"period": {"interval": 10, "unit": "Minutes"}},
        "window_delay": {"period": {"interval": 1, "unit": "Minutes"}},
    }
    r = client.post(
        "/api/v1/opensearch/detectors", json=payload, headers=HEADERS
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["detector_id"] == "new-detector-id"
    assert body["version"] == 1
    assert body["result"]["name"] == "new-detector"

    # Confirm body was sent through to upstream untouched.
    posted = stub.calls[0]["json"]
    assert posted["name"] == "new-detector"
    assert posted["indices"] == ["logs-*"]

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_create_detector_rejects_missing_name(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    app, _ = _build_app(
        base_url="https://opensearch.local:9200",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    # Missing required "name" field — engine raises ValueError -> 422.
    r = client.post(
        "/api/v1/opensearch/detectors",
        json={"indices": ["logs-*"]},
        headers=HEADERS,
    )
    assert r.status_code == 422

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_get_detector_happy_path(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    raw = {
        "_id": "det-1",
        "anomaly_detector": {
            "name": "cpu-anomaly",
            "description": "CPU detector",
            "time_field": "@timestamp",
            "indices": ["metrics-*"],
            "feature_attributes": [],
            "detection_interval": {
                "period": {"interval": 10, "unit": "Minutes"}
            },
            "window_delay": {
                "period": {"interval": 1, "unit": "Minutes"}
            },
            "last_update_time": 1714857600000,
        },
    }
    app, _ = _build_app(
        base_url="https://opensearch.local:9200",
        stub_responses={
            ("GET", "/_plugins/_anomaly_detection/detectors/det-1"): _StubResponse(
                200, raw
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/opensearch/detectors/det-1", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detector_id"] == "det-1"
    assert body["name"] == "cpu-anomaly"
    assert body["last_update_time"] == 1714857600000

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_start_detector_happy_path(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    raw = {"_id": "det-1", "_version": 2}
    app, _ = _build_app(
        base_url="https://opensearch.local:9200",
        stub_responses={
            ("POST", "/_plugins/_anomaly_detection/detectors/det-1/_start"):
                _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/opensearch/detectors/det-1/_start", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detector_id"] == "det-1"
    assert body["started"] is True

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_stop_detector_happy_path(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    raw = {"_id": "det-1", "_version": 3}
    app, _ = _build_app(
        base_url="https://opensearch.local:9200",
        stub_responses={
            ("POST", "/_plugins/_anomaly_detection/detectors/det-1/_stop"):
                _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/opensearch/detectors/det-1/_stop", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detector_id"] == "det-1"
    assert body["stopped"] is True

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_get_results_happy_path_with_window(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    raw = {
        "hits": {
            "total": {"value": 1},
            "hits": [
                {
                    "_id": "result-1",
                    "_source": {
                        "detector_id": "det-1",
                        "data_start_time": 1714857600000,
                        "data_end_time": 1714858200000,
                        "anomaly_grade": 0.85,
                        "confidence": 0.92,
                        "feature_data": [
                            {"feature_name": "cpu_avg", "data": 92.5}
                        ],
                    },
                }
            ],
        }
    }
    app, stub = _build_app(
        base_url="https://opensearch.local:9200",
        stub_responses={
            ("POST", "/_plugins/_anomaly_detection/detectors/results/_search"):
                _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/opensearch/detectors/det-1/results",
        params={"startTime": 1714857600000, "endTime": 1714858200000},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detector_id"] == "det-1"
    assert body["totalResults"] == 1
    assert len(body["results"]) == 1
    assert body["results"][0]["anomaly_grade"] == 0.85
    assert body["results"][0]["confidence"] == 0.92

    # Confirm the range filter was passed through.
    posted = stub.calls[0]["json"]
    must = posted["query"]["bool"]["must"]
    range_clause = next((c for c in must if "range" in c), None)
    assert range_clause is not None
    assert range_clause["range"]["data_start_time"]["gte"] == 1714857600000
    assert range_clause["range"]["data_start_time"]["lte"] == 1714858200000

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()


def test_basic_auth_credentials_passed_through(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_URL", "https://opensearch.local:9200")
    monkeypatch.setenv("OPENSEARCH_USERNAME", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "secret")
    raw = {"hits": {"total": {"value": 0}, "hits": []}}
    app, stub = _build_app(
        base_url="https://opensearch.local:9200",
        username="admin",
        password="secret",
        stub_responses={
            ("POST", "/_plugins/_anomaly_detection/detectors/_search"):
                _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/opensearch/detectors", headers=HEADERS)
    assert r.status_code == 200
    assert stub.calls[0]["auth"] == ("admin", "secret")

    from core import opensearch_detection_engine as engine_mod
    engine_mod.reset_opensearch_detection_engine()
