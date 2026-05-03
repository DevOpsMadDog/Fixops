"""Tests for traceable_router — ALDECI.

Mounts the Traceable router on a minimal FastAPI app, swaps the singleton
engine to use a stub ``httpx.Client``, and verifies:

  * Capability summary toggles ``status`` based on creds.
  * 503 when TRACEABLE_BASE_URL / TRACEABLE_API_TOKEN are unset.
  * Happy paths normalize Traceable payloads.
  * Bearer token is sent on the upstream request.
  * 422 when the policy-test body is malformed.
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
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,  # noqa: A002
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
                "json": json,
            }
        )
        return self._resolve(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_OK_BASE_URL = "https://api.traceable.ai"
_OK_TOKEN = "trc-test-token-abc"


def _build_app(
    *,
    creds_ok: bool,
    stub_responses: Dict[str, Any],
):
    from core import traceable_engine as engine_mod

    engine_mod.reset_traceable_engine()
    stub_client = _StubClient(stub_responses)
    if creds_ok:
        engine_mod.get_traceable_engine(
            base_url=_OK_BASE_URL,
            api_token=_OK_TOKEN,
            client=stub_client,
        )
    else:
        engine_mod.get_traceable_engine(client=stub_client)

    from apps.api.traceable_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import traceable_engine as engine_mod

    engine_mod.reset_traceable_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    for var in ("TRACEABLE_BASE_URL", "TRACEABLE_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds():
    app, _ = _build_app(creds_ok=False, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/traceable/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Traceable AI"
    assert body["endpoints"] == [
        "/api/v1/services",
        "/api/v1/apis",
        "/api/v1/anomalies",
        "/api/v1/threats",
        "/api/v1/users-and-attribution",
    ]
    assert body["traceable_base_url_present"] is False
    assert body["traceable_api_token_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds_ok=True, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/traceable/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["traceable_base_url_present"] is True
    assert body["traceable_api_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths
# ---------------------------------------------------------------------------


def test_services_503_when_creds_missing():
    app, _ = _build_app(creds_ok=False, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/traceable/api/v1/services", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "TRACEABLE" in r.json()["detail"]


def test_anomalies_503_when_creds_missing():
    app, _ = _build_app(creds_ok=False, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/traceable/api/v1/anomalies",
        params={"severity": "high"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_policy_test_503_when_creds_missing():
    app, _ = _build_app(creds_ok=False, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/traceable/api/v1/policies/test",
        json={
            "policyId": "pol-123",
            "sampleRequest": {
                "method": "POST",
                "path": "/api/v1/login",
                "headers": {"User-Agent": "x"},
                "body": {"u": "a"},
                "queryParams": {},
            },
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_anomalies_422_on_bad_severity():
    app, _ = _build_app(creds_ok=True, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get(
        "/api/v1/traceable/api/v1/anomalies",
        params={"severity": "weird"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_policy_test_422_on_missing_policy_id():
    app, _ = _build_app(creds_ok=True, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/traceable/api/v1/policies/test",
        json={
            "sampleRequest": {
                "method": "GET",
                "path": "/",
                "headers": {},
                "queryParams": {},
            }
        },
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_services_happy_path_normalizes_and_sets_bearer():
    raw = {
        "services": [
            {
                "id": "svc-1",
                "name": "checkout",
                "environment": "prod",
                "type": "HTTP",
                "technologyStack": {"language": "Python", "framework": "FastAPI"},
                "totalRequests": 12345,
                "totalErrors": 12,
                "errorRate": 0.001,
                "avgLatencyMs": 47,
                "p50": 30,
                "p95": 120,
                "p99": 250,
                "riskScore": 72,
                "sensitiveDataDetected": True,
                "dataTypes": ["PCI", "PII"],
                "firstSeen": "2026-01-01T00:00:00Z",
                "lastSeen": "2026-05-04T10:00:00Z",
            }
        ],
        "pagination": {"nextPageToken": "tok-2"},
    }
    app, stub = _build_app(
        creds_ok=True,
        stub_responses={"/api/v1/services": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/traceable/api/v1/services",
        params={"startTime": "2026-05-01T00:00:00Z", "pageSize": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["services"]) == 1
    svc = body["services"][0]
    assert svc["id"] == "svc-1"
    assert svc["technologyStack"]["framework"] == "FastAPI"
    assert svc["dataTypes"] == ["PCI", "PII"]
    assert svc["sensitiveDataDetected"] is True
    assert body["pagination"]["nextPageToken"] == "tok-2"

    assert len(stub.calls) == 1
    auth = stub.calls[0]["headers"].get("Authorization", "")
    assert auth == f"Bearer {_OK_TOKEN}"
    assert stub.calls[0]["params"].get("startTime") == "2026-05-01T00:00:00Z"
    assert stub.calls[0]["params"].get("pageSize") == 50


def test_apis_happy_path_normalizes():
    raw = {
        "apis": [
            {
                "id": "api-1",
                "name": "POST /login",
                "path": "/api/v1/login",
                "method": "POST",
                "serviceId": "svc-1",
                "serviceName": "checkout",
                "host": "checkout.example.com",
                "port": 443,
                "protocol": "https",
                "totalRequests": 9999,
                "totalErrors": 12,
                "anomalyCount": 1,
                "threatCount": 0,
                "sensitiveDataAccessed": [
                    {"type": "PII", "count": 5},
                    {"type": "PCI", "count": 1},
                ],
                "firstSeen": "2026-01-01T00:00:00Z",
                "lastSeen": "2026-05-04T10:00:00Z",
                "riskScore": 65,
                "status": "active",
                "owner": {
                    "name": "API Team",
                    "email": "api@example.com",
                    "team": "platform",
                },
                "classification": "external",
                "schema": {
                    "requestParams": [{"name": "username", "type": "string"}],
                    "responseParams": [{"name": "token", "type": "string"}],
                },
            }
        ],
        "pagination": {"nextPageToken": ""},
    }
    app, _ = _build_app(
        creds_ok=True,
        stub_responses={"/api/v1/apis": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/traceable/api/v1/apis",
        params={"sensitiveDataOnly": "true", "riskScoreGte": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["apis"]) == 1
    api_obj = body["apis"][0]
    assert api_obj["method"] == "POST"
    assert api_obj["sensitiveDataAccessed"][0]["type"] == "PII"
    assert api_obj["owner"]["team"] == "platform"
    assert api_obj["classification"] == "external"
    assert api_obj["schema"]["requestParams"][0]["name"] == "username"


def test_api_detail_happy_path():
    raw = {
        "api": {
            "id": "api-1",
            "name": "GET /users",
            "path": "/api/v1/users",
            "method": "GET",
            "serviceId": "svc-1",
            "serviceName": "core",
            "host": "core.example.com",
            "port": 443,
            "protocol": "https",
            "totalRequests": 200,
            "totalErrors": 0,
            "anomalyCount": 0,
            "threatCount": 0,
            "riskScore": 10,
            "status": "active",
            "owner": {"name": "Core", "email": "core@example.com", "team": "core"},
            "classification": "internal",
        }
    }
    app, _ = _build_app(
        creds_ok=True,
        stub_responses={"/api/v1/apis/api-1": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/traceable/api/v1/apis/api-1", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api"]["id"] == "api-1"
    assert body["api"]["method"] == "GET"
    assert body["api"]["classification"] == "internal"


def test_anomalies_happy_path_normalizes():
    raw = {
        "anomalies": [
            {
                "id": "anom-1",
                "type": "LATENCY_SPIKE",
                "severity": "high",
                "title": "p99 latency 5x baseline",
                "description": "checkout API latency surged",
                "serviceId": "svc-1",
                "apiId": "api-1",
                "startTime": "2026-05-04T08:00:00Z",
                "endTime": "2026-05-04T08:15:00Z",
                "evidence": {"baseline_ms": 50, "observed_ms": 250},
                "riskScore": 70,
            }
        ],
        "pagination": {"nextPageToken": ""},
    }
    app, _ = _build_app(
        creds_ok=True,
        stub_responses={"/api/v1/anomalies": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/traceable/api/v1/anomalies",
        params={"severity": "high", "serviceId": "svc-1"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["anomalies"]) == 1
    anom = body["anomalies"][0]
    assert anom["type"] == "LATENCY_SPIKE"
    assert anom["severity"] == "high"
    assert anom["evidence"]["observed_ms"] == 250


def test_threats_happy_path_normalizes():
    raw = {
        "threats": [
            {
                "id": "thr-1",
                "name": "SQLi attempt",
                "type": "injection",
                "severity": "critical",
                "status": "active",
                "attackerIp": "1.2.3.4",
                "attackerUserAgent": "sqlmap/1.0",
                "attackerCountry": "RU",
                "targetApi": {"id": "api-1", "name": "POST /login"},
                "evidence": [
                    {
                        "requestId": "req-1",
                        "payload": "' OR 1=1 --",
                        "response": "500 Internal Server Error",
                        "timestamp": "2026-05-04T08:00:00Z",
                    }
                ],
                "firstSeen": "2026-05-04T07:55:00Z",
                "lastSeen": "2026-05-04T08:00:00Z",
                "mitigationApplied": False,
                "mitigationDetails": "",
                "attackVector": "request body",
                "owaspCategory": "API8:2023",
                "cwe": "CWE-89",
            }
        ],
        "pagination": {"nextPageToken": ""},
    }
    app, _ = _build_app(
        creds_ok=True,
        stub_responses={"/api/v1/threats": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/traceable/api/v1/threats",
        params={"type": "injection", "severity": "critical"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["threats"]) == 1
    thr = body["threats"][0]
    assert thr["type"] == "injection"
    assert thr["targetApi"]["id"] == "api-1"
    assert thr["evidence"][0]["payload"] == "' OR 1=1 --"
    assert thr["owaspCategory"] == "API8:2023"


def test_users_and_attribution_happy_path():
    raw = {
        "users": [
            {
                "userId": "user-42",
                "userType": "HUMAN",
                "totalRequests": 150,
                "uniqueIps": 3,
                "geoCountries": ["US", "CA"],
                "topApis": [
                    {"apiId": "api-1", "count": 90},
                    {"apiId": "api-2", "count": 60},
                ],
                "totalAnomalies": 2,
                "totalThreats": 0,
                "riskScore": 35,
                "firstSeen": "2026-04-01T00:00:00Z",
                "lastSeen": "2026-05-04T10:00:00Z",
            }
        ],
        "pagination": {"nextPageToken": ""},
    }
    app, _ = _build_app(
        creds_ok=True,
        stub_responses={"/api/v1/users-and-attribution": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/traceable/api/v1/users-and-attribution",
        params={"searchUserId": "user-42"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["users"]) == 1
    u = body["users"][0]
    assert u["userId"] == "user-42"
    assert u["userType"] == "HUMAN"
    assert u["topApis"][0]["apiId"] == "api-1"
    assert u["geoCountries"] == ["US", "CA"]


def test_policy_test_happy_path():
    raw = {
        "evaluationResult": "deny",
        "ruleResults": [
            {"ruleId": "r-1", "matched": True, "action": "deny"},
            {"ruleId": "r-2", "matched": False, "action": "allow"},
        ],
    }
    app, stub = _build_app(
        creds_ok=True,
        stub_responses={"/api/v1/policies/test": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/traceable/api/v1/policies/test",
        json={
            "policyId": "pol-123",
            "sampleRequest": {
                "method": "POST",
                "path": "/api/v1/login",
                "headers": {"User-Agent": "x"},
                "body": {"u": "a"},
                "queryParams": {},
            },
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["evaluationResult"] == "deny"
    assert len(body["ruleResults"]) == 2

    # Verify upstream POST signed with bearer.
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "POST"
    assert call["headers"].get("Authorization") == f"Bearer {_OK_TOKEN}"
    assert call["headers"].get("Content-Type") == "application/json"
    assert call["json"]["policyId"] == "pol-123"
