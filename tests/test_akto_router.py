"""Tests for akto_router — ALDECI.

Mounts a minimal FastAPI app with the Akto router. Each test gets an
isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * GET /, GET /api/discovered-apis, /api/sensitive-data, /api/test-results,
    /api/runtime-issues, /api/test-runs, /api/collections, POST /api/start-test
    return HTTP 503 when AKTO_* env is unset.
  * Capability summary reports ``status="unavailable"`` when creds missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the X-API-KEY signing + JSON parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

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

    def get(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {})}
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

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_OK_CREDS = {
    "base_url": "https://flash.akto.io",
    "api_token": "akto-test-api-token-value",
}


def _build_app(
    *,
    creds: Optional[Dict[str, str]],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine."""
    from core import akto_engine as engine_mod

    engine_mod.reset_akto_engine()

    stub_client = _StubClient(stub_responses)
    if creds is None:
        engine_mod.get_akto_engine(client=stub_client)
    else:
        engine_mod.get_akto_engine(
            base_url=creds.get("base_url"),
            api_token=creds.get("api_token"),
            client=stub_client,
        )

    from apps.api.akto_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import akto_engine as engine_mod

    engine_mod.reset_akto_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in ("AKTO_BASE_URL", "AKTO_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akto/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Akto"
    assert body["endpoints"] == [
        "/api/discovered-apis",
        "/api/sensitive-data",
        "/api/test-results",
        "/api/runtime-issues",
        "/api/start-test",
    ]
    assert body["akto_base_url_present"] is False
    assert body["akto_api_token_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akto/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["akto_base_url_present"] is True
    assert body["akto_api_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_discovered_apis_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akto/api/discovered-apis", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "AKTO" in r.json()["detail"]


def test_sensitive_data_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akto/api/sensitive-data", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_start_test_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/akto/api/start-test",
        json={
            "collectionId": 100,
            "testIds": ["BOLA"],
            "testRunTime": 1714780800,
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_runtime_issues_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akto/api/runtime-issues", headers=HEADERS)
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# 422 validation
# ---------------------------------------------------------------------------


def test_discovered_apis_422_on_bad_sort_order():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get(
        "/api/v1/akto/api/discovered-apis?sortOrder=sideways",
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_start_test_422_on_empty_test_ids():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/akto/api/start-test",
        json={
            "collectionId": 100,
            "testIds": [],
            "testRunTime": 1714780800,
        },
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_runtime_issues_422_on_bad_severity():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get(
        "/api/v1/akto/api/runtime-issues?severity=URGENT",
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_discovered_apis_happy_path_normalizes():
    raw = {
        "apiInfoList": [
            {
                "apiCollectionId": 100,
                "url": "/api/v1/users/{userId}",
                "method": "GET",
                "allAuthTypes": ["BEARER", "JWT"],
                "usersCount": 12,
                "lastSeen": 1714780800,
                "severityScore": 75,
                "totalRequests": 9023,
                "sensitiveDataDetected": True,
                "sensitiveDataTypes": ["PII", "TOKEN"],
                "discoveredTimestamp": 1714680800,
                "firstSeenTimestamp": 1713000000,
                "hasTested": True,
                "lastTestedTimestamp": 1714780800,
                "openIssuesCount": 3,
                "isCustomized": False,
                "hostName": "api.example.com",
                "environments": ["prod"],
            }
        ],
        "totalCount": 1,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/discovered-apis": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akto/api/discovered-apis?collectionId=100&limit=25&skip=0",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert len(body["apiInfoList"]) == 1
    item = body["apiInfoList"][0]
    assert item["apiCollectionId"] == 100
    assert item["method"] == "GET"
    assert item["allAuthTypes"] == ["BEARER", "JWT"]
    assert item["sensitiveDataDetected"] is True

    # Ensure X-API-KEY header was set on the upstream call.
    assert len(stub.calls) == 1
    assert stub.calls[0]["headers"].get("X-API-KEY") == _OK_CREDS["api_token"]
    assert "collectionId=100" in stub.calls[0]["url"]
    assert "limit=25" in stub.calls[0]["url"]


def test_sensitive_data_happy_path():
    raw = {
        "sensitiveDataList": [
            {
                "apiCollectionId": 100,
                "url": "/api/v1/users/profile",
                "method": "POST",
                "parameterName": "ssn",
                "parameterLocation": "request_body",
                "dataType": "SSN",
                "severity": "HIGH",
                "count": 42,
                "firstDetected": 1713000000,
                "lastDetected": 1714780800,
                "sampleValues": [],
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/sensitive-data": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akto/api/sensitive-data?collectionId=100&dataType=SSN",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert body["sensitiveDataList"][0]["dataType"] == "SSN"
    assert body["sensitiveDataList"][0]["severity"] == "HIGH"


def test_test_results_happy_path():
    raw = {
        "testResults": [
            {
                "testRunId": "trun-001",
                "testRunResultSummaryHexId": "hex-abc",
                "apiInfoKey": {
                    "apiCollectionId": 100,
                    "url": "/api/v1/orders/{orderId}",
                    "method": "GET",
                },
                "testSubType": "BOLA",
                "vulnerable": True,
                "severity": "HIGH",
                "errors": [],
                "testResults": [
                    {
                        "message": "BOLA bypass via /orders/2",
                        "request": "GET /api/v1/orders/2 HTTP/1.1",
                        "response": "HTTP/1.1 200 OK",
                        "statusCode": 200,
                    }
                ],
                "confidence": "HIGH",
                "startTimestamp": 1714780800,
                "endTimestamp": 1714780900,
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/test-results": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akto/api/test-results?testRunId=trun-001",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    tr = body["testResults"][0]
    assert tr["testSubType"] == "BOLA"
    assert tr["vulnerable"] is True
    assert tr["severity"] == "HIGH"
    assert tr["apiInfoKey"]["url"] == "/api/v1/orders/{orderId}"
    assert len(tr["testResults"]) == 1
    assert tr["testResults"][0]["statusCode"] == 200


def test_runtime_issues_happy_path():
    raw = {
        "issues": [
            {
                "id": "issue-001",
                "type": "EXCESSIVE_DATA_EXPOSURE",
                "severity": "HIGH",
                "title": "Excessive data exposure on /users",
                "description": "Endpoint returns SSN, DOB unconditionally",
                "firstDetected": 1714680800,
                "lastDetected": 1714780800,
                "status": "open",
                "apiCollectionId": 100,
                "urlPattern": "/api/v1/users",
                "method": "GET",
                "evidenceCount": 17,
                "recommendedAction": "Filter response fields by role",
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/runtime-issues": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akto/api/runtime-issues?severity=HIGH&limit=10",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    issue = body["issues"][0]
    assert issue["type"] == "EXCESSIVE_DATA_EXPOSURE"
    assert issue["severity"] == "HIGH"
    assert issue["status"] == "open"


def test_start_test_happy_path_post():
    raw = {
        "testRunId": "trun-xyz",
        "status": "STARTED",
        "scheduledAt": 1714780800,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/start-test": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/akto/api/start-test",
        json={
            "collectionId": 100,
            "testIds": ["BOLA", "BFLA", "RATE_LIMIT"],
            "testRunTime": 1714780800,
            "sendSlackAlert": True,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["testRunId"] == "trun-xyz"
    assert body["status"] == "STARTED"
    assert body["scheduledAt"] == 1714780800

    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "POST"
    assert call["headers"].get("X-API-KEY") == _OK_CREDS["api_token"]
    assert call["headers"].get("Content-Type") == "application/json"
    body_sent = json.loads(call["content"])
    assert body_sent["collectionId"] == 100
    assert body_sent["testIds"] == ["BOLA", "BFLA", "RATE_LIMIT"]
    assert body_sent["sendSlackAlert"] is True


def test_test_runs_happy_path():
    raw = {
        "testingRuns": [
            {
                "testRunId": "trun-001",
                "name": "Nightly auth tests",
                "state": "COMPLETED",
                "scheduleTimestamp": 1714680800,
                "endTimestamp": 1714681000,
                "testingRunConfigId": 7,
                "totalApis": 250,
                "vulnerableApis": 12,
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/test-runs": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/akto/api/test-runs?state=COMPLETED",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert body["testRuns"][0]["state"] == "COMPLETED"
    assert body["testRuns"][0]["totalApis"] == 250


def test_collections_happy_path():
    raw = {
        "apiCollections": [
            {
                "id": 100,
                "name": "Production API",
                "hostName": "api.example.com",
                "type": "API_GROUP",
                "urlsCount": 250,
                "startTs": 1713000000,
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/collections": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akto/api/collections", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert body["apiCollections"][0]["name"] == "Production API"


# ---------------------------------------------------------------------------
# Upstream error handling
# ---------------------------------------------------------------------------


def test_discovered_apis_503_on_upstream_401():
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/discovered-apis": _StubResponse(401, {"error": "bad token"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akto/api/discovered-apis", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"]


def test_discovered_apis_503_on_upstream_429():
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/discovered-apis": _StubResponse(429, {"error": "rate limit"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/akto/api/discovered-apis", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "429" in r.json()["detail"] or "rate-limit" in r.json()["detail"]
