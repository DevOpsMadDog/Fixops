"""Tests for contrast_router — ALDECI.

Spins up a minimal FastAPI app with the Contrast router mounted. Each test
gets an isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * GET / and all GET /api/ng/* endpoints return HTTP 503 when any of the
    four Contrast env vars (BASE_URL, API_KEY, AUTH_HEADER, SERVICE_KEY) is
    unset.
  * Capability summary reports ``status="unavailable"`` when creds are missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real header-construction + parsing code paths.
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
        # Longest match first so /applications/{id} doesn't shadow /applications
        for path in sorted(self._responses.keys(), key=len, reverse=True):
            if path in url:
                return self._responses[path]
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {})}
        )
        return self._resolve(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_OK_CREDS = {
    "base_url": "https://app.contrastsecurity.com/Contrast",
    "api_key": "test-api-key-value",
    "auth_header": "dXNlcjpzZXJ2aWNla2V5",  # "user:servicekey" base64
    "service_key": "test-service-key-value",
}


def _build_app(
    *,
    creds: Optional[Dict[str, str]],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine."""
    from core import contrast_engine as engine_mod

    engine_mod.reset_contrast_engine()

    stub_client = _StubClient(stub_responses)
    if creds is None:
        engine_mod.get_contrast_engine(client=stub_client)
    else:
        engine_mod.get_contrast_engine(
            base_url=creds.get("base_url"),
            api_key=creds.get("api_key"),
            auth_header=creds.get("auth_header"),
            service_key=creds.get("service_key"),
            client=stub_client,
        )

    from apps.api.contrast_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import contrast_engine as engine_mod

    engine_mod.reset_contrast_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in (
        "CONTRAST_BASE_URL",
        "CONTRAST_API_KEY",
        "CONTRAST_AUTH_HEADER",
        "CONTRAST_SERVICE_KEY",
    ):
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

    r = client.get("/api/v1/contrast/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Contrast Security"
    assert body["endpoints"] == [
        "/api/ng/{org}/applications",
        "/api/ng/{org}/traces",
        "/api/ng/{org}/protect/policies",
        "/api/ng/{org}/servers",
        "/api/ng/{org}/libraries",
    ]
    assert body["contrast_base_url_present"] is False
    assert body["contrast_api_key_present"] is False
    assert body["contrast_auth_header_present"] is False
    assert body["contrast_service_key_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/contrast/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["contrast_base_url_present"] is True
    assert body["contrast_api_key_present"] is True
    assert body["contrast_auth_header_present"] is True
    assert body["contrast_service_key_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_applications_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-123/applications", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    assert "CONTRAST" in r.json()["detail"]


def test_traces_filter_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-123/traces/app-1/filter",
        params={"severities": "CRITICAL,HIGH", "limit": 10},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_protect_policies_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-123/protect/policies", headers=HEADERS
    )
    assert r.status_code == 503, r.text


def test_libraries_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-123/libraries",
        params={"filterScore": "F", "limit": 5},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_applications_happy_path_normalizes():
    raw = {
        "success": True,
        "applications": [
            {
                "app_id": "app-uuid-1",
                "name": "WebApp One",
                "status": "online",
                "language": "Java",
                "license": "Enterprise",
                "last_seen": "2026-05-01T12:00:00Z",
                "importance": "HIGH",
                "tags": ["pci", "prod"],
                "assess": True,
                "defend": False,
            },
            {
                "appId": "app-uuid-2",
                "name": "API Service",
                "status": "online",
                "language": "Node",
                "license": "Enterprise",
                "lastSeen": "2026-05-02T08:00:00Z",
                "importance": "MEDIUM",
                "tags": [],
                "assess": True,
                "defend": True,
            },
        ],
        "facets": {"language": [{"name": "Java", "count": 1}]},
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/applications": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/applications",
        params={"limit": 50, "offset": 0, "filterText": "web"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert len(body["applications"]) == 2
    assert body["applications"][0]["app_id"] == "app-uuid-1"
    assert body["applications"][0]["language"] == "Java"
    assert body["applications"][1]["app_id"] == "app-uuid-2"
    assert body["applications"][1]["defend"] is True
    assert body["facets"]["language"][0]["name"] == "Java"

    # Confirm Authorization + API-Key headers were forwarded upstream.
    assert stub.calls, "expected at least one upstream call"
    sent_headers = stub.calls[0]["headers"]
    assert sent_headers["Authorization"] == _OK_CREDS["auth_header"]
    assert sent_headers["API-Key"] == _OK_CREDS["api_key"]
    # Confirm filter query string was passed through.
    assert "filterText=web" in stub.calls[0]["url"]


def test_single_application_happy_path():
    raw = {
        "success": True,
        "application": {
            "app_id": "app-uuid-1",
            "name": "WebApp One",
            "status": "online",
            "language": "Java",
            "license": "Enterprise",
            "last_seen": "2026-05-01T12:00:00Z",
            "importance": "HIGH",
            "tags": ["pci"],
            "assess": True,
            "defend": False,
        },
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/applications/app-uuid-1": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/applications/app-uuid-1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["application"]["app_id"] == "app-uuid-1"
    assert body["application"]["importance"] == "HIGH"


def test_traces_filter_happy_path_normalizes():
    raw = {
        "success": True,
        "traces": [
            {
                "uuid": "trace-uuid-1",
                "request": {
                    "method": "POST",
                    "uri": "/login",
                    "host": "app.example.com",
                },
                "rule_name": "sql-injection",
                "severity": "CRITICAL",
                "status": "REPORTED",
                "application": {"app_id": "app-uuid-1", "name": "WebApp"},
                "evidence": "SELECT * FROM users WHERE name='${param}'",
                "tags": ["pci"],
                "first_time_seen": "2026-04-01T00:00:00Z",
                "last_time_seen": "2026-05-01T00:00:00Z",
            },
            {
                "uuid": "trace-uuid-2",
                "request": {
                    "method": "GET",
                    "uri": "/profile",
                    "host": "app.example.com",
                },
                "ruleName": "xss-reflected",
                "severity": "HIGH",
                "status": "CONFIRMED",
                "application": {"appId": "app-uuid-1", "name": "WebApp"},
                "evidence": "<script>alert(1)</script>",
                "tags": [],
                "firstTimeSeen": "2026-04-15T00:00:00Z",
                "lastTimeSeen": "2026-05-02T00:00:00Z",
            },
        ],
        "facets": {"severity": [{"name": "CRITICAL", "count": 1}]},
        "count": 2,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/traces/app-uuid-1/filter": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/traces/app-uuid-1/filter",
        params={
            "severities": "CRITICAL,HIGH",
            "statuses": "REPORTED,CONFIRMED",
            "limit": 25,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert body["count"] == 2
    assert len(body["traces"]) == 2
    t0 = body["traces"][0]
    assert t0["uuid"] == "trace-uuid-1"
    assert t0["request"]["method"] == "POST"
    assert t0["rule_name"] == "sql-injection"
    assert t0["severity"] == "CRITICAL"
    t1 = body["traces"][1]
    assert t1["rule_name"] == "xss-reflected"  # ruleName -> rule_name
    assert t1["application"]["app_id"] == "app-uuid-1"  # appId -> app_id
    # Confirm filter query string was passed through to upstream.
    assert "severities=CRITICAL%2CHIGH" in stub.calls[0]["url"]


def test_single_trace_happy_path():
    raw = {
        "success": True,
        "trace": {
            "uuid": "trace-uuid-9",
            "request": {
                "method": "POST",
                "uri": "/cart",
                "host": "shop.example.com",
            },
            "rule_name": "command-injection",
            "severity": "CRITICAL",
            "status": "CONFIRMED",
            "application": {"app_id": "app-X", "name": "Shop"},
            "evidence": "; cat /etc/passwd",
            "tags": ["high-risk"],
            "first_time_seen": "2026-01-01T00:00:00Z",
            "last_time_seen": "2026-05-01T00:00:00Z",
        },
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/traces/trace-uuid-9": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/traces/trace-uuid-9",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["trace"]["uuid"] == "trace-uuid-9"
    assert body["trace"]["rule_name"] == "command-injection"


def test_protect_policies_happy_path():
    raw = {
        "success": True,
        "policies": [
            {
                "id": 11,
                "name": "Default",
                "mode": "MONITOR",
                "applications": ["app-uuid-1"],
                "rules": ["sql-injection", "xss"],
            },
            {
                "id": 12,
                "name": "Strict",
                "mode": "BLOCK",
                "applications": ["app-uuid-2"],
                "rules": ["sql-injection", "command-injection"],
            },
        ],
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/protect/policies": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/protect/policies", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["policies"]) == 2
    assert body["policies"][1]["mode"] == "BLOCK"


def test_servers_happy_path_normalizes():
    raw = {
        "success": True,
        "servers": [
            {
                "server_id": 100,
                "name": "prod-app-01",
                "hostname": "prod-app-01.internal",
                "environment": "PRODUCTION",
                "language": "Java",
                "container": "tomcat-9",
                "last_activity": "2026-05-04T01:00:00Z",
                "status": "ONLINE",
                "applications": ["app-uuid-1"],
                "assess": True,
                "defend": True,
            },
            {
                "serverId": 101,
                "name": "qa-app-02",
                "hostname": "qa-app-02.internal",
                "environment": "QA",
                "language": "Node",
                "container": "node-18",
                "lastActivity": "2026-05-04T00:00:00Z",
                "status": "ONLINE",
                "applications": ["app-uuid-2"],
                "assess": True,
                "defend": False,
            },
        ],
        "count": 2,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/servers": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/servers",
        params={
            "expand": "skip_links",
            "environment": "PRODUCTION",
            "limit": 50,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert body["count"] == 2
    assert body["servers"][0]["server_id"] == 100
    assert body["servers"][0]["environment"] == "PRODUCTION"
    assert body["servers"][1]["server_id"] == 101  # serverId -> server_id
    # Confirm expand/environment query was forwarded.
    assert "expand=skip_links" in stub.calls[0]["url"]
    assert "environment=PRODUCTION" in stub.calls[0]["url"]


def test_libraries_happy_path_with_vuln_overlay():
    raw = {
        "success": True,
        "libraries": [
            {
                "hash": "abc123",
                "file_name": "log4j-core-2.14.1.jar",
                "file_version": "2.14.1",
                "language": "Java",
                "grade": "F",
                "latest_version": "2.21.0",
                "release_date": "2021-03-12T00:00:00Z",
                "applications": ["app-uuid-1"],
                "vulns": [
                    {
                        "cve": "CVE-2021-44228",
                        "severity": "CRITICAL",
                        "title": "Log4Shell",
                        "cvss": 10.0,
                    },
                    {
                        "cve": "CVE-2021-45046",
                        "severity": "CRITICAL",
                        "title": "Log4Shell-2",
                        "cvss": 9.0,
                    },
                ],
            },
            {
                "hash": "def456",
                "fileName": "lodash-4.17.20.tgz",
                "fileVersion": "4.17.20",
                "language": "JavaScript",
                "grade": "B",
                "latestVersion": "4.17.21",
                "releaseDate": "2020-08-13T00:00:00Z",
                "applications": ["app-uuid-2"],
                "vulnerabilities": [
                    {
                        "cve": "CVE-2021-23337",
                        "severity": "HIGH",
                        "title": "Command Injection in lodash",
                        "cvss": 7.2,
                    }
                ],
            },
        ],
        "count": 2,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/libraries": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/libraries",
        params={
            "expand": "manifest,vulns",
            "filterScore": "F",
            "filterLanguage": "Java",
            "limit": 100,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert body["count"] == 2
    assert len(body["libraries"]) == 2
    lib0 = body["libraries"][0]
    assert lib0["file_name"] == "log4j-core-2.14.1.jar"
    assert lib0["grade"] == "F"
    assert len(lib0["vulns"]) == 2
    assert lib0["vulns"][0]["cve"] == "CVE-2021-44228"
    lib1 = body["libraries"][1]
    assert lib1["file_name"] == "lodash-4.17.20.tgz"  # fileName -> file_name
    assert len(lib1["vulns"]) == 1  # vulnerabilities -> vulns
    assert lib1["vulns"][0]["cve"] == "CVE-2021-23337"
    # Confirm filter query passed through.
    assert "filterScore=F" in stub.calls[0]["url"]


# ---------------------------------------------------------------------------
# Validation / error mapping
# ---------------------------------------------------------------------------


def test_libraries_422_on_bad_limit():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    # limit=0 fails the FastAPI Query(ge=1) constraint -> 422
    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/libraries",
        params={"limit": 0},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_upstream_401_maps_to_503():
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/applications": _StubResponse(401, {"error": "unauthorized"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/applications", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    assert "credentials" in r.json()["detail"].lower() or "401" in r.json()["detail"]


def test_upstream_429_maps_to_503():
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/servers": _StubResponse(429, {"error": "too many"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/contrast/api/ng/org-uuid/servers", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    assert "rate" in r.json()["detail"].lower() or "429" in r.json()["detail"]
