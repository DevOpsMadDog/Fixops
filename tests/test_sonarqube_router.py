"""Tests for sonarqube_router — ALDECI SonarQube Web API wrapper.

NO MOCKS rule:
  * When SONARQUBE_URL or SONAR_TOKEN is unset the capability summary reports
    ``status="unavailable"`` and every live SonarQube endpoint returns 503.
  * Happy-path tests inject a stub httpx.Client so we exercise the real
    auth + parsing code paths without hitting a real SonarQube server.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

import pytest

# ── env bootstrap (mirrors tests/conftest.py defaults) ────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-for-jwt-validation-32chars")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from tests.conftest import API_TOKEN  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# Stub httpx client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        import json as _json
        self.text = text or _json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Routes calls by URL substring -> queued response."""

    def __init__(self, get_responses: Optional[Dict[str, Any]] = None):
        self._get = get_responses or {}
        self.calls: List[Dict[str, Any]] = []

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        auth: Optional[Tuple[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "params": params or {},
                "auth": auth,
                "headers": headers or {},
            }
        )
        for needle, resp in self._get.items():
            if needle in url:
                return resp
        return _StubResponse(404, {"errors": [{"msg": "not found"}]})

    def close(self) -> None:
        pass


def _build_app(
    *,
    base_url: Optional[str],
    token: Optional[str],
    get_responses: Optional[Dict[str, Any]] = None,
):
    """Construct an isolated FastAPI app with the SonarQube router mounted."""
    from core import sonarqube_engine as engine_mod

    engine_mod.reset_sonarqube_engine()
    stub = _StubClient(get_responses or {})
    engine_mod.get_sonarqube_engine(
        base_url=base_url,
        token=token,
        client=stub,
    )

    from apps.api.sonarqube_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import sonarqube_engine as engine_mod
    engine_mod.reset_sonarqube_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("SONARQUBE_URL", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    app, _ = _build_app(base_url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sonarqube/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "SonarQube"
    for needle in (
        "/api/projects/search",
        "/api/issues/search",
        "/api/qualitygates/project_status",
        "/api/measures/component",
        "/api/components/show",
        "/api/hotspots/search",
    ):
        assert needle in body["endpoints"], needle
    assert body["sonarqube_url_present"] is False
    assert body["sonar_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_creds_present(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com/")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    app, _ = _build_app(base_url="https://sonar.example.com/", token="tok-123")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sonarqube/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sonarqube_url_present"] is True
    assert body["sonar_token_present"] is True
    assert body["status"] == "empty"
    _reset()


def test_capability_summary_unavailable_when_only_url(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    app, _ = _build_app(base_url="https://sonar.example.com", token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sonarqube/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["sonarqube_url_present"] is True
    assert body["sonar_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


# ---------------------------------------------------------------------------
# 503 — credentials missing
# ---------------------------------------------------------------------------


def test_projects_search_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SONARQUBE_URL", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    app, _ = _build_app(base_url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sonarqube/api/projects/search", headers=HEADERS)
    assert r.status_code == 503
    assert "SONARQUBE_URL" in r.json()["detail"]
    _reset()


def test_issues_search_returns_503_when_no_token(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    app, _ = _build_app(base_url="https://sonar.example.com", token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sonarqube/api/issues/search", headers=HEADERS)
    assert r.status_code == 503
    assert "SONAR_TOKEN" in r.json()["detail"]
    _reset()


def test_qualitygates_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SONARQUBE_URL", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    app, _ = _build_app(base_url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/qualitygates/project_status?projectKey=demo",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_hotspots_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SONARQUBE_URL", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    app, _ = _build_app(base_url=None, token=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sonarqube/api/hotspots/search", headers=HEADERS)
    assert r.status_code == 503
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx
# ---------------------------------------------------------------------------


def test_projects_search_happy_path(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    raw = {
        "paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
        "components": [
            {
                "key": "demo:proj",
                "name": "Demo Project",
                "qualifier": "TRK",
                "project": "demo:proj",
                "lastAnalysisDate": "2026-04-01T12:00:00+0000",
                "revision": "deadbeef",
                "visibility": "private",
                "managed": False,
            }
        ],
    }
    app, stub = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
        get_responses={"/api/projects/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/projects/search?qualifiers=TRK&q=demo&p=1&ps=100",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["paging"]["total"] == 1
    assert body["components"][0]["key"] == "demo:proj"
    assert body["components"][0]["qualifier"] == "TRK"
    assert body["components"][0]["visibility"] == "private"

    call = stub.calls[0]
    assert call["method"] == "GET"
    assert call["url"].endswith("/api/projects/search")
    # Token-as-username basic auth
    assert call["auth"] == ("tok-123", "")
    assert call["params"]["qualifiers"] == "TRK"
    assert call["params"]["q"] == "demo"
    assert call["params"]["p"] == 1
    assert call["params"]["ps"] == 100
    _reset()


def test_issues_search_happy_path(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    raw = {
        "total": 1,
        "p": 1,
        "ps": 100,
        "paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
        "components": [{"key": "demo:proj"}],
        "rules": [{"key": "java:S1234"}],
        "users": [],
        "facets": [],
        "issues": [
            {
                "key": "AY-001",
                "rule": "java:S1234",
                "severity": "CRITICAL",
                "component": "demo:proj:src/Main.java",
                "project": "demo:proj",
                "line": 42,
                "hash": "abc123",
                "textRange": {
                    "startLine": 42, "endLine": 42,
                    "startOffset": 4, "endOffset": 20,
                },
                "flows": [],
                "status": "OPEN",
                "message": "Use a logger",
                "effort": "5min",
                "debt": "5min",
                "author": "alice@example.com",
                "tags": ["bad-practice"],
                "creationDate": "2026-04-01T00:00:00+0000",
                "updateDate": "2026-04-02T00:00:00+0000",
                "type": "VULNERABILITY",
                "cleanCodeAttribute": "CONVENTIONAL",
                "cleanCodeAttributeCategory": "INTENTIONAL",
                "impacts": [
                    {"softwareQuality": "SECURITY", "severity": "HIGH"}
                ],
                "scope": "MAIN",
            }
        ],
    }
    app, stub = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
        get_responses={"/api/issues/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/issues/search"
        "?componentKeys=demo:proj"
        "&severities=CRITICAL,BLOCKER"
        "&types=VULNERABILITY"
        "&statuses=OPEN"
        "&p=1&ps=100",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    assert body["issues"][0]["key"] == "AY-001"
    assert body["issues"][0]["severity"] == "CRITICAL"
    assert body["issues"][0]["type"] == "VULNERABILITY"
    assert body["issues"][0]["impacts"][0]["softwareQuality"] == "SECURITY"

    call = stub.calls[0]
    assert call["params"]["componentKeys"] == "demo:proj"
    assert call["params"]["severities"] == "CRITICAL,BLOCKER"
    assert call["params"]["types"] == "VULNERABILITY"
    _reset()


def test_issues_search_rejects_invalid_severity(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    app, _ = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/issues/search?severities=NUCLEAR",
        headers=HEADERS,
    )
    assert r.status_code == 422
    assert "NUCLEAR" in r.json()["detail"]
    _reset()


def test_qualitygates_project_status_happy_path(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    raw = {
        "projectStatus": {
            "status": "ERROR",
            "ignoredConditions": False,
            "conditions": [
                {
                    "status": "ERROR",
                    "metricKey": "new_coverage",
                    "comparator": "LT",
                    "errorThreshold": "80",
                    "actualValue": "60.5",
                }
            ],
            "periods": [
                {
                    "index": 1,
                    "mode": "previous_version",
                    "date": "2026-03-01T00:00:00+0000",
                    "parameter": "1.0",
                }
            ],
            "period": {
                "mode": "previous_version",
                "date": "2026-03-01T00:00:00+0000",
                "parameter": "1.0",
            },
            "caycStatus": "compliant",
        }
    }
    app, stub = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
        get_responses={"/api/qualitygates/project_status": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/qualitygates/project_status?projectKey=demo:proj&branch=main",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["projectStatus"]["status"] == "ERROR"
    assert body["projectStatus"]["caycStatus"] == "compliant"
    assert body["projectStatus"]["conditions"][0]["metricKey"] == "new_coverage"

    call = stub.calls[0]
    assert call["params"]["projectKey"] == "demo:proj"
    assert call["params"]["branch"] == "main"
    _reset()


def test_measures_component_happy_path(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    raw = {
        "component": {
            "key": "demo:proj",
            "name": "Demo",
            "qualifier": "TRK",
            "measures": [
                {"metric": "coverage", "value": "85.2", "periods": []},
                {"metric": "bugs", "value": "3", "periods": []},
            ],
        },
        "period": {"mode": "previous_version", "date": "2026-03-01", "parameter": "1.0"},
        "periods": [],
    }
    app, _ = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
        get_responses={"/api/measures/component": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/measures/component"
        "?component=demo:proj&metricKeys=coverage,bugs",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["component"]["key"] == "demo:proj"
    metrics = {m["metric"]: m["value"] for m in body["component"]["measures"]}
    assert metrics["coverage"] == "85.2"
    assert metrics["bugs"] == "3"
    _reset()


def test_measures_component_rejects_missing_metrics(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    app, _ = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
    )
    client = TestClient(app, raise_server_exceptions=True)

    # Missing required metricKeys param -> FastAPI 422
    r = client.get(
        "/api/v1/sonarqube/api/measures/component?component=demo:proj",
        headers=HEADERS,
    )
    assert r.status_code == 422
    _reset()


def test_components_show_happy_path(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    raw = {
        "component": {
            "key": "demo:proj:src/Main.java",
            "name": "Main.java",
            "qualifier": "FIL",
            "path": "src/Main.java",
            "language": "java",
            "version": "1.0",
            "description": "Entry point",
        },
        "ancestors": [
            {"key": "demo:proj", "name": "Demo", "qualifier": "TRK"}
        ],
    }
    app, _ = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
        get_responses={"/api/components/show": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/components/show?key=demo:proj:src/Main.java",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["component"]["language"] == "java"
    assert body["ancestors"][0]["key"] == "demo:proj"
    _reset()


def test_hotspots_search_happy_path(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    raw = {
        "paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
        "hotspots": [
            {
                "key": "HOT-1",
                "component": "demo:proj:src/Main.java",
                "project": "demo:proj",
                "securityCategory": "sql-injection",
                "vulnerabilityProbability": "HIGH",
                "status": "TO_REVIEW",
                "line": 17,
                "message": "Make sure SQL injection is prevented.",
                "author": "bob@example.com",
                "creationDate": "2026-04-01T00:00:00+0000",
                "updateDate": "2026-04-02T00:00:00+0000",
                "textRange": {
                    "startLine": 17, "endLine": 17,
                    "startOffset": 4, "endOffset": 20,
                },
                "flows": [],
                "ruleKey": "javasecurity:S3649",
            }
        ],
        "components": [{"key": "demo:proj"}],
    }
    app, stub = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
        get_responses={"/api/hotspots/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/hotspots/search"
        "?projectKey=demo:proj&status=TO_REVIEW",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["paging"]["total"] == 1
    assert body["hotspots"][0]["securityCategory"] == "sql-injection"
    assert body["hotspots"][0]["vulnerabilityProbability"] == "HIGH"
    assert body["hotspots"][0]["status"] == "TO_REVIEW"

    call = stub.calls[0]
    assert call["params"]["projectKey"] == "demo:proj"
    assert call["params"]["status"] == "TO_REVIEW"
    _reset()


def test_hotspots_search_rejects_invalid_status(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    app, _ = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sonarqube/api/hotspots/search?status=BOGUS",
        headers=HEADERS,
    )
    assert r.status_code == 422
    _reset()


def test_upstream_403_translates_to_503(monkeypatch):
    monkeypatch.setenv("SONARQUBE_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "tok-123")
    app, _ = _build_app(
        base_url="https://sonar.example.com",
        token="tok-123",
        get_responses={
            "/api/projects/search": _StubResponse(403, {"errors": [{"msg": "denied"}]})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sonarqube/api/projects/search", headers=HEADERS)
    assert r.status_code == 503
    assert "permission denied" in r.json()["detail"].lower()
    _reset()
