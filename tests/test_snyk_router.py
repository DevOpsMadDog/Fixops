"""Tests for snyk_router — ALDECI.

Spins up a minimal FastAPI app with the Snyk router mounted. Each test gets
an isolated engine singleton with a stub httpx.Client.

NO MOCKS rule:
  * /v1/orgs, /v1/orgs/{org}/projects, /v1/test, /v1/orgs/.../issues
    return HTTP 503 when SNYK_TOKEN is unset.
  * Capability summary reports ``status="unavailable"`` with no token.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real networking + parsing code paths.
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
    """Minimal stand-in for httpx.Response with .json() + .status_code."""

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

    def _match(self, url: str) -> Any:
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):  # noqa: D401
        self.calls.append(
            {"method": "GET", "url": url, "headers": headers or {}, "params": params or {}}
        )
        return self._match(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ):  # noqa: D401, A002 (json is keyword used by httpx)
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "json": json or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    api_key: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import snyk_vuln_engine as engine_mod

    engine_mod.reset_snyk_vuln_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_snyk_vuln_engine(api_key=api_key, client=stub_client)

    from apps.api.snyk_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import snyk_vuln_engine as engine_mod

    engine_mod.reset_snyk_vuln_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_token(monkeypatch):
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snyk/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Snyk"
    assert "/v1/orgs" in body["endpoints"]
    assert "/v1/orgs/{org}/projects" in body["endpoints"]
    assert "/v1/test" in body["endpoints"]
    assert "/v1/orgs/{org}/projects/{project}/issues" in body["endpoints"]
    assert "/v1/reporting" in body["endpoints"]
    assert body["snyk_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    app, _ = _build_app(api_key="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snyk/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["snyk_token_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no token
# ---------------------------------------------------------------------------


def test_orgs_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snyk/v1/orgs", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "SNYK_TOKEN" in r.json()["detail"]
    _reset()


def test_projects_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/snyk/v1/orgs/abc-123/projects",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_test_endpoint_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/snyk/v1/test/npm/package.json",
        json={
            "encoding": "plain",
            "files": {"target": {"contents": "{}"}},
            "displayTargetFile": "package.json",
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_issues_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.request(
        "GET",
        "/api/v1/snyk/v1/orgs/abc-123/projects/proj-1/issues",
        json={"filters": {"severities": ["critical"]}},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_reporting_status_unavailable_without_token(monkeypatch):
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snyk/v1/reporting", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["snyk_token_present"] is False
    assert body["status"] == "unavailable"
    assert "SNYK_TOKEN" in body["notes"]
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_orgs_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    raw = {
        "orgs": [
            {
                "id": "org-uuid-1",
                "name": "Acme Security",
                "slug": "acme-security",
                "group": {"id": "grp-1", "name": "Acme Group"},
            },
            {
                "id": "org-uuid-2",
                "name": "Solo Org",
                "slug": "solo-org",
            },
        ]
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={"/orgs": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snyk/v1/orgs", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["orgs"]) == 2
    assert body["orgs"][0]["id"] == "org-uuid-1"
    assert body["orgs"][0]["group"]["name"] == "Acme Group"
    assert body["orgs"][1]["group"]["id"] == ""
    # Authorization header was set
    assert stub.calls[0]["headers"]["Authorization"] == "token test-token"
    _reset()


def test_projects_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    raw = {
        "projects": [
            {
                "id": "proj-uuid-1",
                "name": "acme/web",
                "type": "npm",
                "origin": "github",
                "branch": "main",
                "isMonitored": True,
                "totalDependencies": 245,
                "issueCountsBySeverity": {
                    "critical": 2,
                    "high": 7,
                    "medium": 14,
                    "low": 33,
                },
            }
        ]
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={"/org/abc-123/projects": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/snyk/v1/orgs/abc-123/projects",
        params=[("filters[]", "tags"), ("filters[]", "status"), ("names", "web,api")],
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["projects"]) == 1
    assert body["projects"][0]["id"] == "proj-uuid-1"
    assert body["projects"][0]["type"] == "npm"
    assert body["projects"][0]["totalDependencies"] == 245
    assert body["projects"][0]["issueCountsBySeverity"]["critical"] == 2
    # Verify filters[] and names were forwarded as upstream params
    upstream_params = stub.calls[0]["params"]
    assert "filters[]" in upstream_params
    assert upstream_params["names"] == "web,api"
    _reset()


def test_test_manifest_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    raw = {
        "ok": False,
        "dependencyCount": 17,
        "issues": {
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-LODASH-1",
                    "title": "Prototype pollution in lodash",
                    "severity": "high",
                    "package": "lodash",
                    "version": "4.17.20",
                    "fixedIn": ["4.17.21"],
                }
            ],
            "licenses": [],
        },
    }
    app, stub = _build_app(
        api_key="test-token",
        stub_responses={"/test/npm/package.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/snyk/v1/test/npm/package.json",
        json={
            "encoding": "plain",
            "files": {"target": {"contents": "{}"}},
            "displayTargetFile": "package.json",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is False
    assert body["dependencyCount"] == 17
    assert len(body["issues"]["vulnerabilities"]) == 1
    vuln = body["issues"]["vulnerabilities"][0]
    assert vuln["id"] == "SNYK-JS-LODASH-1"
    assert vuln["severity"] == "high"
    assert vuln["fixedIn"] == ["4.17.21"]
    # Body forwarded
    posted = stub.calls[0]["json"]
    assert posted["encoding"] == "plain"
    assert posted["displayTargetFile"] == "package.json"
    _reset()


def test_test_manifest_rejects_unknown_ecosystem(monkeypatch):
    """FastAPI Path validator rejects unknown ecosystems with 422 before
    dispatching to the engine."""
    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    app, _ = _build_app(api_key="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/snyk/v1/test/cargo/Cargo.toml",
        json={"encoding": "plain", "files": {}, "displayTargetFile": ""},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_project_issues_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    raw = {
        "issues": {
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-AXIOS-9",
                    "title": "SSRF in axios",
                    "severity": "critical",
                    "package": "axios",
                    "version": "0.21.0",
                    "fixedIn": ["0.21.1"],
                },
                {
                    "id": "SNYK-JS-MINIMIST-2",
                    "title": "Prototype pollution",
                    "severity": "high",
                    "package": "minimist",
                    "version": "1.2.5",
                    "fixedIn": ["1.2.6"],
                },
            ],
            "licenses": [
                {
                    "id": "snyk:lic:npm:gpl-1",
                    "title": "GPL-3.0",
                    "severity": "medium",
                    "package": "some-pkg",
                    "version": "1.0.0",
                }
            ],
        }
    }
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/org/abc-123/project/proj-1/issues": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.request(
        "GET",
        "/api/v1/snyk/v1/orgs/abc-123/projects/proj-1/issues",
        json={"filters": {"severities": ["critical", "high"]}},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["issues"]["vulnerabilities"]) == 2
    assert body["issues"]["vulnerabilities"][0]["id"] == "SNYK-JS-AXIOS-9"
    assert body["issues"]["vulnerabilities"][0]["severity"] == "critical"
    assert len(body["issues"]["licenses"]) == 1
    assert body["issues"]["licenses"][0]["title"] == "GPL-3.0"
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths
# ---------------------------------------------------------------------------


def test_orgs_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    app, _ = _build_app(
        api_key="test-token",
        stub_responses={
            "/orgs": _StubResponse(
                429, {"error": "rate limit"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snyk/v1/orgs", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "rate-limit" in detail.lower() or "429" in detail
    _reset()


def test_projects_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "bad-token")
    app, _ = _build_app(
        api_key="bad-token",
        stub_responses={
            "/org/abc-123/projects": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snyk/v1/orgs/abc-123/projects", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"] or "credential" in r.json()["detail"].lower()
    _reset()


def test_reporting_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    app, _ = _build_app(api_key="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snyk/v1/reporting", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["snyk_token_present"] is True
    assert body["status"] == "ok"
    _reset()
