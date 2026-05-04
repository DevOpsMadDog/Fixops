"""Tests for checkmarx_router — ALDECI.

Mounts a minimal FastAPI app with the Checkmarx router. Each test injects
an isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * GET /, GET /api/projects, GET /api/projects/{id}, GET /api/scans,
    POST /api/scans, GET /api/scan-results, GET /api/scan-results/{id},
    POST /api/scan-results, GET /api/cx-policy-management/policies, and
    POST /api/iam/.../token return HTTP 503 when CHECKMARX_* env unset.
  * Capability summary reports ``status="unavailable"`` when creds missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise OAuth bearer caching + JSON parsing code paths.
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
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix.

    Routes containing ``openid-connect/token`` always issue a synthetic
    bearer so cached-token checks succeed for happy-path tests.
    """

    def __init__(
        self,
        responses: Dict[str, Any],
        *,
        token_response: Optional[Any] = None,
    ):
        self._responses = responses
        self._token_response = token_response or _StubResponse(
            200,
            {
                "access_token": "stub-bearer-token",
                "token_type": "Bearer",
                "expires_in": 1800,
            },
        )
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, url: str) -> _StubResponse:
        if "openid-connect/token" in url:
            return self._token_response
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
        json: Optional[Any] = None,
        data: Optional[Any] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
                "json": json,
                "data": data,
            }
        )
        return self._resolve(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_OK_CREDS = {
    "base_url": "https://us.ast.checkmarx.net",
    "client_id": "cx-client-id",
    "client_secret": "cx-client-secret",
    "tenant": "acme-tenant",
}


def _build_app(
    *,
    creds: Optional[Dict[str, str]],
    stub_responses: Dict[str, Any],
    token_response: Optional[Any] = None,
):
    """Construct an isolated app+engine."""
    from core import checkmarx_engine as engine_mod

    engine_mod.reset_checkmarx_engine()

    stub_client = _StubClient(stub_responses, token_response=token_response)
    if creds is None:
        engine_mod.get_checkmarx_engine(client=stub_client)
    else:
        engine_mod.get_checkmarx_engine(
            base_url=creds.get("base_url"),
            client_id=creds.get("client_id"),
            client_secret=creds.get("client_secret"),
            tenant=creds.get("tenant"),
            client=stub_client,
        )

    from apps.api.checkmarx_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import checkmarx_engine as engine_mod

    engine_mod.reset_checkmarx_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in (
        "CHECKMARX_BASE_URL",
        "CHECKMARX_CLIENT_ID",
        "CHECKMARX_CLIENT_SECRET",
        "CHECKMARX_TENANT",
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

    r = client.get("/api/v1/checkmarx/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Checkmarx One"
    assert "/api/projects" in body["endpoints"]
    assert "/api/scans" in body["endpoints"]
    assert "/api/cx-policy-management/policies" in body["endpoints"]
    assert body["checkmarx_base_url_present"] is False
    assert body["checkmarx_client_id_present"] is False
    assert body["checkmarx_client_secret_present"] is False
    assert body["checkmarx_tenant_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/checkmarx/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["checkmarx_base_url_present"] is True
    assert body["checkmarx_client_id_present"] is True
    assert body["checkmarx_client_secret_present"] is True
    assert body["checkmarx_tenant_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_list_projects_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/checkmarx/api/projects", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "CHECKMARX" in r.json()["detail"]


def test_list_scans_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/checkmarx/api/scans", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_create_scan_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/checkmarx/api/scans",
        json={
            "project": {"id": "proj-001"},
            "branch": "main",
            "sourceType": "git",
            "handler": {"repoUrl": "https://github.com/acme/widget.git"},
            "config": [{"type": "sast", "value": {"incremental": "false"}}],
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_token_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/checkmarx/api/iam/auth/realms/acme/protocol/openid-connect/token",
        json={"grant_type": "client_credentials"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_scan_results_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/checkmarx/api/scan-results?scan-id=scan-1",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_policies_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/checkmarx/api/cx-policy-management/policies",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# 422 validation
# ---------------------------------------------------------------------------


def test_create_scan_422_on_missing_project_id():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/checkmarx/api/scans",
        json={"project": {}, "branch": "main"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_list_scans_422_on_bad_status():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get(
        "/api/v1/checkmarx/api/scans?statuses=Bogus",
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_update_scan_result_422_on_missing_required_field():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post(
        "/api/v1/checkmarx/api/scan-results",
        json={"scanId": "s1", "projectId": "p1"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_list_scan_results_422_on_bad_severity():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get(
        "/api/v1/checkmarx/api/scan-results?scan-id=s1&severity=URGENT",
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_projects_happy_path():
    raw = {
        "projects": [
            {
                "id": "proj-001",
                "name": "widget-svc",
                "createdAt": "2024-04-01T00:00:00Z",
                "updatedAt": "2024-04-15T12:00:00Z",
                "tags": {},
                "groups": [],
                "repoUrl": "https://github.com/acme/widget.git",
                "mainBranch": "main",
            }
        ],
        "totalCount": 1,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/projects": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/checkmarx/api/projects?limit=25&offset=0",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert body["projects"][0]["id"] == "proj-001"

    # Token + projects = 2 calls; ensure Bearer header was set on the projects call.
    project_calls = [c for c in stub.calls if "/api/projects" in c["url"]]
    assert len(project_calls) == 1
    assert project_calls[0]["headers"].get("Authorization", "").startswith("Bearer ")
    assert project_calls[0]["params"].get("limit") == 25


def test_get_project_happy_path():
    raw = {
        "id": "proj-001",
        "name": "widget-svc",
        "mainBranch": "main",
        "tags": {"env": "prod"},
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/projects/proj-001": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/checkmarx/api/projects/proj-001", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "proj-001"
    assert body["mainBranch"] == "main"


def test_list_scans_happy_path():
    raw = {
        "scans": [
            {
                "id": "scan-101",
                "status": "Completed",
                "projectId": "proj-001",
                "branch": "main",
                "createdAt": "2024-04-15T12:00:00Z",
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/scans": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/checkmarx/api/scans?project-id=proj-001&statuses=Completed&limit=10",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scans"][0]["id"] == "scan-101"
    assert body["scans"][0]["status"] == "Completed"


def test_create_scan_happy_path_post():
    raw = {
        "id": "scan-202",
        "status": "Queued",
        "projectId": "proj-001",
        "branch": "main",
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/scans": _StubResponse(201, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/checkmarx/api/scans",
        json={
            "project": {"id": "proj-001"},
            "branch": "main",
            "sourceType": "git",
            "handler": {"repoUrl": "https://github.com/acme/widget.git"},
            "config": [{"type": "sast", "value": {"incremental": "false"}}],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "scan-202"
    assert body["status"] == "Queued"

    scan_posts = [
        c for c in stub.calls if c["method"] == "POST" and "/api/scans" in c["url"]
    ]
    assert len(scan_posts) == 1
    sent = scan_posts[0]["json"]
    assert sent["project"]["id"] == "proj-001"
    assert sent["sourceType"] == "git"


def test_list_scan_results_happy_path():
    raw = {
        "results": [
            {
                "id": "res-1",
                "severity": "HIGH",
                "state": "TO_VERIFY",
                "status": "NEW",
                "queryName": "SQL_Injection",
                "similarityId": "sim-abc",
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/scan-results": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/checkmarx/api/scan-results?scan-id=scan-101&severity=HIGH",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["results"][0]["severity"] == "HIGH"
    assert body["results"][0]["queryName"] == "SQL_Injection"


def test_get_scan_result_happy_path():
    raw = {
        "id": "res-1",
        "severity": "HIGH",
        "state": "TO_VERIFY",
        "status": "NEW",
        "description": "User input flows into raw SQL",
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/scan-results/res-1": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/checkmarx/api/scan-results/res-1", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "res-1"


def test_update_scan_result_happy_path():
    raw = {"updated": True, "id": "res-1"}
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/scan-results": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/checkmarx/api/scan-results",
        json={
            "scanId": "scan-101",
            "projectId": "proj-001",
            "similarityId": "sim-abc",
            "severity": "MEDIUM",
            "state": "CONFIRMED",
            "status": "RECURRENT",
            "comment": "triaged via aldeci",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["updated"] is True

    triage_posts = [
        c
        for c in stub.calls
        if c["method"] == "POST" and "/api/scan-results" in c["url"]
    ]
    assert len(triage_posts) == 1
    sent = triage_posts[0]["json"]
    assert sent["scanId"] == "scan-101"
    assert sent["state"] == "CONFIRMED"


def test_list_policies_happy_path():
    raw = {
        "policies": [
            {
                "id": "pol-1",
                "name": "Block-on-Critical",
                "description": "Fail build on critical SAST findings",
            }
        ],
        "totalCount": 1,
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "/api/cx-policy-management/policies": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/checkmarx/api/cx-policy-management/policies?tenantId=acme-tenant",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["policies"][0]["id"] == "pol-1"


def test_token_happy_path_pass_through():
    """POST /api/iam/.../token returns the OAuth payload as-is."""
    token_response = _StubResponse(
        200,
        {
            "access_token": "fresh-bearer-xyz",
            "token_type": "Bearer",
            "expires_in": 1800,
        },
    )
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={},
        token_response=token_response,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/checkmarx/api/iam/auth/realms/acme-tenant/protocol/openid-connect/token",
        json={
            "grant_type": "client_credentials",
            "client_id": "cx-client-id",
            "client_secret": "cx-client-secret",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"] == "fresh-bearer-xyz"
    assert body["token_type"] == "Bearer"


# ---------------------------------------------------------------------------
# Upstream error handling
# ---------------------------------------------------------------------------


def test_list_projects_503_on_upstream_401():
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/projects": _StubResponse(401, {"error": "bad token"})},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/checkmarx/api/projects", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"]


def test_list_scans_503_on_upstream_429():
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={"/api/scans": _StubResponse(429, {"error": "rate limit"})},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/checkmarx/api/scans", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "429" in r.json()["detail"] or "rate-limit" in r.json()["detail"]
