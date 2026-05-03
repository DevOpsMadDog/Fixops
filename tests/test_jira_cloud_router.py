"""Router-level HTTP tests for Jira Cloud pass-through API.

Covers /api/v1/jira-cloud/* via FastAPI TestClient with a stub httpx.Client
so no real Jira call is made.

Tests:
1. GET /                                     — capability summary (unavailable when env unset)
2. GET /                                     — capability summary (ok when env set)
3. POST /rest/api/3/issue                    — create issue (envelope shape)
4. GET  /rest/api/3/issue/{key}              — fetch issue with fields/expand pass-through
5. POST /rest/api/3/search                   — JQL search
6. GET  /rest/api/3/issue/{key}/transitions  — list transitions
7. POST /rest/api/3/issue/{key}/transitions  — transition (204)
8. GET  /rest/api/3/project                  — project list
9. unavailable env returns 503 on lookup endpoint
10. upstream 404 surfaces as 404 with payload echo
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite paths are importable regardless of cwd
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import apps.api.jira_cloud_router as _router_mod
from apps.api.jira_cloud_router import router
from core.jira_cloud_engine import JiraCloudEngine, reset_jira_cloud_engine


# ---------------------------------------------------------------------------
# Stub httpx.Client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, json_payload: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        self.content = (text or (b"" if json_payload is None else b"x")) if isinstance(text, (bytes, str)) else b""
        if json_payload is not None and not text:
            self.content = b"{}"

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class StubHTTPXClient:
    """Captures requests and returns scripted responses keyed by (method, path-suffix)."""

    def __init__(self, routes: Optional[Dict[str, _StubResponse]] = None) -> None:
        # routes keyed by f"{METHOD} {path-suffix-after-/rest/api/3/}"
        self.routes: Dict[str, _StubResponse] = routes or {}
        self.calls: List[Dict[str, Any]] = []

    def set(self, method: str, suffix: str, response: _StubResponse) -> None:
        self.routes[f"{method.upper()} {suffix}"] = response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,  # noqa: A002 - mirror httpx signature
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> _StubResponse:
        # Strip everything up to /rest/api/3/
        marker = "/rest/api/3/"
        idx = url.find(marker)
        suffix = url[idx + len(marker):] if idx >= 0 else url
        key = f"{method.upper()} {suffix}"
        self.calls.append(
            {"method": method.upper(), "url": url, "suffix": suffix, "json": json, "params": params, "headers": headers}
        )
        if key in self.routes:
            return self.routes[key]
        # Default: echo a generic 200 with empty body
        return _StubResponse(200, {})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test gets a fresh engine singleton."""
    reset_jira_cloud_engine()
    yield
    reset_jira_cloud_engine()


def _build_app(engine: JiraCloudEngine) -> TestClient:
    """Mount the router with engine injection."""
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> JiraCloudEngine:
    return JiraCloudEngine(
        jira_url="https://example.atlassian.net",
        jira_auth="bot@example.com:tok-12345",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> JiraCloudEngine:
    return JiraCloudEngine(jira_url="", jira_auth="", client=httpx.Client())


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: JiraCloudEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/jira-cloud/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Jira Cloud"
    assert body["jira_url_present"] is False
    assert body["jira_auth_present"] is False
    assert body["status"] == "unavailable"
    assert "/rest/api/3/issue" in body["endpoints"]
    assert "/rest/api/3/search" in body["endpoints"]
    assert "/rest/api/3/project" in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: JiraCloudEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jira-cloud/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["jira_url_present"] is True
    assert body["jira_auth_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. Create issue
# ---------------------------------------------------------------------------


def test_create_issue_returns_id_key(configured_engine: JiraCloudEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "POST",
        "issue",
        _StubResponse(201, {"id": "10001", "key": "SEC-42", "self": "https://example.atlassian.net/rest/api/3/issue/10001"}),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/jira-cloud/rest/api/3/issue",
        json={
            "fields": {
                "project": {"key": "SEC"},
                "summary": "CVE-2025-9999 affects api-gateway",
                "issuetype": {"name": "Bug"},
                "priority": {"name": "High"},
                "labels": ["aldeci", "auto"],
            }
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "10001"
    assert body["key"] == "SEC-42"
    assert body["self"].endswith("/issue/10001")
    # Verify upstream call carried the fields envelope
    assert stub.calls[0]["json"] == {
        "fields": {
            "project": {"key": "SEC"},
            "summary": "CVE-2025-9999 affects api-gateway",
            "issuetype": {"name": "Bug"},
            "priority": {"name": "High"},
            "labels": ["aldeci", "auto"],
        }
    }
    # Auth header was set
    assert stub.calls[0]["headers"]["Authorization"].startswith("Basic ")


# ---------------------------------------------------------------------------
# 4. Fetch issue with fields + expand
# ---------------------------------------------------------------------------


def test_get_issue_passes_fields_and_expand(configured_engine: JiraCloudEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "issue/SEC-42",
        _StubResponse(
            200,
            {
                "id": "10001",
                "key": "SEC-42",
                "fields": {
                    "summary": "CVE-2025-9999 affects api-gateway",
                    "status": {"name": "In Progress"},
                    "priority": {"name": "High"},
                    "labels": ["aldeci"],
                },
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/jira-cloud/rest/api/3/issue/SEC-42",
        params={"fields": "summary,status,priority", "expand": "renderedFields,changelog"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["key"] == "SEC-42"
    assert body["fields"]["status"]["name"] == "In Progress"
    # Confirm engine forwarded fields/expand as comma-joined strings
    assert stub.calls[0]["params"]["fields"] == "summary,status,priority"
    assert stub.calls[0]["params"]["expand"] == "renderedFields,changelog"


# ---------------------------------------------------------------------------
# 5. Search
# ---------------------------------------------------------------------------


def test_search_jql(configured_engine: JiraCloudEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "POST",
        "search",
        _StubResponse(
            200,
            {
                "expand": "schema,names",
                "startAt": 0,
                "maxResults": 50,
                "total": 1,
                "issues": [
                    {"id": "10001", "key": "SEC-42", "fields": {"summary": "CVE-2025-9999"}},
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/jira-cloud/rest/api/3/search",
        json={
            "jql": "project = SEC AND status = 'In Progress'",
            "startAt": 0,
            "maxResults": 50,
            "fields": ["summary", "status"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["issues"][0]["key"] == "SEC-42"
    # Body forwarded with camelCase
    sent = stub.calls[0]["json"]
    assert sent["jql"] == "project = SEC AND status = 'In Progress'"
    assert sent["startAt"] == 0
    assert sent["maxResults"] == 50
    assert sent["fields"] == ["summary", "status"]


# ---------------------------------------------------------------------------
# 6. Get transitions
# ---------------------------------------------------------------------------


def test_get_transitions(configured_engine: JiraCloudEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "issue/SEC-42/transitions",
        _StubResponse(
            200,
            {
                "transitions": [
                    {"id": "11", "name": "To Do", "to": {"id": "1", "name": "To Do"}},
                    {"id": "21", "name": "In Progress", "to": {"id": "3", "name": "In Progress"}},
                    {"id": "31", "name": "Done", "to": {"id": "10", "name": "Done"}},
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jira-cloud/rest/api/3/issue/SEC-42/transitions")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["transitions"]) == 3
    assert body["transitions"][1]["name"] == "In Progress"


# ---------------------------------------------------------------------------
# 7. Transition issue (204)
# ---------------------------------------------------------------------------


def test_transition_issue_returns_204(configured_engine: JiraCloudEngine, stub: StubHTTPXClient) -> None:
    stub.set("POST", "issue/SEC-42/transitions", _StubResponse(204, None, text=""))
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/jira-cloud/rest/api/3/issue/SEC-42/transitions",
        json={"transition": {"id": "31"}},
    )
    assert resp.status_code == 204
    sent = stub.calls[0]["json"]
    assert sent == {"transition": {"id": "31"}}


# ---------------------------------------------------------------------------
# 8. List projects
# ---------------------------------------------------------------------------


def test_list_projects(configured_engine: JiraCloudEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "project",
        _StubResponse(
            200,
            [
                {"id": "10000", "key": "SEC", "name": "Security"},
                {"id": "10001", "key": "PLAT", "name": "Platform"},
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jira-cloud/rest/api/3/project")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    assert body[0]["key"] == "SEC"


# ---------------------------------------------------------------------------
# 9. Lookup endpoint returns 503 when env unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(unavailable_engine: JiraCloudEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/jira-cloud/rest/api/3/project")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "jira_cloud_unavailable"


# ---------------------------------------------------------------------------
# 10. Upstream 404 surfaces as 404 with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(configured_engine: JiraCloudEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "issue/SEC-9999",
        _StubResponse(404, {"errorMessages": ["Issue does not exist"], "errors": {}}),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jira-cloud/rest/api/3/issue/SEC-9999")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "jira_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert "Issue does not exist" in body["detail"]["payload"]["errorMessages"]
