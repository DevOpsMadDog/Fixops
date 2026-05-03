"""Router-level HTTP tests for Bitbucket Cloud pass-through API.

Covers /api/v1/bitbucket/* via FastAPI TestClient with a stub
httpx.Client so no real Bitbucket Cloud call is made.

Tests:
1.  GET /                                                                       — capability summary (unavailable)
2.  GET /                                                                       — capability summary (ok)
3.  GET /2.0/workspaces                                                         — list workspaces
4.  GET /2.0/workspaces/{ws}/repositories                                       — list repos with role/q/sort/pagelen
5.  GET /2.0/repositories/{ws}/{repo}/pipelines                                 — list pipelines + sort filter
6.  POST /2.0/repositories/{ws}/{repo}/pipelines                                — trigger pipeline (201) with variables
7.  POST /2.0/repositories/{ws}/{repo}/pipelines/{uuid}/stopPipeline            — stop pipeline (204)
8.  GET /2.0/repositories/{ws}/{repo}/pipelines/{uuid}/steps                    — list pipeline steps
9.  GET /2.0/repositories/{ws}/{repo}/pullrequests                              — list PRs + state filter
10. GET /2.0/repositories/{ws}/{repo}/branches                                  — list branches
11. GET /2.0/repositories/{ws}/{repo}/commit/{sha}/statuses                     — list commit build statuses
12. unavailable (no env) returns 503 on lookup
13. upstream 404 surfaces as 404 with payload echo
14. HTTP basic auth tuple is attached on every authenticated call
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

import apps.api.bitbucket_router as _router_mod
from apps.api.bitbucket_router import router
from core.bitbucket_engine import (
    BitbucketEngine,
    reset_bitbucket_engine,
)


# ---------------------------------------------------------------------------
# Stub httpx.Client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(
        self,
        status_code: int,
        json_payload: Any = None,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        self.headers = headers or {}
        if json_payload is not None:
            self.content = b"{}"
        elif text:
            self.content = text.encode("utf-8") if isinstance(text, str) else text
        else:
            self.content = b""

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class StubHTTPXClient:
    """Captures requests and returns scripted responses keyed by (method, suffix)."""

    BASE = "https://api.bitbucket.org/"

    def __init__(self, routes: Optional[Dict[str, _StubResponse]] = None) -> None:
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
        auth: Any = None,
    ) -> _StubResponse:
        suffix = url[len(self.BASE):] if url.startswith(self.BASE) else url
        key = f"{method.upper()} {suffix}"
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "suffix": suffix,
                "json": json,
                "params": params,
                "headers": headers,
                "auth": auth,
            }
        )
        if key in self.routes:
            return self.routes[key]
        return _StubResponse(200, {})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton(monkeypatch):
    # Wipe any inherited env so a fresh engine init reflects test intent
    monkeypatch.delenv("BITBUCKET_USER", raising=False)
    monkeypatch.delenv("BITBUCKET_APP_PASSWORD", raising=False)
    reset_bitbucket_engine()
    yield
    reset_bitbucket_engine()


def _build_app(engine: BitbucketEngine) -> TestClient:
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> BitbucketEngine:
    return BitbucketEngine(
        bitbucket_user="aldeci-bot",
        bitbucket_app_password="ATBB-app-pwd-12345",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> BitbucketEngine:
    return BitbucketEngine(
        bitbucket_user="",
        bitbucket_app_password="",
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability — unavailable when env unset
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: BitbucketEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/bitbucket/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Bitbucket Cloud"
    assert body["bitbucket_user_present"] is False
    assert body["bitbucket_app_password_present"] is False
    assert body["status"] == "unavailable"
    assert "/2.0/workspaces" in body["endpoints"]
    assert "/2.0/workspaces/{ws}/repositories" in body["endpoints"]
    assert "/2.0/repositories/{ws}/{repo}/pipelines" in body["endpoints"]
    assert "/2.0/repositories/{ws}/{repo}/pullrequests" in body["endpoints"]
    assert "/2.0/repositories/{ws}/{repo}/branches" in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: BitbucketEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/bitbucket/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["bitbucket_user_present"] is True
    assert body["bitbucket_app_password_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. List workspaces
# ---------------------------------------------------------------------------


def test_list_workspaces(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "2.0/workspaces",
        _StubResponse(
            200,
            {
                "pagelen": 10,
                "page": 1,
                "size": 1,
                "values": [
                    {
                        "type": "workspace",
                        "uuid": "{abc-uuid}",
                        "name": "ALDECI",
                        "slug": "aldeci",
                        "is_private": True,
                        "links": {
                            "owner": {"href": "https://api.bitbucket.org/2.0/users/aldeci"},
                            "html": {"href": "https://bitbucket.org/aldeci/"},
                            "repositories": {
                                "href": "https://api.bitbucket.org/2.0/workspaces/aldeci/repositories"
                            },
                            "projects": {
                                "href": "https://api.bitbucket.org/2.0/workspaces/aldeci/projects"
                            },
                            "snippets": {"href": "https://api.bitbucket.org/2.0/snippets/aldeci"},
                            "members": {
                                "href": "https://api.bitbucket.org/2.0/workspaces/aldeci/members"
                            },
                            "avatar": {"href": "https://bitbucket.org/aldeci/avatar/"},
                        },
                        "created_on": "2026-04-01T00:00:00Z",
                        "updated_on": "2026-05-04T12:00:00Z",
                    }
                ],
                "next": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/bitbucket/2.0/workspaces?pagelen=10&page=1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["pagelen"] == 10
    assert body["page"] == 1
    assert body["size"] == 1
    assert len(body["values"]) == 1
    ws = body["values"][0]
    assert ws["uuid"] == "{abc-uuid}"
    assert ws["slug"] == "aldeci"
    assert ws["is_private"] is True
    # query forwarded
    params = stub.calls[0]["params"]
    assert params["pagelen"] == 10
    assert params["page"] == 1


# ---------------------------------------------------------------------------
# 4. List repositories within workspace
# ---------------------------------------------------------------------------


def test_list_repositories(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "2.0/workspaces/aldeci/repositories",
        _StubResponse(
            200,
            {
                "pagelen": 10,
                "page": 1,
                "size": 1,
                "values": [
                    {
                        "uuid": "{repo-uuid}",
                        "full_name": "aldeci/core",
                        "name": "core",
                        "slug": "core",
                        "description": "ALDECI core",
                        "scm": "git",
                        "is_private": True,
                        "links": {
                            "html": {"href": "https://bitbucket.org/aldeci/core"},
                            "clone": [
                                {
                                    "href": "https://bitbucket.org/aldeci/core.git",
                                    "name": "https",
                                },
                                {
                                    "href": "git@bitbucket.org:aldeci/core.git",
                                    "name": "ssh",
                                },
                            ],
                        },
                        "fork_policy": "no_public_forks",
                        "mainbranch": {"name": "main", "type": "branch"},
                        "owner": {"type": "team", "uuid": "{abc-uuid}"},
                        "project": {"uuid": "{p-uuid}", "key": "ALD", "name": "ALDECI"},
                        "language": "python",
                        "has_issues": True,
                        "has_wiki": False,
                        "created_on": "2026-04-01T00:00:00Z",
                        "updated_on": "2026-05-04T12:00:00Z",
                    }
                ],
                "next": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/bitbucket/2.0/workspaces/aldeci/repositories"
        "?role=admin&q=name~%22core%22&sort=-updated_on&pagelen=10&page=1"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["size"] == 1
    repo = body["values"][0]
    assert repo["full_name"] == "aldeci/core"
    assert repo["scm"] == "git"
    assert repo["mainbranch"]["name"] == "main"
    params = stub.calls[0]["params"]
    assert params["role"] == "admin"
    assert params["q"] == 'name~"core"'
    assert params["sort"] == "-updated_on"
    assert params["pagelen"] == 10
    assert params["page"] == 1


# ---------------------------------------------------------------------------
# 5. List pipelines + sort filter
# ---------------------------------------------------------------------------


def test_list_pipelines_with_sort_filter(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "2.0/repositories/aldeci/core/pipelines",
        _StubResponse(
            200,
            {
                "pagelen": 5,
                "page": 1,
                "size": 2,
                "values": [
                    {
                        "uuid": "{pl-1}",
                        "build_number": 100,
                        "repository": {
                            "type": "repository",
                            "uuid": "{repo-uuid}",
                            "name": "core",
                            "full_name": "aldeci/core",
                        },
                        "target": {
                            "type": "pipeline_ref_target",
                            "ref_type": "branch",
                            "ref_name": "main",
                            "commit": {"type": "commit", "hash": "abc1234"},
                            "selector": {"type": "default", "pattern": "**"},
                        },
                        "state": {
                            "name": "COMPLETED",
                            "type": "pipeline_state_completed",
                            "result": {
                                "name": "SUCCESSFUL",
                                "type": "pipeline_state_completed_successful",
                            },
                        },
                        "creator": {
                            "type": "user",
                            "uuid": "{user-uuid}",
                            "display_name": "Bot",
                            "account_id": "557058:abc",
                        },
                        "created_on": "2026-05-04T10:00:00Z",
                        "completed_on": "2026-05-04T10:05:00Z",
                        "run_number": 1,
                        "duration_in_seconds": 270,
                        "build_seconds_used": 270,
                        "trigger": {"type": "pipeline_trigger_push"},
                    },
                    {
                        "uuid": "{pl-2}",
                        "build_number": 101,
                        "state": {
                            "name": "IN_PROGRESS",
                            "type": "pipeline_state_in_progress",
                            "stage": {
                                "name": "RUNNING",
                                "type": "pipeline_state_in_progress_running",
                            },
                        },
                        "trigger": {"type": "pipeline_trigger_manual"},
                    },
                ],
                "next": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/bitbucket/2.0/repositories/aldeci/core/pipelines?sort=-created_on&pagelen=5"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["size"] == 2
    pipelines = body["values"]
    assert pipelines[0]["state"]["name"] == "COMPLETED"
    assert pipelines[0]["state"]["result"]["name"] == "SUCCESSFUL"
    assert pipelines[1]["state"]["name"] == "IN_PROGRESS"
    assert pipelines[0]["trigger"]["type"] == "pipeline_trigger_push"
    params = stub.calls[0]["params"]
    assert params["sort"] == "-created_on"
    assert params["pagelen"] == 5


# ---------------------------------------------------------------------------
# 6. Trigger pipeline (201) with variables
# ---------------------------------------------------------------------------


def test_trigger_pipeline_with_variables_returns_201(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "2.0/repositories/aldeci/core/pipelines",
        _StubResponse(
            201,
            {
                "uuid": "{pl-200}",
                "build_number": 200,
                "state": {
                    "name": "PENDING",
                    "type": "pipeline_state_pending",
                },
                "target": {
                    "type": "pipeline_ref_target",
                    "ref_type": "branch",
                    "ref_name": "main",
                },
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/bitbucket/2.0/repositories/aldeci/core/pipelines",
        json={
            "target": {
                "type": "pipeline_ref_target",
                "ref_type": "branch",
                "ref_name": "main",
                "selector": {"type": "custom", "pattern": "deploy"},
            },
            "variables": [
                {"key": "DEPLOY_ENV", "value": "staging", "secured": False},
                {"key": "API_TOKEN", "value": "secret", "secured": True},
            ],
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["uuid"] == "{pl-200}"
    assert body["build_number"] == 200
    assert body["state"]["name"] == "PENDING"
    sent = stub.calls[0]["json"]
    assert sent["target"]["ref_name"] == "main"
    assert sent["target"]["selector"]["type"] == "custom"
    assert len(sent["variables"]) == 2
    assert sent["variables"][0]["key"] == "DEPLOY_ENV"
    assert sent["variables"][1]["secured"] is True


# ---------------------------------------------------------------------------
# 7. Stop pipeline (204)
# ---------------------------------------------------------------------------


def test_stop_pipeline_returns_204(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "2.0/repositories/aldeci/core/pipelines/{pl-100}/stopPipeline",
        _StubResponse(204),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/bitbucket/2.0/repositories/aldeci/core/pipelines/{pl-100}/stopPipeline"
    )
    assert resp.status_code == 204
    assert resp.content == b""


# ---------------------------------------------------------------------------
# 8. List pipeline steps
# ---------------------------------------------------------------------------


def test_list_pipeline_steps(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "2.0/repositories/aldeci/core/pipelines/{pl-100}/steps",
        _StubResponse(
            200,
            {
                "pagelen": 10,
                "page": 1,
                "values": [
                    {
                        "uuid": "{step-1}",
                        "name": "build",
                        "image": {"name": "atlassian/default-image:3"},
                        "run_number": 1,
                        "started_on": "2026-05-04T10:00:30Z",
                        "completed_on": "2026-05-04T10:03:00Z",
                        "duration_in_seconds": 150,
                        "build_seconds_used": 150,
                        "state": {
                            "name": "COMPLETED",
                            "type": "pipeline_step_state_completed",
                            "result": {
                                "name": "SUCCESSFUL",
                                "type": "pipeline_step_state_completed_successful",
                            },
                        },
                        "trigger": {"type": "automatic"},
                        "max_time": 60,
                        "script_commands": [
                            {
                                "name": "checkout",
                                "command": "git fetch --all",
                                "type": "BUILD",
                            }
                        ],
                        "logs_url": (
                            "https://api.bitbucket.org/2.0/repositories/aldeci/core/"
                            "pipelines/{pl-100}/steps/{step-1}/log"
                        ),
                    },
                    {
                        "uuid": "{step-2}",
                        "name": "test",
                        "state": {
                            "name": "COMPLETED",
                            "type": "pipeline_step_state_completed",
                            "result": {
                                "name": "FAILED",
                                "type": "pipeline_step_state_completed_failed",
                            },
                        },
                    },
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/bitbucket/2.0/repositories/aldeci/core/pipelines/{pl-100}/steps"
    )
    assert resp.status_code == 200
    body = resp.json()
    steps = body["values"]
    assert len(steps) == 2
    assert steps[0]["name"] == "build"
    assert steps[0]["image"]["name"] == "atlassian/default-image:3"
    assert steps[0]["state"]["result"]["name"] == "SUCCESSFUL"
    assert steps[1]["state"]["result"]["name"] == "FAILED"


# ---------------------------------------------------------------------------
# 9. List pull requests + state filter
# ---------------------------------------------------------------------------


def test_list_pull_requests_with_state(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "2.0/repositories/aldeci/core/pullrequests",
        _StubResponse(
            200,
            {
                "pagelen": 10,
                "page": 1,
                "size": 1,
                "values": [
                    {
                        "id": 42,
                        "type": "pullrequest",
                        "title": "Add bitbucket router",
                        "description": "Wires Bitbucket Cloud REST API",
                        "state": "OPEN",
                        "merge_commit": None,
                        "close_source_branch": True,
                        "closed_by": None,
                        "author": {
                            "type": "user",
                            "uuid": "{user-uuid}",
                            "display_name": "Bot",
                            "account_id": "557058:abc",
                            "links": {
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/users/{user-uuid}"
                                }
                            },
                        },
                        "reason": "",
                        "created_on": "2026-05-04T08:00:00Z",
                        "updated_on": "2026-05-04T09:00:00Z",
                        "source": {
                            "branch": {"name": "feat/bitbucket"},
                            "commit": {"hash": "deadbeef"},
                            "repository": {
                                "type": "repository",
                                "uuid": "{repo-uuid}",
                                "full_name": "aldeci/core",
                            },
                        },
                        "destination": {
                            "branch": {"name": "main"},
                            "commit": {"hash": "cafebabe"},
                            "repository": {
                                "type": "repository",
                                "uuid": "{repo-uuid}",
                                "full_name": "aldeci/core",
                            },
                        },
                        "links": {
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/aldeci/core/pullrequests/42"
                            },
                            "html": {
                                "href": "https://bitbucket.org/aldeci/core/pull-requests/42"
                            },
                            "commits": {
                                "href": "https://api.bitbucket.org/2.0/repositories/aldeci/core/pullrequests/42/commits"
                            },
                            "approve": {
                                "href": "https://api.bitbucket.org/2.0/repositories/aldeci/core/pullrequests/42/approve"
                            },
                            "diff": {
                                "href": "https://api.bitbucket.org/2.0/repositories/aldeci/core/pullrequests/42/diff"
                            },
                            "comments": {
                                "href": "https://api.bitbucket.org/2.0/repositories/aldeci/core/pullrequests/42/comments"
                            },
                        },
                        "summary": {
                            "type": "rendered",
                            "raw": "PR body",
                            "markup": "markdown",
                            "html": "<p>PR body</p>",
                        },
                        "comment_count": 0,
                        "task_count": 0,
                        "reviewers": [],
                    }
                ],
                "next": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/bitbucket/2.0/repositories/aldeci/core/pullrequests?state=OPEN&pagelen=10"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["size"] == 1
    pr = body["values"][0]
    assert pr["id"] == 42
    assert pr["state"] == "OPEN"
    assert pr["source"]["branch"]["name"] == "feat/bitbucket"
    assert pr["destination"]["branch"]["name"] == "main"
    params = stub.calls[0]["params"]
    assert params["state"] == "OPEN"
    assert params["pagelen"] == 10


# ---------------------------------------------------------------------------
# 10. List branches
# ---------------------------------------------------------------------------


def test_list_branches(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "2.0/repositories/aldeci/core/refs/branches",
        _StubResponse(
            200,
            {
                "pagelen": 25,
                "page": 1,
                "size": 2,
                "values": [
                    {
                        "name": "main",
                        "target": {
                            "hash": "abc1234",
                            "type": "commit",
                        },
                        "type": "branch",
                    },
                    {
                        "name": "feat/bitbucket",
                        "target": {
                            "hash": "deadbeef",
                            "type": "commit",
                        },
                        "type": "branch",
                    },
                ],
                "next": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/bitbucket/2.0/repositories/aldeci/core/branches?pagelen=25"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["size"] == 2
    names = {b["name"] for b in body["values"]}
    assert names == {"main", "feat/bitbucket"}
    params = stub.calls[0]["params"]
    assert params["pagelen"] == 25


# ---------------------------------------------------------------------------
# 11. List commit build statuses
# ---------------------------------------------------------------------------


def test_list_commit_statuses(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "2.0/repositories/aldeci/core/commit/abc1234/statuses",
        _StubResponse(
            200,
            {
                "pagelen": 10,
                "page": 1,
                "size": 1,
                "values": [
                    {
                        "type": "build",
                        "key": "BB-PIPELINES",
                        "name": "Bitbucket Pipelines #100",
                        "url": "https://bitbucket.org/aldeci/core/addon/pipelines/home",
                        "state": "SUCCESSFUL",
                        "description": "Build #100 passed",
                        "created_on": "2026-05-04T10:00:00Z",
                        "updated_on": "2026-05-04T10:05:00Z",
                    }
                ],
                "next": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/bitbucket/2.0/repositories/aldeci/core/commit/abc1234/statuses"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["size"] == 1
    status_entry = body["values"][0]
    assert status_entry["state"] == "SUCCESSFUL"
    assert status_entry["key"] == "BB-PIPELINES"


# ---------------------------------------------------------------------------
# 12. Lookup endpoint returns 503 when env unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(
    unavailable_engine: BitbucketEngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/bitbucket/2.0/workspaces")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "bitbucket_unavailable"


# ---------------------------------------------------------------------------
# 13. Upstream 404 surfaces as 404 with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "2.0/repositories/aldeci/missing/pipelines",
        _StubResponse(404, {"type": "error", "error": {"message": "Repository not found"}}),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/bitbucket/2.0/repositories/aldeci/missing/pipelines")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "bitbucket_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["error"]["message"] == "Repository not found"


# ---------------------------------------------------------------------------
# 14. HTTP basic auth tuple is attached on every authenticated call
# ---------------------------------------------------------------------------


def test_basic_auth_attached(
    configured_engine: BitbucketEngine, stub: StubHTTPXClient
) -> None:
    stub.set("GET", "2.0/workspaces", _StubResponse(200, {"values": [], "size": 0}))
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/bitbucket/2.0/workspaces")
    assert resp.status_code == 200
    auth = stub.calls[0]["auth"]
    assert auth == ("aldeci-bot", "ATBB-app-pwd-12345")
    headers = stub.calls[0]["headers"]
    assert headers["Accept"] == "application/json"
