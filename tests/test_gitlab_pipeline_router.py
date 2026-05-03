"""Router-level HTTP tests for GitLab CI/CD pass-through API.

Covers /api/v1/gitlab-pipeline/* via FastAPI TestClient with a stub
httpx.Client so no real GitLab call is made.

Tests:
1.  GET /                                   — capability summary (unavailable when env unset)
2.  GET /                                   — capability summary (ok when token set)
3.  GET /api/v4/projects                    — list projects + query passthrough
4.  GET /api/v4/projects/{id}/pipelines     — list pipelines + status filter
5.  GET single pipeline                      — full PipelineDetail
6.  POST /api/v4/projects/{id}/pipeline     — trigger w/ variables (201)
7.  POST cancel/retry pipeline + DELETE 204
8.  GET /jobs + scope filter
9.  GET /pipelines/{pid}/jobs + include_retried
10. GET single job + POST retry/cancel job
11. unavailable (no GITLAB_TOKEN) returns 503 on lookup
12. upstream 404 surfaces as 404 with payload echo
13. PRIVATE-TOKEN header is attached on every authenticated call
14. project_id can be a URL-encoded path (group%2Fproject)
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

import apps.api.gitlab_pipeline_router as _router_mod
from apps.api.gitlab_pipeline_router import router
from core.gitlab_pipeline_engine import (
    GitLabPipelineEngine,
    reset_gitlab_pipeline_engine,
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

    BASE = "https://gitlab.example.com/"

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
    monkeypatch.delenv("GITLAB_URL", raising=False)
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    reset_gitlab_pipeline_engine()
    yield
    reset_gitlab_pipeline_engine()


def _build_app(engine: GitLabPipelineEngine) -> TestClient:
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> GitLabPipelineEngine:
    return GitLabPipelineEngine(
        gitlab_url="https://gitlab.example.com",
        gitlab_token="glpat-12345",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> GitLabPipelineEngine:
    # No URL, no token → status=unavailable; default URL fallback irrelevant
    return GitLabPipelineEngine(
        gitlab_url="",
        gitlab_token="",
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability — unavailable when token unset
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: GitLabPipelineEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/gitlab-pipeline/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "GitLab CI/CD"
    assert body["gitlab_url_present"] is False
    assert body["gitlab_token_present"] is False
    assert body["status"] == "unavailable"
    assert "/api/v4/projects" in body["endpoints"]
    assert "/api/v4/projects/{id}/pipelines" in body["endpoints"]
    assert "/api/v4/projects/{id}/jobs" in body["endpoints"]
    assert "/api/v4/projects/{id}/pipelines/{pid}/jobs" in body["endpoints"]
    assert "/api/v4/projects/{id}/pipeline (POST trigger)" in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: GitLabPipelineEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/gitlab-pipeline/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["gitlab_url_present"] is True
    assert body["gitlab_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. List projects + query passthrough
# ---------------------------------------------------------------------------


def test_list_projects(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v4/projects",
        _StubResponse(
            200,
            [
                {
                    "id": 1,
                    "description": "ALDECI core",
                    "default_branch": "main",
                    "visibility": "private",
                    "ssh_url_to_repo": "git@gitlab.example.com:aldeci/core.git",
                    "http_url_to_repo": "https://gitlab.example.com/aldeci/core.git",
                    "web_url": "https://gitlab.example.com/aldeci/core",
                    "name": "core",
                    "name_with_namespace": "ALDECI / core",
                    "path": "core",
                    "path_with_namespace": "aldeci/core",
                    "created_at": "2026-04-01T00:00:00Z",
                    "last_activity_at": "2026-05-04T12:00:00Z",
                    "namespace": {
                        "id": 10,
                        "name": "ALDECI",
                        "path": "aldeci",
                        "kind": "group",
                        "full_path": "aldeci",
                    },
                    "archived": False,
                    "forks_count": 2,
                    "star_count": 17,
                    "open_issues_count": 4,
                    "default_protected_branch": "main",
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gitlab-pipeline/api/v4/projects"
        "?membership=true&per_page=10&page=2&search=core&order_by=last_activity_at&sort=desc"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    proj = body[0]
    assert proj["id"] == 1
    assert proj["visibility"] == "private"
    assert proj["namespace"]["full_path"] == "aldeci"
    assert proj["star_count"] == 17
    # query forwarded to upstream
    params = stub.calls[0]["params"]
    assert params["membership"] == "true"
    assert params["per_page"] == 10
    assert params["page"] == 2
    assert params["search"] == "core"
    assert params["order_by"] == "last_activity_at"
    assert params["sort"] == "desc"


# ---------------------------------------------------------------------------
# 4. List pipelines + status filter
# ---------------------------------------------------------------------------


def test_list_pipelines_with_status_filter(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v4/projects/1/pipelines",
        _StubResponse(
            200,
            [
                {
                    "id": 100,
                    "project_id": 1,
                    "sha": "abc1234",
                    "ref": "main",
                    "status": "success",
                    "source": "push",
                    "created_at": "2026-05-04T10:00:00Z",
                    "updated_at": "2026-05-04T10:05:00Z",
                    "web_url": "https://gitlab.example.com/aldeci/core/-/pipelines/100",
                },
                {
                    "id": 101,
                    "project_id": 1,
                    "sha": "def5678",
                    "ref": "main",
                    "status": "running",
                    "source": "schedule",
                    "created_at": "2026-05-04T11:00:00Z",
                    "updated_at": "2026-05-04T11:01:00Z",
                    "web_url": "https://gitlab.example.com/aldeci/core/-/pipelines/101",
                },
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gitlab-pipeline/api/v4/projects/1/pipelines?status=running&per_page=5"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2  # stub returns both — confirming filter is forwarded
    assert body[0]["status"] == "success"
    assert body[1]["status"] == "running"
    params = stub.calls[0]["params"]
    assert params["status"] == "running"
    assert params["per_page"] == 5


# ---------------------------------------------------------------------------
# 5. Get pipeline detail
# ---------------------------------------------------------------------------


def test_get_pipeline_detail(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v4/projects/1/pipelines/100",
        _StubResponse(
            200,
            {
                "id": 100,
                "project_id": 1,
                "sha": "abc1234",
                "ref": "main",
                "status": "success",
                "source": "push",
                "before_sha": "0000000000000000000000000000000000000000",
                "tag": False,
                "yaml_errors": None,
                "user": {
                    "id": 9,
                    "name": "Bot",
                    "username": "bot",
                    "state": "active",
                    "avatar_url": "https://gitlab.example.com/avatar.png",
                    "web_url": "https://gitlab.example.com/bot",
                },
                "created_at": "2026-05-04T10:00:00Z",
                "updated_at": "2026-05-04T10:05:00Z",
                "started_at": "2026-05-04T10:00:30Z",
                "finished_at": "2026-05-04T10:05:00Z",
                "committed_at": "2026-05-04T09:59:00Z",
                "duration": 270.5,
                "queued_duration": 30.0,
                "coverage": "92.4",
                "detailed_status": {
                    "icon": "status_success",
                    "text": "passed",
                    "label": "passed",
                    "group": "success",
                    "tooltip": "passed",
                    "has_details": True,
                    "details_path": "/aldeci/core/-/pipelines/100",
                    "illustration": None,
                    "favicon": "favicon_status_success.png",
                },
                "web_url": "https://gitlab.example.com/aldeci/core/-/pipelines/100",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/gitlab-pipeline/api/v4/projects/1/pipelines/100")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 100
    assert body["sha"] == "abc1234"
    assert body["status"] == "success"
    assert body["user"]["username"] == "bot"
    assert body["duration"] == 270.5
    assert body["detailed_status"]["group"] == "success"
    assert body["detailed_status"]["has_details"] is True


# ---------------------------------------------------------------------------
# 6. Trigger pipeline (201) with variables
# ---------------------------------------------------------------------------


def test_trigger_pipeline_with_variables_returns_201(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "api/v4/projects/1/pipeline",
        _StubResponse(
            201,
            {
                "id": 200,
                "project_id": 1,
                "sha": "newsha",
                "ref": "main",
                "status": "pending",
                "source": "api",
                "web_url": "https://gitlab.example.com/aldeci/core/-/pipelines/200",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/gitlab-pipeline/api/v4/projects/1/pipeline",
        json={
            "ref": "main",
            "variables": [
                {"key": "DEPLOY_ENV", "value": "staging", "variable_type": "env_var"},
                {"key": "CONFIG", "value": "cfg.yaml", "variable_type": "file"},
            ],
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["id"] == 200
    assert body["status"] == "pending"
    sent = stub.calls[0]["json"]
    assert sent["ref"] == "main"
    assert len(sent["variables"]) == 2
    assert sent["variables"][0]["key"] == "DEPLOY_ENV"
    assert sent["variables"][1]["variable_type"] == "file"


# ---------------------------------------------------------------------------
# 7. Cancel + retry + delete pipeline
# ---------------------------------------------------------------------------


def test_pipeline_lifecycle_cancel_retry_delete(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "api/v4/projects/1/pipelines/100/cancel",
        _StubResponse(200, {"id": 100, "status": "canceled", "project_id": 1}),
    )
    stub.set(
        "POST",
        "api/v4/projects/1/pipelines/100/retry",
        _StubResponse(200, {"id": 100, "status": "pending", "project_id": 1}),
    )
    stub.set("DELETE", "api/v4/projects/1/pipelines/100", _StubResponse(204))
    client = _build_app(configured_engine)

    r1 = client.post("/api/v1/gitlab-pipeline/api/v4/projects/1/pipelines/100/cancel")
    assert r1.status_code == 200
    assert r1.json()["status"] == "canceled"

    r2 = client.post("/api/v1/gitlab-pipeline/api/v4/projects/1/pipelines/100/retry")
    assert r2.status_code == 200
    assert r2.json()["status"] == "pending"

    r3 = client.delete("/api/v1/gitlab-pipeline/api/v4/projects/1/pipelines/100")
    assert r3.status_code == 204
    assert r3.content == b""


# ---------------------------------------------------------------------------
# 8. List jobs + scope filter
# ---------------------------------------------------------------------------


def test_list_jobs_with_scope(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v4/projects/1/jobs",
        _StubResponse(
            200,
            [
                {
                    "id": 9001,
                    "status": "failed",
                    "stage": "test",
                    "name": "pytest",
                    "ref": "main",
                    "tag": False,
                    "coverage": None,
                    "allow_failure": False,
                    "duration": 42.0,
                    "queued_duration": 1.5,
                    "web_url": "https://gitlab.example.com/aldeci/core/-/jobs/9001",
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gitlab-pipeline/api/v4/projects/1/jobs?scope=failed&per_page=50"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["status"] == "failed"
    params = stub.calls[0]["params"]
    assert params["scope"] == "failed"
    assert params["per_page"] == 50


# ---------------------------------------------------------------------------
# 9. List pipeline jobs + include_retried passthrough
# ---------------------------------------------------------------------------


def test_list_pipeline_jobs_include_retried(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v4/projects/1/pipelines/100/jobs",
        _StubResponse(
            200,
            [
                {"id": 9001, "status": "success", "stage": "build", "name": "compile"},
                {"id": 9002, "status": "success", "stage": "test", "name": "pytest"},
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/gitlab-pipeline/api/v4/projects/1/pipelines/100/jobs"
        "?include_retried=true&per_page=25"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    assert {j["name"] for j in body} == {"compile", "pytest"}
    params = stub.calls[0]["params"]
    assert params["include_retried"] == "true"
    assert params["per_page"] == 25


# ---------------------------------------------------------------------------
# 10. Single job + retry/cancel
# ---------------------------------------------------------------------------


def test_job_lifecycle_get_retry_cancel(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v4/projects/1/jobs/9001",
        _StubResponse(
            200,
            {
                "id": 9001,
                "status": "failed",
                "stage": "test",
                "name": "pytest",
                "ref": "main",
                "tag": False,
                "duration": 42.0,
                "queued_duration": 1.5,
                "user": {"id": 9, "name": "Bot"},
                "commit": {"id": "abc1234"},
                "pipeline": {"id": 100},
                "web_url": "https://gitlab.example.com/aldeci/core/-/jobs/9001",
                "project": {"id": 1, "ci_job_token_scope_enabled": False},
                "artifacts": [{"file_type": "trace", "size": 1024}],
                "runner": {"id": 5, "description": "shared-runner-1"},
                "artifacts_expire_at": "2026-06-01T00:00:00Z",
                "archived": False,
            },
        ),
    )
    stub.set(
        "POST",
        "api/v4/projects/1/jobs/9001/retry",
        _StubResponse(200, {"id": 9002, "status": "pending", "name": "pytest"}),
    )
    stub.set(
        "POST",
        "api/v4/projects/1/jobs/9001/cancel",
        _StubResponse(200, {"id": 9001, "status": "canceled", "name": "pytest"}),
    )
    client = _build_app(configured_engine)

    r1 = client.get("/api/v1/gitlab-pipeline/api/v4/projects/1/jobs/9001")
    assert r1.status_code == 200
    body = r1.json()
    assert body["id"] == 9001
    assert body["pipeline"]["id"] == 100
    assert body["artifacts"][0]["file_type"] == "trace"
    assert body["runner"]["description"] == "shared-runner-1"

    r2 = client.post("/api/v1/gitlab-pipeline/api/v4/projects/1/jobs/9001/retry")
    assert r2.status_code == 200
    assert r2.json()["id"] == 9002
    assert r2.json()["status"] == "pending"

    r3 = client.post("/api/v1/gitlab-pipeline/api/v4/projects/1/jobs/9001/cancel")
    assert r3.status_code == 200
    assert r3.json()["status"] == "canceled"


# ---------------------------------------------------------------------------
# 11. Lookup endpoint returns 503 when token unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(
    unavailable_engine: GitLabPipelineEngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/gitlab-pipeline/api/v4/projects")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "gitlab_pipeline_unavailable"


# ---------------------------------------------------------------------------
# 12. Upstream 404 surfaces as 404 with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v4/projects/999/pipelines/100",
        _StubResponse(404, {"message": "404 Not found"}),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/gitlab-pipeline/api/v4/projects/999/pipelines/100")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "gitlab_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["message"] == "404 Not found"


# ---------------------------------------------------------------------------
# 13. PRIVATE-TOKEN header is attached on calls
# ---------------------------------------------------------------------------


def test_private_token_header_attached(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    stub.set("GET", "api/v4/projects", _StubResponse(200, []))
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/gitlab-pipeline/api/v4/projects")
    assert resp.status_code == 200
    headers = stub.calls[0]["headers"]
    assert headers["PRIVATE-TOKEN"] == "glpat-12345"
    assert headers["Accept"] == "application/json"


# ---------------------------------------------------------------------------
# 14. project_id is URL-encoded by the engine when non-numeric
# ---------------------------------------------------------------------------


def test_project_id_path_style_is_url_encoded_by_engine(
    configured_engine: GitLabPipelineEngine, stub: StubHTTPXClient
) -> None:
    """Non-numeric project_id (e.g. ``aldeci/core``) is forwarded URL-encoded.

    A direct engine call exercises the path-style id path because FastAPI's
    route matcher consumes literal ``/`` before the engine sees it; the
    engine ``_project_id_segment`` helper guarantees encoding.
    """
    stub.set(
        "GET",
        "api/v4/projects/aldeci%2Fcore/pipelines",
        _StubResponse(200, [{"id": 100, "project_id": 1, "status": "success"}]),
    )
    out = configured_engine.list_pipelines("aldeci/core")
    assert len(out) == 1
    assert stub.calls[0]["suffix"] == "api/v4/projects/aldeci%2Fcore/pipelines"

    # And a non-numeric no-slash id from the router path also passes through
    stub.set(
        "GET",
        "api/v4/projects/my-project/pipelines",
        _StubResponse(200, [{"id": 101, "project_id": 2, "status": "success"}]),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/gitlab-pipeline/api/v4/projects/my-project/pipelines")
    assert resp.status_code == 200
    assert resp.json()[0]["id"] == 101
