"""Router-level HTTP tests for CircleCI v2 pass-through API.

Covers /api/v1/circleci/* via FastAPI TestClient with a stub httpx.Client
so no real CircleCI call is made.

Tests:
1.  GET /                                    — capability summary (unavailable when env unset)
2.  GET /                                    — capability summary (ok when env set)
3.  GET /api/v2/project/{slug}/pipeline      — list pipelines + Circle-Token header
4.  GET pipeline list with branch + page_token query forwarded
5.  POST /api/v2/project/{slug}/pipeline     — trigger pipeline body forwarded
6.  GET /api/v2/pipeline/{id}                — pipeline detail
7.  GET /api/v2/pipeline/{id}/workflow       — workflow list
8.  GET /api/v2/workflow/{id}                — workflow detail
9.  POST /api/v2/workflow/{id}/cancel        — cancel
10. POST /api/v2/workflow/{id}/rerun         — rerun body forwarded
11. GET /api/v2/workflow/{id}/job            — job list
12. GET insights workflows                   — metrics + trends
13. unavailable env returns 503 on lookup endpoint
14. upstream 404 surfaces as 404 with payload echo
15. project_slug with forward slashes is preserved verbatim
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

import apps.api.circleci_router as _router_mod
from apps.api.circleci_router import router
from core.circleci_engine import CircleCIEngine, reset_circleci_engine


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
    """Captures requests and returns scripted responses keyed by (method, path-suffix)."""

    BASE = "https://circleci.com/"

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
def _reset_singleton():
    """Each test gets a fresh engine singleton."""
    reset_circleci_engine()
    yield
    reset_circleci_engine()


def _build_app(engine: CircleCIEngine) -> TestClient:
    """Mount the router with engine injection."""
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> CircleCIEngine:
    return CircleCIEngine(
        token="ccitok-12345",
        base_url="https://circleci.com",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> CircleCIEngine:
    return CircleCIEngine(token="", client=httpx.Client())


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: CircleCIEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/circleci/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "CircleCI v2"
    assert body["token_present"] is False
    assert body["status"] == "unavailable"
    assert "/api/v2/project/{slug}/pipeline" in body["endpoints"]
    assert "/api/v2/pipeline/{id}/workflow" in body["endpoints"]
    assert "/api/v2/workflow/{id}/job" in body["endpoints"]
    assert "/api/v2/insights/workflows" in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: CircleCIEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/circleci/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. List pipelines — Circle-Token header attached
# ---------------------------------------------------------------------------


def test_list_pipelines(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/project/gh/myorg/myrepo/pipeline",
        _StubResponse(
            200,
            {
                "items": [
                    {
                        "id": "pipe-abc",
                        "errors": [],
                        "project_slug": "gh/myorg/myrepo",
                        "updated_at": "2026-05-04T12:00:00Z",
                        "number": 42,
                        "state": "created",
                        "created_at": "2026-05-04T11:59:00Z",
                        "trigger": {
                            "type": "webhook",
                            "received_at": "2026-05-04T11:58:55Z",
                            "actor": {
                                "login": "DevOpsMadDog",
                                "avatar_url": "https://avatars.example.com/u/1",
                            },
                        },
                        "vcs": {
                            "provider_name": "GitHub",
                            "target_repository_url": "https://github.com/myorg/myrepo",
                            "branch": "main",
                            "revision": "abc123def456",
                            "commit": {
                                "subject": "feat: ship CircleCI router",
                                "body": "details",
                            },
                            "origin_repository_url": "https://github.com/myorg/myrepo",
                        },
                    }
                ],
                "next_page_token": "tok-next",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/circleci/api/v2/project/gh/myorg/myrepo/pipeline")
    assert resp.status_code == 200
    body = resp.json()
    assert body["next_page_token"] == "tok-next"
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["id"] == "pipe-abc"
    assert item["number"] == 42
    assert item["state"] == "created"
    assert item["trigger"]["type"] == "webhook"
    assert item["trigger"]["actor"]["login"] == "DevOpsMadDog"
    assert item["vcs"]["branch"] == "main"
    assert item["vcs"]["commit"]["subject"].startswith("feat:")
    # Header Circle-Token attached
    sent = stub.calls[0]["headers"]
    assert sent.get("Circle-Token") == "ccitok-12345"


# ---------------------------------------------------------------------------
# 4. List pipelines forwards branch + page-token query params
# ---------------------------------------------------------------------------


def test_list_pipelines_forwards_query_params(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/project/gh/myorg/myrepo/pipeline",
        _StubResponse(200, {"items": [], "next_page_token": None}),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/circleci/api/v2/project/gh/myorg/myrepo/pipeline"
        "?branch=feature/x&page-token=abc"
    )
    assert resp.status_code == 200
    sent = stub.calls[0]["params"]
    assert sent == {"branch": "feature/x", "page-token": "abc"}


# ---------------------------------------------------------------------------
# 5. Trigger pipeline — body forwarded, 201 returned
# ---------------------------------------------------------------------------


def test_trigger_pipeline(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "api/v2/project/gh/myorg/myrepo/pipeline",
        _StubResponse(
            201,
            {
                "id": "pipe-new",
                "state": "created",
                "number": 43,
                "created_at": "2026-05-04T12:30:00Z",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/circleci/api/v2/project/gh/myorg/myrepo/pipeline",
        json={
            "branch": "main",
            "parameters": {"deploy": True, "env": "prod"},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["id"] == "pipe-new"
    assert body["state"] == "created"
    assert body["number"] == 43
    sent = stub.calls[0]["json"]
    assert sent == {
        "branch": "main",
        "parameters": {"deploy": True, "env": "prod"},
    }


# ---------------------------------------------------------------------------
# 6. Pipeline detail
# ---------------------------------------------------------------------------


def test_get_pipeline(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/pipeline/pipe-abc",
        _StubResponse(
            200,
            {
                "id": "pipe-abc",
                "errors": [],
                "project_slug": "gh/myorg/myrepo",
                "number": 42,
                "state": "created",
                "created_at": "2026-05-04T11:59:00Z",
                "updated_at": "2026-05-04T12:00:00Z",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/circleci/api/v2/pipeline/pipe-abc")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "pipe-abc"
    assert body["state"] == "created"
    assert body["number"] == 42


# ---------------------------------------------------------------------------
# 7. List workflows for a pipeline
# ---------------------------------------------------------------------------


def test_list_workflows(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/pipeline/pipe-abc/workflow",
        _StubResponse(
            200,
            {
                "items": [
                    {
                        "id": "wf-1",
                        "name": "build-and-test",
                        "project_slug": "gh/myorg/myrepo",
                        "status": "success",
                        "started_by": "user-99",
                        "pipeline_id": "pipe-abc",
                        "pipeline_number": 42,
                        "created_at": "2026-05-04T11:59:10Z",
                        "stopped_at": "2026-05-04T12:05:00Z",
                    },
                    {
                        "id": "wf-2",
                        "name": "deploy",
                        "project_slug": "gh/myorg/myrepo",
                        "status": "on_hold",
                        "pipeline_id": "pipe-abc",
                        "pipeline_number": 42,
                        "created_at": "2026-05-04T12:05:30Z",
                    },
                ],
                "next_page_token": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/circleci/api/v2/pipeline/pipe-abc/workflow")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 2
    assert body["items"][0]["name"] == "build-and-test"
    assert body["items"][0]["status"] == "success"
    assert body["items"][1]["status"] == "on_hold"


# ---------------------------------------------------------------------------
# 8. Workflow detail
# ---------------------------------------------------------------------------


def test_get_workflow(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/workflow/wf-1",
        _StubResponse(
            200,
            {
                "id": "wf-1",
                "name": "build-and-test",
                "project_slug": "gh/myorg/myrepo",
                "status": "running",
                "started_by": "user-99",
                "pipeline_id": "pipe-abc",
                "pipeline_number": 42,
                "created_at": "2026-05-04T11:59:10Z",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/circleci/api/v2/workflow/wf-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "wf-1"
    assert body["status"] == "running"


# ---------------------------------------------------------------------------
# 9. Cancel workflow
# ---------------------------------------------------------------------------


def test_cancel_workflow(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "api/v2/workflow/wf-1/cancel",
        _StubResponse(202, {"message": "Accepted."}),
    )
    client = _build_app(configured_engine)
    resp = client.post("/api/v1/circleci/api/v2/workflow/wf-1/cancel")
    assert resp.status_code == 200
    body = resp.json()
    assert body["message"] == "Accepted."
    assert stub.calls[0]["method"] == "POST"
    assert stub.calls[0]["suffix"] == "api/v2/workflow/wf-1/cancel"


# ---------------------------------------------------------------------------
# 10. Rerun workflow — body forwarded
# ---------------------------------------------------------------------------


def test_rerun_workflow_forwards_body(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "POST",
        "api/v2/workflow/wf-1/rerun",
        _StubResponse(202, {"workflow_id": "wf-1-rerun", "message": "Accepted."}),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/circleci/api/v2/workflow/wf-1/rerun",
        json={
            "from_failed": True,
            "enable_ssh": False,
            "jobs": ["job-7"],
            "sparse_tree": True,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["workflow_id"] == "wf-1-rerun"
    sent = stub.calls[0]["json"]
    assert sent == {
        "jobs": ["job-7"],
        "from_failed": True,
        "sparse_tree": True,
        "enable_ssh": False,
    }


# ---------------------------------------------------------------------------
# 11. List workflow jobs
# ---------------------------------------------------------------------------


def test_list_workflow_jobs(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/workflow/wf-1/job",
        _StubResponse(
            200,
            {
                "items": [
                    {
                        "canceled_by": None,
                        "dependencies": [],
                        "job_number": 11,
                        "id": "job-7",
                        "started_at": "2026-05-04T12:00:01Z",
                        "name": "test",
                        "project_slug": "gh/myorg/myrepo",
                        "status": "success",
                        "type": "build",
                        "stopped_at": "2026-05-04T12:04:00Z",
                    },
                    {
                        "dependencies": ["job-7"],
                        "id": "job-approve",
                        "name": "approval-gate",
                        "project_slug": "gh/myorg/myrepo",
                        "status": "queued",
                        "type": "approval",
                        "approval_request_id": "ar-1",
                    },
                ],
                "next_page_token": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/circleci/api/v2/workflow/wf-1/job")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 2
    assert body["items"][0]["job_number"] == 11
    assert body["items"][0]["type"] == "build"
    assert body["items"][1]["type"] == "approval"
    assert body["items"][1]["approval_request_id"] == "ar-1"


# ---------------------------------------------------------------------------
# 12. Workflow insights
# ---------------------------------------------------------------------------


def test_workflow_insights(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/insights/gh/myorg/myrepo/workflows/build-and-test",
        _StubResponse(
            200,
            {
                "items": [
                    {
                        "name": "build-and-test",
                        "window_start": "2026-05-01T00:00:00Z",
                        "window_end": "2026-05-04T00:00:00Z",
                        "metrics": {
                            "success_rate": 0.92,
                            "total_runs": 50,
                            "successful_runs": 46,
                            "mttr": 1800.0,
                            "total_credits_used": 12000,
                            "failed_runs": 4,
                            "median_credits_used": 240,
                            "throughput": 16.5,
                            "total_recoveries": 4,
                            "duration_metrics": {
                                "min": 60,
                                "max": 600,
                                "median": 240,
                            },
                        },
                        "trends": {
                            "total_runs": 0.05,
                            "success_rate": 0.02,
                            "total_credits_used": -0.10,
                            "failed_runs": -0.50,
                            "mttr": -0.20,
                            "throughput": 0.05,
                            "total_recoveries": 0.0,
                        },
                    }
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/circleci/api/v2/project/gh/myorg/myrepo/insights/workflows/"
        "build-and-test?branch=main&start-date=2026-05-01&end-date=2026-05-04"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["name"] == "build-and-test"
    assert item["metrics"]["success_rate"] == 0.92
    assert item["metrics"]["total_runs"] == 50
    assert item["metrics"]["duration_metrics"]["median"] == 240
    assert item["trends"]["failed_runs"] == -0.5
    sent = stub.calls[0]["params"]
    assert sent == {
        "branch": "main",
        "start-date": "2026-05-01",
        "end-date": "2026-05-04",
    }


# ---------------------------------------------------------------------------
# 13. Lookup endpoint returns 503 when env unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(
    unavailable_engine: CircleCIEngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/circleci/api/v2/pipeline/pipe-abc")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "circleci_unavailable"


# ---------------------------------------------------------------------------
# 14. Upstream 404 surfaces as 404 with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/pipeline/missing",
        _StubResponse(
            404, {"message": "Pipeline not found", "type": "not-found"}
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/circleci/api/v2/pipeline/missing")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "circleci_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["message"] == "Pipeline not found"


# ---------------------------------------------------------------------------
# 15. Project slug forward-slashes preserved verbatim
# ---------------------------------------------------------------------------


def test_project_slug_with_slashes_preserved(
    configured_engine: CircleCIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "api/v2/project/bb/team/repo-name/pipeline",
        _StubResponse(200, {"items": [], "next_page_token": None}),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/circleci/api/v2/project/bb/team/repo-name/pipeline"
    )
    assert resp.status_code == 200
    assert stub.calls[0]["suffix"] == "api/v2/project/bb/team/repo-name/pipeline"
