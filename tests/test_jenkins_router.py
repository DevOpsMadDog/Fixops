"""Router-level HTTP tests for Jenkins CI pass-through API.

Covers /api/v1/jenkins/* via FastAPI TestClient with a stub httpx.Client
so no real Jenkins call is made.

Tests:
1.  GET /                                   — capability summary (unavailable when env unset)
2.  GET /                                   — capability summary (ok when env set)
3.  GET /api/json                           — Jenkins root summary
4.  GET /job/{name}/api/json                — job summary
5.  GET /job/{name}/{n}/api/json            — build summary
6.  GET /queue/api/json                     — queue
7.  GET /computer/api/json                  — computers / executors
8.  POST /job/{name}/build                  — trigger build (201 + Location)
9.  POST /job/{name}/build?token=...        — trigger build forwards token param
10. unavailable env returns 503 on lookup endpoint
11. upstream 404 surfaces as 404 with payload echo
12. job name with spaces gets URL-encoded
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

import apps.api.jenkins_router as _router_mod
from apps.api.jenkins_router import router
from core.jenkins_ci_engine import JenkinsCIEngine, reset_jenkins_ci_engine


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
        # Strip the Jenkins base; everything after the host path is the suffix.
        # Test base is https://jenkins.example.com/ so keep the path part.
        base = "https://jenkins.example.com/"
        suffix = url[len(base):] if url.startswith(base) else url
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
    reset_jenkins_ci_engine()
    yield
    reset_jenkins_ci_engine()


def _build_app(engine: JenkinsCIEngine) -> TestClient:
    """Mount the router with engine injection."""
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> JenkinsCIEngine:
    return JenkinsCIEngine(
        jenkins_url="https://jenkins.example.com",
        jenkins_user="bot",
        jenkins_token="tok-12345",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> JenkinsCIEngine:
    return JenkinsCIEngine(
        jenkins_url="",
        jenkins_user="",
        jenkins_token="",
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: JenkinsCIEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/jenkins/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Jenkins"
    assert body["jenkins_url_present"] is False
    assert body["jenkins_user_present"] is False
    assert body["jenkins_token_present"] is False
    assert body["status"] == "unavailable"
    assert "/api/json" in body["endpoints"]
    assert "/job/{name}/api/json" in body["endpoints"]
    assert "/queue/api/json" in body["endpoints"]
    assert "/computer/api/json" in body["endpoints"]
    assert "/job/{name}/build" in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: JenkinsCIEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jenkins/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["jenkins_url_present"] is True
    assert body["jenkins_user_present"] is True
    assert body["jenkins_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. Root summary
# ---------------------------------------------------------------------------


def test_root_summary(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "api/json",
        _StubResponse(
            200,
            {
                "jobs": [
                    {"name": "aldeci-ci", "url": "https://jenkins.example.com/job/aldeci-ci/", "color": "blue"},
                    {"name": "release", "url": "https://jenkins.example.com/job/release/", "color": "red"},
                ],
                "views": [{"name": "All", "url": "https://jenkins.example.com/"}],
                "numExecutors": 4,
                "useSecurity": True,
                "mode": "NORMAL",
                "nodeName": "",
                "nodeDescription": "the master Jenkins node",
                "quietingDown": False,
                "slaveAgentPort": 50000,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jenkins/api/json")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["jobs"]) == 2
    assert body["jobs"][0]["name"] == "aldeci-ci"
    assert body["jobs"][1]["color"] == "red"
    assert body["numExecutors"] == 4
    assert body["useSecurity"] is True
    assert body["mode"] == "NORMAL"
    assert body["nodeDescription"] == "the master Jenkins node"
    assert body["slaveAgentPort"] == 50000
    # BasicAuth was attached
    assert stub.calls[0]["auth"] is not None


# ---------------------------------------------------------------------------
# 4. Job summary
# ---------------------------------------------------------------------------


def test_job_summary(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "job/aldeci-ci/api/json",
        _StubResponse(
            200,
            {
                "name": "aldeci-ci",
                "url": "https://jenkins.example.com/job/aldeci-ci/",
                "displayName": "ALDECI CI",
                "description": "Beast Mode CI",
                "buildable": True,
                "color": "blue",
                "lastBuild": {"number": 142, "url": "https://jenkins.example.com/job/aldeci-ci/142/"},
                "lastSuccessfulBuild": {"number": 142, "url": "https://jenkins.example.com/job/aldeci-ci/142/"},
                "lastFailedBuild": {"number": 138, "url": "https://jenkins.example.com/job/aldeci-ci/138/"},
                "healthReport": [
                    {"description": "Build stability: No recent builds failed.", "score": 100},
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jenkins/job/aldeci-ci/api/json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "aldeci-ci"
    assert body["displayName"] == "ALDECI CI"
    assert body["buildable"] is True
    assert body["color"] == "blue"
    assert body["lastBuild"]["number"] == 142
    assert body["lastFailedBuild"]["number"] == 138
    assert body["healthReport"][0]["score"] == 100


# ---------------------------------------------------------------------------
# 5. Build summary
# ---------------------------------------------------------------------------


def test_build_summary(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "job/aldeci-ci/142/api/json",
        _StubResponse(
            200,
            {
                "number": 142,
                "result": "SUCCESS",
                "building": False,
                "duration": 425000,
                "timestamp": 1735000000000,
                "url": "https://jenkins.example.com/job/aldeci-ci/142/",
                "actions": [
                    {"causes": [{"shortDescription": "Started by user admin", "userId": "admin"}]},
                ],
                "changeSet": {
                    "items": [
                        {"commitId": "abc1234", "msg": "fix(jenkins): wire CI router", "author": {"fullName": "DevOpsMadDog"}},
                    ]
                },
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jenkins/job/aldeci-ci/142/api/json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["number"] == 142
    assert body["result"] == "SUCCESS"
    assert body["building"] is False
    assert body["duration"] == 425000
    assert body["timestamp"] == 1735000000000
    assert body["actions"][0]["causes"][0]["userId"] == "admin"
    assert body["changeSet"]["items"][0]["commitId"] == "abc1234"


# ---------------------------------------------------------------------------
# 6. Queue
# ---------------------------------------------------------------------------


def test_queue_summary(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "queue/api/json",
        _StubResponse(
            200,
            {
                "items": [
                    {
                        "id": 7,
                        "task": {"name": "aldeci-ci", "url": "https://jenkins.example.com/job/aldeci-ci/"},
                        "inQueueSince": 1735000050000,
                        "blocked": True,
                        "why": "Waiting for next available executor",
                        "params": "",
                    }
                ]
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jenkins/queue/api/json")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["id"] == 7
    assert body["items"][0]["task"]["name"] == "aldeci-ci"
    assert body["items"][0]["blocked"] is True
    assert body["items"][0]["why"].startswith("Waiting")


# ---------------------------------------------------------------------------
# 7. Computer (executors)
# ---------------------------------------------------------------------------


def test_computer_summary(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "computer/api/json",
        _StubResponse(
            200,
            {
                "computer": [
                    {
                        "displayName": "master",
                        "idle": False,
                        "jnlpAgent": False,
                        "launchSupported": True,
                        "manualLaunchAllowed": True,
                        "monitorData": {"swap": "N/A"},
                        "numExecutors": 4,
                        "offline": False,
                        "temporarilyOffline": False,
                    }
                ],
                "totalExecutors": 4,
                "busyExecutors": 2,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jenkins/computer/api/json")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["computer"]) == 1
    assert body["computer"][0]["displayName"] == "master"
    assert body["computer"][0]["numExecutors"] == 4
    assert body["computer"][0]["offline"] is False
    assert body["totalExecutors"] == 4
    assert body["busyExecutors"] == 2


# ---------------------------------------------------------------------------
# 8. Trigger build (201 + Location)
# ---------------------------------------------------------------------------


def test_trigger_build_returns_201(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "POST",
        "job/aldeci-ci/build",
        _StubResponse(
            201,
            None,
            text="",
            headers={"Location": "https://jenkins.example.com/queue/item/8/"},
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post("/api/v1/jenkins/job/aldeci-ci/build")
    assert resp.status_code == 201
    body = resp.json()
    assert body["queued"] is True
    assert body["location"] == "https://jenkins.example.com/queue/item/8/"


# ---------------------------------------------------------------------------
# 9. Trigger build with token
# ---------------------------------------------------------------------------


def test_trigger_build_forwards_token(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "POST",
        "job/aldeci-ci/build",
        _StubResponse(201, None, text="", headers={"Location": "https://jenkins.example.com/queue/item/9/"}),
    )
    client = _build_app(configured_engine)
    resp = client.post("/api/v1/jenkins/job/aldeci-ci/build?token=secret-token")
    assert resp.status_code == 201
    # token forwarded as query param to upstream
    assert stub.calls[0]["params"] == {"token": "secret-token"}


# ---------------------------------------------------------------------------
# 10. Lookup endpoint returns 503 when env unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(unavailable_engine: JenkinsCIEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/jenkins/queue/api/json")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "jenkins_ci_unavailable"


# ---------------------------------------------------------------------------
# 11. Upstream 404 surfaces as 404 with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "job/missing/api/json",
        _StubResponse(404, {"error": "no such job", "name": "missing"}),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/jenkins/job/missing/api/json")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "jenkins_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["error"] == "no such job"


# ---------------------------------------------------------------------------
# 12. Job name with spaces is URL-encoded
# ---------------------------------------------------------------------------


def test_job_name_with_spaces_url_encoded(configured_engine: JenkinsCIEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "job/My%20Pipeline/api/json",
        _StubResponse(200, {"name": "My Pipeline", "color": "blue", "buildable": True}),
    )
    client = _build_app(configured_engine)
    # FastAPI accepts the encoded path
    resp = client.get("/api/v1/jenkins/job/My Pipeline/api/json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "My Pipeline"
    assert stub.calls[0]["suffix"] == "job/My%20Pipeline/api/json"
