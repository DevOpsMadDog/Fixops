"""Tests for harness_router — ALDECI Harness CD platform.

NO MOCKS rule:
  * When HARNESS_API_KEY / HARNESS_ACCOUNT_ID are unset, capability summary
    reports ``status="unavailable"`` and every live endpoint returns 503.
  * Happy-path tests inject a stub httpx.Client so we exercise the real
    parsing code paths without hitting the network.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

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
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Routes calls by URL substring -> queued response."""

    def __init__(
        self,
        get_responses: Optional[Dict[str, Any]] = None,
        post_responses: Optional[Dict[str, Any]] = None,
    ):
        self._get = get_responses or {}
        self._post = post_responses or {}
        self.calls: List[Dict[str, Any]] = []

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "params": params or {},
                "headers": headers or {},
            }
        )
        for needle, resp in self._get.items():
            if needle in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def post(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        content: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "params": params or {},
                "json": json,
                "content": content,
                "data": data,
                "headers": headers or {},
            }
        )
        for needle, resp in self._post.items():
            if needle in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


def _build_app(
    *,
    api_key: Optional[str],
    account_id: Optional[str],
    base_url: Optional[str] = None,
    get_responses: Optional[Dict[str, Any]] = None,
    post_responses: Optional[Dict[str, Any]] = None,
):
    """Construct an isolated FastAPI app with the Harness router mounted."""
    from core import harness_cd_engine as engine_mod

    engine_mod.reset_harness_cd_engine()
    stub = _StubClient(get_responses or {}, post_responses or {})

    engine_mod.get_harness_cd_engine(
        api_key=api_key,
        account_id=account_id,
        base_url=base_url,
        client=stub,
    )

    from apps.api.harness_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import harness_cd_engine as engine_mod
    engine_mod.reset_harness_cd_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("HARNESS_API_KEY", raising=False)
    monkeypatch.delenv("HARNESS_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("HARNESS_BASE_URL", raising=False)
    app, _ = _build_app(api_key=None, account_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/harness/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Harness CD"
    assert "/pipeline/api/pipelines" in body["endpoints"]
    assert "/pipeline/api/pipelines/execute" in body["endpoints"]
    assert "/ng/api/services" in body["endpoints"]
    assert "/ng/api/environments" in body["endpoints"]
    assert "/pipeline/api/pipelines/execution" in body["endpoints"]
    assert body["api_key_present"] is False
    assert body["account_id_present"] is False
    assert body["base_url"] == "https://app.harness.io"
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_creds_present(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    app, _ = _build_app(api_key="pat.abc", account_id="acct-123")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/harness/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api_key_present"] is True
    assert body["account_id_present"] is True
    assert body["status"] == "empty"
    assert body["base_url"] == "https://app.harness.io"
    _reset()


def test_capability_summary_honors_custom_base_url(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    monkeypatch.setenv("HARNESS_BASE_URL", "https://app3.harness.io/")
    app, _ = _build_app(
        api_key="pat.abc",
        account_id="acct-123",
        base_url="https://app3.harness.io/",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/harness/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    # trailing slash trimmed
    assert body["base_url"] == "https://app3.harness.io"
    _reset()


# ---------------------------------------------------------------------------
# 503 — credentials missing
# ---------------------------------------------------------------------------


def test_list_pipelines_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("HARNESS_API_KEY", raising=False)
    monkeypatch.delenv("HARNESS_ACCOUNT_ID", raising=False)
    app, _ = _build_app(api_key=None, account_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/pipeline/api/pipelines"
        "?projectIdentifier=p1&orgIdentifier=o1",
        headers=HEADERS,
    )
    assert r.status_code == 503
    assert "HARNESS_API_KEY" in r.json()["detail"]
    _reset()


def test_execute_pipeline_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("HARNESS_API_KEY", raising=False)
    monkeypatch.delenv("HARNESS_ACCOUNT_ID", raising=False)
    app, _ = _build_app(api_key=None, account_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/harness/pipeline/api/pipelines/execute/pipe1"
        "?projectIdentifier=p1&orgIdentifier=o1",
        headers=HEADERS,
        content=b"pipeline:\n  variables: []\n",
    )
    assert r.status_code == 503
    _reset()


def test_get_execution_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("HARNESS_API_KEY", raising=False)
    monkeypatch.delenv("HARNESS_ACCOUNT_ID", raising=False)
    app, _ = _build_app(api_key=None, account_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/pipeline/api/pipelines/execution/exec-1",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_list_services_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("HARNESS_API_KEY", raising=False)
    monkeypatch.delenv("HARNESS_ACCOUNT_ID", raising=False)
    app, _ = _build_app(api_key=None, account_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/ng/api/services?orgIdentifier=o1&projectIdentifier=p1",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_list_environments_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("HARNESS_API_KEY", raising=False)
    monkeypatch.delenv("HARNESS_ACCOUNT_ID", raising=False)
    app, _ = _build_app(api_key=None, account_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/ng/api/environments?orgIdentifier=o1&projectIdentifier=p1",
        headers=HEADERS,
    )
    assert r.status_code == 503
    _reset()


def test_create_connector_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("HARNESS_API_KEY", raising=False)
    monkeypatch.delenv("HARNESS_ACCOUNT_ID", raising=False)
    app, _ = _build_app(api_key=None, account_id=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/harness/ng/api/connectors",
        headers=HEADERS,
        json={"connector": {"name": "n", "identifier": "n", "type": "Github"}},
    )
    assert r.status_code == 503
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx
# ---------------------------------------------------------------------------


def test_list_pipelines_happy_path(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    raw = {
        "data": {
            "content": [
                {
                    "identifier": "deploy_app",
                    "name": "Deploy App",
                    "description": "Production deploy",
                    "tags": {"team": "platform"},
                    "lastUpdatedAt": 1714500000000,
                    "executionSummaryInfo": {"lastExecutionStatus": "Success"},
                }
            ],
            "totalElements": 1,
            "totalPages": 1,
        },
        "status": "SUCCESS",
    }
    app, stub = _build_app(
        api_key="pat.abc",
        account_id="acct-123",
        get_responses={"/pipeline/api/pipelines": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/pipeline/api/pipelines"
        "?projectIdentifier=proj1&orgIdentifier=org1&size=10&page=0",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["totalElements"] == 1
    assert body["data"]["content"][0]["identifier"] == "deploy_app"
    assert (
        body["data"]["content"][0]["executionSummaryInfo"]["lastExecutionStatus"]
        == "Success"
    )

    call = stub.calls[0]
    assert call["method"] == "GET"
    assert "/pipeline/api/pipelines" in call["url"]
    assert call["headers"]["x-api-key"] == "pat.abc"
    assert call["params"]["accountIdentifier"] == "acct-123"
    assert call["params"]["projectIdentifier"] == "proj1"
    assert call["params"]["orgIdentifier"] == "org1"
    assert call["params"]["size"] == 10
    assert call["params"]["page"] == 0
    _reset()


def test_execute_pipeline_happy_path(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    raw = {
        "data": {
            "planExecution": {
                "uuid": "exec-uuid-1",
                "status": "RUNNING",
            }
        },
        "status": "SUCCESS",
    }
    app, stub = _build_app(
        api_key="pat.abc",
        account_id="acct-123",
        post_responses={
            "/pipeline/api/pipelines/execute/deploy_app": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    runtime_yaml = (
        "pipeline:\n  identifier: deploy_app\n"
        "  variables:\n    - name: env\n      value: prod\n"
    )
    r = client.post(
        "/api/v1/harness/pipeline/api/pipelines/execute/deploy_app"
        "?projectIdentifier=proj1&orgIdentifier=org1",
        headers=HEADERS,
        content=runtime_yaml.encode("utf-8"),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["planExecution"]["uuid"] == "exec-uuid-1"
    assert body["data"]["planExecution"]["status"] == "RUNNING"

    call = next(c for c in stub.calls if c["method"] == "POST")
    assert "/pipeline/api/pipelines/execute/deploy_app" in call["url"]
    assert call["params"]["projectIdentifier"] == "proj1"
    assert call["params"]["orgIdentifier"] == "org1"
    assert call["params"]["accountIdentifier"] == "acct-123"
    # YAML body forwarded verbatim
    assert "deploy_app" in (call["content"] or "")
    assert call["headers"]["Content-Type"] == "application/yaml"
    _reset()


def test_get_execution_happy_path(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    raw = {
        "data": {
            "pipelineExecutionSummary": {
                "name": "Deploy App",
                "status": "Success",
                "startTs": 1714500000000,
                "endTs": 1714500300000,
                "modules": ["cd"],
            }
        },
        "status": "SUCCESS",
    }
    app, stub = _build_app(
        api_key="pat.abc",
        account_id="acct-123",
        get_responses={
            "/pipeline/api/pipelines/execution/exec-uuid-1": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/pipeline/api/pipelines/execution/exec-uuid-1"
        "?projectIdentifier=proj1&orgIdentifier=org1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    summary = body["data"]["pipelineExecutionSummary"]
    assert summary["name"] == "Deploy App"
    assert summary["status"] == "Success"
    assert "cd" in summary["modules"]

    call = stub.calls[0]
    assert call["params"]["accountIdentifier"] == "acct-123"
    assert call["params"]["projectIdentifier"] == "proj1"
    assert call["params"]["orgIdentifier"] == "org1"
    _reset()


def test_list_services_happy_path(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    raw = {
        "data": {
            "content": [
                {
                    "service": {
                        "identifier": "svc1",
                        "name": "svc-1",
                        "description": "API service",
                        "tags": {"team": "platform"},
                        "deploymentTypeName": "Kubernetes",
                        "lastUpdatedAt": 1714500000000,
                    }
                }
            ],
            "totalElements": 1,
        },
        "status": "SUCCESS",
    }
    app, stub = _build_app(
        api_key="pat.abc",
        account_id="acct-123",
        get_responses={"/ng/api/services": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/ng/api/services?orgIdentifier=org1&projectIdentifier=proj1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["totalElements"] == 1
    svc = body["data"]["content"][0]["service"]
    assert svc["identifier"] == "svc1"
    assert svc["deploymentTypeName"] == "Kubernetes"

    call = stub.calls[0]
    assert call["params"]["orgIdentifier"] == "org1"
    assert call["params"]["projectIdentifier"] == "proj1"
    _reset()


def test_list_environments_happy_path(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    raw = {
        "data": {
            "content": [
                {
                    "environment": {
                        "identifier": "prod",
                        "name": "Production",
                        "type": "Production",
                        "lastUpdatedAt": 1714500000000,
                    }
                },
                {
                    "environment": {
                        "identifier": "stg",
                        "name": "Staging",
                        "type": "PreProduction",
                        "lastUpdatedAt": 1714500000000,
                    }
                },
            ]
        },
        "status": "SUCCESS",
    }
    app, _ = _build_app(
        api_key="pat.abc",
        account_id="acct-123",
        get_responses={"/ng/api/environments": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/ng/api/environments?orgIdentifier=org1&projectIdentifier=proj1",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    envs = body["data"]["content"]
    assert len(envs) == 2
    assert envs[0]["environment"]["type"] == "Production"
    assert envs[1]["environment"]["type"] == "PreProduction"
    _reset()


def test_create_connector_happy_path(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    connector_body = {
        "connector": {
            "name": "github-prod",
            "identifier": "github_prod",
            "type": "Github",
            "spec": {"url": "https://github.com/org/repo", "type": "Repo"},
        }
    }
    raw = {"data": {**connector_body, "createdAt": 1714500000000}, "status": "SUCCESS"}
    app, stub = _build_app(
        api_key="pat.abc",
        account_id="acct-123",
        post_responses={"/ng/api/connectors": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/harness/ng/api/connectors",
        headers=HEADERS,
        json=connector_body,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["connector"]["identifier"] == "github_prod"

    post_call = next(c for c in stub.calls if c["method"] == "POST")
    assert post_call["json"] == connector_body
    assert post_call["params"]["accountIdentifier"] == "acct-123"
    assert post_call["headers"]["x-api-key"] == "pat.abc"
    _reset()


def test_pipelines_translates_upstream_403_to_503(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    app, _ = _build_app(
        api_key="pat.abc",
        account_id="acct-123",
        get_responses={
            "/pipeline/api/pipelines": _StubResponse(403, {"error": "denied"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/harness/pipeline/api/pipelines"
        "?projectIdentifier=p&orgIdentifier=o",
        headers=HEADERS,
    )
    assert r.status_code == 503
    assert "permission denied" in r.json()["detail"].lower()
    _reset()


def test_execute_pipeline_validates_required_query(monkeypatch):
    monkeypatch.setenv("HARNESS_API_KEY", "pat.abc")
    monkeypatch.setenv("HARNESS_ACCOUNT_ID", "acct-123")
    app, _ = _build_app(api_key="pat.abc", account_id="acct-123")
    client = TestClient(app, raise_server_exceptions=True)

    # Missing projectIdentifier + orgIdentifier -> FastAPI 422
    r = client.post(
        "/api/v1/harness/pipeline/api/pipelines/execute/deploy_app",
        headers=HEADERS,
        content=b"pipeline: {}",
    )
    assert r.status_code == 422
    _reset()
