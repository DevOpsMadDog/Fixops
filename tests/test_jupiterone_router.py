"""Tests for jupiterone_router — ALDECI.

NO MOCKS rule:
  * Live endpoints return HTTP 503 when JUPITERONE_API_KEY or
    JUPITERONE_ACCOUNT is missing.
  * Capability summary surfaces ``status="unavailable"`` when not configured.
  * Happy paths inject a stub httpx.Client (not a hard-coded engine payload),
    so we exercise the real request building + parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for httpx.Response."""

    def __init__(self, status_code: int, payload: Any = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        if text:
            self.text = text
        elif payload is None:
            self.text = ""
        else:
            try:
                self.text = json.dumps(payload)
            except (TypeError, ValueError):
                self.text = ""

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str):
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(self, url: str, headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, Any]] = None):  # noqa: D401
        self.calls.append(
            {"method": "GET", "url": url, "headers": headers or {},
             "params": params or {}}
        )
        return self._match(url)

    def post(self, url: str, headers: Optional[Dict[str, str]] = None,
             params: Optional[Dict[str, Any]] = None,
             json: Optional[Any] = None,
             files: Optional[Any] = None,
             data: Optional[Any] = None):  # noqa: D401,A002
        self.calls.append(
            {"method": "POST", "url": url, "headers": headers or {},
             "params": params or {}, "json": json, "files": files, "data": data}
        )
        return self._match(url)

    def put(self, url: str, headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, Any]] = None,
            json: Optional[Any] = None):  # noqa: D401,A002
        self.calls.append(
            {"method": "PUT", "url": url, "headers": headers or {},
             "params": params or {}, "json": json}
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
    account: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to the stub client."""
    from core import jupiterone_engine as engine_mod

    engine_mod.reset_jupiterone_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_jupiterone_engine(
        api_key=api_key,
        account=account,
        base_url="https://api.us.jupiterone.io",
        client=stub_client,
    )

    from apps.api.jupiterone_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import jupiterone_engine as engine_mod

    engine_mod.reset_jupiterone_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_without_credentials(monkeypatch):
    monkeypatch.delenv("JUPITERONE_API_KEY", raising=False)
    monkeypatch.delenv("JUPITERONE_ACCOUNT", raising=False)
    app, _ = _build_app(api_key=None, account=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/jupiterone/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "JupiterOne"
    assert "/graphql" in body["endpoints"]
    assert body["jupiterone_api_key_present"] is False
    assert body["jupiterone_account_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_configured(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    app, _ = _build_app(
        api_key="test-key", account="test-account", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/jupiterone/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["jupiterone_api_key_present"] is True
    assert body["jupiterone_account_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when not configured
# ---------------------------------------------------------------------------


def test_graphql_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("JUPITERONE_API_KEY", raising=False)
    monkeypatch.delenv("JUPITERONE_ACCOUNT", raising=False)
    app, _ = _build_app(api_key=None, account=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/jupiterone/graphql",
        json={"query": "Find Host"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "JUPITERONE_API_KEY" in detail or "JUPITERONE_ACCOUNT" in detail
    _reset()


def test_list_sync_jobs_returns_503_when_no_account(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.delenv("JUPITERONE_ACCOUNT", raising=False)
    app, _ = _build_app(
        api_key="test-key", account=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/jupiterone/persister/synchronization/jobs",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "JUPITERONE_ACCOUNT" in r.json()["detail"]
    _reset()


def test_list_alerts_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("JUPITERONE_API_KEY", raising=False)
    monkeypatch.delenv("JUPITERONE_ACCOUNT", raising=False)
    app, _ = _build_app(api_key=None, account=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/jupiterone/alerts", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_graphql_happy_path_normalizes_envelope(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    raw = {
        "data": {
            "queryV1": {
                "type": "list",
                "data": [
                    {
                        "vertices": [{"id": "v1", "entity": {"_class": "Host"}}],
                        "edges": [],
                        "properties": {},
                    }
                ],
                "totalCount": 1,
                "cursor": "",
            }
        },
        "errors": [],
    }
    app, stub = _build_app(
        api_key="test-key",
        account="test-account",
        stub_responses={"/graphql": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/jupiterone/graphql",
        json={
            "query": "Find Host",
            "variables": {"limit": 10},
            "includeDeleted": False,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["queryV1"]["totalCount"] == 1
    assert body["errors"] == []

    # Verify auth headers + JSON body
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "POST"
    assert call["headers"]["Authorization"] == "Bearer test-key"
    assert call["headers"]["JupiterOne-Account"] == "test-account"
    assert call["json"]["query"] == "Find Host"
    assert call["json"]["variables"]["limit"] == 10
    assert call["json"]["variables"]["includeDeleted"] is False
    _reset()


def test_list_sync_jobs_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    raw = {
        "jobs": [
            {
                "id": "job-1",
                "type": "integration",
                "source": "integration-managed",
                "scope": "aws",
                "status": "FINISHED",
                "partialDatasets": {
                    "deletedTypes": [],
                    "updatedEntities": ["aws_instance"],
                    "createdEntities": ["aws_instance"],
                },
                "integrationInstanceId": "inst-1",
                "integrationJobId": "intjob-1",
                "syncMode": "DIFF",
                "createDate": "2026-05-04T00:00:00Z",
                "lastModifyDate": "2026-05-04T00:05:00Z",
                "finishDate": "2026-05-04T00:05:00Z",
                "etcdEpoch": 12345,
                "integrationDefinitionId": "def-aws",
                "batchSize": 250,
                "integrationDefinitionDescription": {
                    "name": "AWS",
                    "type": "aws",
                    "integrationClass": "Cloud",
                    "integrationCategory": ["IaaS"],
                },
                "jobMetadata": {"runId": "abc"},
            }
        ]
    }
    app, stub = _build_app(
        api_key="test-key",
        account="test-account",
        stub_responses={
            "/persister/synchronization/jobs": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/jupiterone/persister/synchronization/jobs",
        params={"size": 10, "pageNumber": 0, "source": "integration-managed"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["jobs"]) == 1
    job = body["jobs"][0]
    assert job["id"] == "job-1"
    assert job["status"] == "FINISHED"
    assert job["syncMode"] == "DIFF"
    assert job["integrationDefinitionDescription"]["name"] == "AWS"
    assert job["partialDatasets"]["updatedEntities"] == ["aws_instance"]
    assert stub.calls[0]["params"]["source"] == "integration-managed"
    _reset()


def test_create_sync_job_validates_source(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    app, _ = _build_app(
        api_key="test-key", account="test-account", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/jupiterone/persister/synchronization/jobs",
        json={"source": "bogus", "scope": "test"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_create_sync_job_happy_path(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    raw = {
        "job": {
            "id": "job-new",
            "type": "integration",
            "source": "api-managed",
            "scope": "aldeci-test",
            "status": "CREATED",
            "syncMode": "CREATE_OR_UPDATE",
            "createDate": "2026-05-04T01:00:00Z",
        }
    }
    app, stub = _build_app(
        api_key="test-key",
        account="test-account",
        stub_responses={
            "/persister/synchronization/jobs": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/jupiterone/persister/synchronization/jobs",
        json={
            "source": "api-managed",
            "scope": "aldeci-test",
            "properties": {"description": "ALDECI sync"},
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job"]["id"] == "job-new"
    assert body["job"]["status"] == "CREATED"
    assert body["job"]["syncMode"] == "CREATE_OR_UPDATE"

    # Verify upstream POST body
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert len(posts) == 1
    assert posts[0]["json"]["source"] == "api-managed"
    assert posts[0]["json"]["scope"] == "aldeci-test"
    _reset()


def test_upload_and_finalize_sync_job(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    app, stub = _build_app(
        api_key="test-key",
        account="test-account",
        stub_responses={
            "/upload": _StubResponse(200, None, text=""),
            "/finalize": _StubResponse(200, None, text=""),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r1 = client.post(
        "/api/v1/jupiterone/persister/synchronization/jobs/job-1/upload",
        json={
            "entities": [{"_key": "e1", "_type": "host", "_class": "Host"}],
            "relationships": [
                {"_key": "r1", "_type": "host_owns_disk",
                 "_class": "OWNS", "_fromEntityKey": "e1", "_toEntityKey": "d1"}
            ],
        },
        headers=HEADERS,
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["ok"] is True

    r2 = client.post(
        "/api/v1/jupiterone/persister/synchronization/jobs/job-1/finalize",
        headers=HEADERS,
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["ok"] is True

    upload_calls = [c for c in stub.calls if "/upload" in c["url"]]
    finalize_calls = [c for c in stub.calls if "/finalize" in c["url"]]
    assert len(upload_calls) == 1
    assert len(finalize_calls) == 1
    assert upload_calls[0]["json"]["entities"][0]["_key"] == "e1"
    _reset()


def test_list_alerts_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    raw = {
        "alerts": [
            {
                "id": "alert-1",
                "accountId": "acct-1",
                "ruleId": "rule-1",
                "ruleName": "Public S3 bucket",
                "ruleVersion": 3,
                "ruleSpec": {"version": 3},
                "level": "HIGH",
                "type": "RULE_VIOLATION",
                "status": "ALERTED",
                "lastEvaluationStartOn": "2026-05-04T01:00:00Z",
                "lastEvaluationEndOn": "2026-05-04T01:00:30Z",
                "lastEvaluationResult": {
                    "rawDataDescriptors": [
                        {"name": "buckets", "query": "Find aws_s3_bucket",
                         "persist": True}
                    ]
                },
                "alertedAt": "2026-05-04T01:00:30Z",
                "questionRuleInstance": {
                    "question": {
                        "queries": [{"name": "buckets",
                                     "query": "Find aws_s3_bucket"}]
                    }
                },
            }
        ],
        "totalCount": 1,
        "cursor": "next-page",
    }
    app, stub = _build_app(
        api_key="test-key",
        account="test-account",
        stub_responses={"/alerts": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/jupiterone/alerts",
        params={
            "fromDate": "2026-05-01T00:00:00Z",
            "pageSize": 10,
            "statuses": "ALERTED",
            "severities": "HIGH,CRITICAL",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalCount"] == 1
    assert body["cursor"] == "next-page"
    alert = body["alerts"][0]
    assert alert["ruleName"] == "Public S3 bucket"
    assert alert["level"] == "HIGH"
    assert alert["status"] == "ALERTED"
    assert (
        alert["lastEvaluationResult"]["rawDataDescriptors"][0]["query"]
        == "Find aws_s3_bucket"
    )
    assert stub.calls[0]["params"]["statuses"] == "ALERTED"
    assert stub.calls[0]["params"]["severities"] == "HIGH,CRITICAL"
    _reset()


def test_get_alert_dismiss_snooze(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    detail_raw = {
        "id": "alert-1",
        "accountId": "acct-1",
        "ruleId": "rule-1",
        "ruleName": "Public S3 bucket",
        "level": "HIGH",
        "status": "ALERTED",
    }
    app, stub = _build_app(
        api_key="test-key",
        account="test-account",
        stub_responses={
            "/alerts/alert-1/dismiss": _StubResponse(200, None, text=""),
            "/alerts/alert-1/snooze": _StubResponse(200, None, text=""),
            "/alerts/alert-1": _StubResponse(200, detail_raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/jupiterone/alerts/alert-1", headers=HEADERS)
    assert r.status_code == 200, r.text
    assert r.json()["alert"]["id"] == "alert-1"

    r2 = client.post(
        "/api/v1/jupiterone/alerts/alert-1/dismiss",
        json={"reason": "false-positive"},
        headers=HEADERS,
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["ok"] is True

    r3 = client.post(
        "/api/v1/jupiterone/alerts/alert-1/snooze",
        json={"until": "2026-06-01T00:00:00Z"},
        headers=HEADERS,
    )
    assert r3.status_code == 200, r3.text
    assert r3.json()["ok"] is True

    dismiss_posts = [
        c for c in stub.calls if "/alerts/alert-1/dismiss" in c["url"]
    ]
    snooze_posts = [
        c for c in stub.calls if "/alerts/alert-1/snooze" in c["url"]
    ]
    assert len(dismiss_posts) == 1
    assert dismiss_posts[0]["json"]["reason"] == "false-positive"
    assert len(snooze_posts) == 1
    assert snooze_posts[0]["json"]["until"] == "2026-06-01T00:00:00Z"
    _reset()


def test_list_integrations_happy_path(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    raw = {
        "integrations": [
            {
                "id": "int-1",
                "name": "AWS Production",
                "type": "aws",
                "accountId": "acct-1",
                "definitionId": "def-aws",
                "config": {"region": "us-east-1"},
                "enabled": True,
                "createdAt": "2026-01-01T00:00:00Z",
                "updatedAt": "2026-05-01T00:00:00Z",
            }
        ],
        "cursor": "next",
    }
    app, _ = _build_app(
        api_key="test-key",
        account="test-account",
        stub_responses={"/accounts/acct-1/integrations": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/jupiterone/accounts/acct-1/integrations",
        params={"limit": 50, "type": "aws"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cursor"] == "next"
    assert len(body["integrations"]) == 1
    assert body["integrations"][0]["name"] == "AWS Production"
    assert body["integrations"][0]["type"] == "aws"
    _reset()


# ---------------------------------------------------------------------------
# Upstream errors + input validation
# ---------------------------------------------------------------------------


def test_graphql_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    app, _ = _build_app(
        api_key="test-key",
        account="test-account",
        stub_responses={
            "/graphql": _StubResponse(
                429, {"errors": [{"detail": "Too Many Requests"}]},
                text="rate limit",
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/jupiterone/graphql",
        json={"query": "Find Host"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"].lower()
    assert "rate-limit" in detail or "429" in detail
    _reset()


def test_graphql_validation_rejects_bad_deferred_response(monkeypatch):
    monkeypatch.setenv("JUPITERONE_API_KEY", "test-key")
    monkeypatch.setenv("JUPITERONE_ACCOUNT", "test-account")
    app, _ = _build_app(
        api_key="test-key", account="test-account", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/jupiterone/graphql",
        json={"query": "Find Host", "deferredResponse": "BOGUS"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()
