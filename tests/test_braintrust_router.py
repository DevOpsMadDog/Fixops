"""Tests for braintrust_router — ALDECI.

Spins up a minimal FastAPI app with the Braintrust router mounted. Each test
gets a stub httpx client and resets the engine singleton so state doesn't
bleed between tests.

NO MOCKS rule:
  * Live endpoints return HTTP 503 when no key.
  * Capability summary reports ``status="unavailable"`` when key is missing.
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

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
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
    ):
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

    def _match(self, url: str):
        # Prefer longest-match so /v1/experiment/{id}/insert beats /v1/experiment.
        for path in sorted(self._responses.keys(), key=len, reverse=True):
            if path in url:
                return self._responses[path]
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(*, api_key: Optional[str], stub_responses: Dict[str, Any]):
    """Construct an isolated app+engine."""
    from core import braintrust_engine as engine_mod

    engine_mod.reset_braintrust_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_braintrust_engine(
        api_key=api_key,
        api_url="https://api.braintrust.dev",
        client=stub_client,
    )

    from apps.api.braintrust_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import braintrust_engine as engine_mod

    engine_mod.reset_braintrust_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_api_key(monkeypatch):
    monkeypatch.delenv("BRAINTRUST_API_KEY", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Braintrust"
    assert "/v1/experiment" in body["endpoints"]
    assert "/v1/dataset" in body["endpoints"]
    assert "/v1/project" in body["endpoints"]
    assert "/v1/score" in body["endpoints"]
    assert "/v1/prompt" in body["endpoints"]
    assert "/v1/function" in body["endpoints"]
    assert body["braintrust_api_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_key_present(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    app, _ = _build_app(api_key="test-key", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["braintrust_api_key_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no key
# ---------------------------------------------------------------------------


def test_list_experiments_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("BRAINTRUST_API_KEY", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/experiment", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "BRAINTRUST_API_KEY" in r.json()["detail"]
    _reset()


def test_list_datasets_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("BRAINTRUST_API_KEY", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/dataset", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_list_projects_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("BRAINTRUST_API_KEY", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/project", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_list_scores_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("BRAINTRUST_API_KEY", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/score", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_create_experiment_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("BRAINTRUST_API_KEY", raising=False)
    app, _ = _build_app(api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/braintrust/v1/experiment",
        json={"project_id": "proj-1", "name": "exp-1"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_experiments_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {
        "objects": [
            {
                "id": "exp-uuid-1",
                "project_id": "proj-uuid-1",
                "name": "ranking-eval-2026-05-04",
                "description": "ranking model regression eval",
                "created": "2026-05-04T01:00:00Z",
                "repo_info": {
                    "commit": "abc123",
                    "branch": "features/intermediate-stage",
                    "dirty": False,
                },
                "public": False,
                "dataset_id": "ds-uuid-1",
                "dataset_version": "v1",
                "metadata": {"owner": "qa"},
                "tags": ["regression"],
            }
        ],
        "cursor": "exp-uuid-1",
    }
    app, stub = _build_app(
        api_key="test-key",
        stub_responses={"/v1/experiment": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/braintrust/v1/experiment",
        params={"project_id": "proj-uuid-1", "limit": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["objects"]) == 1
    assert body["objects"][0]["id"] == "exp-uuid-1"
    assert body["objects"][0]["repo_info"]["commit"] == "abc123"
    assert body["cursor"] == "exp-uuid-1"

    # Verify Authorization Bearer header was attached.
    assert stub.calls
    headers = stub.calls[0]["headers"]
    assert headers.get("Authorization") == "Bearer test-key"
    _reset()


def test_get_experiment_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {
        "id": "exp-uuid-7",
        "project_id": "proj-uuid-1",
        "name": "ranking-eval-detail",
        "metadata": {"k": "v"},
    }
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={"/v1/experiment/exp-uuid-7": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/experiment/exp-uuid-7", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "exp-uuid-7"
    assert body["name"] == "ranking-eval-detail"
    _reset()


def test_create_experiment_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {
        "id": "exp-new",
        "project_id": "proj-uuid-1",
        "name": "new-exp",
        "created": "2026-05-04T01:30:00Z",
    }
    app, stub = _build_app(
        api_key="test-key",
        stub_responses={"/v1/experiment": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/braintrust/v1/experiment",
        json={
            "project_id": "proj-uuid-1",
            "name": "new-exp",
            "description": "a new exp",
            "tags": ["a", "b"],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "exp-new"

    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert len(posts) == 1
    forwarded = posts[0]["json"]
    assert forwarded["project_id"] == "proj-uuid-1"
    assert forwarded["name"] == "new-exp"
    assert forwarded["tags"] == ["a", "b"]
    _reset()


def test_insert_experiment_events_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {"row_ids": ["row-1", "row-2"]}
    app, stub = _build_app(
        api_key="test-key",
        stub_responses={
            "/v1/experiment/exp-1/insert": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/braintrust/v1/experiment/exp-1/insert",
        json={
            "events": [
                {
                    "input": {"q": "what is 2+2?"},
                    "output": "4",
                    "expected": "4",
                    "scores": {"exact_match": 1.0},
                    "metadata": {"model": "gpt-4"},
                },
                {
                    "input": {"q": "capital of france?"},
                    "output": "Paris",
                    "expected": "Paris",
                    "scores": {"exact_match": 1.0},
                },
            ]
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["row_ids"] == ["row-1", "row-2"]

    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert len(posts) == 1
    assert "/v1/experiment/exp-1/insert" in posts[0]["url"]
    assert len(posts[0]["json"]["events"]) == 2
    _reset()


def test_list_datasets_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {
        "objects": [
            {"id": "ds-1", "project_id": "proj-1", "name": "ds-foo"},
            {"id": "ds-2", "project_id": "proj-1", "name": "ds-bar"},
        ],
        "cursor": "ds-2",
    }
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={"/v1/dataset": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/braintrust/v1/dataset",
        params={"project_name": "demo", "limit": 10},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["objects"]) == 2
    assert body["objects"][1]["name"] == "ds-bar"
    _reset()


def test_get_dataset_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {"id": "ds-9", "project_id": "proj-1", "name": "ds-detail"}
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={"/v1/dataset/ds-9": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/dataset/ds-9", headers=HEADERS)
    assert r.status_code == 200, r.text
    assert r.json()["id"] == "ds-9"
    _reset()


def test_insert_dataset_events_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {"row_ids": ["r1"]}
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={"/v1/dataset/ds-9/insert": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/braintrust/v1/dataset/ds-9/insert",
        json={
            "events": [
                {
                    "input": {"prompt": "hi"},
                    "expected": "hello",
                    "metadata": {"v": 1},
                }
            ]
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    assert r.json()["row_ids"] == ["r1"]
    _reset()


def test_list_projects_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {
        "objects": [
            {
                "id": "proj-1",
                "org_id": "org-1",
                "user_id": "user-1",
                "name": "aldeci",
                "created": "2026-01-01T00:00:00Z",
                "settings": {},
            }
        ],
        "cursor": None,
    }
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={"/v1/project": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/braintrust/v1/project",
        params={"org_name": "aldeci-org", "limit": 25},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["objects"][0]["name"] == "aldeci"
    assert body["cursor"] is None
    _reset()


def test_list_scores_happy_path(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    raw = {
        "objects": [
            {"id": "score-1", "name": "exact_match"},
            {"id": "score-2", "name": "factuality"},
        ],
        "cursor": None,
    }
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={"/v1/score": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/score", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["objects"]) == 2
    assert body["objects"][1]["name"] == "factuality"
    _reset()


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_list_experiments_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={
            "/v1/experiment": _StubResponse(
                429, {"error": "rate limit"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/experiment", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()


def test_list_experiments_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={
            "/v1/experiment": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/experiment", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "credentials" in r.json()["detail"].lower() or "401" in r.json()["detail"]
    _reset()


def test_create_experiment_validation_rejects_missing_name(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    app, _ = _build_app(api_key="test-key", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/braintrust/v1/experiment",
        json={"project_id": "proj-1"},  # missing required `name`
        headers=HEADERS,
    )
    # Pydantic enforces required fields → 422 from FastAPI.
    assert r.status_code == 422, r.text
    _reset()


def test_insert_experiment_events_rejects_empty_events(monkeypatch):
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")
    app, _ = _build_app(api_key="test-key", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/braintrust/v1/experiment/exp-1/insert",
        json={"events": []},
        headers=HEADERS,
    )
    # Engine raises ValueError → 422.
    assert r.status_code == 422, r.text
    _reset()


def test_authorization_header_uses_bearer_prefix(monkeypatch):
    """Regression: contract says `Authorization: Bearer {key}`."""
    monkeypatch.setenv("BRAINTRUST_API_KEY", "abc-secret-key")
    app, stub = _build_app(
        api_key="abc-secret-key",
        stub_responses={
            "/v1/score": _StubResponse(200, {"objects": [], "cursor": None})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/score", headers=HEADERS)
    assert r.status_code == 200, r.text
    assert stub.calls
    auth = stub.calls[0]["headers"].get("Authorization")
    assert auth == "Bearer abc-secret-key"
    _reset()


def test_custom_braintrust_api_url_is_honored(monkeypatch):
    """Regression: BRAINTRUST_API_URL env should be used when set on engine ctor."""
    monkeypatch.setenv("BRAINTRUST_API_KEY", "test-key")

    from core import braintrust_engine as engine_mod

    engine_mod.reset_braintrust_engine()
    stub = _StubClient({"/v1/score": _StubResponse(200, {"objects": [], "cursor": None})})
    engine_mod.get_braintrust_engine(
        api_key="test-key",
        api_url="https://custom.braintrust.example",
        client=stub,
    )

    from apps.api.braintrust_router import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/braintrust/v1/score", headers=HEADERS)
    assert r.status_code == 200, r.text
    assert stub.calls
    assert stub.calls[0]["url"].startswith("https://custom.braintrust.example")
    _reset()
