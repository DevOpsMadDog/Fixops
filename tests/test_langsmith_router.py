"""Tests for langsmith_router — ALDECI.

Spins up a minimal FastAPI app with the LangSmith router mounted. Each test
resets the engine singleton (no SQLite cache, so no tmp_path needed for state).

NO MOCKS rule:
  * /api/v1/runs, /api/v1/datasets, /api/v1/feedback, /api/v1/sessions
    return HTTP 503 when no key.
  * Capability summary reports ``status="unavailable"`` when key missing
    and ``status="ok"`` when key present.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise real networking + parsing code paths.
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
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Routes upstream calls by URL substring + method."""

    def __init__(self, responses: Dict[str, Any]):
        # responses is keyed by "<METHOD> <path-substring>", e.g.
        #   "GET /api/v1/runs"
        # First match wins.
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, method: str, url: str):
        for key, resp in self._responses.items():
            try:
                k_method, k_path = key.split(" ", 1)
            except ValueError:
                continue
            if k_method.upper() == method.upper() and k_path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {"method": "GET", "url": url,
             "headers": headers or {}, "params": params or {}}
        )
        return self._match("GET", url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
    ):
        self.calls.append(
            {"method": "POST", "url": url, "headers": headers or {},
             "params": params or {}, "json": json}
        )
        return self._match("POST", url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    api_key: Optional[str],
    endpoint: Optional[str] = None,
    stub_responses: Optional[Dict[str, Any]] = None,
):
    """Construct an isolated app+engine bound to a stub httpx client."""
    from core import langsmith_engine as engine_mod

    engine_mod.reset_langsmith_engine()
    stub_client = _StubClient(stub_responses or {})
    engine_mod.get_langsmith_engine(
        api_key=api_key, endpoint=endpoint, client=stub_client
    )

    from apps.api.langsmith_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import langsmith_engine as engine_mod

    engine_mod.reset_langsmith_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_api_key(monkeypatch):
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    monkeypatch.delenv("LANGSMITH_ENDPOINT", raising=False)
    app, _ = _build_app(api_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/langsmith/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "LangSmith"
    assert "/api/v1/runs" in body["endpoints"]
    assert "/api/v1/datasets" in body["endpoints"]
    assert "/api/v1/datasets/{id}/examples" in body["endpoints"]
    assert "/api/v1/feedback" in body["endpoints"]
    assert "/api/v1/sessions" in body["endpoints"]
    assert body["langsmith_api_key_present"] is False
    assert body["langsmith_endpoint"] == "https://api.smith.langchain.com"
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_key_present_and_custom_endpoint(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    monkeypatch.setenv("LANGSMITH_ENDPOINT", "https://eu.smith.langchain.com")
    # Use env (no explicit override) to also exercise the env-read path.
    app, _ = _build_app(api_key=None, endpoint=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/langsmith/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["langsmith_api_key_present"] is True
    assert body["langsmith_endpoint"] == "https://eu.smith.langchain.com"
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no key
# ---------------------------------------------------------------------------


def test_runs_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    app, _ = _build_app(api_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/langsmith/api/v1/runs", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "LANGSMITH_API_KEY" in r.json()["detail"]
    _reset()


def test_datasets_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    app, _ = _build_app(api_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/langsmith/api/v1/datasets", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_feedback_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    app, _ = _build_app(api_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/langsmith/api/v1/feedback",
        json={
            "run_id": "11111111-2222-3333-4444-555555555555",
            "key": "helpfulness",
            "score": 0.9,
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_sessions_returns_503_when_no_api_key(monkeypatch):
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    app, _ = _build_app(api_key=None)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/langsmith/api/v1/sessions", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_runs_happy_path_normalizes_and_sends_x_api_key(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    raw = {
        "runs": [
            {
                "id": "11111111-2222-3333-4444-555555555555",
                "name": "openai-chat",
                "run_type": "llm",
                "start_time": "2026-05-04T00:00:00+00:00",
                "end_time": "2026-05-04T00:00:01+00:00",
                "session_id": "abcdef00-0000-0000-0000-000000000000",
                "total_tokens": 1234,
                "prompt_tokens": 1000,
                "completion_tokens": 234,
                "total_cost": 0.0567,
                "trace_id": "trace-1",
                "dotted_order": "20260504T000000Z.run-1",
                "in_dataset": True,
            }
        ],
        "cursor": "next-page",
    }
    app, stub = _build_app(
        api_key="test-key",
        stub_responses={"GET /api/v1/runs": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/langsmith/api/v1/runs",
        params={
            "session_id": "abcdef00-0000-0000-0000-000000000000",
            "run_type": "llm",
            "limit": 10,
            "error": "false",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cursor"] == "next-page"
    assert len(body["runs"]) == 1
    row = body["runs"][0]
    assert row["id"] == "11111111-2222-3333-4444-555555555555"
    assert row["run_type"] == "llm"
    assert row["total_tokens"] == 1234
    assert row["in_dataset"] is True
    assert row["dotted_order"] == "20260504T000000Z.run-1"

    # Auth header propagation + None-stripped query params.
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["headers"].get("x-api-key") == "test-key"
    assert call["params"].get("session_id") == "abcdef00-0000-0000-0000-000000000000"
    assert call["params"].get("run_type") == "llm"
    assert call["params"].get("error") == "false"
    assert "start_time" not in call["params"], "None-valued params should be stripped"
    _reset()


def test_get_run_happy_path(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    raw = {
        "id": "deadbeef-dead-beef-dead-beefdeadbeef",
        "name": "council.convene",
        "run_type": "chain",
        "status": "completed",
    }
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={
            "GET /api/v1/runs/deadbeef-dead-beef-dead-beefdeadbeef":
                _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/langsmith/api/v1/runs/deadbeef-dead-beef-dead-beefdeadbeef",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "deadbeef-dead-beef-dead-beefdeadbeef"
    assert body["run_type"] == "chain"
    assert body["status"] == "completed"
    _reset()


def test_list_datasets_happy_path(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    raw = [
        {
            "id": "ds-1",
            "name": "council-verdicts",
            "data_type": "kv",
            "example_count": 5196,
            "session_count": 12,
            "created_at": "2026-04-01T00:00:00+00:00",
        },
        {
            "id": "ds-2",
            "name": "brain-pipeline-eval",
            "data_type": "chat",
            "example_count": 200,
        },
    ]
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={"GET /api/v1/datasets": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/langsmith/api/v1/datasets",
        params={"data_type": "kv", "limit": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list)
    assert len(body) == 2
    assert body[0]["name"] == "council-verdicts"
    assert body[0]["example_count"] == 5196
    assert body[1]["data_type"] == "chat"
    _reset()


def test_create_examples_happy_path(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    raw = {
        "created_at": "2026-05-04T01:00:00+00:00",
        "modified_at": "2026-05-04T01:00:00+00:00",
        "ids": [
            "ex-1111-1111-1111-111111111111",
            "ex-2222-2222-2222-222222222222",
        ],
    }
    app, stub = _build_app(
        api_key="test-key",
        stub_responses={
            "POST /api/v1/datasets/ds-1/examples":
                _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/langsmith/api/v1/datasets/ds-1/examples",
        json=[
            {
                "inputs": {"prompt": "what is ALDECI?"},
                "outputs": {"answer": "an ASPM+CTEM+CSPM platform"},
                "metadata": {"persona": "ciso"},
                "source_run_id": "11111111-2222-3333-4444-555555555555",
            },
            {
                "inputs": {"prompt": "what is TrustGraph?"},
            },
        ],
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dataset_id"] == "ds-1"
    assert body["created_at"] == "2026-05-04T01:00:00+00:00"
    assert len(body["ids"]) == 2

    # Verify the upstream payload was constructed correctly.
    assert len(stub.calls) == 1
    posted = stub.calls[0]["json"]
    assert isinstance(posted, list)
    assert len(posted) == 2
    assert posted[0]["dataset_id"] == "ds-1"
    assert posted[0]["inputs"] == {"prompt": "what is ALDECI?"}
    assert posted[0]["outputs"] == {"answer": "an ASPM+CTEM+CSPM platform"}
    assert posted[0]["source_run_id"] == "11111111-2222-3333-4444-555555555555"
    # Second example has no outputs / metadata / source — those keys must not
    # leak through as `null`.
    assert "outputs" not in posted[1]
    assert "metadata" not in posted[1]
    assert "source_run_id" not in posted[1]
    _reset()


def test_create_feedback_happy_path(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    raw = {
        "id": "fb-1111-1111-1111-111111111111",
        "created_at": "2026-05-04T01:30:00+00:00",
        "modified_at": "2026-05-04T01:30:00+00:00",
        "run_id": "11111111-2222-3333-4444-555555555555",
        "key": "correctness",
        "score": 0.92,
        "comment": "Council agreed",
        "feedback_source": {"type": "model", "metadata": {"judge": "opus-4.7"}},
        "trace_id": "trace-1",
    }
    app, stub = _build_app(
        api_key="test-key",
        stub_responses={"POST /api/v1/feedback": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/langsmith/api/v1/feedback",
        json={
            "run_id": "11111111-2222-3333-4444-555555555555",
            "key": "correctness",
            "score": 0.92,
            "comment": "Council agreed",
            "feedback_source": {
                "type": "model",
                "metadata": {"judge": "opus-4.7"},
            },
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "fb-1111-1111-1111-111111111111"
    assert body["score"] == 0.92
    assert body["key"] == "correctness"
    assert body["feedback_source"]["type"] == "model"
    assert body["feedback_source"]["metadata"] == {"judge": "opus-4.7"}

    # Verify upstream POST body.
    assert len(stub.calls) == 1
    posted = stub.calls[0]["json"]
    assert posted["run_id"] == "11111111-2222-3333-4444-555555555555"
    assert posted["score"] == 0.92
    assert posted["feedback_source"] == {
        "type": "model", "metadata": {"judge": "opus-4.7"}
    }
    _reset()


def test_list_sessions_happy_path(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    raw = {
        "sessions": [
            {
                "id": "sess-1",
                "name": "council-loop",
                "start_time": "2026-05-04T00:00:00+00:00",
                "run_count": 5196,
                "total_tokens": 10_485_760,
                "total_cost": 12.34,
                "error_rate": 0.0123,
            }
        ],
        "cursor": "next-cursor",
    }
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={"GET /api/v1/sessions": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/langsmith/api/v1/sessions",
        params={"limit": 25},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cursor"] == "next-cursor"
    assert len(body["sessions"]) == 1
    s = body["sessions"][0]
    assert s["name"] == "council-loop"
    assert s["run_count"] == 5196
    assert s["total_cost"] == 12.34
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths + input validation
# ---------------------------------------------------------------------------


def test_runs_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    app, _ = _build_app(
        api_key="test-key",
        stub_responses={
            "GET /api/v1/runs": _StubResponse(
                429, {"detail": "Too Many Requests"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/langsmith/api/v1/runs", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()


def test_runs_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "bad-key")
    app, _ = _build_app(
        api_key="bad-key",
        stub_responses={
            "GET /api/v1/runs": _StubResponse(
                401, {"detail": "Unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/langsmith/api/v1/runs", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "credentials" in r.json()["detail"].lower() or "401" in r.json()["detail"]
    _reset()


def test_runs_invalid_run_type_rejected(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    app, _ = _build_app(api_key="test-key")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/langsmith/api/v1/runs",
        params={"run_type": "not-a-real-type"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_create_examples_validation_rejects_empty_list(monkeypatch):
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    app, _ = _build_app(api_key="test-key")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/langsmith/api/v1/datasets/ds-1/examples",
        json=[],
        headers=HEADERS,
    )
    # Engine raises ValueError("examples must contain at least one entry") -> 422
    assert r.status_code == 422, r.text
    _reset()
