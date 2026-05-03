"""Tests for tanium_router (live Tanium Endpoint Platform REST surface) — ALDECI.

Spins up a minimal FastAPI app with the Tanium router mounted. Each test
gets an isolated engine singleton + stub httpx.Client so we exercise the
real session-token + parsing code paths without hitting the network.

NO MOCKS rule:
  * When TANIUM_URL/TANIUM_USER/TANIUM_PASSWORD are unset the capability
    summary reports ``status="unavailable"`` and every live endpoint
    returns 503.
  * Happy-path tests inject a stub client (not baked-in fake payloads)
    so session-fetch + REST + result normalization all run.
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
# Stubs
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
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> Any:
        for path, resp in self._responses.items():
            if url.endswith(path):
                return resp
        return _StubResponse(404, {"text": "not found"}, text="not found")

    def get(self, url: str, params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None):
        self.calls.append({
            "method": "GET", "url": url, "params": params or {}, "headers": headers or {},
        })
        return self._match(url)

    def post(self, url: str, data: Optional[Dict[str, Any]] = None,
             json: Optional[Dict[str, Any]] = None,
             headers: Optional[Dict[str, str]] = None):
        self.calls.append({
            "method": "POST", "url": url, "data": data or {}, "json": json or {},
            "headers": headers or {},
        })
        return self._match(url)

    def close(self) -> None:
        pass


def _build_app(*, url: Optional[str], user: Optional[str], password: Optional[str],
               stub_responses: Dict[str, Any], domain: Optional[str] = None):
    """Construct an isolated app+engine bound to a stub client."""
    from core import tanium_endpoint_engine as engine_mod

    engine_mod.reset_tanium_endpoint_engine()
    stub = _StubClient(stub_responses)
    engine_mod.get_tanium_endpoint_engine(
        url=url,
        user=user,
        password=password,
        domain=domain,
        client=stub,
    )

    from apps.api.tanium_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Always reset the singleton before AND after each test."""
    from core import tanium_endpoint_engine as engine_mod
    engine_mod.reset_tanium_endpoint_engine()
    yield
    engine_mod.reset_tanium_endpoint_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("TANIUM_URL", raising=False)
    monkeypatch.delenv("TANIUM_USER", raising=False)
    monkeypatch.delenv("TANIUM_PASSWORD", raising=False)
    app, _ = _build_app(url=None, user=None, password=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tanium/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Tanium"
    for ep in [
        "/api/v2/sessions", "/api/v2/parse_question", "/api/v2/result_data",
        "/api/v2/sensors", "/api/v2/saved_questions", "/api/v2/system_status",
    ]:
        assert ep in body["endpoints"]
    assert body["tanium_url_present"] is False
    assert body["tanium_user_present"] is False
    assert body["tanium_password_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_all_creds_present(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    app, _ = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tanium/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tanium_url_present"] is True
    assert body["tanium_user_present"] is True
    assert body["tanium_password_present"] is True
    assert body["status"] == "ok"


def test_capability_summary_empty_when_only_url_set(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.delenv("TANIUM_USER", raising=False)
    monkeypatch.delenv("TANIUM_PASSWORD", raising=False)
    app, _ = _build_app(
        url="https://tanium.example.com",
        user=None,
        password=None,
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tanium/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "empty"


# ---------------------------------------------------------------------------
# Live endpoints — unavailable path (no creds) returns 503
# ---------------------------------------------------------------------------


def test_system_status_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("TANIUM_URL", raising=False)
    monkeypatch.delenv("TANIUM_USER", raising=False)
    monkeypatch.delenv("TANIUM_PASSWORD", raising=False)
    app, _ = _build_app(url=None, user=None, password=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tanium/api/v2/system_status", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "TANIUM_URL" in detail


def test_sensors_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("TANIUM_URL", raising=False)
    monkeypatch.delenv("TANIUM_USER", raising=False)
    monkeypatch.delenv("TANIUM_PASSWORD", raising=False)
    app, _ = _build_app(url=None, user=None, password=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/tanium/api/v2/sensors",
        params={"max_age_seconds": 600},
        headers=HEADERS,
    )
    assert r.status_code == 503


def test_parse_question_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("TANIUM_URL", raising=False)
    monkeypatch.delenv("TANIUM_USER", raising=False)
    monkeypatch.delenv("TANIUM_PASSWORD", raising=False)
    app, _ = _build_app(url=None, user=None, password=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/tanium/api/v2/parse_question",
        json={"text": "Get Computer Name from all machines"},
        headers=HEADERS,
    )
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# POST /api/v2/sessions — explicit session open
# ---------------------------------------------------------------------------


def test_open_session_happy_path(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sessions_resp = _StubResponse(200, {
        "data": {
            "session": "sess-token-abcdef-1234567890",
            "expiration": "2026-05-04T18:30:00",
            "persistent": False,
        }
    })
    app, stub = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={"/api/v2/sessions": sessions_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/tanium/api/v2/sessions",
        json={"username": "alt-user", "password": "alt-pass", "domain": "CORP"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["session"] == "sess-token-abcdef-1234567890"
    assert body["data"]["persistent"] is False

    # Verify body sent included supplied creds (not env creds)
    sess_call = next(c for c in stub.calls if c["url"].endswith("/api/v2/sessions"))
    assert sess_call["json"]["username"] == "alt-user"
    assert sess_call["json"]["password"] == "alt-pass"
    assert sess_call["json"]["domain"] == "CORP"


def test_open_session_rejects_missing_password():
    app, _ = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/tanium/api/v2/sessions",
        json={"username": "alt-user", "password": ""},
        headers=HEADERS,
    )
    # Pydantic validation kicks in (password min_length=1) -> 422
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_system_status_happy_path(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sess_resp = _StubResponse(200, {"data": {"session": "tk-1"}})
    status_resp = _StubResponse(200, {
        "data": {
            "server_clusters": [
                {"name": "TS-prod-01", "ip": "10.0.0.10", "status": "OK"},
                {"name": "TS-prod-02", "ip": "10.0.0.11", "status": "OK"},
            ],
            "dependent_clusters": [],
        }
    })
    app, stub = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={
            "/api/v2/sessions": sess_resp,
            "/api/v2/system_status": status_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tanium/api/v2/system_status", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]["server_clusters"]) == 2
    assert body["data"]["server_clusters"][0]["name"] == "TS-prod-01"
    assert body["data"]["dependent_clusters"] == []

    # Verify session-token header was sent
    status_call = next(c for c in stub.calls if c["url"].endswith("/api/v2/system_status"))
    assert status_call["headers"].get("session") == "tk-1"


def test_parse_question_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sess_resp = _StubResponse(200, {"data": {"session": "tk-2"}})
    parse_resp = _StubResponse(200, {
        "data": [
            {
                "from_canonical_text":   True,
                "parameter_values":      [],
                "picked_intrinsic_type": "ComputerName",
                "question_text":         "Get Computer Name from all machines",
                "parsed_text":           "Get Computer Name from all machines",
                "sensor_references": [
                    {"name": "Computer Name", "real_ms_avg": 12,
                     "source_hash": "abc123"},
                ],
                "result_groups": [
                    {"select": [
                        {"aggregation": "", "max_data_age_seconds": 600,
                         "sensor": {"name": "Computer Name", "source_hash": "abc123"}}
                    ]}
                ],
                "score":  1000,
                "source": "canonical",
            }
        ]
    })
    app, stub = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={
            "/api/v2/sessions": sess_resp,
            "/api/v2/parse_question": parse_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/tanium/api/v2/parse_question",
        json={"text": "Get Computer Name from all machines"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 1
    item = body["data"][0]
    assert item["from_canonical_text"] is True
    assert item["picked_intrinsic_type"] == "ComputerName"
    assert item["sensor_references"][0]["name"] == "Computer Name"
    assert item["sensor_references"][0]["real_ms_avg"] == 12
    assert item["result_groups"][0]["select"][0]["sensor"]["source_hash"] == "abc123"
    assert item["score"] == 1000

    # Body of POST must contain the supplied text
    parse_call = next(c for c in stub.calls if c["url"].endswith("/api/v2/parse_question"))
    assert parse_call["json"]["text"] == "Get Computer Name from all machines"


def test_issue_question_happy_path(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sess_resp = _StubResponse(200, {"data": {"session": "tk-3"}})
    q_resp = _StubResponse(200, {
        "data": {
            "id": 9001,
            "query_text": "Get Computer Name from all machines",
            "action_tracking_flag": False,
            "expiration": "2026-05-04T19:00:00",
            "expire_seconds": 600,
            "question_id": 9001,
        }
    })
    app, stub = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={
            "/api/v2/sessions": sess_resp,
            "/api/v2/questions": q_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/tanium/api/v2/questions",
        json={
            "query_text": "Get Computer Name from all machines",
            "expire_seconds": 600,
            "force_computer_id_flag": False,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["id"] == 9001
    assert body["data"]["question_id"] == 9001
    assert body["data"]["query_text"] == "Get Computer Name from all machines"
    assert body["data"]["expire_seconds"] == 600

    q_call = next(c for c in stub.calls if c["url"].endswith("/api/v2/questions"))
    assert q_call["json"]["query_text"] == "Get Computer Name from all machines"
    assert q_call["json"]["expire_seconds"] == 600
    assert q_call["json"]["force_computer_id_flag"] is False


def test_get_result_data_happy_path(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sess_resp = _StubResponse(200, {"data": {"session": "tk-4"}})
    rd_resp = _StubResponse(200, {
        "data": {
            "result_sets": [
                {
                    "age": 5,
                    "archived_question_id": 0,
                    "cache_id": "cache-9001",
                    "error_count": 0,
                    "estimated_total": 2,
                    "expiration": 1714849200,
                    "columns": [
                        {"name": "Computer Name", "hash": "abc123", "type": "String"},
                        {"name": "Count", "hash": "ccount", "type": "Numeric"},
                    ],
                    "rows": [
                        {"id": 1, "cid": 100, "data": [[{"text": "WIN-001"}], [{"text": "1"}]]},
                        {"id": 2, "cid": 200, "data": [[{"text": "WIN-002"}], [{"text": "1"}]]},
                    ],
                    "no_results_count": 0,
                    "mr_passed": 2,
                    "mr_tested": 2,
                    "passed": 2,
                    "tested": 2,
                    "question_id": 9001,
                    "report_count": 1,
                    "row_count": 2,
                    "saved_question_id": 0,
                    "seconds_since_issued": 5,
                    "select_count": 2,
                }
            ]
        }
    })
    app, stub = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={
            "/api/v2/sessions": sess_resp,
            "/api/v2/result_data": rd_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/tanium/api/v2/result_data",
        params={"question_id": 9001, "hide_no_results_flag": 1},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    sets = body["data"]["result_sets"]
    assert len(sets) == 1
    rs = sets[0]
    assert rs["question_id"] == 9001
    assert rs["row_count"] == 2
    assert len(rs["columns"]) == 2
    assert rs["columns"][0]["name"] == "Computer Name"
    assert rs["columns"][0]["type"] == "String"
    assert len(rs["rows"]) == 2

    rd_call = next(c for c in stub.calls if c["url"].endswith("/api/v2/result_data"))
    assert rd_call["params"]["question_id"] == 9001
    assert rd_call["params"]["hide_no_results_flag"] == 1


def test_list_sensors_happy_path(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sess_resp = _StubResponse(200, {"data": {"session": "tk-5"}})
    sensors_resp = _StubResponse(200, {
        "data": [
            {
                "id": 1, "name": "Computer Name", "hash": "abc", "source_hash": "src-abc",
                "source_id": 0, "max_age_seconds": 600,
                "hidden_flag": False, "ignore_case_flag": True,
                "exclude_from_parse_flag": False,
                "value_type": "String",
                "queries": [
                    {"platform": "Windows", "script": "echo %COMPUTERNAME%",
                     "script_type": "WMIQuery", "signature": "sig-1"},
                ],
                "parameters": [],
                "category": "Reserved",
            },
            {
                "id": 2, "name": "Operating System", "hash": "def", "source_hash": "src-def",
                "source_id": 0, "max_age_seconds": 3600,
                "hidden_flag": False, "ignore_case_flag": False,
                "exclude_from_parse_flag": False,
                "value_type": "String",
                "queries": [],
                "parameters": [
                    {"key": "verbose", "default_value": "no", "type": "Select",
                     "label": "Verbose", "value_type": "String",
                     "allow_set_multiple_flags": False},
                ],
                "category": "Reserved",
            },
        ]
    })
    app, stub = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={
            "/api/v2/sessions": sess_resp,
            "/api/v2/sensors": sensors_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/tanium/api/v2/sensors",
        params={"max_age_seconds": 600},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 2
    s1 = body["data"][0]
    assert s1["name"] == "Computer Name"
    assert s1["value_type"] == "String"
    assert s1["queries"][0]["platform"] == "Windows"
    assert s1["queries"][0]["script_type"] == "WMIQuery"
    s2 = body["data"][1]
    assert s2["name"] == "Operating System"
    assert s2["parameters"][0]["key"] == "verbose"

    sens_call = next(c for c in stub.calls if c["url"].endswith("/api/v2/sensors"))
    assert sens_call["params"]["max_age_seconds"] == 600


def test_list_saved_questions_happy_path(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sess_resp = _StubResponse(200, {"data": {"session": "tk-6"}})
    sq_resp = _StubResponse(200, {
        "data": [
            {"id": 100, "name": "All Hosts", "query_text": "Get Computer Name from all machines",
             "action_tracking_flag": False, "archive_enabled_flag": True,
             "expire_seconds": 600, "hidden_flag": False, "public_flag": True},
            {"id": 101, "name": "Patch Status",
             "query_text": "Get Patch Status from all machines",
             "action_tracking_flag": True, "archive_enabled_flag": False,
             "expire_seconds": 1200, "hidden_flag": False, "public_flag": True},
        ]
    })
    app, _ = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={
            "/api/v2/sessions": sess_resp,
            "/api/v2/saved_questions": sq_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/tanium/api/v2/saved_questions",
        params={"max_age_seconds": 86400},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 2
    assert body["data"][0]["name"] == "All Hosts"
    assert body["data"][0]["public_flag"] is True
    assert body["data"][1]["expire_seconds"] == 1200


def test_session_token_cached_across_calls(monkeypatch):
    """Session token should be fetched once and reused for subsequent calls."""
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sess_resp = _StubResponse(200, {"data": {"session": "tk-cache"}})
    status_resp = _StubResponse(200, {
        "data": {"server_clusters": [], "dependent_clusters": []}
    })
    app, stub = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={
            "/api/v2/sessions": sess_resp,
            "/api/v2/system_status": status_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    for _ in range(3):
        r = client.get("/api/v1/tanium/api/v2/system_status", headers=HEADERS)
        assert r.status_code == 200

    sess_calls = [c for c in stub.calls if c["url"].endswith("/api/v2/sessions")]
    assert len(sess_calls) == 1, f"expected 1 session call, saw {len(sess_calls)}"


def test_parse_question_rejects_empty_text(monkeypatch):
    monkeypatch.setenv("TANIUM_URL", "https://tanium.example.com")
    monkeypatch.setenv("TANIUM_USER", "svc-aldeci")
    monkeypatch.setenv("TANIUM_PASSWORD", "s3cret")
    sess_resp = _StubResponse(200, {"data": {"session": "tk-empty"}})
    app, _ = _build_app(
        url="https://tanium.example.com",
        user="svc-aldeci",
        password="s3cret",
        stub_responses={"/api/v2/sessions": sess_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/tanium/api/v2/parse_question",
        json={"text": ""},
        headers=HEADERS,
    )
    # Pydantic min_length=1 catches this -> 422
    assert r.status_code == 422
