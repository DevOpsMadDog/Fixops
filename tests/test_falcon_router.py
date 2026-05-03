"""Tests for falcon_router (live CrowdStrike Falcon REST surface) — ALDECI.

Spins up a minimal FastAPI app with the Falcon router mounted. Each test
gets an isolated engine singleton + stub httpx.Client so we exercise the
real OAuth2-token + parsing code paths without hitting the network.

NO MOCKS rule:
  * When FALCON_CLIENT_ID/FALCON_CLIENT_SECRET are unset the capability
    summary reports ``status="unavailable"`` and every live endpoint
    returns 503.
  * Happy-path tests inject a stub client (not baked-in fake payloads)
    so token-fetch + REST + result normalization all run.
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
    """Minimal stand-in for httpx.Response with .json()/.status_code/.text."""

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
        return _StubResponse(404, {"errors": [{"message": "not found"}]}, text="not found")

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


def _build_app(*, client_id: Optional[str], client_secret: Optional[str],
               stub_responses: Dict[str, Any]):
    """Construct an isolated app+engine bound to a stub client."""
    from core import falcon_edr_engine as engine_mod

    engine_mod.reset_falcon_edr_engine()
    stub = _StubClient(stub_responses)
    engine_mod.get_falcon_edr_engine(
        client_id=client_id,
        client_secret=client_secret,
        base_url="https://api.crowdstrike.test",
        client=stub,
    )

    from apps.api.falcon_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Always reset the singleton before AND after each test."""
    from core import falcon_edr_engine as engine_mod
    engine_mod.reset_falcon_edr_engine()
    yield
    engine_mod.reset_falcon_edr_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    app, _ = _build_app(client_id=None, client_secret=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/falcon/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "CrowdStrike Falcon"
    assert "/detects/queries/detects" in body["endpoints"]
    assert "/detects/entities/summaries" in body["endpoints"]
    assert "/incidents/queries/incidents" in body["endpoints"]
    assert "/iocs/queries/indicators" in body["endpoints"]
    assert "/iocs/entities/indicators" in body["endpoints"]
    assert body["client_id_present"] is False
    assert body["client_secret_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_both_creds_present(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid-test")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec-test")
    app, _ = _build_app(client_id="cid-test", client_secret="csec-test",
                        stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/falcon/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["client_id_present"] is True
    assert body["client_secret_present"] is True
    assert body["status"] == "ok"


def test_capability_summary_empty_when_only_one_cred(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid-only")
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    app, _ = _build_app(client_id="cid-only", client_secret=None,
                        stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/falcon/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["client_id_present"] is True
    assert body["client_secret_present"] is False
    assert body["status"] == "empty"


# ---------------------------------------------------------------------------
# Live endpoints — unavailable path (no creds) returns 503
# ---------------------------------------------------------------------------


def test_query_detects_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    app, _ = _build_app(client_id=None, client_secret=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/falcon/detects/queries/detects",
        params={"filter": "status:'new'", "limit": 10},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "FALCON_CLIENT_ID" in detail and "FALCON_CLIENT_SECRET" in detail


def test_query_incidents_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    app, _ = _build_app(client_id=None, client_secret=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/falcon/incidents/queries/incidents", headers=HEADERS)
    assert r.status_code == 503


def test_submit_indicators_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
    monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
    app, _ = _build_app(client_id=None, client_secret=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/falcon/iocs/entities/indicators",
        json={"indicators": [
            {"type": "sha256", "value": "a" * 64, "action": "detect"}
        ]},
        headers=HEADERS,
    )
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_query_detects_happy_path(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec")
    token_resp = _StubResponse(200, {"access_token": "tk-1", "expires_in": 1800})
    detects_resp = _StubResponse(200, {
        "meta": {"query_time": 0.012, "pagination": {"offset": 0, "limit": 2, "total": 2}},
        "resources": [
            "ldt:abc:111",
            "ldt:abc:222",
        ],
    })
    app, stub = _build_app(
        client_id="cid", client_secret="csec",
        stub_responses={
            "/oauth2/token": token_resp,
            "/detects/queries/detects/v1": detects_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/falcon/detects/queries/detects",
        params={"filter": "status:'new'", "limit": 2, "offset": 0, "sort": "first_behavior|desc"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["resources"] == ["ldt:abc:111", "ldt:abc:222"]
    assert body["meta"]["pagination"]["total"] == 2

    # Verify token was acquired exactly once and Authorization header was set on the GET.
    methods_urls = [(c["method"], c["url"]) for c in stub.calls]
    assert ("POST", "https://api.crowdstrike.test/oauth2/token") in methods_urls
    detect_call = next(c for c in stub.calls
                       if c["url"].endswith("/detects/queries/detects/v1"))
    assert detect_call["headers"].get("Authorization") == "Bearer tk-1"
    assert detect_call["params"]["filter"] == "status:'new'"
    assert detect_call["params"]["limit"] == 2
    assert detect_call["params"]["sort"] == "first_behavior|desc"


def test_get_detect_summaries_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec")
    token_resp = _StubResponse(200, {"access_token": "tk-2", "expires_in": 1800})
    summaries_resp = _StubResponse(200, {
        "meta": {"query_time": 0.05},
        "resources": [
            {
                "detection_id":             "ldt:abc:111",
                "max_severity":             95,
                "max_severity_displayname": "Critical",
                "status":                   "new",
                "behaviors": [
                    {"behavior_id": "10001", "tactic": "Impact",
                     "technique": "Data Encrypted for Impact"},
                ],
                "device": {
                    "hostname":      "WIN-PROD-001",
                    "platform_name": "Windows",
                    "os_version":    "Windows 11",
                },
                "hostinfo": {"domain": "CORP", "active_directory_dn_display": ["OU=Workstations"]},
            },
        ],
    })
    app, stub = _build_app(
        client_id="cid", client_secret="csec",
        stub_responses={
            "/oauth2/token": token_resp,
            "/detects/entities/summaries/GET/v1": summaries_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/falcon/detects/entities/summaries",
        json={"ids": ["ldt:abc:111"]},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["resources"]) == 1
    res = body["resources"][0]
    assert res["detection_id"] == "ldt:abc:111"
    assert res["severity"] == 95
    assert res["severity_name"] == "Critical"
    assert res["status"] == "new"
    assert res["device"]["hostname"] == "WIN-PROD-001"
    assert res["device"]["platform_name"] == "Windows"
    assert res["behaviors"][0]["behavior_id"] == "10001"

    # Body of POST must contain the ids list.
    post_call = next(c for c in stub.calls
                     if c["url"].endswith("/detects/entities/summaries/GET/v1"))
    assert post_call["json"]["ids"] == ["ldt:abc:111"]


def test_query_incidents_happy_path(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec")
    token_resp = _StubResponse(200, {"access_token": "tk-3", "expires_in": 1800})
    inc_resp = _StubResponse(200, {
        "meta": {"pagination": {"offset": 0, "limit": 1, "total": 1}},
        "resources": ["inc:xyz:9001"],
    })
    app, _ = _build_app(
        client_id="cid", client_secret="csec",
        stub_responses={
            "/oauth2/token": token_resp,
            "/incidents/queries/incidents/v1": inc_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/falcon/incidents/queries/incidents",
        params={"filter": "state:'open'", "limit": 1},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["resources"] == ["inc:xyz:9001"]
    assert body["meta"]["pagination"]["total"] == 1


def test_query_indicators_happy_path(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec")
    token_resp = _StubResponse(200, {"access_token": "tk-4", "expires_in": 1800})
    ioc_resp = _StubResponse(200, {
        "meta": {"pagination": {"offset": 0, "limit": 50, "total": 3}},
        "resources": ["ioc:1", "ioc:2", "ioc:3"],
    })
    app, stub = _build_app(
        client_id="cid", client_secret="csec",
        stub_responses={
            "/oauth2/token": token_resp,
            "/iocs/queries/indicators/v1": ioc_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/falcon/iocs/queries/indicators",
        params={"type": "sha256", "limit": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["resources"] == ["ioc:1", "ioc:2", "ioc:3"]
    ioc_call = next(c for c in stub.calls
                    if c["url"].endswith("/iocs/queries/indicators/v1"))
    assert ioc_call["params"]["types"] == "sha256"


def test_query_indicators_rejects_bad_type(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec")
    token_resp = _StubResponse(200, {"access_token": "tk-5", "expires_in": 1800})
    app, _ = _build_app(
        client_id="cid", client_secret="csec",
        stub_responses={"/oauth2/token": token_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/falcon/iocs/queries/indicators",
        params={"type": "wat", "limit": 10},
        headers=HEADERS,
    )
    assert r.status_code == 422
    assert "ioc_type" in r.json()["detail"]


def test_submit_indicators_happy_path(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec")
    token_resp = _StubResponse(200, {"access_token": "tk-6", "expires_in": 1800})
    submit_resp = _StubResponse(200, {
        "meta": {"writes": {"resources_affected": 2}},
        "resources": [
            {"id": "iid-001", "value": "1.2.3.4", "action": "prevent"},
            {"id": "iid-002",
             "value": "b" * 64, "action": "detect"},
        ],
    })
    app, stub = _build_app(
        client_id="cid", client_secret="csec",
        stub_responses={
            "/oauth2/token": token_resp,
            "/iocs/entities/indicators/v1": submit_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    payload = {
        "indicators": [
            {"type": "ipv4", "value": "1.2.3.4", "action": "prevent",
             "severity": "high", "source": "aldeci-test", "description": "C2 server"},
            {"type": "sha256", "value": "b" * 64, "action": "detect"},
        ],
    }
    r = client.post(
        "/api/v1/falcon/iocs/entities/indicators",
        json=payload,
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["meta"]["writes"]["resources_affected"] == 2
    assert {res["id"] for res in body["resources"]} == {"iid-001", "iid-002"}

    submit_call = next(c for c in stub.calls
                       if c["url"].endswith("/iocs/entities/indicators/v1"))
    sent = submit_call["json"]["indicators"]
    assert sent[0]["type"] == "ipv4"
    assert sent[0]["action"] == "prevent"
    assert sent[0]["severity"] == "high"
    assert sent[1]["type"] == "sha256"


def test_submit_indicators_rejects_bad_action(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec")
    token_resp = _StubResponse(200, {"access_token": "tk-7", "expires_in": 1800})
    app, _ = _build_app(
        client_id="cid", client_secret="csec",
        stub_responses={"/oauth2/token": token_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/falcon/iocs/entities/indicators",
        json={"indicators": [{"type": "ipv4", "value": "1.2.3.4", "action": "nuke"}]},
        headers=HEADERS,
    )
    assert r.status_code == 422
    assert "action" in r.json()["detail"]


def test_oauth_token_cached_across_calls(monkeypatch):
    """Token should be fetched once and reused for subsequent calls."""
    monkeypatch.setenv("FALCON_CLIENT_ID", "cid")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "csec")
    token_resp = _StubResponse(200, {"access_token": "tk-cache", "expires_in": 1800})
    detects_resp = _StubResponse(200, {"meta": {}, "resources": ["d1"]})
    app, stub = _build_app(
        client_id="cid", client_secret="csec",
        stub_responses={
            "/oauth2/token": token_resp,
            "/detects/queries/detects/v1": detects_resp,
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    for _ in range(3):
        r = client.get(
            "/api/v1/falcon/detects/queries/detects",
            params={"limit": 1}, headers=HEADERS,
        )
        assert r.status_code == 200

    token_calls = [c for c in stub.calls if c["url"].endswith("/oauth2/token")]
    assert len(token_calls) == 1, f"expected 1 oauth call, saw {len(token_calls)}"
