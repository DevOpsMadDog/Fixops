"""Tests for sentinelone_router (live SentinelOne EDR REST surface) — ALDECI.

Spins up a minimal FastAPI app with the SentinelOne router mounted. Each
test gets an isolated engine singleton + stub httpx.Client so we
exercise the real ApiToken-header + parsing code paths without hitting
the network.

NO MOCKS rule:
  * When SENTINELONE_URL/SENTINELONE_API_TOKEN are unset the capability
    summary reports ``status="unavailable"`` and every live endpoint
    returns 503.
  * Happy-path tests inject a stub client (not baked-in fake payloads)
    so header-injection + REST + result normalization all run.
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
            if url.endswith(path) or path in url:
                return resp
        return _StubResponse(404, {"errors": [{"message": "not found"}]}, text="not found")

    def get(self, url: str, params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None):
        self.calls.append({
            "method": "GET", "url": url, "params": params or {}, "headers": headers or {},
        })
        return self._match(url)

    def post(self, url: str, json: Optional[Dict[str, Any]] = None,
             headers: Optional[Dict[str, str]] = None):
        self.calls.append({
            "method": "POST", "url": url, "json": json or {},
            "headers": headers or {},
        })
        return self._match(url)

    def close(self) -> None:
        pass


def _build_app(*, url: Optional[str], api_token: Optional[str],
               stub_responses: Dict[str, Any]):
    """Construct an isolated app+engine bound to a stub client."""
    from core import sentinelone_edr_engine as engine_mod

    engine_mod.reset_sentinelone_edr_engine()
    stub = _StubClient(stub_responses)
    engine_mod.get_sentinelone_edr_engine(
        url=url,
        api_token=api_token,
        client=stub,
    )

    from apps.api.sentinelone_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Always reset the singleton before AND after each test."""
    from core import sentinelone_edr_engine as engine_mod
    engine_mod.reset_sentinelone_edr_engine()
    yield
    engine_mod.reset_sentinelone_edr_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("SENTINELONE_URL", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    app, _ = _build_app(url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sentinelone/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "SentinelOne EDR"
    assert "/web/api/v2.1/agents" in body["endpoints"]
    assert "/web/api/v2.1/threats" in body["endpoints"]
    assert "/web/api/v2.1/sites" in body["endpoints"]
    assert "/web/api/v2.1/groups" in body["endpoints"]
    assert "/web/api/v2.1/threats/mitigate" in body["endpoints"]
    assert body["sentinelone_url_present"] is False
    assert body["sentinelone_api_token_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_both_creds_present(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "tok-test")
    app, _ = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token="tok-test",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sentinelone/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sentinelone_url_present"] is True
    assert body["sentinelone_api_token_present"] is True
    assert body["status"] == "ok"


def test_capability_summary_empty_when_only_one_cred(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    app, _ = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token=None,
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sentinelone/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sentinelone_url_present"] is True
    assert body["sentinelone_api_token_present"] is False
    assert body["status"] == "empty"


# ---------------------------------------------------------------------------
# Live endpoints — unavailable path (no creds) returns 503
# ---------------------------------------------------------------------------


def test_list_agents_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SENTINELONE_URL", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    app, _ = _build_app(url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sentinelone/web/api/v2.1/agents",
        params={"limit": 10},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "SENTINELONE_URL" in detail and "SENTINELONE_API_TOKEN" in detail


def test_list_threats_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SENTINELONE_URL", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    app, _ = _build_app(url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sentinelone/web/api/v2.1/threats", headers=HEADERS)
    assert r.status_code == 503


def test_list_sites_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SENTINELONE_URL", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    app, _ = _build_app(url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sentinelone/web/api/v2.1/sites", headers=HEADERS)
    assert r.status_code == 503


def test_list_groups_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SENTINELONE_URL", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    app, _ = _build_app(url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/sentinelone/web/api/v2.1/groups", headers=HEADERS)
    assert r.status_code == 503


def test_mitigate_threats_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SENTINELONE_URL", raising=False)
    monkeypatch.delenv("SENTINELONE_API_TOKEN", raising=False)
    app, _ = _build_app(url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/sentinelone/web/api/v2.1/threats/mitigate/kill",
        json={"filter": {"ids": ["1234"]}},
        headers=HEADERS,
    )
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_agents_happy_path(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "tok-1")
    agents_resp = _StubResponse(200, {
        "data": [
            {
                "id": "111", "computerName": "WS-WIN-01",
                "osType": "windows", "isActive": True, "infected": False,
            },
            {
                "id": "222", "computerName": "WS-LNX-02",
                "osType": "linux", "isActive": True, "infected": True,
            },
        ],
        "pagination": {"nextCursor": "abc", "totalItems": 2},
    })
    app, stub = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token="tok-1",
        stub_responses={"/web/api/v2.1/agents": agents_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sentinelone/web/api/v2.1/agents",
        params={"limit": 50, "isActive": True, "osTypes": "windows,linux"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 2
    assert body["data"][0]["id"] == "111"
    assert body["pagination"]["totalItems"] == 2

    # Verify ApiToken header was sent
    agent_call = next(c for c in stub.calls if "/agents" in c["url"])
    assert agent_call["headers"].get("Authorization") == "ApiToken tok-1"
    assert agent_call["params"]["limit"] == 50
    assert agent_call["params"]["isActive"] == "true"
    assert agent_call["params"]["osTypes"] == "windows,linux"


def test_list_threats_happy_path(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "tok-2")
    threats_resp = _StubResponse(200, {
        "data": [
            {
                "id": "t-1",
                "threatInfo": {
                    "threatName": "WannaCry.exe",
                    "classification": "Ransomware",
                    "confidenceLevel": "malicious",
                    "mitigationStatus": "mitigated",
                },
                "agentRealtimeInfo": {
                    "agentComputerName": "WS-WIN-01",
                    "agentOsType": "windows",
                },
            },
        ],
        "pagination": {"nextCursor": None, "totalItems": 1},
    })
    app, stub = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token="tok-2",
        stub_responses={"/web/api/v2.1/threats": threats_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sentinelone/web/api/v2.1/threats",
        params={"limit": 25, "statuses": "not_mitigated", "resolved": False},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["threatInfo"]["threatName"] == "WannaCry.exe"

    threats_call = next(c for c in stub.calls if "/threats" in c["url"])
    assert threats_call["headers"].get("Authorization") == "ApiToken tok-2"
    assert threats_call["params"]["resolved"] == "false"


def test_list_sites_happy_path(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "tok-3")
    sites_resp = _StubResponse(200, {
        "data": {
            "allSites": {
                "sites": [
                    {
                        "id": "site-001", "name": "Production",
                        "sku": "complete", "state": "active",
                        "totalLicenses": 500, "activeLicenses": 412,
                    },
                ],
                "pagination": {"totalItems": 1, "nextCursor": None},
            },
            "allAccounts": [],
        },
    })
    app, _ = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token="tok-3",
        stub_responses={"/web/api/v2.1/sites": sites_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sentinelone/web/api/v2.1/sites",
        params={"siteType": "paid", "state": "active"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["allSites"]["sites"][0]["id"] == "site-001"
    assert body["data"]["allSites"]["sites"][0]["activeLicenses"] == 412


def test_list_groups_happy_path(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "tok-4")
    groups_resp = _StubResponse(200, {
        "data": [
            {
                "id": "grp-001", "name": "Default",
                "type": "static", "totalAgents": 250,
                "siteId": "site-001", "siteName": "Production",
            },
        ],
        "pagination": {"totalItems": 1, "nextCursor": None},
    })
    app, _ = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token="tok-4",
        stub_responses={"/web/api/v2.1/groups": groups_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/sentinelone/web/api/v2.1/groups",
        params={"siteIds": "site-001", "type": "static"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"][0]["name"] == "Default"
    assert body["data"][0]["totalAgents"] == 250


def test_mitigate_threats_happy_path(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "tok-5")
    mitigate_resp = _StubResponse(200, {"data": {"affected": 3}})
    app, stub = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token="tok-5",
        stub_responses={"/web/api/v2.1/threats/mitigate/kill": mitigate_resp},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/sentinelone/web/api/v2.1/threats/mitigate/kill",
        json={"filter": {"ids": ["t-1", "t-2", "t-3"]}},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["affected"] == 3

    mitigate_call = next(c for c in stub.calls if "/mitigate/kill" in c["url"])
    assert mitigate_call["headers"].get("Authorization") == "ApiToken tok-5"
    assert mitigate_call["json"]["filter"]["ids"] == ["t-1", "t-2", "t-3"]


def test_mitigate_threats_rejects_bad_action(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "tok-6")
    app, _ = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token="tok-6",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/sentinelone/web/api/v2.1/threats/mitigate/nuke-from-orbit",
        json={"filter": {"ids": ["t-1"]}},
        headers=HEADERS,
    )
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "action" in detail


def test_mitigate_threats_rejects_empty_filter(monkeypatch):
    monkeypatch.setenv("SENTINELONE_URL", "https://usea1-test.sentinelone.net")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "tok-7")
    app, _ = _build_app(
        url="https://usea1-test.sentinelone.net",
        api_token="tok-7",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/sentinelone/web/api/v2.1/threats/mitigate/quarantine",
        json={"filter": {}},
        headers=HEADERS,
    )
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "filter" in detail
