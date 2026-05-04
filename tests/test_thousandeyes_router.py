"""Tests for thousandeyes_router — ALDECI.

Spins up a minimal FastAPI app with the ThousandEyes router mounted. Each
test resets the engine singleton so state doesn't bleed between tests.

NO MOCKS rule:
  * Live endpoints return HTTP 503 when no token is set.
  * Capability summary reports ``status="unavailable"`` when token is missing.
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
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "params": params or {},
            }
        )
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(*, api_token: Optional[str], stub_responses: Dict[str, Any]):
    """Construct an isolated app+engine with a stub httpx client."""
    from core import thousandeyes_engine as engine_mod

    engine_mod.reset_thousandeyes_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_thousandeyes_engine(api_token=api_token, client=stub_client)

    from apps.api.thousandeyes_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import thousandeyes_engine as engine_mod

    engine_mod.reset_thousandeyes_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_token(monkeypatch):
    monkeypatch.delenv("THOUSANDEYES_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/thousandeyes/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "ThousandEyes"
    assert "/v6/tests" in body["endpoints"]
    assert "/v6/agents" in body["endpoints"]
    assert "/v6/alerts" in body["endpoints"]
    assert "/v6/web/page-load" in body["endpoints"]
    assert "/v6/net/metrics" in body["endpoints"]
    assert "/v6/dns/server-metrics" in body["endpoints"]
    assert body["thousandeyes_api_token_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    app, _ = _build_app(api_token="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/thousandeyes/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["thousandeyes_api_token_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no token
# ---------------------------------------------------------------------------


def test_list_tests_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("THOUSANDEYES_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/thousandeyes/v6/tests.json", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "THOUSANDEYES_API_TOKEN" in r.json()["detail"]
    _reset()


def test_list_agents_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("THOUSANDEYES_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/thousandeyes/v6/agents.json", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_alerts_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("THOUSANDEYES_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/thousandeyes/v6/alerts.json",
        params={"from": "2026-05-04T00:00:00Z", "to": "2026-05-04T01:00:00Z"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_list_tests_happy_path(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    raw = {
        "test": [
            {
                "testId": 12345,
                "testName": "Acme HTTP Server",
                "type": "http-server",
                "interval": 120,
                "alertsEnabled": 1,
                "enabled": 1,
                "savedEvent": 0,
                "liveShare": False,
                "sourceAgents": [],
                "targetAgents": [],
                "targetTrace": {},
                "modifiedDate": "2026-04-30 12:00:00",
                "modifiedBy": "ops@acme.com",
                "createdDate": "2026-01-01 09:00:00",
                "createdBy": "ops@acme.com",
                "apiLinks": [],
            }
        ]
    }
    app, stub = _build_app(
        api_token="test-token",
        stub_responses={"/v6/tests.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/thousandeyes/v6/tests.json",
        params={"aid": "1234"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body["test"], list)
    assert body["test"][0]["testId"] == 12345
    assert body["test"][0]["type"] == "http-server"
    # Bearer auth header was sent
    assert stub.calls[0]["headers"].get("Authorization") == "Bearer test-token"
    # aid pass-through
    assert stub.calls[0]["params"].get("aid") == "1234"
    _reset()


def test_test_detail_happy_path(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    raw = {
        "test": [
            {
                "testId": 999,
                "testName": "BGP Watch",
                "type": "bgp",
            }
        ]
    }
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={"/v6/tests/999.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/thousandeyes/v6/tests/999.json", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["test"][0]["testId"] == 999
    _reset()


def test_list_agents_happy_path(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    raw = {
        "agents": [
            {
                "agentId": 42,
                "agentName": "AWS-us-east-1",
                "agentType": "cloud",
                "location": "Ashburn, VA",
                "country_id": "US",
                "ipAddresses": ["3.4.5.6"],
                "publicIpAddresses": ["3.4.5.6"],
                "network": "Amazon.com, Inc. (AS16509)",
                "accountGroups": [{"aid": 1234, "accountGroupName": "Default"}],
                "lastSeen": "2026-05-04 00:00:00",
                "agentState": "online",
                "prefix": "3.4.0.0/16",
                "errorDetails": [],
                "targetForTests": "3.4.5.6",
                "ipv6Policy": "force-ipv4",
                "hostname": "agent-1.thousandeyes.com",
                "kernelVersion": "5.15.0",
                "createdDate": "2025-01-01 00:00:00",
                "agentVersion": "1.140.0",
            }
        ]
    }
    app, stub = _build_app(
        api_token="test-token",
        stub_responses={"/v6/agents.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/thousandeyes/v6/agents.json",
        params={"agentTypes": "cloud"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["agents"][0]["agentName"] == "AWS-us-east-1"
    assert body["agents"][0]["agentType"] == "cloud"
    assert stub.calls[0]["params"].get("agentTypes") == "cloud"
    _reset()


def test_list_agents_rejects_invalid_type(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    app, _ = _build_app(api_token="test-token", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/thousandeyes/v6/agents.json",
        params={"agentTypes": "bogus"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_alerts_happy_path(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    raw = {
        "alert": [
            {
                "alertId": 7,
                "alertState": "active",
                "type": "HTTP",
                "ruleId": 100,
                "ruleName": "HTTP-Server availability",
                "dateStart": "2026-05-04 00:05:00",
                "dateEnd": "",
                "severity": "high",
                "agents": [
                    {
                        "agentId": 42,
                        "agentName": "AWS-us-east-1",
                        "alerted": 1,
                        "dateStart": "2026-05-04 00:05:00",
                        "dateEnd": "",
                        "ipAddress": "3.4.5.6",
                        "country": "US",
                        "network": "Amazon",
                        "prefix": "3.4.0.0/16",
                        "asn": 16509,
                        "asName": "AMAZON-02",
                    }
                ],
                "testId": 12345,
                "testName": "Acme HTTP Server",
                "violationCount": 1,
                "apiLinks": [],
            }
        ]
    }
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={"/v6/alerts.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/thousandeyes/v6/alerts.json",
        params={
            "from": "2026-05-04T00:00:00Z",
            "to": "2026-05-04T01:00:00Z",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["alert"][0]["alertId"] == 7
    assert body["alert"][0]["alertState"] == "active"
    _reset()


def test_web_page_load_happy_path(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    raw = {
        "web": {
            "pageLoad": [
                {
                    "aid": 1234,
                    "agentId": 42,
                    "agentName": "AWS-us-east-1",
                    "country_id": "US",
                    "date": "2026-05-04 00:00:00",
                    "location": "Ashburn, VA",
                    "prefix": "3.4.0.0/16",
                    "networkLayer": {},
                    "pageLoadTime": 1280,
                    "totalSize": 245678,
                    "totalRequests": 47,
                    "totalErrors": 0,
                    "errors": [],
                    "waterfallTime": 1240,
                    "errorCount": 0,
                    "retryCount": 0,
                    "downloadTime": 200,
                    "dnsTime": 12,
                    "sslTime": 23,
                    "connectTime": 18,
                    "responseTime": 145,
                    "networkProfile": {
                        "packetLoss": 0,
                        "packetLossDetails": {},
                        "latency": 12,
                        "jitter": 1,
                        "mtu": 1500,
                    },
                }
            ]
        }
    }
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={"/v6/web/page-load.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/thousandeyes/v6/web/page-load.json",
        params={"testId": "12345", "window": "10m"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["web"]["pageLoad"][0]["pageLoadTime"] == 1280
    _reset()


def test_net_metrics_happy_path(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    raw = {
        "net": {
            "metrics": [
                {
                    "aid": 1234,
                    "agentId": 42,
                    "agentName": "AWS-us-east-1",
                    "country_id": "US",
                    "date": "2026-05-04 00:00:00",
                    "location": "Ashburn, VA",
                    "prefix": "3.4.0.0/16",
                    "networkLayer": {},
                    "lossPct": 0.0,
                    "latency": 12.5,
                    "jitter": 0.8,
                    "networkProfile": {},
                }
            ]
        }
    }
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={"/v6/net/metrics.json": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/thousandeyes/v6/net/metrics.json",
        params={"testId": "12345"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["net"]["metrics"][0]["latency"] == 12.5
    _reset()


def test_alerts_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("THOUSANDEYES_API_TOKEN", "test-token")
    app, _ = _build_app(
        api_token="test-token",
        stub_responses={
            "/v6/alerts.json": _StubResponse(
                429, {"errors": [{"detail": "Too Many Requests"}]}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/thousandeyes/v6/alerts.json",
        params={"from": "2026-05-04T00:00:00Z", "to": "2026-05-04T01:00:00Z"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert (
        "rate-limit" in r.json()["detail"].lower()
        or "429" in r.json()["detail"]
    )
    _reset()
