"""Tests for duo_router (Auth v2 + Admin v1) - ALDECI.

Spins up a minimal FastAPI app with the Duo router mounted. Each test
gets a fresh engine singleton bound to a stub httpx client so we exercise
the real signing + parsing code paths (not a hardcoded engine payload).

NO MOCKS rule:
  * /auth/* and /admin/* return HTTP 503 when DUO_IKEY/SKEY/HOST missing.
  * Capability summary -> ``status="unavailable"`` when any cred missing.
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

    def _match(self, url: str):
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(self, url: str, headers=None, params=None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": headers or {}, "params": params or {}}
        )
        return self._match(url)

    def post(self, url: str, headers=None, content=None, data=None, params=None):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "content": content,
                "data": data,
                "params": params or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    ikey: Optional[str],
    skey: Optional[str],
    host: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated FastAPI app + Duo engine bound to stubs."""
    from core import duo_mfa_engine as engine_mod

    engine_mod.reset_duo_mfa_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_duo_mfa_engine(
        ikey=ikey,
        skey=skey,
        host=host,
        client=stub_client,
    )

    from apps.api.duo_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import duo_mfa_engine as engine_mod

    engine_mod.reset_duo_mfa_engine()


def _ok(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"stat": "OK", "response": payload}


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("DUO_IKEY", raising=False)
    monkeypatch.delenv("DUO_SKEY", raising=False)
    monkeypatch.delenv("DUO_HOST", raising=False)
    app, _ = _build_app(ikey=None, skey=None, host=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/duo/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Duo Security"
    assert "/auth/v2/auth" in body["endpoints"]
    assert "/admin/v1/users" in body["endpoints"]
    assert body["duo_ikey_present"] is False
    assert body["duo_skey_present"] is False
    assert body["duo_host_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_all_creds_present(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIXXXXXXXXXXXXXXXXXX")
    monkeypatch.setenv("DUO_SKEY", "skey-test")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    app, _ = _build_app(
        ikey="DIXXXXXXXXXXXXXXXXXX",
        skey="skey-test",
        host="api-12345.duosecurity.com",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/duo/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["duo_ikey_present"] is True
    assert body["duo_skey_present"] is True
    assert body["duo_host_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no creds
# ---------------------------------------------------------------------------


def test_preauth_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("DUO_IKEY", raising=False)
    monkeypatch.delenv("DUO_SKEY", raising=False)
    monkeypatch.delenv("DUO_HOST", raising=False)
    app, _ = _build_app(ikey=None, skey=None, host=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/duo/auth/v2/preauth",
        json={"username": "alice"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "DUO_" in r.json()["detail"]
    _reset()


def test_check_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("DUO_IKEY", raising=False)
    monkeypatch.delenv("DUO_SKEY", raising=False)
    monkeypatch.delenv("DUO_HOST", raising=False)
    app, _ = _build_app(ikey=None, skey=None, host=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/duo/auth/v2/check", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_admin_users_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("DUO_IKEY", raising=False)
    monkeypatch.delenv("DUO_SKEY", raising=False)
    monkeypatch.delenv("DUO_HOST", raising=False)
    app, _ = _build_app(ikey=None, skey=None, host=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/duo/admin/v1/users",
        params={"username": "alice", "limit": 50, "offset": 0},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths - stubbed httpx client (real signing + parsing exercised)
# ---------------------------------------------------------------------------


def test_preauth_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    raw = _ok(
        {
            "result": "auth",
            "status_msg": "Account is active",
            "devices": [
                {
                    "capabilities": ["push", "sms", "phone", "mobile_otp"],
                    "device": "DPFZRS9FB0D46QFTM891",
                    "type": "phone",
                    "name": "",
                    "number": "XXX-XXX-0100",
                    "sms_nextcode": "1234",
                }
            ],
        }
    )
    app, stub = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={"/auth/v2/preauth": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/duo/auth/v2/preauth",
        json={"username": "alice", "ipaddr": "10.0.0.5"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"] == "auth"
    assert body["status_msg"] == "Account is active"
    assert len(body["devices"]) == 1
    dev = body["devices"][0]
    assert dev["device"] == "DPFZRS9FB0D46QFTM891"
    assert "push" in dev["capabilities"]
    assert dev["number"] == "XXX-XXX-0100"
    # Verify signing happened: Authorization + Date headers present.
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert len(posts) == 1
    h = posts[0]["headers"]
    assert h.get("Authorization", "").startswith("Basic ")
    assert "Date" in h
    _reset()


def test_auth_happy_path_async_returns_txid(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    raw = _ok({"txid": "tx-abc-123"})
    app, stub = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={"/auth/v2/auth": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/duo/auth/v2/auth",
        json={
            "username": "alice",
            "factor": "push",
            "device": "auto",
            "async": True,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["txid"] == "tx-abc-123"
    # Verify signed POST went out with form-urlencoded body.
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert len(posts) == 1
    body_str = posts[0]["content"] or ""
    assert "factor=push" in body_str
    assert "username=alice" in body_str
    assert "async=1" in body_str
    _reset()


def test_auth_status_returns_waiting(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    raw = _ok(
        {"result": "waiting", "status": "pushed", "status_msg": "Pushed a login request to your phone..."}
    )
    app, _ = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={"/auth/v2/auth_status": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/duo/auth/v2/auth_status",
        params={"txid": "tx-abc-123"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"] == "waiting"
    assert body["status"] == "pushed"
    _reset()


def test_check_returns_time(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    raw = _ok({"time": 1714838400})
    app, _ = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={"/auth/v2/check": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/duo/auth/v2/check", headers=HEADERS)
    assert r.status_code == 200, r.text
    assert r.json()["time"] == 1714838400
    _reset()


def test_admin_users_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    raw = _ok(
        [
            {
                "user_id": "DUKM2N6F6QGY8XL5A8KR",
                "username": "alice",
                "alias1": "alice@example.com",
                "alias2": "",
                "alias3": "",
                "alias4": "",
                "realname": "Alice Anderson",
                "email": "alice@example.com",
                "status": "active",
                "last_login": 1714000000,
                "phones": [{"phone_id": "DPFZRS9FB0D46QFTM891"}],
                "tokens": [],
                "u2ftokens": [],
                "groups": [{"group_id": "DGXXXXXXXXXXXXXXXXXX", "name": "engineering"}],
            }
        ]
    )
    app, _ = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={"/admin/v1/users": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/duo/admin/v1/users",
        params={"username": "alice", "limit": 50, "offset": 0},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["users"]) == 1
    u = body["users"][0]
    assert u["user_id"] == "DUKM2N6F6QGY8XL5A8KR"
    assert u["username"] == "alice"
    assert u["alias1"] == "alice@example.com"
    assert u["status"] == "active"
    assert len(u["phones"]) == 1
    assert len(u["groups"]) == 1
    _reset()


def test_admin_integrations_happy_path(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    raw = _ok(
        [
            {
                "integration_key": "DIWJ8X6AEYOR5OMC6TQ1",
                "name": "VPN Gateway",
                "type": "ldapproxy",
                "enroll_policy": "enroll",
                "greeting": "Welcome",
                "networks_for_api_access": ["10.0.0.0/8"],
            }
        ]
    )
    app, _ = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={"/admin/v1/integrations": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/duo/admin/v1/integrations",
        params={"limit": 100, "offset": 0},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["integrations"]) == 1
    i = body["integrations"][0]
    assert i["integration_key"] == "DIWJ8X6AEYOR5OMC6TQ1"
    assert i["type"] == "ldapproxy"
    assert i["networks_for_api_access"] == ["10.0.0.0/8"]
    _reset()


# ---------------------------------------------------------------------------
# Upstream error / FAIL stat / validation
# ---------------------------------------------------------------------------


def test_check_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    app, _ = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={
            "/auth/v2/check": _StubResponse(
                429, {"stat": "FAIL", "code": 42901}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/duo/auth/v2/check", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()


def test_auth_returns_422_on_invalid_factor(monkeypatch):
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    app, _ = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/duo/auth/v2/auth",
        json={"username": "alice", "factor": "totally-bogus"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_admin_users_503_on_fail_stat(monkeypatch):
    """Duo wraps everything in {stat:OK|FAIL,...}. A FAIL must surface 503."""
    monkeypatch.setenv("DUO_IKEY", "DIIIIIIIIIIIIIIIIIII")
    monkeypatch.setenv("DUO_SKEY", "secret-key")
    monkeypatch.setenv("DUO_HOST", "api-12345.duosecurity.com")
    raw = {"stat": "FAIL", "code": 40103, "message": "Invalid signature"}
    app, _ = _build_app(
        ikey="DIIIIIIIIIIIIIIIIIII",
        skey="secret-key",
        host="api-12345.duosecurity.com",
        stub_responses={"/admin/v1/users": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/duo/admin/v1/users",
        params={"limit": 10, "offset": 0},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "FAIL" in r.json()["detail"]
    _reset()
