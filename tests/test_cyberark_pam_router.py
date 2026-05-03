"""Tests for cyberark_pam_router — ALDECI CyberArk PAM (PVWA REST) integration.

NO MOCKS rule:
  * When CYBERARK_URL / CYBERARK_USERNAME / CYBERARK_PASSWORD is unset, the
    capability summary reports ``status="unavailable"`` and every live
    endpoint returns 503.
  * Happy-path tests inject a stub httpx.Client so we still exercise the
    real header construction + JSON parsing paths (logon, token cache,
    Authorization header forwarding, normalisers).
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

LOGON_TOKEN = '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test-session-token.signature"'


# ---------------------------------------------------------------------------
# Stub httpx client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: Any = None, text: Optional[str] = None):
        self.status_code = status_code
        self._payload = payload
        if text is not None:
            self.text = text
        elif payload is None:
            self.text = ""
        elif isinstance(payload, str):
            self.text = payload
        else:
            self.text = json.dumps(payload)

    def json(self) -> Any:
        if isinstance(self._payload, str):
            # CyberArk returns raw quoted strings for /Logon and /Password/Retrieve
            return json.loads(self._payload)
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
            {"method": "GET", "url": url, "params": params or {}, "headers": headers or {}}
        )
        for needle, resp in self._get.items():
            if needle in url:
                return resp
        return _StubResponse(404, {"errors": ["not found"]}, text="not found")

    def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "data": data,
                "json": json,
                "headers": headers or {},
            }
        )
        for needle, resp in self._post.items():
            if needle in url:
                return resp
        return _StubResponse(404, {"errors": ["not found"]}, text="not found")

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# App builder
# ---------------------------------------------------------------------------


def _build_app(
    *,
    cyberark_url: Optional[str],
    cyberark_username: Optional[str],
    cyberark_password: Optional[str],
    get_responses: Optional[Dict[str, Any]] = None,
    post_responses: Optional[Dict[str, Any]] = None,
):
    from core import cyberark_pam_engine as engine_mod

    engine_mod.reset_cyberark_pam_engine()
    # Pre-prime the logon stub so authenticated calls auto-acquire a token.
    post_responses = dict(post_responses or {})
    post_responses.setdefault(
        "/PasswordVault/API/auth/Cyberark/Logon",
        _StubResponse(200, LOGON_TOKEN.strip('"'), text=LOGON_TOKEN),
    )
    stub = _StubClient(get_responses, post_responses)

    engine_mod.get_cyberark_pam_engine(
        cyberark_url=cyberark_url,
        cyberark_username=cyberark_username,
        cyberark_password=cyberark_password,
        verify_ssl=False,
        client=stub,
    )

    from apps.api.cyberark_pam_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import cyberark_pam_engine as engine_mod
    engine_mod.reset_cyberark_pam_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_env(monkeypatch):
    monkeypatch.delenv("CYBERARK_URL", raising=False)
    monkeypatch.delenv("CYBERARK_USERNAME", raising=False)
    monkeypatch.delenv("CYBERARK_PASSWORD", raising=False)
    app, _ = _build_app(
        cyberark_url=None, cyberark_username=None, cyberark_password=None
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/cyberark-pam/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "CyberArk PAM (PVWA)"
    for ep in (
        "/PasswordVault/API/auth/Cyberark/Logon",
        "/PasswordVault/API/Accounts",
        "/PasswordVault/API/Safes",
        "/PasswordVault/API/PSM/Sessions",
        "/PasswordVault/API/Accounts/{id}/Password/Retrieve",
    ):
        assert ep in body["endpoints"]
    assert body["cyberark_url_present"] is False
    assert body["cyberark_username_present"] is False
    assert body["cyberark_password_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_empty_when_env_present(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    app, _ = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/cyberark-pam/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cyberark_url_present"] is True
    assert body["cyberark_username_present"] is True
    assert body["cyberark_password_present"] is True
    assert body["status"] == "empty"
    _reset()


# ---------------------------------------------------------------------------
# 503 — env missing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/api/v1/cyberark-pam/PasswordVault/API/auth/Cyberark/Logon",
         {"username": "u", "password": "p"}),
        ("POST", "/api/v1/cyberark-pam/PasswordVault/API/auth/Logoff", None),
        ("GET", "/api/v1/cyberark-pam/PasswordVault/API/Accounts", None),
        ("GET", "/api/v1/cyberark-pam/PasswordVault/API/Accounts/abc-123", None),
        ("POST", "/api/v1/cyberark-pam/PasswordVault/API/Accounts/abc-123/Password/Retrieve",
         {"reason": "unit-test"}),
        ("GET", "/api/v1/cyberark-pam/PasswordVault/API/Safes", None),
        ("GET", "/api/v1/cyberark-pam/PasswordVault/API/Safes/payments-safe/Members", None),
        ("GET", "/api/v1/cyberark-pam/PasswordVault/API/PSM/Sessions", None),
        ("GET", "/api/v1/cyberark-pam/PasswordVault/API/PSM/Recordings", None),
    ],
)
def test_endpoint_returns_503_when_env_missing(monkeypatch, method, path, body):
    monkeypatch.delenv("CYBERARK_URL", raising=False)
    monkeypatch.delenv("CYBERARK_USERNAME", raising=False)
    monkeypatch.delenv("CYBERARK_PASSWORD", raising=False)
    app, _ = _build_app(
        cyberark_url=None, cyberark_username=None, cyberark_password=None
    )
    client = TestClient(app, raise_server_exceptions=True)
    if method == "GET":
        r = client.get(path, headers=HEADERS)
    else:
        r = client.post(path, headers=HEADERS, json=body)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "CYBERARK_URL" in detail or "CYBERARK_USERNAME" in detail or "CYBERARK_PASSWORD" in detail
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx
# ---------------------------------------------------------------------------


def test_logon_returns_quoted_token(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    app, stub = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        post_responses={
            "/PasswordVault/API/auth/Cyberark/Logon": _StubResponse(
                200, LOGON_TOKEN.strip('"'), text=LOGON_TOKEN
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/cyberark-pam/PasswordVault/API/auth/Cyberark/Logon",
        headers=HEADERS,
        json={"username": "ci-user", "password": "ci-pass", "concurrentSession": True},
    )
    assert r.status_code == 200, r.text
    # Raw quoted string contract
    assert r.text == LOGON_TOKEN
    assert r.headers["content-type"].startswith("application/json")

    call = next(c for c in stub.calls if c["method"] == "POST" and "/Logon" in c["url"])
    assert call["json"]["username"] == "ci-user"
    assert call["json"]["password"] == "ci-pass"
    assert call["json"]["concurrentSession"] is True
    _reset()


def test_list_accounts_happy_path(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    raw = {
        "value": [
            {
                "id": "11_22",
                "name": "Operating System-WinDomain-payments-svc",
                "address": "10.0.0.5",
                "userName": "payments-svc",
                "platformId": "WinDomain",
                "safeName": "payments-safe",
                "secretType": "password",
                "secretManagement": {
                    "automaticManagementEnabled": True,
                    "status": "succeeded",
                    "lastModifiedTime": 1714000000,
                    "lastReconciledTime": 1714100000,
                    "lastVerifiedTime": 1714200000,
                },
                "platformAccountProperties": {"LogonDomain": "CORP"},
                "createdTime": 1700000000,
                "categoryModificationTime": 1710000000,
                "secretMode": {},
                "remoteMachinesAccess": {
                    "remoteMachines": "rds-1.corp,rds-2.corp",
                    "accessRestrictedToRemoteMachines": True,
                },
                "status": "active",
                "owners": [{"name": "platform-team"}],
            }
        ],
        "count": 1,
        "nextLink": "",
    }
    app, stub = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        get_responses={"/PasswordVault/API/Accounts": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cyberark-pam/PasswordVault/API/Accounts?search=payments&limit=25&offset=0&sort=name",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1
    acct = body["value"][0]
    assert acct["id"] == "11_22"
    assert acct["safeName"] == "payments-safe"
    assert acct["secretManagement"]["status"] == "succeeded"
    assert acct["remoteMachinesAccess"]["accessRestrictedToRemoteMachines"] is True
    assert acct["platformAccountProperties"]["LogonDomain"] == "CORP"

    # Verify Authorization header forwarded with cached token.
    get_call = next(c for c in stub.calls if c["method"] == "GET")
    assert get_call["headers"]["Authorization"] == LOGON_TOKEN
    assert get_call["params"]["search"] == "payments"
    assert get_call["params"]["limit"] == 25
    assert get_call["params"]["offset"] == 0
    assert get_call["params"]["sort"] == "name"
    _reset()


def test_get_account_happy_path(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    raw = {
        "id": "44_55",
        "name": "RootShell-prod-db1",
        "address": "10.0.0.99",
        "userName": "root",
        "platformId": "UnixSSH",
        "safeName": "db-prod-safe",
        "secretType": "password",
        "secretManagement": {"automaticManagementEnabled": False, "status": "failed"},
        "createdTime": 1700000000,
    }
    app, _ = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        get_responses={"/PasswordVault/API/Accounts/44_55": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cyberark-pam/PasswordVault/API/Accounts/44_55", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "44_55"
    assert body["userName"] == "root"
    assert body["secretManagement"]["status"] == "failed"
    _reset()


def test_retrieve_password_returns_quoted_string(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    pw_raw = '"S3cret!Pass#123"'
    app, stub = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        post_responses={
            "/PasswordVault/API/Accounts/77_88/Password/Retrieve": _StubResponse(
                200, "S3cret!Pass#123", text=pw_raw
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/cyberark-pam/PasswordVault/API/Accounts/77_88/Password/Retrieve",
        headers=HEADERS,
        json={
            "reason": "incident-2026-05-04",
            "ticketingSystemName": "Jira",
            "ticketId": "INC-12345",
            "actionType": "show",
            "isUse": False,
            "useDoubleAuth": True,
        },
    )
    assert r.status_code == 200, r.text
    assert r.text == pw_raw
    assert r.headers["content-type"].startswith("application/json")

    post_call = next(
        c for c in stub.calls
        if c["method"] == "POST" and "/Password/Retrieve" in c["url"]
    )
    assert post_call["json"]["reason"] == "incident-2026-05-04"
    assert post_call["json"]["ticketingSystemName"] == "Jira"
    assert post_call["json"]["ticketId"] == "INC-12345"
    assert post_call["json"]["actionType"] == "show"
    assert post_call["json"]["isUse"] is False
    assert post_call["json"]["useDoubleAuth"] is True
    assert post_call["headers"]["Authorization"] == LOGON_TOKEN
    _reset()


def test_retrieve_password_rejects_invalid_action_type(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    app, _ = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/cyberark-pam/PasswordVault/API/Accounts/77_88/Password/Retrieve",
        headers=HEADERS,
        json={"reason": "any", "actionType": "delete"},
    )
    assert r.status_code == 422, r.text
    assert "actionType" in r.json()["detail"]
    _reset()


def test_list_safes_happy_path(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    raw = {
        "value": [
            {
                "safeUrlId": "payments-safe",
                "safeName": "payments-safe",
                "safeNumber": 7,
                "description": "Payments service vault",
                "location": "\\",
                "creator": {"id": "u-1", "name": "vault-admin"},
                "olacEnabled": True,
                "managingCPM": "PasswordManager",
                "numberOfVersionsRetention": 5,
                "numberOfDaysRetention": 30,
                "autoPurgeEnabled": False,
                "creationTime": 1700000000,
                "lastModificationTime": 1714000000,
                "accounts": [],
            }
        ],
        "count": 1,
        "nextLink": "",
    }
    app, stub = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        get_responses={"/PasswordVault/API/Safes": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cyberark-pam/PasswordVault/API/Safes?limit=10&extendedDetails=true",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1
    safe = body["value"][0]
    assert safe["safeName"] == "payments-safe"
    assert safe["creator"]["name"] == "vault-admin"
    assert safe["olacEnabled"] is True
    assert safe["numberOfVersionsRetention"] == 5

    get_call = next(c for c in stub.calls if c["method"] == "GET")
    assert get_call["params"]["extendedDetails"] == "true"
    assert get_call["params"]["limit"] == 10
    _reset()


def test_list_safe_members_validates_member_type(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    raw = {
        "value": [
            {"memberName": "vault-admin", "memberType": "User", "permissions": {}}
        ],
        "count": 1,
    }
    app, _ = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        get_responses={
            "/PasswordVault/API/Safes/payments-safe/Members": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    # Bad memberType -> 422
    r_bad = client.get(
        "/api/v1/cyberark-pam/PasswordVault/API/Safes/payments-safe/Members?memberType=Admin",
        headers=HEADERS,
    )
    assert r_bad.status_code == 422, r_bad.text

    # Good memberType -> 200
    r = client.get(
        "/api/v1/cyberark-pam/PasswordVault/API/Safes/payments-safe/Members?memberType=User",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1
    assert body["value"][0]["memberName"] == "vault-admin"
    _reset()


def test_list_psm_sessions_happy_path(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    raw = {
        "value": [
            {
                "sessionID": "sess-001",
                "safeName": "payments-safe",
                "accountID": "11_22",
                "user": "ci-user",
                "source": "10.0.0.10",
                "target": "10.0.0.5",
                "accountUsername": "payments-svc",
                "accountAddress": "10.0.0.5",
                "platform": "WinDomain",
                "connectionComponentID": "PSM-RDP",
                "protocol": "RDP",
                "applicativeUsername": "",
                "command": "",
                "accountVerificationStatus": "succeeded",
                "totalCommands": 12,
                "completedCommands": 12,
                "sessionDuration": 305,
                "startTime": 1714200000,
                "endTime": 1714200305,
                "riskScore": 0,
                "fromIP": "10.0.0.10",
                "ticketID": "INC-12345",
                "sessionGuid": "abc-def-1234",
            }
        ]
    }
    app, _ = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        get_responses={"/PasswordVault/API/PSM/Sessions": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cyberark-pam/PasswordVault/API/PSM/Sessions?limit=50&search=payments",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    sess = body["value"][0]
    assert sess["sessionID"] == "sess-001"
    assert sess["protocol"] == "RDP"
    assert sess["totalCommands"] == 12
    assert sess["sessionDuration"] == 305
    _reset()


def test_list_psm_recordings_happy_path(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    raw = {
        "value": [
            {
                "recordingID": "rec-001",
                "sessionID": "sess-001",
                "user": "ci-user",
                "duration": 305,
                "startTime": 1714200000,
                "size": 1024000,
            }
        ]
    }
    app, stub = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        get_responses={"/PasswordVault/API/PSM/Recordings": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cyberark-pam/PasswordVault/API/PSM/Recordings"
        "?fromDate=2026-05-01T00:00:00Z&toDate=2026-05-04T23:59:59Z&limit=100",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["value"][0]["recordingID"] == "rec-001"
    get_call = next(c for c in stub.calls if c["method"] == "GET")
    assert get_call["params"]["fromDate"] == "2026-05-01T00:00:00Z"
    assert get_call["params"]["toDate"] == "2026-05-04T23:59:59Z"
    assert get_call["params"]["limit"] == 100
    _reset()


def test_logoff_returns_204(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    app, stub = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        post_responses={
            "/PasswordVault/API/auth/Logoff": _StubResponse(200, {}, text="{}"),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/cyberark-pam/PasswordVault/API/auth/Logoff", headers=HEADERS
    )
    assert r.status_code == 204, r.text
    logoff_call = next(c for c in stub.calls if "/Logoff" in c["url"])
    assert logoff_call["headers"]["Authorization"] == LOGON_TOKEN
    _reset()


def test_upstream_403_translates_to_503(monkeypatch):
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    app, _ = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        get_responses={
            "/PasswordVault/API/Accounts": _StubResponse(
                403, {"errorCode": "ITATS003E", "errorMessage": "Forbidden"},
                text="forbidden",
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cyberark-pam/PasswordVault/API/Accounts", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    assert "rejected token" in r.json()["detail"].lower()
    _reset()


def test_token_caching_avoids_relogon(monkeypatch):
    """Second call must reuse cached token — no second Logon POST."""
    monkeypatch.setenv("CYBERARK_URL", "https://pvwa.example.com")
    monkeypatch.setenv("CYBERARK_USERNAME", "ci-user")
    monkeypatch.setenv("CYBERARK_PASSWORD", "ci-pass")
    raw = {"value": [], "count": 0}
    app, stub = _build_app(
        cyberark_url="https://pvwa.example.com",
        cyberark_username="ci-user",
        cyberark_password="ci-pass",
        get_responses={"/PasswordVault/API/Accounts": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    for _ in range(3):
        r = client.get(
            "/api/v1/cyberark-pam/PasswordVault/API/Accounts", headers=HEADERS
        )
        assert r.status_code == 200, r.text

    logon_calls = [c for c in stub.calls if "/Logon" in c["url"]]
    assert len(logon_calls) == 1, (
        f"Expected single logon, saw {len(logon_calls)}: {[c['url'] for c in logon_calls]}"
    )
    _reset()
