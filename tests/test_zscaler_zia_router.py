"""Tests for zscaler_zia_router — ALDECI.

Spins up a minimal FastAPI app with the Zscaler ZIA router mounted. Each test
gets an isolated httpx stub client and resets the engine singleton so state
doesn't bleed between tests.

NO MOCKS rule:
  * GET /, GET sandbox/url-categories/firewall/users/locations and POST/DELETE
    authenticatedSession all return HTTP 503 when ZIA creds are unset.
  * Capability summary reports ``status="unavailable"`` when creds are missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise login + cookie + parsing code paths.
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
    def __init__(
        self,
        status_code: int,
        payload: Any,
        text: str = "",
        set_cookie: Optional[str] = None,
    ):
        self.status_code = status_code
        self._payload = payload
        try:
            self.text = text or json.dumps(payload)
        except (TypeError, ValueError):
            self.text = text or str(payload)
        self.headers: Dict[str, str] = {}
        self.cookies: Dict[str, str] = {}
        if set_cookie:
            self.headers["Set-Cookie"] = set_cookie
            # Crude parse: JSESSIONID=xxx; ...
            for kv in set_cookie.split(";"):
                kv = kv.strip()
                if kv.upper().startswith("JSESSIONID="):
                    self.cookies["JSESSIONID"] = kv.split("=", 1)[1]

    def json(self) -> Any:
        if isinstance(self._payload, (dict, list)):
            return self._payload
        raise ValueError("non-JSON body")


class _StubClient:
    """Records calls and returns a queued response per URL suffix + method."""

    def __init__(self, responses: Dict[str, Any]):
        # Key format: "METHOD path" or just "path" (defaults to any method)
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, method: str, url: str) -> _StubResponse:
        # Prefer "METHOD path" matches first.
        for key, resp in self._responses.items():
            if " " in key:
                m, path = key.split(" ", 1)
                if m.upper() == method.upper() and path in url:
                    return resp
        for key, resp in self._responses.items():
            if " " in key:
                continue
            if key in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {})}
        )
        return self._resolve("GET", url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        content: Optional[bytes] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "json": json,
                "content": content,
            }
        )
        return self._resolve("POST", url)

    def put(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        content: Optional[bytes] = None,
    ):
        self.calls.append(
            {"method": "PUT", "url": url, "headers": dict(headers or {}), "json": json}
        )
        return self._resolve("PUT", url)

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **_):
        self.calls.append(
            {"method": method.upper(), "url": url, "headers": dict(headers or {})}
        )
        return self._resolve(method, url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_OK_CREDS = {
    "base_url": "https://zsapi.zscalerthree.net",
    "username": "secops@aldeci.example",
    "password": "p@ssw0rd-not-real",
    # 16-char API key satisfies the >= 12 char obfuscation requirement and
    # has enough characters to safely index up to position 11 (digit 9 + 2).
    "api_key": "abcdef0123456789",
}


def _build_app(
    *,
    creds: Optional[Dict[str, str]],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine."""
    from core import zscaler_zia_engine as engine_mod

    engine_mod.reset_zscaler_zia_engine()

    stub_client = _StubClient(stub_responses)
    if creds is None:
        engine_mod.get_zscaler_zia_engine(client=stub_client)
    else:
        engine_mod.get_zscaler_zia_engine(
            base_url=creds.get("base_url"),
            username=creds.get("username"),
            password=creds.get("password"),
            api_key=creds.get("api_key"),
            client=stub_client,
        )

    from apps.api.zscaler_zia_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import zscaler_zia_engine as engine_mod

    engine_mod.reset_zscaler_zia_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in (
        "ZSCALER_ZIA_BASE_URL",
        "ZSCALER_ZIA_USERNAME",
        "ZSCALER_ZIA_PASSWORD",
        "ZSCALER_ZIA_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


# A canned authenticatedSession login response, used by every happy-path test.
_LOGIN_RESPONSE = _StubResponse(
    200,
    {"authType": "ADMIN_LOGIN"},
    set_cookie="JSESSIONID=ABCD1234EFGH5678; Path=/; HttpOnly",
)


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/zscaler-zia/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Zscaler ZIA"
    assert body["endpoints"] == [
        "/api/v1/sandbox/report",
        "/api/v1/urlCategories",
        "/api/v1/firewallFilteringRules",
        "/api/v1/users",
        "/api/v1/locations",
        "/api/v1/security/advanced",
    ]
    assert body["zscaler_zia_base_url_present"] is False
    assert body["zscaler_zia_username_present"] is False
    assert body["zscaler_zia_password_present"] is False
    assert body["zscaler_zia_api_key_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/zscaler-zia/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["zscaler_zia_base_url_present"] is True
    assert body["zscaler_zia_username_present"] is True
    assert body["zscaler_zia_password_present"] is True
    assert body["zscaler_zia_api_key_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_login_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post("/api/v1/zscaler-zia/api/v1/authenticatedSession", json={}, headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "ZSCALER" in r.json()["detail"]


def test_sandbox_report_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/zscaler-zia/api/v1/sandbox/report/" + "a" * 32,
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


def test_url_categories_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/zscaler-zia/api/v1/urlCategories", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_firewall_filtering_rules_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/zscaler-zia/api/v1/firewallFilteringRules", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_users_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/zscaler-zia/api/v1/users", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_locations_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/zscaler-zia/api/v1/locations", headers=HEADERS)
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# Validation 422
# ---------------------------------------------------------------------------


def test_sandbox_report_422_on_bad_md5_length():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    # 31-char md5 violates Path(min_length=32) -> FastAPI 422
    r = client.get(
        "/api/v1/zscaler-zia/api/v1/sandbox/report/" + "a" * 31,
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_sandbox_report_422_on_bad_details_value():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get(
        "/api/v1/zscaler-zia/api/v1/sandbox/report/" + "a" * 32,
        params={"details": "deep"},  # not summary|full
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# Auth flow — login + logout
# ---------------------------------------------------------------------------


def test_login_happy_path_returns_session_metadata():
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={"POST /api/v1/authenticatedSession": _LOGIN_RESPONSE},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/zscaler-zia/api/v1/authenticatedSession",
        json={},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["authType"] == "ADMIN_LOGIN"
    assert body["obfuscateApiKey"] is True

    # The login call must include obfuscatedKey + ms timestamp + username + password.
    assert len(stub.calls) == 1
    call = stub.calls[0]
    assert call["method"] == "POST"
    payload = call["json"] or {}
    assert "apiKey" in payload and len(payload["apiKey"]) == 12  # 6 + 6
    assert payload["username"] == _OK_CREDS["username"]
    assert payload["password"] == _OK_CREDS["password"]
    assert payload["timestamp"].isdigit() and len(payload["timestamp"]) >= 12


def test_logout_happy_path_after_login():
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "POST /api/v1/authenticatedSession": _LOGIN_RESPONSE,
            "DELETE /api/v1/authenticatedSession": _StubResponse(204, {}),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    # Prime a session
    r1 = client.post(
        "/api/v1/zscaler-zia/api/v1/authenticatedSession",
        json={},
        headers=HEADERS,
    )
    assert r1.status_code == 200

    # Logout
    r2 = client.delete(
        "/api/v1/zscaler-zia/api/v1/authenticatedSession",
        headers=HEADERS,
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["loggedOut"] is True

    # The DELETE call must carry the JSESSIONID cookie obtained at login.
    delete_calls = [c for c in stub.calls if c["method"] == "DELETE"]
    assert len(delete_calls) == 1
    assert "JSESSIONID=ABCD1234EFGH5678" in delete_calls[0]["headers"].get("Cookie", "")


def test_logout_idempotent_when_no_session():
    app, stub = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.delete(
        "/api/v1/zscaler-zia/api/v1/authenticatedSession",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    assert r.json()["loggedOut"] is True
    # No upstream calls should have been made.
    assert all(c["method"] != "DELETE" for c in stub.calls)


# ---------------------------------------------------------------------------
# Sandbox report
# ---------------------------------------------------------------------------


def test_sandbox_report_happy_path_normalizes():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    raw = {
        "Summary": {
            "Status": "ABNORMAL",
            "Category": "OFFICE_DOCUMENTS",
            "Score": 88,
            "FileType": "DOC",
            "StartTime": 1730000000,
            "Duration": 12000,
        },
        "Classification": {
            "Type": "MALICIOUS",
            "Category": "TROJAN",
            "Score": 88,
            "DetectedMalware": "W97M.Downloader",
        },
        "FileProperties": {
            "FileType": "DOC",
            "FileSize": 23456,
            "MD5": md5.upper(),
            "SHA1": "11" * 20,
            "SHA256": "22" * 32,
            "IssuerName": "",
            "RootCAVerified": False,
            "ExtractionMime": "application/msword",
            "FileFamily": "Office",
        },
        "ConnectionsMade": [
            {"ip": "203.0.113.5", "port": 443, "protocol": "TCP", "type": "OUT", "country": "US", "asn": 64500}
        ],
        "DnsRequests": [{"name": "evil.example", "qtype": "A"}],
        "FilesCreated": ["C:/temp/x.exe"],
        "FilesModified": [],
        "FilesDeleted": [],
        "RegistryChanges": [],
        "MutexesCreated": [],
        "ProcessesCreated": [{"name": "wscript.exe"}],
        "DigitalSignature": {},
        "ReportSummary": "Document drops a downloader and beacons to evil.example",
        "Origin": {"Country": "RU", "Risk": "HIGH", "ASN": 12345, "ASNName": "EVIL-ASN"},
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "POST /api/v1/authenticatedSession": _LOGIN_RESPONSE,
            f"GET /api/v1/sandbox/report/{md5}": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        f"/api/v1/zscaler-zia/api/v1/sandbox/report/{md5}",
        params={"details": "full"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["Summary"]["Status"] == "ABNORMAL"
    assert body["Classification"]["Type"] == "MALICIOUS"
    assert body["Classification"]["DetectedMalware"] == "W97M.Downloader"
    assert body["FileProperties"]["MD5"] == md5.upper()
    assert body["ConnectionsMade"][0]["ip"] == "203.0.113.5"
    assert body["Origin"]["Country"] == "RU"
    assert body["Origin"]["Risk"] == "HIGH"

    # Verify we logged in then fetched the sandbox report with the cookie.
    methods = [c["method"] for c in stub.calls]
    assert methods == ["POST", "GET"]
    sandbox_call = stub.calls[1]
    assert "JSESSIONID=ABCD1234EFGH5678" in sandbox_call["headers"].get("Cookie", "")
    assert "details=full" in sandbox_call["url"]


# ---------------------------------------------------------------------------
# URL categories / firewall rules / users / locations — happy paths
# ---------------------------------------------------------------------------


def test_url_categories_happy_path_normalizes():
    raw = [
        {
            "id": "CUSTOM_01",
            "configuredName": "Sanctioned SaaS",
            "urls": ["app.example.com"],
            "dbCategorizedUrls": [],
            "type": "URL_CATEGORY",
            "customCategory": True,
            "scopes": [
                {
                    "Type": "ORGANIZATION",
                    "ScopeGroupMemberEntities": [],
                    "ScopeEntities": [],
                }
            ],
            "editable": True,
            "description": "Approved SaaS apps",
            "customUrlsCount": 1,
            "urlsRetainingParentCategoryCount": 0,
            "customIpRangesCount": 0,
            "ipRangesRetainingParentCategoryCount": 0,
            "ipRanges": [],
            "ipRangesRetainingParentCategory": [],
            "superCategory": "BUSINESS_AND_ECONOMY",
            "keywords": ["saas"],
            "keywordsRetainingParentCategory": [],
        }
    ]
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "POST /api/v1/authenticatedSession": _LOGIN_RESPONSE,
            "GET /api/v1/urlCategories": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/zscaler-zia/api/v1/urlCategories",
        params={"customOnly": "true", "includeIcap": "false"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list) and len(body) == 1
    cat = body[0]
    assert cat["id"] == "CUSTOM_01"
    assert cat["customCategory"] is True
    assert cat["scopes"][0]["Type"] == "ORGANIZATION"
    assert cat["urls"] == ["app.example.com"]

    # Confirm the GET sent customOnly=true
    get_calls = [c for c in stub.calls if c["method"] == "GET"]
    assert any("customOnly=true" in c["url"] for c in get_calls)


def test_firewall_filtering_rules_happy_path():
    raw = [
        {
            "id": 7777,
            "name": "Block-Known-Bad",
            "order": 1,
            "rank": 7,
            "action": "BLOCK_DROP",
            "state": "ENABLED",
            "defaultRule": False,
            "predefined": False,
            "srcIps": ["10.0.0.0/8"],
            "destAddresses": ["1.2.3.4"],
            "destIpCategories": ["MALWARE_SITE"],
            "destCountries": ["RU"],
            "srcIpGroups": [],
            "destIpGroups": [],
            "departments": [],
            "users": [],
            "groups": [],
            "appServices": [],
            "appServiceGroups": [],
            "srcIpv6Groups": [],
            "destIpv6Groups": [],
            "description": "Block known bad",
            "lastModifiedTime": 1730000000,
            "lastModifiedBy": {"id": 1, "name": "secops"},
            "accessControl": "READ_WRITE",
        }
    ]
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "POST /api/v1/authenticatedSession": _LOGIN_RESPONSE,
            "GET /api/v1/firewallFilteringRules": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/zscaler-zia/api/v1/firewallFilteringRules",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    rule = body[0]
    assert rule["action"] == "BLOCK_DROP"
    assert rule["state"] == "ENABLED"
    assert rule["destCountries"] == ["RU"]
    assert rule["accessControl"] == "READ_WRITE"


def test_users_happy_path_with_filters():
    raw = [
        {
            "id": 42,
            "name": "Jane SecOps",
            "email": "jane@aldeci.example",
            "groups": [{"id": 5, "name": "SecOps"}],
            "department": {"id": 9, "name": "Security"},
            "comments": "",
            "tempAuthEmail": "",
            "adminUser": True,
            "type": "USER",
        }
    ]
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "POST /api/v1/authenticatedSession": _LOGIN_RESPONSE,
            "GET /api/v1/users": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/zscaler-zia/api/v1/users",
        params={"name": "Jane", "page": 1, "pageSize": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    assert body[0]["email"] == "jane@aldeci.example"
    assert body[0]["groups"][0]["name"] == "SecOps"
    assert body[0]["adminUser"] is True

    # Confirm query string passed through
    get_calls = [c for c in stub.calls if c["method"] == "GET"]
    assert any("name=Jane" in c["url"] for c in get_calls)
    assert any("pageSize=50" in c["url"] for c in get_calls)


def test_locations_happy_path():
    raw = [
        {
            "id": 1001,
            "name": "HQ-Austin",
            "parentId": 0,
            "upBandwidth": 1000000,
            "dnBandwidth": 1000000,
            "country": "UNITED_STATES",
            "tz": "AMERICA_CHICAGO",
            "ipAddresses": ["198.51.100.10"],
            "ports": [443],
            "vpnCredentials": [],
            "authRequired": True,
            "sslScanEnabled": True,
            "zappSSLScanEnabled": True,
            "xffForwardEnabled": True,
            "surrogateIP": True,
            "idleTimeInMinutes": 30,
            "displayTimeUnit": "MINUTE",
            "surrogateIPEnforcedForKnownBrowsers": False,
            "surrogatePAC": False,
            "surrogateRefreshTimeInMinutes": 0,
            "surrogateRefreshTimeUnit": "MINUTE",
            "ofwEnabled": True,
            "ipsControl": True,
            "aupEnabled": False,
            "cautionEnabled": False,
            "aupBlockInternetUntilAccepted": False,
            "aupForceSslInspection": False,
            "aupTimeoutInDays": 0,
            "profile": "CORPORATE",
            "description": "Austin HQ branch",
        }
    ]
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            "POST /api/v1/authenticatedSession": _LOGIN_RESPONSE,
            "GET /api/v1/locations": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/zscaler-zia/api/v1/locations",
        params={"search": "HQ"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    loc = body[0]
    assert loc["name"] == "HQ-Austin"
    assert loc["sslScanEnabled"] is True
    assert loc["profile"] == "CORPORATE"


# ---------------------------------------------------------------------------
# 401 retry path — session expired -> re-login then succeed
# ---------------------------------------------------------------------------


class _SequencedStubClient(_StubClient):
    """Like _StubClient but cycles through a list of responses per key."""

    def __init__(self, responses: Dict[str, List[_StubResponse]]):
        super().__init__({})
        self._sequenced = {k: list(v) for k, v in responses.items()}

    def _resolve(self, method: str, url: str) -> _StubResponse:
        # Find the first key (METHOD path) that matches and pop next response.
        for key, seq in self._sequenced.items():
            if not seq:
                continue
            if " " in key:
                m, path = key.split(" ", 1)
                if m.upper() == method.upper() and path in url:
                    return seq.pop(0)
            elif key in url:
                return seq.pop(0)
        return _StubResponse(404, {"error": "not found"}, text="not found")


def test_request_retries_after_401_re_login():
    """A 401 mid-flight should trigger silent re-login + one retry."""
    from core import zscaler_zia_engine as engine_mod

    engine_mod.reset_zscaler_zia_engine()

    final_users = [
        {
            "id": 1,
            "name": "Alice",
            "email": "alice@aldeci.example",
            "groups": [],
            "department": {"id": 0, "name": ""},
            "comments": "",
            "tempAuthEmail": "",
            "adminUser": False,
            "type": "USER",
        }
    ]
    stub = _SequencedStubClient(
        {
            "POST /api/v1/authenticatedSession": [
                _LOGIN_RESPONSE,
                _StubResponse(
                    200,
                    {"authType": "ADMIN_LOGIN"},
                    set_cookie="JSESSIONID=NEWSESSION9999; Path=/",
                ),
            ],
            "GET /api/v1/users": [
                _StubResponse(401, {"message": "session expired"}),
                _StubResponse(200, final_users),
            ],
        }
    )
    engine_mod.get_zscaler_zia_engine(
        base_url=_OK_CREDS["base_url"],
        username=_OK_CREDS["username"],
        password=_OK_CREDS["password"],
        api_key=_OK_CREDS["api_key"],
        client=stub,
    )
    from apps.api.zscaler_zia_router import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/zscaler-zia/api/v1/users", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == [
        {
            "id": 1,
            "name": "Alice",
            "email": "alice@aldeci.example",
            "groups": [],
            "department": {"id": 0, "name": ""},
            "comments": "",
            "tempAuthEmail": "",
            "adminUser": False,
            "type": "USER",
        }
    ]

    # Sequence should be: POST login -> GET users (401) -> POST login -> GET users (200)
    methods = [c["method"] for c in stub.calls]
    assert methods == ["POST", "GET", "POST", "GET"]
    # The retried GET must use the newer JSESSIONID.
    assert "JSESSIONID=NEWSESSION9999" in stub.calls[3]["headers"].get("Cookie", "")


# ---------------------------------------------------------------------------
# Obfuscation unit tests
# ---------------------------------------------------------------------------


def test_obfuscate_api_key_deterministic_for_fixed_timestamp():
    from core.zscaler_zia_engine import obfuscate_api_key

    api_key = "abcdef0123456789"
    result = obfuscate_api_key(api_key, timestamp_ms="1730000000000")
    assert result["timestamp"] == "1730000000000"
    # n = "000000" -> all 'a's; r = "000000" -> "ccccccc..." (index 0 + 2 = 2 -> 'c')
    assert result["obfuscatedKey"] == "aaaaaa" + "cccccc"
    assert len(result["obfuscatedKey"]) == 12


def test_obfuscate_api_key_rejects_short_key():
    from core.zscaler_zia_engine import (
        ZscalerZIAUnavailableError,
        obfuscate_api_key,
    )

    with pytest.raises(ZscalerZIAUnavailableError):
        obfuscate_api_key("short", timestamp_ms="1730000000000")


def test_obfuscate_api_key_uses_ms_now_when_no_timestamp():
    from core.zscaler_zia_engine import obfuscate_api_key

    out = obfuscate_api_key("abcdef0123456789")
    assert out["timestamp"].isdigit()
    # ms epoch should be at least 13 digits as of 2026.
    assert len(out["timestamp"]) >= 12
    assert len(out["obfuscatedKey"]) == 12
