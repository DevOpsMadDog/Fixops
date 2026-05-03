"""Tests for imperva_router — ALDECI.

Spins up a minimal FastAPI app with the Imperva Cloud WAF router mounted.
Each test resets the engine singleton so state doesn't bleed.

NO MOCKS rule:
  * /api/prov/v1/sites/list, /sites/status, /sites/configure/security,
    /api/v3/policies, /api/v3/sites/{id}, /api/incidents/v1/incidents
    return HTTP 503 when credentials are missing.
  * Capability summary reports ``status="unavailable"`` when keys missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real networking + parsing code paths.
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
        for path, resp in self._responses.items():
            if path in url:
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
    ):
        self.calls.append(
            {"method": "POST", "url": url, "headers": headers or {}, "data": data or {}}
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


def _build_app(
    *,
    api_id: Optional[str],
    api_key: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine."""
    from core import imperva_waf_engine as engine_mod

    engine_mod.reset_imperva_waf_engine()
    stub_client = _StubClient(stub_responses)
    engine_mod.get_imperva_waf_engine(
        api_id=api_id, api_key=api_key, client=stub_client
    )

    from apps.api.imperva_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import imperva_waf_engine as engine_mod

    engine_mod.reset_imperva_waf_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_credentials(monkeypatch):
    monkeypatch.delenv("IMPERVA_API_ID", raising=False)
    monkeypatch.delenv("IMPERVA_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/imperva/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Imperva Cloud WAF"
    assert "/api/prov/v1/sites/list" in body["endpoints"]
    assert "/api/prov/v1/sites/status" in body["endpoints"]
    assert "/api/incidents/v1/incidents" in body["endpoints"]
    assert body["imperva_api_id_present"] is False
    assert body["imperva_api_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_credentials_present(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "test-id")
    monkeypatch.setenv("IMPERVA_API_KEY", "test-key")
    app, _ = _build_app(
        api_id="test-id", api_key="test-key", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/imperva/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["imperva_api_id_present"] is True
    assert body["imperva_api_key_present"] is True
    assert body["status"] == "ok"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no credentials
# ---------------------------------------------------------------------------


def test_policies_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("IMPERVA_API_ID", raising=False)
    monkeypatch.delenv("IMPERVA_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/imperva/api/v3/policies",
        params={"accountId": "12345"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "IMPERVA_API_ID" in r.json()["detail"] or "IMPERVA_API_KEY" in r.json()["detail"]
    _reset()


def test_get_site_v3_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("IMPERVA_API_ID", raising=False)
    monkeypatch.delenv("IMPERVA_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/imperva/api/v3/sites/site-1", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_incidents_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("IMPERVA_API_ID", raising=False)
    monkeypatch.delenv("IMPERVA_API_KEY", raising=False)
    app, _ = _build_app(api_id=None, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/imperva/api/incidents/v1/incidents",
        params={"accountId": "12345"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_sites_list_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "id1")
    monkeypatch.setenv("IMPERVA_API_KEY", "key1")
    raw = {
        "res": 0,
        "res_message": "OK",
        "sites": [
            {
                "site_id": "1001",
                "status": "active",
                "domain": "example.com",
                "account_id": 555,
                "acceleration_level": "standard",
                "site_creation_date": 1714000000,
                "ips": ["1.2.3.4", "1.2.3.5"],
                "dns": [
                    {
                        "dns_record_name": "example.com",
                        "set_data_to": [{"a": "1.2.3.4"}],
                        "set_type_to": "A",
                    }
                ],
                "ssl": {
                    "custom_certificate": {"active": False},
                    "generated_certificate": {
                        "ca": "letsencrypt",
                        "validation_method": "dns",
                        "validation_data": "TXT _imperva",
                        "san": ["example.com", "www.example.com"],
                        "generation_time": "2026-04-01T00:00:00Z",
                    },
                },
                "original_dns_records": [],
                "warnings": [],
                "log_level": "full",
                "security": {
                    "waf": {
                        "rules": [
                            {
                                "action": "api.threats.action.block_request",
                                "action_text": "Block Request",
                                "id": "api.threats.sql_injection",
                                "name": "SQL Injection",
                            }
                        ]
                    },
                    "owasp_v2": {},
                    "hackerProtect": {},
                },
                "sealLocation": {"id": "footer", "name": "Footer"},
                "ssl_safe_browsing_id": "sb-123",
                "login_protect": {
                    "enabled": True,
                    "specific_users_list": [],
                    "send_lp_notifications": True,
                    "allow_all_users": False,
                    "sms_enabled": False,
                    "allowed_users": [],
                },
                "performance_configuration": {},
                "extended_ddos": {},
            }
        ],
        "total_count": 1,
        "total_pages": 1,
    }
    app, stub = _build_app(
        api_id="id1",
        api_key="key1",
        stub_responses={"/api/prov/v1/sites/list": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/imperva/api/prov/v1/sites/list",
        data={
            "api_id": "id1",
            "api_key": "key1",
            "page_size": "50",
            "page_num": "0",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["res"] == 0
    assert body["total_count"] == 1
    assert len(body["sites"]) == 1
    s = body["sites"][0]
    assert s["site_id"] == "1001"
    assert s["status"] == "active"
    assert s["domain"] == "example.com"
    assert s["ips"] == ["1.2.3.4", "1.2.3.5"]
    assert s["security"]["waf"]["rules"][0]["name"] == "SQL Injection"
    assert s["sealLocation"]["name"] == "Footer"
    assert s["login_protect"]["enabled"] is True

    # Ensure form-encoded creds were sent in body of legacy POST.
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert len(posts) == 1
    assert posts[0]["data"]["api_id"] == "id1"
    assert posts[0]["data"]["api_key"] == "key1"
    _reset()


def test_sites_status_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "id1")
    monkeypatch.setenv("IMPERVA_API_KEY", "key1")
    raw = {
        "res": 0,
        "res_message": "OK",
        "site_id": "1001",
        "status": "active",
        "domain": "example.com",
        "account_id": 555,
        "acceleration_level": "aggressive",
        "ips": ["1.2.3.4"],
        "dns": [],
        "ssl": {},
        "warnings": [],
        "log_level": "security",
        "security": {"waf": {"rules": []}},
        "sealLocation": {"id": "header", "name": "Header"},
        "login_protect": {"enabled": False},
    }
    app, _ = _build_app(
        api_id="id1",
        api_key="key1",
        stub_responses={"/api/prov/v1/sites/status": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/imperva/api/prov/v1/sites/status",
        data={
            "api_id": "id1",
            "api_key": "key1",
            "site_id": "1001",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["site_id"] == "1001"
    assert body["status"] == "active"
    assert body["acceleration_level"] == "aggressive"
    assert body["sealLocation"]["name"] == "Header"
    assert body["res"] == 0
    _reset()


def test_sites_configure_security_happy_path(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "id1")
    monkeypatch.setenv("IMPERVA_API_KEY", "key1")
    raw = {"res": 0, "res_message": "WAF rule updated"}
    app, _ = _build_app(
        api_id="id1",
        api_key="key1",
        stub_responses={
            "/api/prov/v1/sites/configure/security": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/imperva/api/prov/v1/sites/configure/security",
        data={
            "api_id": "id1",
            "api_key": "key1",
            "site_id": "1001",
            "rule_id": "api.threats.sql_injection",
            "security_rule_action": "api.threats.action.block_request",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["res"] == 0
    assert "WAF rule updated" in body["res_message"]
    _reset()


def test_list_policies_happy_path_modern_v3(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "id1")
    monkeypatch.setenv("IMPERVA_API_KEY", "key1")
    raw = {
        "data": [
            {
                "id": "policy-1",
                "type": "WAF_RULES",
                "name": "Default WAF",
                "description": "Imperva managed WAF",
                "enabled": True,
                "default": True,
                "source": "MANAGED",
                "accountId": 555,
                "lastModified": 1714010000,
                "lastModifiedBy": "admin@example.com",
                "ratePolicyDefinition": {},
                "aclPolicyDefinition": {},
                "exceptions": [],
                "policySettings": [
                    {
                        "settingsAction": "BLOCK",
                        "policySettingType": "WAF_INJECTION",
                        "data": [{"sql": "block"}],
                    }
                ],
            },
            {
                "id": "policy-2",
                "type": "ACL",
                "name": "IP Allowlist",
                "enabled": True,
                "default": False,
                "source": "LOCAL",
            },
        ]
    }
    app, stub = _build_app(
        api_id="id1",
        api_key="key1",
        stub_responses={"/policies/v3/policies": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/imperva/api/v3/policies",
        params={"accountId": "555"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["data"]) == 2
    assert body["data"][0]["type"] == "WAF_RULES"
    assert body["data"][0]["source"] == "MANAGED"
    assert body["data"][0]["policySettings"][0]["settingsAction"] == "BLOCK"
    assert body["data"][1]["type"] == "ACL"

    # Ensure modern v3 used header auth, not body.
    gets = [c for c in stub.calls if c["method"] == "GET"]
    assert len(gets) == 1
    headers = gets[0]["headers"]
    assert headers.get("x-API-Id") == "id1"
    assert headers.get("x-API-Key") == "key1"
    _reset()


def test_get_site_v3_happy_path(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "id1")
    monkeypatch.setenv("IMPERVA_API_KEY", "key1")
    raw = {
        "data": {
            "id": "site-1",
            "name": "example.com",
            "type": "WEBSITE",
            "accountId": 555,
            "refId": "ref-001",
            "accountInheritance": {
                "accountInheritedFromTier1": True,
                "accountInheritedFromTier2": False,
                "accountInheritedFromTier3": False,
            },
        }
    }
    app, _ = _build_app(
        api_id="id1",
        api_key="key1",
        stub_responses={"/sites/v3/sites/site-1": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/imperva/api/v3/sites/site-1", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["id"] == "site-1"
    assert body["data"]["name"] == "example.com"
    assert body["data"]["accountInheritance"]["accountInheritedFromTier1"] is True
    _reset()


def test_incidents_happy_path(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "id1")
    monkeypatch.setenv("IMPERVA_API_KEY", "key1")
    raw = {
        "incidents": [
            {
                "id": "inc-1",
                "accountId": 555,
                "accountName": "Example Org",
                "severity": "Critical",
                "status": "Open",
                "type": "DDoS",
                "openedAt": "2026-05-04T00:00:00Z",
                "closedAt": None,
                "lastUpdatedAt": "2026-05-04T00:05:00Z",
                "sites": [{"siteId": "1001", "siteName": "example.com"}],
                "assetId": "asset-1",
                "ddosVolume": 12345678,
                "ddosTotalRequests": 250000,
                "mitigationActions": ["RATE_LIMIT", "BLOCK_BOT"],
                "description": "Volumetric DDoS attack",
                "recommendation": "Enable extended DDoS",
                "attackVector": "UDP_FLOOD",
            }
        ],
        "totalIncidents": 1,
    }
    app, stub = _build_app(
        api_id="id1",
        api_key="key1",
        stub_responses={
            "/api/incidents/v1/incidents": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/imperva/api/incidents/v1/incidents",
        params={
            "from_time": "2026-05-04T00:00:00Z",
            "to_time": "2026-05-04T23:59:59Z",
            "accountId": "555",
            "pageSize": "50",
            "offset": "0",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalIncidents"] == 1
    assert len(body["incidents"]) == 1
    inc = body["incidents"][0]
    assert inc["severity"] == "Critical"
    assert inc["status"] == "Open"
    assert inc["type"] == "DDoS"
    assert inc["sites"][0]["siteName"] == "example.com"
    assert inc["mitigationActions"] == ["RATE_LIMIT", "BLOCK_BOT"]

    # Ensure params were forwarded to upstream.
    gets = [c for c in stub.calls if c["method"] == "GET"]
    assert len(gets) == 1
    assert gets[0]["params"].get("accountId") == "555"
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths + input validation
# ---------------------------------------------------------------------------


def test_policies_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "id1")
    monkeypatch.setenv("IMPERVA_API_KEY", "key1")
    app, _ = _build_app(
        api_id="id1",
        api_key="key1",
        stub_responses={
            "/policies/v3/policies": _StubResponse(
                429, {"errors": [{"detail": "Too Many Requests"}]}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/imperva/api/v3/policies",
        params={"accountId": "555"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()


def test_sites_list_rejects_missing_form_creds(monkeypatch):
    monkeypatch.setenv("IMPERVA_API_ID", "id1")
    monkeypatch.setenv("IMPERVA_API_KEY", "key1")
    app, _ = _build_app(api_id="id1", api_key="key1", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    # No api_id / api_key in form body — Pydantic/FastAPI Form(...) is required.
    r = client.post(
        "/api/v1/imperva/api/prov/v1/sites/list",
        data={},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()
