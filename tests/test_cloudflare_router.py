"""Tests for cloudflare_router (live Cloudflare API v4 REST surface) — ALDECI.

Spins up a minimal FastAPI app with the Cloudflare router mounted. Each
test gets an isolated engine singleton + stub httpx.Client so we exercise
the real REST + parsing code paths without hitting the network.

NO MOCKS rule:
  * When CLOUDFLARE_API_TOKEN is unset the capability summary reports
    ``status="unavailable"`` and every live endpoint returns 503.
  * Happy-path tests inject a stub client (not baked-in fake payloads)
    so REST + result normalization all run.
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
    """Minimal stand-in for httpx.Response with .json/.status_code/.text/.headers."""

    def __init__(
        self,
        status_code: int,
        payload: Any,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
    ):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)
        self.headers = headers or {}

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix.

    Longest-path-suffix match wins so e.g.
    ``/client/v4/zones/abc/dns_records`` beats ``/client/v4/zones``.
    """

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> Any:
        keys = sorted(self._responses.keys(), key=len, reverse=True)
        for path in keys:
            if path in url:
                return self._responses[path]
        return _StubResponse(
            404,
            {"success": False, "errors": [{"code": 7003, "message": "not found"}]},
            text="not found",
        )

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "params": params or {},
                "headers": headers or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


def _build_app(
    *,
    api_token: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import cloudflare_engine as engine_mod

    engine_mod.reset_cloudflare_engine()
    stub = _StubClient(stub_responses)
    engine_mod.get_cloudflare_engine(
        api_token=api_token,
        client=stub,
    )

    from apps.api.cloudflare_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Always reset the singleton before AND after each test."""
    from core import cloudflare_engine as engine_mod
    engine_mod.reset_cloudflare_engine()
    yield
    engine_mod.reset_cloudflare_engine()


# ---------------------------------------------------------------------------
# Capability summary — env-driven status flags
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_token(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/cloudflare/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Cloudflare API v4"
    for ep in (
        "/client/v4/zones",
        "/client/v4/zones/{zone_id}/dns_records",
        "/client/v4/zones/{zone_id}/firewall/rules",
        "/client/v4/zones/{zone_id}/waf/packages",
        "/client/v4/zones/{zone_id}/security_events",
        "/client/v4/accounts/{account_id}/access/groups",
    ):
        assert ep in body["endpoints"]
    assert body["cloudflare_api_token_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_token_present(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
    app, _ = _build_app(api_token="cf-tok", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/cloudflare/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cloudflare_api_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# Live endpoints — unavailable path (no creds) returns 503
# ---------------------------------------------------------------------------


def test_zones_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones",
        params={"name": "example.com"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "CLOUDFLARE_API_TOKEN" in r.json()["detail"]


def test_dns_records_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones/zone-1/dns_records",
        headers=HEADERS,
    )
    assert r.status_code == 503


def test_security_events_returns_503_when_no_token(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    app, _ = _build_app(api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones/zone-1/security_events",
        headers=HEADERS,
    )
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# Live endpoints — happy path with stubbed httpx.Client
# ---------------------------------------------------------------------------


def test_list_zones_happy_path_parses_envelope(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")

    payload = {
        "success": True,
        "errors": [],
        "messages": [],
        "result": [
            {
                "id": "zone-abc",
                "name": "example.com",
                "status": "active",
                "paused": False,
                "type": "full",
                "development_mode": 0,
                "name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
                "original_name_servers": ["ns.example.com"],
                "original_registrar": "godaddy",
                "original_dnshost": None,
                "modified_on": "2026-05-01T00:00:00Z",
                "created_on": "2025-01-01T00:00:00Z",
                "activated_on": "2025-01-02T00:00:00Z",
                "meta": {
                    "step": 4,
                    "custom_certificate_quota": 0,
                    "page_rule_quota": 3,
                    "phishing_detected": False,
                    "multiple_railguns_allowed": False,
                },
                "owner": {
                    "id": "owner-1",
                    "type": "user",
                    "email": "admin@example.com",
                },
                "account": {"id": "acct-1", "name": "Example Inc"},
                "tenant": {"id": None, "name": None},
                "tenant_unit": {"id": None},
                "permissions": ["#zone:read"],
                "plan": {
                    "id": "plan-free",
                    "name": "Free Website",
                    "price": 0,
                    "currency": "USD",
                    "frequency": "monthly",
                    "legacy_id": "free",
                    "is_subscribed": True,
                    "can_subscribe": False,
                },
                "plan_pending": None,
                "host": {"name": None, "website": None},
                "vanity_name_servers": [],
                "betas": [],
                "deactivation_reason": None,
            }
        ],
        "result_info": {
            "page": 1,
            "per_page": 20,
            "total_pages": 1,
            "count": 1,
            "total_count": 1,
        },
    }

    app, stub = _build_app(
        api_token="cf-tok",
        stub_responses={"/client/v4/zones": _StubResponse(200, payload)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones",
        params={
            "name": "example.com",
            "status": "active",
            "account.id": "acct-1",
            "page": 1,
            "per_page": 20,
            "order": "name",
            "direction": "asc",
            "match": "all",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert body["result"][0]["id"] == "zone-abc"
    assert body["result"][0]["name"] == "example.com"
    assert body["result"][0]["status"] == "active"
    assert body["result"][0]["plan"]["name"] == "Free Website"
    assert body["result_info"]["total_count"] == 1

    # Confirm the engine actually called Cloudflare with Bearer auth.
    assert stub.calls
    call = stub.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://api.cloudflare.com/client/v4/zones"
    assert call["headers"]["Authorization"] == "Bearer cf-tok"
    assert call["params"]["name"] == "example.com"
    assert call["params"]["status"] == "active"
    assert call["params"]["account.id"] == "acct-1"
    assert call["params"]["per_page"] == 20
    assert call["params"]["match"] == "all"


def test_get_single_zone_happy_path(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
    payload = {
        "success": True,
        "errors": [],
        "messages": [],
        "result": {
            "id": "zone-xyz",
            "name": "secured.test",
            "status": "active",
            "type": "full",
            "paused": False,
        },
    }
    app, stub = _build_app(
        api_token="cf-tok",
        stub_responses={"/client/v4/zones/zone-xyz": _StubResponse(200, payload)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones/zone-xyz",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"]["id"] == "zone-xyz"
    assert body["result"]["name"] == "secured.test"
    assert (
        stub.calls[0]["url"]
        == "https://api.cloudflare.com/client/v4/zones/zone-xyz"
    )


def test_list_dns_records_happy_path(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
    payload = {
        "success": True,
        "errors": [],
        "messages": [],
        "result": [
            {
                "id": "dns-1",
                "type": "A",
                "name": "www.example.com",
                "content": "192.0.2.1",
                "proxiable": True,
                "proxied": True,
                "ttl": 1,
                "locked": False,
                "zone_id": "zone-abc",
                "zone_name": "example.com",
                "modified_on": "2026-05-01T00:00:00Z",
                "created_on": "2025-01-01T00:00:00Z",
                "meta": {"auto_added": False, "source": "primary"},
            }
        ],
        "result_info": {
            "page": 1,
            "per_page": 100,
            "total_pages": 1,
            "count": 1,
            "total_count": 1,
        },
    }
    app, stub = _build_app(
        api_token="cf-tok",
        stub_responses={
            "/client/v4/zones/zone-abc/dns_records": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones/zone-abc/dns_records",
        params={"type": "A", "name": "www.example.com"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"][0]["type"] == "A"
    assert body["result"][0]["content"] == "192.0.2.1"
    assert body["result"][0]["proxied"] is True
    assert stub.calls[0]["params"]["type"] == "A"
    assert stub.calls[0]["params"]["name"] == "www.example.com"


def test_list_firewall_rules_happy_path(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
    payload = {
        "success": True,
        "errors": [],
        "messages": [],
        "result": [
            {
                "id": "fw-1",
                "paused": False,
                "description": "Block bad bots",
                "action": "block",
                "priority": 1,
                "filter": {
                    "id": "flt-1",
                    "expression": '(http.user_agent contains "BadBot")',
                    "paused": False,
                    "description": "BadBot UA",
                },
                "products": ["waf"],
                "created_on": "2025-01-01T00:00:00Z",
                "modified_on": "2026-05-01T00:00:00Z",
                "ref": "REF-1",
            }
        ],
    }
    app, stub = _build_app(
        api_token="cf-tok",
        stub_responses={
            "/client/v4/zones/zone-abc/firewall/rules": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones/zone-abc/firewall/rules",
        params={"page": 1, "per_page": 50},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"][0]["action"] == "block"
    assert body["result"][0]["filter"]["id"] == "flt-1"
    assert stub.calls[0]["params"]["per_page"] == 50


def test_list_waf_packages_happy_path(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
    payload = {
        "success": True,
        "errors": [],
        "messages": [],
        "result": [
            {
                "id": "pkg-1",
                "name": "OWASP ModSecurity Core Rule Set",
                "description": "Generic attack protection",
                "detection_mode": "anomaly",
                "zone_id": "zone-abc",
                "status": "active",
            }
        ],
    }
    app, stub = _build_app(
        api_token="cf-tok",
        stub_responses={
            "/client/v4/zones/zone-abc/waf/packages": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones/zone-abc/waf/packages",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"][0]["detection_mode"] == "anomaly"
    assert body["result"][0]["status"] == "active"


def test_list_security_events_happy_path_with_filters(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
    payload = {
        "success": True,
        "errors": [],
        "messages": [],
        "result": [
            {
                "ray_id": "ray-1",
                "action": "block",
                "source": "firewall",
                "rule_id": "fw-1",
                "host": "www.example.com",
                "ip": "203.0.113.5",
                "ipclass": "noRecord",
                "country": "US",
                "occurred_at": "2026-05-04T00:00:00Z",
                "host_at_change": "www.example.com",
                "scheme": "https",
                "ja3_hash": "abc123",
                "http_method": "GET",
                "http_protocol": "HTTP/2",
                "user_agent": "BadBot/1.0",
                "request_uri": "/admin",
                "decision_set": "any",
                "application_id": None,
                "app_route": None,
                "request_path": "/admin",
                "request_query": "",
            }
        ],
    }
    app, stub = _build_app(
        api_token="cf-tok",
        stub_responses={
            "/client/v4/zones/zone-abc/security_events": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones/zone-abc/security_events",
        params={
            "since": "2026-05-01T00:00:00Z",
            "until": "2026-05-04T00:00:00Z",
            "action": "block",
            "kind": "firewall",
            "limit": 100,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"][0]["action"] == "block"
    assert body["result"][0]["ray_id"] == "ray-1"
    assert body["result"][0]["scheme"] == "https"
    assert stub.calls[0]["params"]["since"] == "2026-05-01T00:00:00Z"
    assert stub.calls[0]["params"]["action"] == "block"
    assert stub.calls[0]["params"]["limit"] == 100


def test_list_access_groups_happy_path(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
    payload = {
        "success": True,
        "errors": [],
        "messages": [],
        "result": [
            {
                "id": "grp-1",
                "name": "Engineering",
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2026-05-01T00:00:00Z",
                "include": [
                    {"email": {"email": "ada@example.com"}},
                    {"github": {"name": "devopsmaddog"}},
                    {"country": {"country_code": "US"}},
                ],
                "exclude": [],
                "require": [{"everyone": {}}],
            }
        ],
    }
    app, stub = _build_app(
        api_token="cf-tok",
        stub_responses={
            "/client/v4/accounts/acct-1/access/groups": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/accounts/acct-1/access/groups",
        params={"name": "eng", "per_page": 25},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"][0]["name"] == "Engineering"
    assert body["result"][0]["include"][0]["email"]["email"] == "ada@example.com"
    assert (
        stub.calls[0]["url"]
        == "https://api.cloudflare.com/client/v4/accounts/acct-1/access/groups"
    )
    assert stub.calls[0]["params"]["name"] == "eng"
    assert stub.calls[0]["params"]["per_page"] == 25


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def test_upstream_error_maps_to_503(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
    app, _ = _build_app(
        api_token="cf-tok",
        stub_responses={
            "/client/v4/zones": _StubResponse(
                401,
                {"success": False, "errors": [{"code": 10000, "message": "auth"}]},
                text="invalid token",
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/cloudflare/client/v4/zones",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"]
