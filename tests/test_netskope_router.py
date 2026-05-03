"""Tests for netskope_router (live Netskope CASB v2 REST surface) — ALDECI.

Spins up a minimal FastAPI app with the Netskope router mounted. Each
test gets an isolated engine singleton + stub httpx.Client so we exercise
the real REST + parsing code paths without hitting the network.

NO MOCKS rule:
  * When NETSKOPE_TENANT_URL / NETSKOPE_API_TOKEN are unset the capability
    summary reports ``status="unavailable"`` and every live endpoint
    returns 503.
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
TENANT = "https://acme.goskope.com"


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
    ``/api/v2/events/data/incidents`` beats ``/api/v2/events/data/page``.
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
            {"error": "not found"},
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

    def post(
        self,
        url: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "json": json or {},
                "headers": headers or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


def _build_app(
    *,
    tenant_url: Optional[str],
    api_token: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import netskope_casb_engine as engine_mod

    engine_mod.reset_netskope_casb_engine()
    stub = _StubClient(stub_responses)
    engine_mod.get_netskope_casb_engine(
        tenant_url=tenant_url,
        api_token=api_token,
        client=stub,
    )

    from apps.api.netskope_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Always reset the singleton before AND after each test."""
    from core import netskope_casb_engine as engine_mod
    engine_mod.reset_netskope_casb_engine()
    yield
    engine_mod.reset_netskope_casb_engine()


# ---------------------------------------------------------------------------
# Capability summary — env-driven status flags
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("NETSKOPE_TENANT_URL", raising=False)
    monkeypatch.delenv("NETSKOPE_API_TOKEN", raising=False)
    app, _ = _build_app(tenant_url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/netskope/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Netskope CASB"
    for ep in (
        "/api/v2/events/data/page",
        "/api/v2/events/data/incidents",
        "/api/v2/scim/Users",
        "/api/v2/policy/url/list",
        "/api/v2/services/operational/uci",
    ):
        assert ep in body["endpoints"]
    assert body["netskope_tenant_url_present"] is False
    assert body["netskope_api_token_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_both_creds_present(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")
    app, _ = _build_app(
        tenant_url=TENANT, api_token="ns-tok", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/netskope/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["netskope_tenant_url_present"] is True
    assert body["netskope_api_token_present"] is True
    assert body["status"] == "ok"


def test_capability_summary_unavailable_when_only_tenant_present(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.delenv("NETSKOPE_API_TOKEN", raising=False)
    app, _ = _build_app(
        tenant_url=TENANT, api_token=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/netskope/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["netskope_tenant_url_present"] is True
    assert body["netskope_api_token_present"] is False
    assert body["status"] == "unavailable"


# ---------------------------------------------------------------------------
# Live endpoints — unavailable path (no creds) returns 503
# ---------------------------------------------------------------------------


def test_events_page_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("NETSKOPE_TENANT_URL", raising=False)
    monkeypatch.delenv("NETSKOPE_API_TOKEN", raising=False)
    app, _ = _build_app(tenant_url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/netskope/api/v2/events/data/page",
        params={"type": "alert", "limit": 10},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "NETSKOPE_TENANT_URL" in r.json()["detail"]


def test_dlp_incidents_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("NETSKOPE_TENANT_URL", raising=False)
    monkeypatch.delenv("NETSKOPE_API_TOKEN", raising=False)
    app, _ = _build_app(tenant_url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/netskope/api/v2/events/data/incidents",
        headers=HEADERS,
    )
    assert r.status_code == 503


def test_scim_users_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("NETSKOPE_TENANT_URL", raising=False)
    monkeypatch.delenv("NETSKOPE_API_TOKEN", raising=False)
    app, _ = _build_app(tenant_url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/netskope/api/v2/scim/Users", headers=HEADERS)
    assert r.status_code == 503


def test_uba_getuci_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("NETSKOPE_TENANT_URL", raising=False)
    monkeypatch.delenv("NETSKOPE_API_TOKEN", raising=False)
    app, _ = _build_app(tenant_url=None, api_token=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/netskope/api/v2/incidents/uba/getuci",
        json={
            "start_time": 1714000000,
            "end_time": 1714086400,
            "ip": "203.0.113.5",
        },
        headers=HEADERS,
    )
    assert r.status_code == 503


# ---------------------------------------------------------------------------
# Live endpoints — happy path with stubbed httpx.Client
# ---------------------------------------------------------------------------


def test_events_page_alert_happy_path_parses_envelope(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")

    payload = {
        "ok": 1,
        "status": "success",
        "result": [
            {
                "_id": "evt-abc-1",
                "instance_id": "tenant-1",
                "organization_unit": "Engineering",
                "alert": True,
                "alert_name": "DLP Profile Match — PCI",
                "alert_type": "DLP",
                "severity": "high",
                "severity_level": 8,
                "action": "block",
                "app": "Box",
                "appcategory": "Cloud Storage",
                "ccl": "high",
                "dst_country": "US",
                "dst_geoip_src": "MaxMind",
                "dst_ip": "203.0.113.10",
                "dst_location": "San Jose",
                "dst_region": "CA",
                "dst_zipcode": "95110",
                "file_size": 1048576,
                "file_type": "pdf",
                "hostname": "alice-mbp",
                "object": "credit-cards.pdf",
                "object_id": "obj-xyz",
                "object_type": "file",
                "policy": "Block PCI Upload",
                "request_id": "req-1",
                "src_country": "US",
                "src_ip": "10.0.0.5",
                "src_location": "San Francisco",
                "src_region": "CA",
                "src_zipcode": "94105",
                "timestamp": 1714000000,
                "traffic_type": "CloudApp",
                "type": "alert",
                "ur_normalized": "alice@example.com",
                "url": "https://acme.box.com/files/upload",
                "user": "alice@example.com",
                "user_id": "alice",
                "useragent": "Mozilla/5.0",
                "dlp_file": "credit-cards.pdf",
                "dlp_incident_id": "dlp-inc-1",
                "dlp_parent_id": None,
                "dlp_profile": "PCI Profile",
                "dlp_profile_id": "prof-1",
                "dlp_rule": "PCI Card Numbers",
                "dlp_rule_count": 12,
                "dlp_rule_severity": "high",
            }
        ],
    }

    app, stub = _build_app(
        tenant_url=TENANT,
        api_token="ns-tok",
        stub_responses={
            "/api/v2/events/data/page": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/netskope/api/v2/events/data/page",
        params={
            "type": "alert",
            "query": 'alert_type eq "DLP"',
            "starttime": 1714000000,
            "endtime": 1714086400,
            "limit": 100,
            "token": "cursor-1",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"][0]["_id"] == "evt-abc-1"
    assert body["result"][0]["alert_type"] == "DLP"
    assert body["result"][0]["severity"] == "high"
    assert body["result"][0]["action"] == "block"
    assert body["result"][0]["app"] == "Box"
    assert body["result"][0]["dlp_profile"] == "PCI Profile"

    # Confirm the engine actually called Netskope with the right header.
    assert stub.calls
    call = stub.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == f"{TENANT}/api/v2/events/data/page"
    assert call["headers"]["Netskope-Api-Token"] == "ns-tok"
    assert call["params"]["type"] == "alert"
    assert call["params"]["query"] == 'alert_type eq "DLP"'
    assert call["params"]["starttime"] == 1714000000
    assert call["params"]["limit"] == 100
    assert call["params"]["token"] == "cursor-1"


def test_dlp_incidents_happy_path(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")
    payload = {
        "ok": 1,
        "result": [
            {
                "_id": "dlp-inc-2",
                "dlp_incident_id": "DLP-12345",
                "dlp_profile": "HIPAA Profile",
                "dlp_rule": "HIPAA SSN",
                "dlp_rule_severity": "critical",
                "user": "bob@example.com",
                "app": "Salesforce",
                "action": "quarantine",
                "severity": "critical",
                "timestamp": 1714050000,
            }
        ],
    }
    app, stub = _build_app(
        tenant_url=TENANT,
        api_token="ns-tok",
        stub_responses={
            "/api/v2/events/data/incidents": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/netskope/api/v2/events/data/incidents",
        params={
            "starttime": 1714000000,
            "endtime": 1714086400,
            "limit": 50,
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"][0]["dlp_incident_id"] == "DLP-12345"
    assert body["result"][0]["dlp_profile"] == "HIPAA Profile"
    assert body["result"][0]["action"] == "quarantine"
    assert (
        stub.calls[0]["url"]
        == f"{TENANT}/api/v2/events/data/incidents"
    )
    assert stub.calls[0]["params"]["starttime"] == 1714000000
    assert stub.calls[0]["params"]["limit"] == 50


def test_scim_users_happy_path_returns_listresponse(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")
    payload = {
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        ],
        "totalResults": 2,
        "startIndex": 1,
        "itemsPerPage": 2,
        "Resources": [
            {
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User"
                ],
                "id": "user-1",
                "externalId": "ext-1",
                "userName": "alice@example.com",
                "name": {
                    "givenName": "Alice",
                    "familyName": "Doe",
                    "formatted": "Alice Doe",
                },
                "emails": [
                    {
                        "value": "alice@example.com",
                        "type": "work",
                        "primary": True,
                    }
                ],
                "active": True,
                "meta": {
                    "resourceType": "User",
                    "created": "2025-01-01T00:00:00Z",
                    "lastModified": "2026-05-04T00:00:00Z",
                },
            },
            {
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User"
                ],
                "id": "user-2",
                "externalId": "ext-2",
                "userName": "bob@example.com",
                "name": {
                    "givenName": "Bob",
                    "familyName": "Roe",
                    "formatted": "Bob Roe",
                },
                "emails": [
                    {
                        "value": "bob@example.com",
                        "type": "work",
                        "primary": True,
                    }
                ],
                "active": True,
                "meta": {
                    "resourceType": "User",
                    "created": "2025-02-01T00:00:00Z",
                    "lastModified": "2026-05-03T00:00:00Z",
                },
            },
        ],
    }
    app, stub = _build_app(
        tenant_url=TENANT,
        api_token="ns-tok",
        stub_responses={"/api/v2/scim/Users": _StubResponse(200, payload)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/netskope/api/v2/scim/Users",
        params={"startIndex": 1, "count": 2, "filter": 'active eq "true"'},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "urn:ietf:params:scim:api:messages:2.0:ListResponse" in body["schemas"]
    assert body["totalResults"] == 2
    assert body["startIndex"] == 1
    assert body["itemsPerPage"] == 2
    assert body["Resources"][0]["userName"] == "alice@example.com"
    assert body["Resources"][1]["userName"] == "bob@example.com"
    assert stub.calls[0]["params"]["startIndex"] == 1
    assert stub.calls[0]["params"]["count"] == 2
    assert stub.calls[0]["params"]["filter"] == 'active eq "true"'


def test_url_policy_list_happy_path(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")
    payload = {
        "ok": 1,
        "result": [
            {
                "id": "url-list-1",
                "name": "Banned Sites",
                "type": "url_list",
                "urls": [
                    "https://malware.example.com",
                    "https://phish.example.com",
                ],
                "modified_at": "2026-05-01T00:00:00Z",
            }
        ],
    }
    app, stub = _build_app(
        tenant_url=TENANT,
        api_token="ns-tok",
        stub_responses={
            "/api/v2/policy/url/list": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/netskope/api/v2/policy/url/list",
        params={"cursor": "next-1", "limit": 25},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"][0]["name"] == "Banned Sites"
    assert "https://malware.example.com" in body["result"][0]["urls"]
    assert stub.calls[0]["params"]["cursor"] == "next-1"
    assert stub.calls[0]["params"]["limit"] == 25


def test_uci_series_happy_path(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")
    payload = {
        "ok": 1,
        "result": {
            "series": [
                {"timestamp": 1714000000, "score": 92},
                {"timestamp": 1714003600, "score": 88},
                {"timestamp": 1714007200, "score": 75},
            ],
            "summary": {"min": 75, "max": 92, "avg": 85.0},
        },
    }
    app, stub = _build_app(
        tenant_url=TENANT,
        api_token="ns-tok",
        stub_responses={
            "/api/v2/services/operational/uci": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/netskope/api/v2/services/operational/uci",
        params={"starttime": 1714000000, "endtime": 1714086400},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"]["summary"]["max"] == 92
    assert len(body["result"]["series"]) == 3
    assert stub.calls[0]["params"]["starttime"] == 1714000000


def test_uba_getuci_happy_path_posts_body(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")
    payload = {
        "ok": 1,
        "result": {
            "user_id": "alice",
            "user_name": "alice@example.com",
            "ip": "203.0.113.5",
            "uci_score": 47,
            "risk_level": "high",
            "behaviors": ["impossible-travel", "anomalous-download"],
        },
    }
    app, stub = _build_app(
        tenant_url=TENANT,
        api_token="ns-tok",
        stub_responses={
            "/api/v2/incidents/uba/getuci": _StubResponse(200, payload),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/netskope/api/v2/incidents/uba/getuci",
        json={
            "start_time": 1714000000,
            "end_time": 1714086400,
            "ip": "203.0.113.5",
            "user_id": "alice",
            "user_name": "alice@example.com",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"]["uci_score"] == 47
    assert body["result"]["risk_level"] == "high"
    call = stub.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == f"{TENANT}/api/v2/incidents/uba/getuci"
    assert call["json"]["start_time"] == 1714000000
    assert call["json"]["end_time"] == 1714086400
    assert call["json"]["ip"] == "203.0.113.5"
    assert call["json"]["user_id"] == "alice"
    assert call["json"]["user_name"] == "alice@example.com"
    assert call["headers"]["Netskope-Api-Token"] == "ns-tok"


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def test_upstream_error_maps_to_503(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")
    app, _ = _build_app(
        tenant_url=TENANT,
        api_token="ns-tok",
        stub_responses={
            "/api/v2/events/data/page": _StubResponse(
                401,
                {"error": "invalid token"},
                text="invalid token",
            ),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/netskope/api/v2/events/data/page",
        params={"type": "alert"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "401" in r.json()["detail"]


def test_uba_getuci_validation_422_when_missing_ip(monkeypatch):
    monkeypatch.setenv("NETSKOPE_TENANT_URL", TENANT)
    monkeypatch.setenv("NETSKOPE_API_TOKEN", "ns-tok")
    app, _ = _build_app(
        tenant_url=TENANT,
        api_token="ns-tok",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    # Pydantic 422 (ip is a required field on the request model)
    r = client.post(
        "/api/v1/netskope/api/v2/incidents/uba/getuci",
        json={
            "start_time": 1714000000,
            "end_time": 1714086400,
        },
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
