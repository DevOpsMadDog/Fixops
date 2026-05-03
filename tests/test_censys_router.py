"""Tests for censys_router — ALDECI.

Spins up a minimal FastAPI app with the Censys router mounted. Each test
gets an isolated SQLite cache via tmp_path and resets the engine
singleton so state doesn't bleed between tests.

NO MOCKS rule:
  * When CENSYS_API_ID/SECRET are unset the capability summary reports
    ``status="unavailable"`` and every live-lookup endpoint returns 503.
  * The happy-path tests inject a stub httpx.Client (not a fake response
    payload baked into the engine) so we still exercise the real
    networking + parsing + caching code paths.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# Helpers
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
    """Records calls and returns a queued response per URL suffix match."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.calls.append(
            {"url": url, "params": params or {}, "headers": headers or {}}
        )
        for path, resp in self._responses.items():
            if url.endswith(path):
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


def _build_app(
    tmp_path: Path,
    *,
    api_id: Optional[str],
    api_secret: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a tmp DB."""
    db_path = tmp_path / "censys_cache.db"

    from core import censys_lookup_engine as engine_mod

    engine_mod.reset_censys_lookup_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_censys_lookup_engine(
        db_path=str(db_path),
        api_id=api_id,
        api_secret=api_secret,
        client=stub_client,
    )

    from apps.api.censys_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    app, _ = _build_app(
        tmp_path, api_id=None, api_secret=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/censys/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Censys"
    assert set(body["endpoints"]) == {
        "/v2/hosts/{ip}",
        "/v2/certificates/{fingerprint}",
        "/v2/hosts/search",
    }
    assert body["api_id_present"] is False
    assert body["api_secret_present"] is False
    assert body["status"] == "unavailable"
    assert body["cache_size"] == 0

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


def test_capability_summary_empty_when_creds_present_no_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "test-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")
    app, _ = _build_app(
        tmp_path,
        api_id="test-id",
        api_secret="test-secret",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/censys/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["api_id_present"] is True
    assert body["api_secret_present"] is True
    assert body["status"] == "empty"

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


# ---------------------------------------------------------------------------
# Live lookups — unavailable path returns 503
# ---------------------------------------------------------------------------


def test_host_lookup_returns_503_when_no_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    app, _ = _build_app(
        tmp_path, api_id=None, api_secret=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/censys/v2/hosts/8.8.8.8", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "CENSYS_API_ID" in r.json()["detail"]

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


def test_certificate_lookup_returns_503_when_no_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    app, _ = _build_app(
        tmp_path, api_id=None, api_secret=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/censys/v2/certificates/abcdef0123456789", headers=HEADERS
    )
    assert r.status_code == 503

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


def test_search_returns_503_when_no_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    app, _ = _build_app(
        tmp_path, api_id=None, api_secret=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/censys/v2/hosts/search",
        params={"q": "services.service_name: HTTP"},
        headers=HEADERS,
    )
    assert r.status_code == 503

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_host_lookup_happy_path_normalizes_and_caches(tmp_path, monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "test-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")
    raw = {
        "code": 200,
        "status": "OK",
        "result": {
            "ip": "8.8.8.8",
            "location": {
                "country": "United States",
                "country_code": "US",
                "city": "Mountain View",
                "continent": "North America",
            },
            "autonomous_system": {
                "asn": 15169,
                "name": "GOOGLE",
                "country_code": "US",
            },
            "services": [
                {
                    "port": 53,
                    "service_name": "DNS",
                    "transport_protocol": "UDP",
                    "software": [{"product": "Google Public DNS"}],
                },
                {
                    "port": 443,
                    "service_name": "HTTP",
                    "transport_protocol": "TCP",
                    "software": [],
                },
            ],
            "last_updated_at": "2026-05-04T00:00:00Z",
        },
    }
    app, stub = _build_app(
        tmp_path,
        api_id="test-id",
        api_secret="test-secret",
        stub_responses={"/hosts/8.8.8.8": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/censys/v2/hosts/8.8.8.8", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ip"] == "8.8.8.8"
    assert body["location"]["country"] == "United States"
    assert body["location"]["country_code"] == "US"
    assert body["autonomous_system"]["asn"] == 15169
    assert body["autonomous_system"]["name"] == "GOOGLE"
    assert body["last_updated_at"] == "2026-05-04T00:00:00Z"
    assert len(body["services"]) == 2
    s0 = body["services"][0]
    assert s0["port"] == 53
    assert s0["protocol"] == "UDP"
    assert s0["software"] and s0["software"][0]["product"] == "Google Public DNS"

    # Verify Basic auth header was sent
    assert stub.calls, "expected at least one upstream call"
    first = stub.calls[0]
    assert first["headers"].get("Authorization", "").startswith("Basic ")

    # Second call must hit cache
    r2 = client.get("/api/v1/censys/v2/hosts/8.8.8.8", headers=HEADERS)
    assert r2.status_code == 200
    assert len(stub.calls) == 1, "expected cache hit on the second call"

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


def test_certificate_lookup_happy_path_normalizes(tmp_path, monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "test-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")
    fingerprint = (
        "fa1b3c4d5e6f7890abcdef0123456789fa1b3c4d5e6f7890abcdef0123456789"
    )
    raw = {
        "code": 200,
        "status": "OK",
        "result": {
            "fingerprint_sha256": fingerprint,
            "names": ["example.com", "www.example.com"],
            "parsed": {
                "subject": {"common_name": ["example.com"]},
                "issuer": {"common_name": ["Let's Encrypt R3"]},
                "validity_period": {
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2026-04-01T00:00:00Z",
                    "length": 7776000,
                },
                "names": ["example.com"],
            },
            "ct": [
                {"log_name": "Argon2026", "index": 12345},
                {"log_name": "Xenon2026", "index": 67890},
            ],
        },
    }
    app, _ = _build_app(
        tmp_path,
        api_id="test-id",
        api_secret="test-secret",
        stub_responses={f"/certificates/{fingerprint}": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        f"/api/v1/censys/v2/certificates/{fingerprint}", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["fingerprint"] == fingerprint
    assert body["parsed"]["subject"]["common_name"] == ["example.com"]
    assert body["parsed"]["issuer"]["common_name"] == ["Let's Encrypt R3"]
    assert body["parsed"]["validity_period"]["start"] == "2026-01-01T00:00:00Z"
    assert body["parsed"]["validity_period"]["end"] == "2026-04-01T00:00:00Z"
    assert body["parsed"]["validity_period"]["length_seconds"] == 7776000
    assert "example.com" in body["parsed"]["names"]
    assert len(body["ct_logs"]) == 2

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


def test_hosts_search_happy_path_returns_total_and_hits(tmp_path, monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "test-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")
    raw = {
        "code": 200,
        "status": "OK",
        "result": {
            "total": 4321,
            "hits": [
                {
                    "ip": "1.1.1.1",
                    "name": "one.one.one.one",
                    "services": [
                        {"port": 443, "service_name": "HTTP"},
                        {"port": 53, "service_name": "DNS"},
                    ],
                },
                {
                    "ip": "9.9.9.9",
                    "names": ["dns.quad9.net"],
                    "services": [{"port": 853, "service_name": "DNS"}],
                },
            ],
        },
    }
    app, stub = _build_app(
        tmp_path,
        api_id="test-id",
        api_secret="test-secret",
        stub_responses={"/hosts/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/censys/v2/hosts/search",
        params={"q": "services.service_name: DNS", "per_page": 10},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"]["total"] == 4321
    assert len(body["result"]["hits"]) == 2
    h0 = body["result"]["hits"][0]
    assert h0["ip"] == "1.1.1.1"
    assert h0["name"] == "one.one.one.one"
    assert {s["port"] for s in h0["services_summary"]} == {443, 53}
    h1 = body["result"]["hits"][1]
    assert h1["ip"] == "9.9.9.9"
    # Falls back to first entry from `names` when `name` is absent
    assert h1["name"] == "dns.quad9.net"

    # per_page parameter forwarded upstream
    assert stub.calls
    assert stub.calls[0]["params"].get("per_page") == 10
    assert stub.calls[0]["params"].get("q") == "services.service_name: DNS"

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------


def test_search_rejects_empty_query(tmp_path, monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "test-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")
    app, _ = _build_app(
        tmp_path,
        api_id="test-id",
        api_secret="test-secret",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/censys/v2/hosts/search", params={"q": ""}, headers=HEADERS
    )
    assert r.status_code == 422

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()


def test_search_per_page_out_of_range(tmp_path, monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "test-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-secret")
    app, _ = _build_app(
        tmp_path,
        api_id="test-id",
        api_secret="test-secret",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/censys/v2/hosts/search",
        params={"q": "x", "per_page": 9999},
        headers=HEADERS,
    )
    assert r.status_code == 422

    from core import censys_lookup_engine as engine_mod
    engine_mod.reset_censys_lookup_engine()
