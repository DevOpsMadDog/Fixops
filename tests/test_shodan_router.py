"""Tests for shodan_router — ALDECI.

Spins up a minimal FastAPI app with the Shodan router mounted. Each test
gets an isolated SQLite cache via tmp_path and resets the engine
singleton so state doesn't bleed between tests.

NO MOCKS rule:
  * When SHODAN_API_KEY is unset the capability summary reports
    ``status="unavailable"`` and every live-lookup endpoint returns 503.
  * The happy-path tests inject a stub httpx.Client (not a fake response
    payload baked into the engine) so we still exercise the real
    networking + parsing + caching code paths.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import httpx
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
    """Records calls and returns a queued response per URL."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def get(self, url: str, params: Optional[Dict[str, Any]] = None):  # noqa: D401
        self.calls.append({"url": url, "params": params or {}})
        # Match by suffix so query-strings don't matter.
        for path, resp in self._responses.items():
            if url.endswith(path):
                return resp
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def close(self) -> None:
        pass


def _build_app(tmp_path: Path, *, api_key: Optional[str], stub_responses: Dict[str, Any]):
    """Construct an isolated app+engine bound to a tmp DB."""
    db_path = tmp_path / "shodan_cache.db"

    from core import shodan_lookup_engine as engine_mod

    engine_mod.reset_shodan_lookup_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_shodan_lookup_engine(
        db_path=str(db_path),
        api_key=api_key,
        client=stub_client,
    )

    from apps.api.shodan_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/shodan/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Shodan"
    assert set(body["endpoints"]) == {
        "/host/{ip}",
        "/search",
        "/honeyscore/{ip}",
        "/count",
        "/dns/resolve",
    }
    assert body["api_key_present"] is False
    assert body["status"] == "unavailable"
    assert body["cache_size"] == 0

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


def test_capability_summary_empty_when_key_present_no_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")
    app, _ = _build_app(tmp_path, api_key="test-key", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/shodan/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["api_key_present"] is True
    assert body["status"] == "empty"

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


# ---------------------------------------------------------------------------
# Live lookups — unavailable path (no key) returns 503
# ---------------------------------------------------------------------------


def test_host_lookup_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/shodan/host/1.2.3.4", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "SHODAN_API_KEY" in r.json()["detail"]

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


def test_search_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/shodan/search", params={"q": "apache"}, headers=HEADERS)
    assert r.status_code == 503

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_host_lookup_happy_path_normalizes_and_caches(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    raw = {
        "ip_str": "8.8.8.8",
        "country_name": "United States",
        "city": "Mountain View",
        "isp": "Google LLC",
        "asn": "AS15169",
        "hostnames": ["dns.google"],
        "vulns": ["CVE-2021-44228"],
        "data": [
            {
                "port": 53,
                "transport": "udp",
                "product": "Google Public DNS",
                "version": "1.0",
                "data": "DNS banner data",
            }
        ],
    }
    app, stub = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={"/shodan/host/8.8.8.8": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/shodan/host/8.8.8.8", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ip"] == "8.8.8.8"
    assert body["country"] == "United States"
    assert body["isp"] == "Google LLC"
    assert "dns.google" in body["hostnames"]
    assert "CVE-2021-44228" in body["vulns"]
    assert body["services"][0]["port"] == 53
    assert body["services"][0]["protocol"] == "udp"
    assert body["services"][0]["product"] == "Google Public DNS"

    # Second call must hit the cache (no second http call).
    r2 = client.get("/api/v1/shodan/host/8.8.8.8", headers=HEADERS)
    assert r2.status_code == 200
    assert len(stub.calls) == 1, "expected cache hit on the second call"

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


def test_search_happy_path_normalizes_matches(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    raw = {
        "total": 42,
        "matches": [
            {
                "ip_str": "9.9.9.9",
                "port": 443,
                "hostnames": ["dns.quad9.net"],
                "location": {"country_name": "Switzerland", "city": "Zurich"},
                "product": "nginx",
            }
        ],
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={"/shodan/host/search": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/shodan/search",
        params={"q": "nginx country:CH", "page": 1},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 42
    assert len(body["matches"]) == 1
    m = body["matches"][0]
    assert m["ip_str"] == "9.9.9.9"
    assert m["port"] == 443
    assert m["product"] == "nginx"
    assert m["location"]["country_name"] == "Switzerland"

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


def test_honeyscore_happy_path_clamps_to_unit_interval(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    app, _ = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={"/labs/honeyscore/4.4.4.4": _StubResponse(200, 0.73)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/shodan/honeyscore/4.4.4.4", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ip"] == "4.4.4.4"
    assert 0.0 <= body["honeyscore"] <= 1.0
    assert abs(body["honeyscore"] - 0.73) < 1e-6

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


def test_count_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    raw = {"total": 12345, "facets": {"country": [{"value": "US", "count": 100}]}}
    app, _ = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={"/shodan/host/count": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/shodan/count", params={"q": "product:nginx"}, headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 12345
    assert body["facets"]["country"][0]["value"] == "US"

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


def test_dns_resolve_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    raw = {"google.com": "142.250.80.46", "cloudflare.com": "104.16.132.229"}
    app, _ = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={"/dns/resolve": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/shodan/dns/resolve",
        params={"hostnames": "google.com,cloudflare.com"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["google.com"] == "142.250.80.46"
    assert body["cloudflare.com"] == "104.16.132.229"

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------


def test_search_rejects_empty_query(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    app, _ = _build_app(tmp_path, api_key="test", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/shodan/search", params={"q": ""}, headers=HEADERS)
    assert r.status_code == 422

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()


def test_dns_resolve_rejects_empty_hostnames(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    app, _ = _build_app(tmp_path, api_key="test", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/shodan/dns/resolve", params={"hostnames": ",,,"}, headers=HEADERS
    )
    assert r.status_code == 422

    from core import shodan_lookup_engine as engine_mod
    engine_mod.reset_shodan_lookup_engine()
