"""Tests for virustotal_router — ALDECI.

Spins up a minimal FastAPI app with the VirusTotal router mounted. Each
test gets an isolated SQLite cache via tmp_path and resets the engine
singleton so state doesn't bleed between tests.

NO MOCKS rule:
  * When VT_API_KEY is unset the capability summary reports
    ``status="unavailable"`` and every live-lookup endpoint returns 503.
  * The happy-path tests inject a stub httpx.Client so we still exercise
    the real networking + parsing + caching code paths.
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
    """Records calls and returns a queued response per URL suffix."""

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
    api_key: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a tmp DB."""
    db_path = tmp_path / "virustotal_cache.db"

    from core import virustotal_lookup_engine as engine_mod

    engine_mod.reset_virustotal_lookup_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_virustotal_lookup_engine(
        db_path=str(db_path),
        api_key=api_key,
        client=stub_client,
    )

    from apps.api.virustotal_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset() -> None:
    from core import virustotal_lookup_engine as engine_mod

    engine_mod.reset_virustotal_lookup_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/virustotal/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "VirusTotal"
    assert set(body["endpoints"]) == {
        "/v3/files/{hash}",
        "/v3/urls/{url_id}",
        "/v3/domains/{domain}",
        "/v3/ip_addresses/{ip}",
    }
    assert body["api_key_present"] is False
    assert body["status"] == "unavailable"
    assert body["cache_size"] == 0
    _reset()


def test_capability_summary_empty_when_key_present_no_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    app, _ = _build_app(tmp_path, api_key="test-key", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/virustotal/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["api_key_present"] is True
    assert body["status"] == "empty"
    _reset()


def test_capability_summary_picks_up_alt_env_var(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "alt-key")
    # api_key=None so engine resolves from env
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/virustotal/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["api_key_present"] is True
    assert body["status"] == "empty"
    _reset()


# ---------------------------------------------------------------------------
# 503 — no API key
# ---------------------------------------------------------------------------


def test_file_lookup_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/virustotal/v3/files/abc123def456", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    assert "VT_API_KEY" in r.json()["detail"]
    _reset()


def test_url_lookup_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/virustotal/v3/urls/some-url-id", headers=HEADERS
    )
    assert r.status_code == 503
    _reset()


def test_domain_lookup_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/virustotal/v3/domains/example.com", headers=HEADERS
    )
    assert r.status_code == 503
    _reset()


def test_ip_lookup_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/virustotal/v3/ip_addresses/8.8.8.8", headers=HEADERS
    )
    assert r.status_code == 503
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_file_lookup_happy_path_normalizes_and_caches(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test")
    file_hash = "44d88612fea8a8f36de82e1278abb02f"
    raw = {
        "data": {
            "id": file_hash,
            "type": "file",
            "attributes": {
                "md5": file_hash,
                "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                "sha256": (
                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2"
                    "fe2a2c4538aabf651fd0f"
                ),
                "type_description": "Text",
                "names": ["eicar.com", "eicar.txt"],
                "last_analysis_stats": {
                    "malicious": 60,
                    "suspicious": 0,
                    "undetected": 5,
                    "harmless": 0,
                },
                "last_analysis_results": {
                    "Microsoft": {"category": "malicious", "result": "EICAR"},
                },
            },
        }
    }
    app, stub = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={f"/files/{file_hash}": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        f"/api/v1/virustotal/v3/files/{file_hash}", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["id"] == file_hash
    assert body["data"]["type"] == "file"
    attrs = body["data"]["attributes"]
    assert attrs["md5"] == file_hash
    assert attrs["sha1"] == "3395856ce81f2b7382dee72602f798b642f14140"
    assert attrs["last_analysis_stats"]["malicious"] == 60
    assert attrs["last_analysis_stats"]["harmless"] == 0
    assert attrs["last_analysis_stats"]["undetected"] == 5
    assert "eicar.com" in attrs["names"]
    assert attrs["type_description"] == "Text"
    assert attrs["last_analysis_results"]["Microsoft"]["result"] == "EICAR"

    # Verify x-apikey header was sent
    assert stub.calls[0]["headers"].get("x-apikey") == "test"

    # Second call must hit the cache (no second http call).
    r2 = client.get(
        f"/api/v1/virustotal/v3/files/{file_hash}", headers=HEADERS
    )
    assert r2.status_code == 200
    assert len(stub.calls) == 1, "expected cache hit on the second call"
    _reset()


def test_url_lookup_happy_path_normalizes(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test")
    url_id = "u32abc"
    raw = {
        "data": {
            "id": url_id,
            "type": "url",
            "attributes": {
                "url": "https://malicious.example.com/payload",
                "title": "Free Bitcoin",
                "last_final_url": "https://redirect.example.com/landing",
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 3,
                    "undetected": 50,
                    "harmless": 5,
                },
                "last_analysis_results": {
                    "Phishtank": {"category": "malicious", "result": "phishing"},
                },
            },
        }
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={f"/urls/{url_id}": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        f"/api/v1/virustotal/v3/urls/{url_id}", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["id"] == url_id
    assert body["data"]["type"] == "url"
    attrs = body["data"]["attributes"]
    assert attrs["url"] == "https://malicious.example.com/payload"
    assert attrs["title"] == "Free Bitcoin"
    assert attrs["last_final_url"] == "https://redirect.example.com/landing"
    assert attrs["last_analysis_stats"]["malicious"] == 12
    assert attrs["last_analysis_results"]["Phishtank"]["result"] == "phishing"
    _reset()


def test_domain_lookup_happy_path_normalizes(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test")
    domain = "example.com"
    raw = {
        "data": {
            "id": domain,
            "type": "domain",
            "attributes": {
                "categories": {
                    "Sophos": "newly registered",
                    "Forcepoint": "information technology",
                },
                "jarm": "29d29d20d29d29d20d29d29d29d29d",
                "popularity_ranks": {
                    "Cisco Umbrella": {"timestamp": 1700000000, "rank": 100},
                    "Majestic": {"timestamp": 1700000000, "rank": 200},
                },
                "registrar": "MarkMonitor Inc.",
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 70,
                    "harmless": 25,
                },
            },
        }
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={f"/domains/{domain}": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        f"/api/v1/virustotal/v3/domains/{domain}", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["id"] == domain
    assert body["data"]["type"] == "domain"
    attrs = body["data"]["attributes"]
    assert attrs["categories"]["Sophos"] == "newly registered"
    assert attrs["jarm"] == "29d29d20d29d29d20d29d29d29d29d"
    assert attrs["registrar"] == "MarkMonitor Inc."
    assert attrs["popularity_ranks"]["Cisco Umbrella"]["rank"] == 100
    assert attrs["last_analysis_stats"]["harmless"] == 25
    _reset()


def test_ip_lookup_happy_path_normalizes(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test")
    ip = "8.8.8.8"
    raw = {
        "data": {
            "id": ip,
            "type": "ip_address",
            "attributes": {
                "country": "US",
                "asn": 15169,
                "as_owner": "GOOGLE",
                "regional_internet_registry": "ARIN",
                "network": "8.8.8.0/24",
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 60,
                    "harmless": 30,
                },
            },
        }
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={f"/ip_addresses/{ip}": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        f"/api/v1/virustotal/v3/ip_addresses/{ip}", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["id"] == ip
    assert body["data"]["type"] == "ip_address"
    attrs = body["data"]["attributes"]
    assert attrs["country"] == "US"
    assert attrs["as_owner"] == "GOOGLE"
    assert attrs["regional_internet_registry"] == "ARIN"
    assert attrs["network"] == "8.8.8.0/24"
    assert attrs["last_analysis_stats"]["harmless"] == 30
    _reset()


# ---------------------------------------------------------------------------
# Upstream errors translate to 503
# ---------------------------------------------------------------------------


def test_file_lookup_translates_upstream_4xx_to_503(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test")
    file_hash = "deadbeef"
    app, _ = _build_app(
        tmp_path,
        api_key="test",
        stub_responses={
            f"/files/{file_hash}": _StubResponse(401, {"error": "bad key"})
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        f"/api/v1/virustotal/v3/files/{file_hash}", headers=HEADERS
    )
    assert r.status_code == 503
    assert "rejected credentials" in r.json()["detail"]
    _reset()
