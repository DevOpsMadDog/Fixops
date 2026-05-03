"""Tests for greynoise_router — ALDECI.

Spins up a minimal FastAPI app with the GreyNoise router mounted. Each test
gets an isolated SQLite cache via tmp_path and resets the engine singleton so
state doesn't bleed between tests.

NO MOCKS rule:
  * Community endpoint works WITHOUT GREYNOISE_API_KEY (free public tier).
  * Context + RIOT endpoints return HTTP 503 when the key is missing.
  * Capability summary reports ``status="unavailable"`` when the key is missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload) so
    we still exercise the real networking + parsing + caching code paths.
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

    def get(self, url: str, headers: Optional[Dict[str, str]] = None):  # noqa: D401
        self.calls.append({"url": url, "headers": headers or {}})
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
    db_path = tmp_path / "greynoise_cache.db"

    from core import greynoise_lookup_engine as engine_mod

    engine_mod.reset_greynoise_lookup_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_greynoise_lookup_engine(
        db_path=str(db_path),
        api_key=api_key,
        client=stub_client,
    )

    from apps.api.greynoise_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import greynoise_lookup_engine as engine_mod

    engine_mod.reset_greynoise_lookup_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/greynoise/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "GreyNoise"
    assert body["endpoints"] == [
        "/v3/community/{ip} (free)",
        "/v2/noise/context/{ip} (paid)",
        "/v2/riot/{ip}",
    ]
    assert body["api_key_present"] is False
    assert body["status"] == "unavailable"
    assert body["cache_size"] == 0
    _reset()


def test_capability_summary_empty_when_key_present_no_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    app, _ = _build_app(tmp_path, api_key="test-key", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/greynoise/", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["api_key_present"] is True
    assert body["status"] == "empty"
    _reset()


# ---------------------------------------------------------------------------
# Paid endpoints — unavailable path returns 503 when no key
# ---------------------------------------------------------------------------


def test_context_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/greynoise/v2/noise/context/1.2.3.4", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "GREYNOISE_API_KEY" in r.json()["detail"]
    _reset()


def test_riot_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/greynoise/v2/riot/1.2.3.4", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_community_lookup_works_without_api_key(tmp_path, monkeypatch):
    """Community v3 is the free tier — must succeed even when no key is set."""
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    raw = {
        "ip": "8.8.8.8",
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
        "link": "https://viz.greynoise.io/riot/8.8.8.8",
        "last_seen": "2026-04-30T00:00:00Z",
        "message": "Success",
    }
    app, stub = _build_app(
        tmp_path,
        api_key=None,
        stub_responses={"/v3/community/8.8.8.8": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/greynoise/v3/community/8.8.8.8", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ip"] == "8.8.8.8"
    assert body["riot"] is True
    assert body["noise"] is False
    assert body["classification"] == "benign"
    assert body["name"] == "Google Public DNS"

    # Cache hit on second call -> no second http call.
    r2 = client.get("/api/v1/greynoise/v3/community/8.8.8.8", headers=HEADERS)
    assert r2.status_code == 200
    assert len(stub.calls) == 1, "expected cache hit on the second call"
    _reset()


def test_context_happy_path_normalizes(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    raw = {
        "ip": "5.6.7.8",
        "seen": True,
        "classification": "malicious",
        "first_seen": "2026-01-01",
        "last_seen": "2026-04-30",
        "actor": "Mirai-like-botnet",
        "tags": ["Mirai", "SSH Bruteforcer"],
        "cve": ["CVE-2023-1234"],
        "metadata": {"asn": "AS12345", "organization": "Acme ISP"},
        "raw_data": {
            "scan": [{"port": 22, "protocol": "TCP"}],
            "web": {"paths": ["/login"]},
            "ja3": [{"fingerprint": "abc123"}],
        },
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={"/v2/noise/context/5.6.7.8": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/greynoise/v2/noise/context/5.6.7.8", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ip"] == "5.6.7.8"
    assert body["seen"] is True
    assert body["classification"] == "malicious"
    assert "Mirai" in body["tags"]
    assert "CVE-2023-1234" in body["cve"]
    assert body["asn"] == "AS12345"
    assert body["organization"] == "Acme ISP"
    assert body["raw_data"]["scan"][0]["port"] == 22
    assert body["raw_data"]["web"]["paths"] == ["/login"]
    _reset()


def test_riot_happy_path_normalizes(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    raw = {
        "ip": "1.1.1.1",
        "riot": True,
        "name": "Cloudflare Public DNS",
        "category": "public_dns",
        "description": "Cloudflare's public DNS resolver",
        "explanation": "Known DNS provider",
        "last_updated": "2026-04-30T12:00:00Z",
        "reference": "https://1.1.1.1",
        "trust_level": "1",
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={"/v2/riot/1.1.1.1": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/greynoise/v2/riot/1.1.1.1", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ip"] == "1.1.1.1"
    assert body["riot"] is True
    assert body["name"] == "Cloudflare Public DNS"
    assert body["category"] == "public_dns"
    assert body["trust_level"] == "1"
    _reset()


# ---------------------------------------------------------------------------
# Cache TTL behaviour & SQLite persistence
# ---------------------------------------------------------------------------


def test_cache_persists_to_sqlite(tmp_path, monkeypatch):
    """Verify the SQLite cache file exists with the expected schema."""
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    raw = {
        "ip": "2.2.2.2",
        "noise": True,
        "riot": False,
        "classification": "malicious",
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={"/v3/community/2.2.2.2": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    # Trigger a cached entry.
    r = client.get("/api/v1/greynoise/v3/community/2.2.2.2", headers=HEADERS)
    assert r.status_code == 200

    db_path = tmp_path / "greynoise_cache.db"
    assert db_path.exists(), "expected SQLite cache DB on disk"

    import sqlite3

    conn = sqlite3.connect(str(db_path))
    cur = conn.execute(
        "SELECT cache_key, query_type FROM greynoise_cache "
        "WHERE cache_key = ?",
        ("community:2.2.2.2",),
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "community:2.2.2.2"
    assert row[1] == "community"

    # Index on expires_at should exist.
    conn = sqlite3.connect(str(db_path))
    idx = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND name='idx_greynoise_cache_expires'"
    ).fetchone()
    conn.close()
    assert idx is not None, "expected expires_at index"
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths
# ---------------------------------------------------------------------------


def test_context_returns_503_on_upstream_429(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    app, _ = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={
            "/v2/noise/context/9.9.9.9": _StubResponse(
                429, {"message": "rate limit"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/greynoise/v2/noise/context/9.9.9.9", headers=HEADERS)
    assert r.status_code == 503
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()
