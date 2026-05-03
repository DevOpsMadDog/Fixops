"""Tests for abuseipdb_router (v2 surface) — ALDECI.

Spins up a minimal FastAPI app with the AbuseIPDB router mounted. Each test
gets an isolated SQLite cache via tmp_path and resets the engine singleton
so state doesn't bleed between tests.

NO MOCKS rule:
  * /v2/check, /v2/blacklist, /v2/report return HTTP 503 when no key.
  * Capability summary reports ``status="unavailable"`` when key is missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real networking + parsing + caching code paths.
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
    ):  # noqa: D401
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
    ):  # noqa: D401
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
    tmp_path: Path,
    *,
    api_key: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a tmp DB."""
    db_path = tmp_path / "abuseipdb_cache.db"

    from core import abuseipdb_lookup_engine as engine_mod

    engine_mod.reset_abuseipdb_lookup_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_abuseipdb_lookup_engine(
        db_path=str(db_path),
        api_key=api_key,
        client=stub_client,
    )

    from apps.api.abuseipdb_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import abuseipdb_lookup_engine as engine_mod

    engine_mod.reset_abuseipdb_lookup_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/abuseipdb/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "AbuseIPDB"
    assert body["endpoints"] == ["/v2/check", "/v2/blacklist", "/v2/report"]
    assert body["api_key_present"] is False
    assert body["status"] == "unavailable"
    assert body["cache_size"] == 0
    _reset()


def test_capability_summary_empty_when_key_present_no_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    app, _ = _build_app(tmp_path, api_key="test-key", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/abuseipdb/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api_key_present"] is True
    assert body["status"] == "empty"
    assert body["cache_size"] == 0
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no key
# ---------------------------------------------------------------------------


def test_check_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/abuseipdb/v2/check",
        params={"ipAddress": "1.2.3.4", "maxAgeInDays": 30},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "ABUSEIPDB_API_KEY" in r.json()["detail"]
    _reset()


def test_blacklist_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/abuseipdb/v2/blacklist",
        params={"confidenceMinimum": 90, "limit": 100},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_report_returns_503_when_no_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    app, _ = _build_app(tmp_path, api_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/abuseipdb/v2/report",
        json={"ip": "1.2.3.4", "categories": [18, 22], "comment": "ssh brute force"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_check_happy_path_normalizes_and_caches(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    raw = {
        "data": {
            "ipAddress": "118.25.6.39",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 100,
            "countryCode": "CN",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Tencent Cloud",
            "domain": "tencent.com",
            "totalReports": 273,
            "numDistinctUsers": 78,
            "lastReportedAt": "2026-04-30T12:34:56+00:00",
        }
    }
    app, stub = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={"/api/v2/check": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/abuseipdb/v2/check",
        params={"ipAddress": "118.25.6.39", "maxAgeInDays": 30},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["ipAddress"] == "118.25.6.39"
    assert body["data"]["abuseConfidenceScore"] == 100
    assert body["data"]["countryCode"] == "CN"
    assert body["data"]["isp"] == "Tencent Cloud"
    assert body["data"]["totalReports"] == 273

    # Cache hit on second call -> no second http call.
    r2 = client.get(
        "/api/v1/abuseipdb/v2/check",
        params={"ipAddress": "118.25.6.39", "maxAgeInDays": 30},
        headers=HEADERS,
    )
    assert r2.status_code == 200
    assert len(stub.calls) == 1, "expected cache hit on the second call"
    _reset()


def test_blacklist_happy_path_normalizes(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    raw = {
        "meta": {"generatedAt": "2026-05-04T00:00:00+00:00"},
        "data": [
            {
                "ipAddress": "5.188.10.179",
                "countryCode": "RU",
                "abuseConfidenceScore": 100,
                "lastReportedAt": "2026-05-03T23:55:00+00:00",
            },
            {
                "ipAddress": "45.227.255.190",
                "countryCode": "PA",
                "abuseConfidenceScore": 95,
                "lastReportedAt": "2026-05-03T23:50:00+00:00",
            },
        ],
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={"/api/v2/blacklist": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/abuseipdb/v2/blacklist",
        params={"confidenceMinimum": 90, "limit": 100},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["meta"]["generatedAt"] == "2026-05-04T00:00:00+00:00"
    assert len(body["data"]) == 2
    assert body["data"][0]["ipAddress"] == "5.188.10.179"
    assert body["data"][0]["abuseConfidenceScore"] == 100
    assert body["data"][1]["countryCode"] == "PA"
    _reset()


def test_report_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    raw = {
        "data": {
            "ipAddress": "127.0.0.2",
            "abuseConfidenceScore": 52,
        }
    }
    app, stub = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={"/api/v2/report": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/abuseipdb/v2/report",
        json={"ip": "127.0.0.2", "categories": [18, 22], "comment": "ssh brute"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["data"]["ipAddress"] == "127.0.0.2"
    assert body["data"]["abuseConfidenceScore"] == 52

    # Reports are NOT cached — second call must hit upstream again.
    r2 = client.post(
        "/api/v1/abuseipdb/v2/report",
        json={"ip": "127.0.0.2", "categories": [18, 22], "comment": "ssh brute"},
        headers=HEADERS,
    )
    assert r2.status_code == 200
    posts = [c for c in stub.calls if c["method"] == "POST"]
    assert len(posts) == 2, "expected reports to NOT be cached"
    _reset()


# ---------------------------------------------------------------------------
# Cache persistence + capability "ok" status
# ---------------------------------------------------------------------------


def test_cache_persists_to_sqlite_and_summary_status_ok(tmp_path, monkeypatch):
    """After a successful lookup the SQLite cache file exists and the
    capability summary flips to status="ok"."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    raw = {
        "data": {
            "ipAddress": "203.0.113.10",
            "isPublic": True,
            "ipVersion": 4,
            "abuseConfidenceScore": 75,
        }
    }
    app, _ = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={"/api/v2/check": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/abuseipdb/v2/check",
        params={"ipAddress": "203.0.113.10", "maxAgeInDays": 90},
        headers=HEADERS,
    )
    assert r.status_code == 200

    db_path = tmp_path / "abuseipdb_cache.db"
    assert db_path.exists(), "expected SQLite cache DB on disk"

    import sqlite3

    conn = sqlite3.connect(str(db_path))
    cur = conn.execute(
        "SELECT cache_key, query_type FROM abuseipdb_cache WHERE cache_key = ?",
        ("check:203.0.113.10:90",),
    )
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "check:203.0.113.10:90"
    assert row[1] == "check"

    idx = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND name='idx_abuseipdb_cache_expires'"
    ).fetchone()
    conn.close()
    assert idx is not None, "expected expires_at index"

    # Summary should now show status="ok".
    s = client.get("/api/v1/abuseipdb/", headers=HEADERS)
    assert s.status_code == 200
    sb = s.json()
    assert sb["status"] == "ok"
    assert sb["cache_size"] >= 1
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths + input validation
# ---------------------------------------------------------------------------


def test_check_returns_503_on_upstream_429(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    app, _ = _build_app(
        tmp_path,
        api_key="test-key",
        stub_responses={
            "/api/v2/check": _StubResponse(
                429, {"errors": [{"detail": "Too Many Requests"}]}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/abuseipdb/v2/check",
        params={"ipAddress": "9.9.9.9", "maxAgeInDays": 30},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    assert "rate-limit" in r.json()["detail"].lower() or "429" in r.json()["detail"]
    _reset()


def test_report_validation_rejects_empty_categories(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    app, _ = _build_app(tmp_path, api_key="test-key", stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/abuseipdb/v2/report",
        json={"ip": "1.2.3.4", "categories": [], "comment": "x"},
        headers=HEADERS,
    )
    # Pydantic already enforces "categories" exists; engine enforces non-empty.
    assert r.status_code == 422, r.text
    _reset()
