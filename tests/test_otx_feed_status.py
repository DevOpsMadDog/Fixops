"""Tests for GET /api/v1/otx/feed-status endpoint.

Tests:
1. Empty store returns status=empty with zero counts
2. After import, status=ok with correct pulse + indicator counts
3. authenticated flag reflects OTX_API_KEY env var
4. source_url switches between public and subscribed endpoints
5. by_indicator_type and with_attack_id populated correctly after import
6. Response schema has all required keys
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(__file__)
for rel in ("..", "../suite-feeds", "../suite-api", "../suite-core"):
    p = os.path.abspath(os.path.join(_HERE, rel))
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Fixture pulses (minimal — 2 pulses, 5 indicators, 1 with ATT&CK id)
# ---------------------------------------------------------------------------

_PULSES: List[Dict[str, Any]] = [
    {
        "id": "fs-pulse-aaaaaaaaaaaaaaaaaaaaaa",
        "name": "Feed-status test pulse A",
        "description": "C2 tracking.",
        "author_name": "aldeci-test",
        "created": "2024-06-01T00:00:00",
        "modified": "2024-06-01T01:00:00",
        "references": [],
        "tags": ["test"],
        "malware_families": [],
        "attack_ids": [{"id": "T1059", "display_name": "Command and Scripting Interpreter"}],
        "industries": [],
        "targeted_countries": [],
        "tlp": "white",
        "public": True,
        "indicators": [
            {"id": 101, "type": "IPv4", "indicator": "203.0.113.10", "created": "2024-06-01T00:00:00"},
            {"id": 102, "type": "domain", "indicator": "bad.example.com", "created": "2024-06-01T00:00:00"},
            {"id": 103, "type": "FileHash-SHA256",
             "indicator": "aabbcc" * 10 + "aabb",
             "created": "2024-06-01T00:00:00"},
        ],
    },
    {
        "id": "fs-pulse-bbbbbbbbbbbbbbbbbbbbbb",
        "name": "Feed-status test pulse B",
        "description": "Ransomware hashes.",
        "author_name": "aldeci-test",
        "created": "2024-06-02T00:00:00",
        "modified": "2024-06-02T00:30:00",
        "references": [],
        "tags": ["ransomware"],
        "malware_families": [],
        "attack_ids": [],
        "industries": [],
        "targeted_countries": [],
        "tlp": "white",
        "public": True,
        "indicators": [
            {"id": 201, "type": "FileHash-MD5", "indicator": "098f6bcd4621d373cade4e832627b4f6", "created": "2024-06-02T00:00:00"},
            {"id": 202, "type": "IPv4", "indicator": "192.0.2.55", "created": "2024-06-02T00:00:00"},
        ],
    },
]

# ---------------------------------------------------------------------------
# In-memory store substitute (no disk writes)
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    def persist(self, key):
        pass


@pytest.fixture(autouse=True)
def _mock_stores(monkeypatch):
    """Patch both pulses + indicators stores with fresh in-memory dicts."""
    from feeds.otx import importer as imp
    pulses = _InMemoryStore()
    indicators = _InMemoryStore()
    monkeypatch.setattr(imp, "_pulses_store", pulses)
    monkeypatch.setattr(imp, "_indicators_store", indicators)
    yield (pulses, indicators)
    monkeypatch.setattr(imp, "_pulses_store", None)
    monkeypatch.setattr(imp, "_indicators_store", None)


# ---------------------------------------------------------------------------
# Shared test-client factory
# ---------------------------------------------------------------------------

def _make_client(monkeypatch) -> TestClient:
    from apps.api import otx_router
    from apps.api.auth_deps import api_key_auth

    async def _no_auth():
        return None

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = _no_auth
    app.include_router(otx_router.router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: Empty store → status=empty, all counts zero
# ---------------------------------------------------------------------------

def test_feed_status_empty_store(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    client = _make_client(monkeypatch)

    r = client.get("/api/v1/otx/feed-status")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["status"] == "empty"
    assert body["total_pulses"] == 0
    assert body["total_indicators"] == 0
    assert body["with_attack_id"] == 0
    assert body["by_indicator_type"] == {}


# ---------------------------------------------------------------------------
# Test 2: After import → status=ok with correct counts
# ---------------------------------------------------------------------------

def test_feed_status_after_import(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    from feeds.otx.importer import import_pulses
    import_pulses(_PULSES)

    client = _make_client(monkeypatch)
    r = client.get("/api/v1/otx/feed-status")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["status"] == "ok"
    assert body["total_pulses"] == 2
    assert body["total_indicators"] == 5


# ---------------------------------------------------------------------------
# Test 3: authenticated=False when OTX_API_KEY is unset
# ---------------------------------------------------------------------------

def test_feed_status_unauthenticated(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    client = _make_client(monkeypatch)

    r = client.get("/api/v1/otx/feed-status")
    assert r.status_code == 200
    assert r.json()["authenticated"] is False


# ---------------------------------------------------------------------------
# Test 4: source_url reflects auth state
# ---------------------------------------------------------------------------

def test_feed_status_source_url_public(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    client = _make_client(monkeypatch)

    body = client.get("/api/v1/otx/feed-status").json()
    assert "activity" in body["source_url"]
    assert "subscribed" not in body["source_url"]


def test_feed_status_source_url_subscribed(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-key-abc123")
    client = _make_client(monkeypatch)

    body = client.get("/api/v1/otx/feed-status").json()
    assert body["authenticated"] is True
    assert "subscribed" in body["source_url"]


# ---------------------------------------------------------------------------
# Test 5: by_indicator_type and with_attack_id after import
# ---------------------------------------------------------------------------

def test_feed_status_indicator_breakdown(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    from feeds.otx.importer import import_pulses
    import_pulses(_PULSES)

    client = _make_client(monkeypatch)
    body = client.get("/api/v1/otx/feed-status").json()

    by_type = body["by_indicator_type"]
    # pulse A: IPv4 + domain + SHA256; pulse B: MD5 + IPv4
    assert by_type.get("IPv4") == 2
    assert by_type.get("domain") == 1
    assert by_type.get("FileHash-SHA256") == 1
    assert by_type.get("FileHash-MD5") == 1
    # only pulse A has attack_ids
    assert body["with_attack_id"] == 1


# ---------------------------------------------------------------------------
# Test 6: Response schema has all required keys
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {
    "feed",
    "source_url",
    "authenticated",
    "total_pulses",
    "total_indicators",
    "by_indicator_type",
    "with_attack_id",
    "status",
}


def test_feed_status_schema_keys(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    client = _make_client(monkeypatch)

    body = client.get("/api/v1/otx/feed-status").json()
    assert _REQUIRED_KEYS.issubset(body.keys()), (
        f"Missing keys: {_REQUIRED_KEYS - body.keys()}"
    )
    assert body["feed"] == "alienvault-otx"
