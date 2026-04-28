"""Tests for the GreyNoise community feed importer.

Tests:
1. Single-IP lookup parses correctly (no network — monkeypatched httpx)
2. Cache hit on second lookup of same IP (no second HTTP call)
3. Bulk-import endpoint returns correct summary shape
4. 404 graceful handling for unknown IPs
5. Idempotent re-import — same IP list produces same store size
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Make suite-feeds importable
# ---------------------------------------------------------------------------

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    """dict subclass with a no-op persist() so it matches PersistentDict surface."""

    def persist(self, key=None):
        pass

    def get(self, key, default=None):  # type: ignore[override]
        return super().get(key, default)


@pytest.fixture(autouse=True)
def _reset_store(monkeypatch):
    """Patch the module-level _store to an in-memory dict for every test."""
    from feeds.greynoise import importer as imp
    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# Sample GreyNoise /v3/community/{ip} responses
_BENIGN_PAYLOAD: Dict[str, Any] = {
    "ip": "8.8.8.8",
    "noise": False,
    "riot": True,
    "classification": "benign",
    "name": "Google Public DNS",
    "link": "https://viz.greynoise.io/ip/8.8.8.8",
    "last_seen": "2026-04-26",
    "message": "This IP is commonly associated with benign activity.",
}

_MALICIOUS_PAYLOAD: Dict[str, Any] = {
    "ip": "198.51.100.1",
    "noise": True,
    "riot": False,
    "classification": "malicious",
    "name": "Mass scanner",
    "link": "https://viz.greynoise.io/ip/198.51.100.1",
    "last_seen": "2026-04-25",
    "message": "This IP is a known mass scanner.",
}

_UNKNOWN_PAYLOAD: Dict[str, Any] = {
    "ip": "203.0.113.99",
    "noise": False,
    "riot": False,
    "classification": "unknown",
    "name": None,
    "link": "https://viz.greynoise.io/ip/203.0.113.99",
    "last_seen": None,
    "message": "This IP is not in the GreyNoise dataset.",
}


def _make_http_response(payload: Dict[str, Any], status_code: int = 200):
    """Build a minimal httpx.Response-like mock."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import httpx
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    return resp


# ---------------------------------------------------------------------------
# Test 1: Single-IP lookup parses correctly
# ---------------------------------------------------------------------------

def test_single_ip_lookup_parses_correctly():
    """lookup_ip returns normalised record with correct fields."""
    from feeds.greynoise.importer import lookup_ip, parse_community_response

    # Verify parser in isolation first
    parsed = parse_community_response(_BENIGN_PAYLOAD, "8.8.8.8")
    assert parsed["ip"] == "8.8.8.8"
    assert parsed["classification"] == "benign"
    assert parsed["name"] == "Google Public DNS"
    assert parsed["last_seen"] == "2026-04-26"
    assert "link" in parsed
    assert "message" in parsed

    # Now exercise lookup_ip with a patched HTTP client
    mock_resp = _make_http_response(_BENIGN_PAYLOAD)

    with patch("httpx.Client") as mock_client_cls:
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.get.return_value = mock_resp
        mock_client_cls.return_value = ctx

        record = lookup_ip("8.8.8.8")

    assert record["ip"] == "8.8.8.8"
    assert record["classification"] == "benign"
    assert record["name"] == "Google Public DNS"
    assert record["cached_at"] is not None
    assert record["imported_at"] is not None


# ---------------------------------------------------------------------------
# Test 2: Cache hit on second lookup of same IP
# ---------------------------------------------------------------------------

def test_cache_hit_on_second_lookup(monkeypatch):
    """A second lookup within TTL must not make a second HTTP call."""
    from feeds.greynoise import importer as imp

    mock_resp = _make_http_response(_BENIGN_PAYLOAD)
    call_count = {"n": 0}

    def _fake_get(url, headers=None):
        call_count["n"] += 1
        return mock_resp

    with patch("httpx.Client") as mock_client_cls:
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.get.side_effect = _fake_get
        mock_client_cls.return_value = ctx

        # First call — goes to API
        r1 = imp.lookup_ip("8.8.8.8")
        # Second call — should hit cache (fresh cached_at timestamp)
        r2 = imp.lookup_ip("8.8.8.8")

    assert call_count["n"] == 1, "Expected exactly 1 HTTP call; cache should be hit on 2nd lookup"
    assert r1["classification"] == r2["classification"] == "benign"


# ---------------------------------------------------------------------------
# Test 3: Bulk-import returns correct summary shape
# ---------------------------------------------------------------------------

def test_bulk_import_summary_shape(monkeypatch):
    """bulk_import returns lookups / by_classification / cache_hits keys."""
    from feeds.greynoise import importer as imp

    ip_payloads = {
        "8.8.8.8":      _BENIGN_PAYLOAD,
        "198.51.100.1": _MALICIOUS_PAYLOAD,
        "203.0.113.99": _UNKNOWN_PAYLOAD,
    }

    def _fake_lookup(ip, *, force_refresh=False, timeout=15.0, db_path=None):
        rec = imp.parse_community_response(ip_payloads[ip], ip)
        rec["cached_at"] = imp._now_iso()
        rec["imported_at"] = imp._now_iso()
        imp._get_store(db_path)[ip] = rec
        return rec

    monkeypatch.setattr(imp, "lookup_ip", _fake_lookup)
    monkeypatch.setattr("time.sleep", lambda _: None)

    result = imp.bulk_import(
        ["8.8.8.8", "198.51.100.1", "203.0.113.99"],
        rate_limit_delay=0,
    )

    assert result["lookups"] == 3
    assert result["cache_hits"] == 0
    assert result["by_classification"]["benign"] == 1
    assert result["by_classification"]["malicious"] == 1
    assert result["by_classification"]["unknown"] == 1


# ---------------------------------------------------------------------------
# Test 4: 404 graceful for unknown IPs
# ---------------------------------------------------------------------------

def test_404_graceful_for_unknown_ip():
    """A 404 from the API is stored as classification=unknown, not raised."""
    from feeds.greynoise.importer import lookup_ip

    not_found_resp = MagicMock()
    not_found_resp.status_code = 404
    not_found_resp.raise_for_status = MagicMock()

    with patch("httpx.Client") as mock_client_cls:
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.get.return_value = not_found_resp
        mock_client_cls.return_value = ctx

        record = lookup_ip("192.0.2.1")

    assert record["ip"] == "192.0.2.1"
    assert record["classification"] == "unknown"
    assert "not in the GreyNoise dataset" in (record.get("message") or "")


# ---------------------------------------------------------------------------
# Test 5: Idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_reimport(monkeypatch):
    """Importing the same IP list twice leaves store size unchanged."""
    from feeds.greynoise import importer as imp

    ip_payloads = {
        "8.8.8.8":      _BENIGN_PAYLOAD,
        "198.51.100.1": _MALICIOUS_PAYLOAD,
    }

    def _fake_lookup(ip, *, force_refresh=False, timeout=15.0, db_path=None):
        rec = imp.parse_community_response(ip_payloads[ip], ip)
        rec["cached_at"] = imp._now_iso()
        rec["imported_at"] = imp._now_iso()
        # Replicate what the real lookup_ip does — persist to store
        imp._get_store(db_path)[ip] = rec
        return rec

    monkeypatch.setattr(imp, "lookup_ip", _fake_lookup)
    monkeypatch.setattr("time.sleep", lambda _: None)

    ip_list = ["8.8.8.8", "198.51.100.1"]

    imp.bulk_import(ip_list, rate_limit_delay=0)
    first_count = imp.total_count()

    # Re-import — cache is fresh so all should be cache hits; store stays same size
    imp.bulk_import(ip_list, rate_limit_delay=0)
    second_count = imp.total_count()

    assert first_count == second_count == 2
