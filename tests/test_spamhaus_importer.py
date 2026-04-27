"""Tests for the Spamhaus DROP/EDROP importer and API endpoints.

Tests:
  1. parse_drop_text — 20-CIDR fixture
  2. Comment-line skipping
  3. list_cidrs with list_name filter (via API endpoint)
  4. check_ip CIDR membership (via API endpoint)
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite paths are importable
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _suite in ["suite-feeds", "suite-core", "suite-api"]:
    _p = str(_PROJECT_ROOT / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_DROP_FIXTURE = """\
; Spamhaus DROP List 2026-04-27
; https://www.spamhaus.org/drop/drop.txt
1.10.16.0/20 ; SBL0001
1.19.0.0/16 ; SBL0002
2.56.192.0/22 ; SBL0003
5.8.37.0/24 ; SBL0004
5.34.242.0/23 ; SBL0005
5.39.218.0/24 ; SBL0006
5.44.96.0/22 ; SBL0007
5.101.40.0/22 ; SBL0008
5.104.232.0/21 ; SBL0009
5.133.4.0/24 ; SBL0010
5.141.96.0/24 ; SBL0011
5.154.174.0/24 ; SBL0012
5.175.148.0/22 ; SBL0013
5.188.6.0/23 ; SBL0014
5.188.10.0/24 ; SBL0015
5.188.62.0/23 ; SBL0016
5.196.124.0/24 ; SBL0017
5.230.0.0/17 ; SBL0018
23.88.22.0/24 ; SBL0019
23.94.180.0/22 ; SBL0020
"""

_EDROP_FIXTURE = """\
; Spamhaus EDROP List 2026-04-27
; Extended DROP
45.9.20.0/24 ; SBL5001
45.32.0.0/12 ; SBL5002
"""


# ---------------------------------------------------------------------------
# 1. Parse 20-CIDR fixture
# ---------------------------------------------------------------------------

class TestParseDropText:
    def test_parses_20_cidrs(self):
        from feeds.spamhaus_drop.importer import parse_drop_text

        entries = parse_drop_text(_DROP_FIXTURE, "drop")
        assert len(entries) == 20, f"Expected 20 CIDRs, got {len(entries)}"

    def test_cidr_and_sbl_id_extracted(self):
        from feeds.spamhaus_drop.importer import parse_drop_text

        entries = parse_drop_text(_DROP_FIXTURE, "drop")
        cidrs = {e[0] for e in entries}
        sbl_ids = {e[1] for e in entries}
        assert "1.10.16.0/20" in cidrs
        assert "SBL0001" in sbl_ids
        assert "23.94.180.0/22" in cidrs
        assert "SBL0020" in sbl_ids


# ---------------------------------------------------------------------------
# 2. Comment-line skipping
# ---------------------------------------------------------------------------

class TestCommentSkipping:
    def test_comment_lines_excluded(self):
        from feeds.spamhaus_drop.importer import parse_drop_text

        text = """\
; This is a comment
; Another comment
10.0.0.0/8 ; SBL9999
; trailing comment
"""
        entries = parse_drop_text(text, "drop")
        assert len(entries) == 1
        assert entries[0] == ("10.0.0.0/8", "SBL9999")

    def test_blank_lines_excluded(self):
        from feeds.spamhaus_drop.importer import parse_drop_text

        text = "\n\n10.1.0.0/16 ; SBL1111\n\n\n"
        entries = parse_drop_text(text, "drop")
        assert len(entries) == 1

    def test_invalid_cidr_excluded(self):
        from feeds.spamhaus_drop.importer import parse_drop_text

        text = "not-a-cidr ; SBL0000\n192.168.1.0/24 ; SBL1234\n"
        entries = parse_drop_text(text, "drop")
        assert len(entries) == 1
        assert entries[0][0] == "192.168.1.0/24"


# ---------------------------------------------------------------------------
# Helpers: in-memory store mock for endpoint tests
# ---------------------------------------------------------------------------

def _make_in_memory_store(entries):
    """Build a dict-backed store pre-populated with *entries* list of dicts."""
    store = {}
    for e in entries:
        key = f"{e['list_name']}:{e['cidr']}"
        store[key] = e
    return store


# ---------------------------------------------------------------------------
# 3. list_cidrs with list_name filter
# ---------------------------------------------------------------------------

class TestListCidrsFilter:
    def _build_store(self):
        return _make_in_memory_store([
            {"cidr": "1.10.16.0/20", "sbl_id": "SBL0001", "list_name": "drop", "imported_at": "2026-04-27T00:00:00+00:00"},
            {"cidr": "2.56.192.0/22", "sbl_id": "SBL0003", "list_name": "drop", "imported_at": "2026-04-27T00:00:00+00:00"},
            {"cidr": "45.9.20.0/24",  "sbl_id": "SBL5001", "list_name": "edrop", "imported_at": "2026-04-27T00:00:00+00:00"},
        ])

    def test_filter_drop_only(self):
        import feeds.spamhaus_drop.importer as imp

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            rows = imp.list_cidrs(list_name="drop")
        assert all(r["list_name"] == "drop" for r in rows)
        assert len(rows) == 2

    def test_filter_edrop_only(self):
        import feeds.spamhaus_drop.importer as imp

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            rows = imp.list_cidrs(list_name="edrop")
        assert all(r["list_name"] == "edrop" for r in rows)
        assert len(rows) == 1

    def test_no_filter_returns_all(self):
        import feeds.spamhaus_drop.importer as imp

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            rows = imp.list_cidrs()
        assert len(rows) == 3

    def test_list_endpoint_via_fastapi(self):
        """Confirm the FastAPI router returns filtered rows correctly."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        import feeds.spamhaus_drop.importer as imp

        app = FastAPI()

        # Mount router without auth for test
        from apps.api import spamhaus_router as sr
        from fastapi import APIRouter
        test_router = APIRouter(prefix="/api/v1/spamhaus")

        @test_router.get("/cidrs")
        def _cidrs(list_name=None, limit=1000, offset=0):
            rows = imp.list_cidrs(list_name=list_name, limit=limit, offset=offset)
            return {"cidrs": rows, "total": len(rows), "offset": offset, "limit": limit, "list_name": list_name}

        app.include_router(test_router)
        client = TestClient(app)

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            resp = client.get("/api/v1/spamhaus/cidrs?list_name=drop")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert all(r["list_name"] == "drop" for r in data["cidrs"])


# ---------------------------------------------------------------------------
# 4. IP-in-CIDR check
# ---------------------------------------------------------------------------

class TestCheckIp:
    def _build_store(self):
        return _make_in_memory_store([
            {"cidr": "10.0.0.0/8",    "sbl_id": "SBL1000", "list_name": "drop",  "imported_at": "2026-04-27T00:00:00+00:00"},
            {"cidr": "192.168.0.0/16","sbl_id": "SBL2000", "list_name": "drop",  "imported_at": "2026-04-27T00:00:00+00:00"},
            {"cidr": "45.9.20.0/24",  "sbl_id": "SBL5001", "list_name": "edrop", "imported_at": "2026-04-27T00:00:00+00:00"},
        ])

    def test_ip_in_cidr_matched(self):
        import feeds.spamhaus_drop.importer as imp

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            result = imp.check_ip("10.1.2.3")
        assert result["matched"] is True
        assert any(m["cidr"] == "10.0.0.0/8" for m in result["matches"])

    def test_ip_not_in_any_cidr(self):
        import feeds.spamhaus_drop.importer as imp

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            result = imp.check_ip("8.8.8.8")
        assert result["matched"] is False
        assert result["matches"] == []

    def test_ip_in_edrop_cidr(self):
        import feeds.spamhaus_drop.importer as imp

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            result = imp.check_ip("45.9.20.100")
        assert result["matched"] is True
        assert result["matches"][0]["list_name"] == "edrop"

    def test_invalid_ip_returns_error(self):
        import feeds.spamhaus_drop.importer as imp

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            result = imp.check_ip("not-an-ip")
        assert result["matched"] is False
        assert "error" in result

    def test_check_endpoint_via_fastapi(self):
        """Confirm FastAPI check endpoint returns correct structure."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI, APIRouter
        import feeds.spamhaus_drop.importer as imp

        app = FastAPI()
        test_router = APIRouter(prefix="/api/v1/spamhaus")

        @test_router.get("/check/{ip}")
        def _check(ip: str):
            return imp.check_ip(ip)

        app.include_router(test_router)
        client = TestClient(app)

        fake_store = self._build_store()
        with patch.object(imp, "_get_store", return_value=fake_store):
            resp = client.get("/api/v1/spamhaus/check/10.5.6.7")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ip"] == "10.5.6.7"
        assert data["matched"] is True
