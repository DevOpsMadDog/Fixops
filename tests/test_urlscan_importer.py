"""Tests for URLscan.io feed importer.

Covers:
1. Parse 5-result fixture JSON
2. Verdict extraction (malicious/suspicious/clean)
3. List endpoint pagination
4. Filter by domain
5. Filter by verdict=malicious
6. Idempotent re-import
"""

from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Ensure suite-feeds and suite-core are on the path
_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in [
    str(_REPO_ROOT / "suite-feeds"),
    str(_REPO_ROOT / "suite-core"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Fixture JSON — 5 results matching the URLscan API shape
# ---------------------------------------------------------------------------

FIXTURE_DATA: Dict[str, Any] = {
    "total": 5,
    "took": 12,
    "has_more": False,
    "results": [
        {
            "_id": "aaa-001",
            "indexedAt": "2026-04-27T10:00:00Z",
            "page": {"url": "http://phish1.example.com/login", "domain": "phish1.example.com", "country": "US"},
            "task": {"method": "manual", "tags": ["phishing", "credential-theft"], "source": "user"},
            "verdicts": {"overall": {"malicious": True, "score": 80}},
            "screenshot": "https://urlscan.io/screenshots/aaa-001.png",
        },
        {
            "_id": "bbb-002",
            "indexedAt": "2026-04-27T10:01:00Z",
            "page": {"url": "http://evil.ru/malware", "domain": "evil.ru", "country": "RU"},
            "task": {"method": "api", "tags": ["malware"], "source": "api"},
            "verdicts": {"overall": {"malicious": True, "score": 95}},
            "screenshot": "",
        },
        {
            "_id": "ccc-003",
            "indexedAt": "2026-04-27T10:02:00Z",
            "page": {"url": "https://safe.org/page", "domain": "safe.org", "country": "DE"},
            "task": {"method": "automatic", "tags": [], "source": "auto"},
            "verdicts": {"overall": {"malicious": False, "score": 0}},
            "screenshot": "https://urlscan.io/screenshots/ccc-003.png",
        },
        {
            "_id": "ddd-004",
            "indexedAt": "2026-04-27T10:03:00Z",
            "page": {"url": "http://suspect.cn/admin", "domain": "suspect.cn", "country": "CN"},
            "task": {"method": "manual", "tags": ["phishing"], "source": "user"},
            "verdicts": {"overall": {"malicious": True, "score": 55}},
            "screenshot": "",
        },
        {
            "_id": "eee-005",
            "indexedAt": "2026-04-27T10:04:00Z",
            "page": {"url": "https://clean.io/home", "domain": "clean.io", "country": "GB"},
            "task": {"method": "automatic", "tags": ["monitor"], "source": "auto"},
            "verdicts": {"overall": {"malicious": False, "score": 5}},
            "screenshot": "https://urlscan.io/screenshots/eee-005.png",
        },
    ],
}


# ---------------------------------------------------------------------------
# Helpers: isolated in-memory store
# ---------------------------------------------------------------------------

def _make_in_memory_importer():
    """Return importer module backed by an in-memory dict store (no disk I/O)."""
    import importlib
    import feeds.urlscan.importer as mod

    # Swap out the module-level store with a fresh dict
    mem: Dict[str, Any] = {}
    mod._store = mem  # type: ignore[attr-defined]
    return mod, mem


# ---------------------------------------------------------------------------
# Test 1: Parse 5-result fixture JSON
# ---------------------------------------------------------------------------

def test_parse_five_results():
    from feeds.urlscan.importer import parse_results

    rows = parse_results(FIXTURE_DATA)
    assert len(rows) == 5, f"Expected 5 rows, got {len(rows)}"

    # Spot-check first row
    first = rows[0]
    assert first["id"] == "aaa-001"
    assert first["domain"] == "phish1.example.com"
    assert first["country"] == "US"
    assert first["method"] == "manual"
    assert "phishing" in first["tags"]
    assert first["malicious"] is True
    assert first["score"] == 80
    assert first["screenshot_url"] == "https://urlscan.io/screenshots/aaa-001.png"


# ---------------------------------------------------------------------------
# Test 2: Verdict extraction (malicious / clean)
# ---------------------------------------------------------------------------

def test_verdict_extraction():
    from feeds.urlscan.importer import parse_results

    rows = parse_results(FIXTURE_DATA)
    malicious = [r for r in rows if r["malicious"]]
    clean = [r for r in rows if not r["malicious"]]

    assert len(malicious) == 3, f"Expected 3 malicious, got {len(malicious)}"
    assert len(clean) == 2, f"Expected 2 clean, got {len(clean)}"

    # Verify score extraction
    scores = {r["id"]: r["score"] for r in rows}
    assert scores["aaa-001"] == 80
    assert scores["bbb-002"] == 95
    assert scores["ccc-003"] == 0
    assert scores["eee-005"] == 5


# ---------------------------------------------------------------------------
# Test 3: List endpoint pagination
# ---------------------------------------------------------------------------

def test_list_pagination(tmp_path):
    import feeds.urlscan.importer as mod
    original_store = mod._store
    try:
        mem: Dict[str, Any] = {}
        mod._store = mem

        rows = mod.parse_results(FIXTURE_DATA)
        mod._upsert(rows)

        # All 5
        page_all = mod.list_results(limit=10, offset=0)
        assert len(page_all) == 5

        # Page 1: first 2
        page1 = mod.list_results(limit=2, offset=0)
        assert len(page1) == 2

        # Page 2: next 2
        page2 = mod.list_results(limit=2, offset=2)
        assert len(page2) == 2

        # Page 3: last 1
        page3 = mod.list_results(limit=2, offset=4)
        assert len(page3) == 1

        # Beyond end
        page4 = mod.list_results(limit=10, offset=10)
        assert len(page4) == 0
    finally:
        mod._store = original_store


# ---------------------------------------------------------------------------
# Test 4: Filter by domain
# ---------------------------------------------------------------------------

def test_filter_by_domain(tmp_path):
    import feeds.urlscan.importer as mod
    original_store = mod._store
    try:
        mem: Dict[str, Any] = {}
        mod._store = mem

        rows = mod.parse_results(FIXTURE_DATA)
        mod._upsert(rows)

        results = mod.list_results(domain="phish1.example.com")
        assert len(results) == 1
        assert results[0]["id"] == "aaa-001"

        # Non-existent domain
        results_empty = mod.list_results(domain="nonexistent.xyz")
        assert len(results_empty) == 0
    finally:
        mod._store = original_store


# ---------------------------------------------------------------------------
# Test 5: Filter by verdict=malicious
# ---------------------------------------------------------------------------

def test_filter_by_verdict_malicious(tmp_path):
    import feeds.urlscan.importer as mod
    original_store = mod._store
    try:
        mem: Dict[str, Any] = {}
        mod._store = mem

        rows = mod.parse_results(FIXTURE_DATA)
        mod._upsert(rows)

        malicious = mod.list_results(verdict="malicious")
        assert len(malicious) == 3
        assert all(r["malicious"] for r in malicious)

        clean = mod.list_results(verdict="clean")
        assert len(clean) == 2
        assert all(not r["malicious"] for r in clean)
    finally:
        mod._store = original_store


# ---------------------------------------------------------------------------
# Test 6: Idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_reimport(tmp_path):
    import feeds.urlscan.importer as mod
    original_store = mod._store
    try:
        mem: Dict[str, Any] = {}
        mod._store = mem

        rows = mod.parse_results(FIXTURE_DATA)

        # First upsert
        count1 = mod._upsert(rows)
        assert count1 == 5
        assert len(mem) == 5

        # Re-upsert same rows — store size must not grow
        count2 = mod._upsert(rows)
        assert count2 == 5
        assert len(mem) == 5, "Re-import must not create duplicate entries"

        # Verify data integrity after re-import
        assert mem["aaa-001"]["domain"] == "phish1.example.com"
        assert mem["bbb-002"]["score"] == 95
    finally:
        mod._store = original_store


# ---------------------------------------------------------------------------
# Test 7: Screenshot URL auto-generation when missing
# ---------------------------------------------------------------------------

def test_screenshot_url_autogenerated():
    from feeds.urlscan.importer import parse_results

    # bbb-002 has empty screenshot in fixture
    rows = parse_results(FIXTURE_DATA)
    bbb = next(r for r in rows if r["id"] == "bbb-002")
    assert bbb["screenshot_url"] == "https://urlscan.io/screenshots/bbb-002.png"


# ---------------------------------------------------------------------------
# Test 8: Summary by_verdict and by_domain_tld
# ---------------------------------------------------------------------------

def test_summary_structure(tmp_path):
    import feeds.urlscan.importer as mod
    original_store = mod._store
    try:
        mem: Dict[str, Any] = {}
        mod._store = mem

        rows = mod.parse_results(FIXTURE_DATA)
        mod._upsert(rows)

        summary = mod._build_summary(results_count=5)
        assert summary["results"] == 5
        assert summary["total_stored"] == 5
        assert "by_verdict" in summary
        assert "by_domain_tld" in summary
        assert summary["by_verdict"]["malicious"] == 3
        assert summary["by_verdict"]["clean"] == 2

        # TLD breakdown: com, ru, org, cn, io -> all count 1
        tlds = summary["by_domain_tld"]
        assert tlds.get("com", 0) >= 1
        assert tlds.get("ru", 0) >= 1
    finally:
        mod._store = original_store
