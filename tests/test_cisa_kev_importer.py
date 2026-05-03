"""Tests for CISA KEV importer and wired endpoint.

Tests:
1. Importer parses sample fixture JSON correctly
2. Upsert dedupes by cveID (idempotent mode)
3. List endpoint returns paginated entries
4. 501 stub is gone — import-kev endpoint now returns real data
5. Filter by knownRansomwareCampaignUse works
6. GET /api/v1/feeds/kev/status — empty DB returns status=empty
7. GET /api/v1/feeds/kev/status — populated DB returns status=active + correct counts
8. GET /api/v1/feeds/kev/status — ransomware_pct is 0 when all entries are Unknown
9. GET /api/v1/feeds/kev/status — all required response fields present
10. GET /api/v1/feeds/kev/status — source_url is the canonical CISA URL
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — suite-feeds must be importable
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent
suite_feeds_path = str(REPO_ROOT / "suite-feeds")
suite_core_path = str(REPO_ROOT / "suite-core")
suite_api_path = str(REPO_ROOT / "suite-api")
for p in [suite_feeds_path, suite_core_path, suite_api_path]:
    if p not in sys.path:
        sys.path.insert(0, p)

from feeds.cisa_kev.importer import CisaKevImporter  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_PAYLOAD: Dict[str, Any] = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2026.04.27",
    "dateReleased": "2026-04-27T00:00:00Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 JNDI features allow RCE.",
            "requiredAction": "Apply vendor updates.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://logging.apache.org/log4j/2.x/security.html",
        },
        {
            "cveID": "CVE-2022-30190",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "Microsoft Windows Support Diagnostic Tool (MSDT) RCE",
            "dateAdded": "2022-06-14",
            "shortDescription": "MSDT RCE via Office documents.",
            "requiredAction": "Apply Microsoft patch.",
            "dueDate": "2022-06-24",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
        {
            "cveID": "CVE-2023-23397",
            "vendorProject": "Microsoft",
            "product": "Outlook",
            "vulnerabilityName": "Microsoft Outlook Elevation of Privilege Vulnerability",
            "dateAdded": "2023-03-14",
            "shortDescription": "Microsoft Outlook privilege escalation via specially crafted email.",
            "requiredAction": "Apply Microsoft updates.",
            "dueDate": "2023-04-04",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
        },
    ],
}


@pytest.fixture
def tmp_db(tmp_path):
    """Return a path to a fresh temporary SQLite DB."""
    return str(tmp_path / "test_cisa_kev.db")


@pytest.fixture
def importer_with_fixture(tmp_db):
    """Importer that returns SAMPLE_PAYLOAD without a real HTTP call."""
    imp = CisaKevImporter(db_path=tmp_db)
    with patch.object(imp, "_fetch", return_value=SAMPLE_PAYLOAD):
        yield imp


# ---------------------------------------------------------------------------
# Test 1: parse sample fixture JSON correctly
# ---------------------------------------------------------------------------

def test_parse_sample_fixture():
    entries = CisaKevImporter._parse(SAMPLE_PAYLOAD)
    assert len(entries) == 3

    log4j = next(e for e in entries if e["cve_id"] == "CVE-2021-44228")
    assert log4j["vendor_project"] == "Apache"
    assert log4j["product"] == "Log4j2"
    assert log4j["known_ransomware_use"] == "Known"
    assert log4j["date_added"] == "2021-12-10"

    msdt = next(e for e in entries if e["cve_id"] == "CVE-2022-30190")
    assert msdt["known_ransomware_use"] == "Unknown"

    # All required fields present
    for e in entries:
        for field in ("cve_id", "vendor_project", "product", "vulnerability_name",
                      "date_added", "short_description", "required_action",
                      "due_date", "known_ransomware_use", "notes"):
            assert field in e, f"Missing field {field!r} in entry {e['cve_id']}"


# ---------------------------------------------------------------------------
# Test 2: upsert dedupes by cveID (idempotent mode)
# ---------------------------------------------------------------------------

def test_upsert_dedupes_idempotent(importer_with_fixture):
    # First run — imports 3 new entries
    result1 = importer_with_fixture.run(idempotent=True)
    assert result1["imported"] == 3
    assert result1["skipped"] == 0
    assert result1["source_count"] == 3

    # Second run with idempotent=True — all 3 skipped
    result2 = importer_with_fixture.run(idempotent=True)
    assert result2["imported"] == 0
    assert result2["skipped"] == 3

    # Total count remains 3 (no duplicates)
    assert importer_with_fixture.total_count() == 3


# ---------------------------------------------------------------------------
# Test 3: list endpoint returns paginated entries
# ---------------------------------------------------------------------------

def test_list_paginated(importer_with_fixture):
    importer_with_fixture.run(idempotent=True)

    # Page 1, size 2
    page1 = importer_with_fixture.list_entries(page=1, page_size=2)
    assert page1["total"] == 3
    assert len(page1["entries"]) == 2
    assert page1["page"] == 1
    assert page1["page_size"] == 2

    # Page 2, size 2 → 1 remaining
    page2 = importer_with_fixture.list_entries(page=2, page_size=2)
    assert len(page2["entries"]) == 1

    # All entries have expected keys
    for entry in page1["entries"] + page2["entries"]:
        assert "cve_id" in entry
        assert "vendor_project" in entry
        assert "known_ransomware_use" in entry
        assert "imported_at" in entry


# ---------------------------------------------------------------------------
# Test 4: 501 stub is gone — import-kev endpoint returns real result
# ---------------------------------------------------------------------------

def test_import_kev_endpoint_no_longer_501(tmp_db):
    """The POST /api/v1/vuln-correlation/import-kev endpoint must not raise 501."""
    from fastapi.testclient import TestClient

    # Patch the importer inside the router before importing the app
    with patch(
        "apps.api.vulnerability_correlation_router._get_kev_importer",
        return_value=_make_mock_importer(tmp_db),
    ):
        from apps.api.vulnerability_correlation_router import router
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        # Must NOT return 501
        resp = client.post("/api/v1/vuln-correlation/import-kev")
        assert resp.status_code != 501, f"Endpoint still returning 501: {resp.json()}"
        assert resp.status_code == 200
        body = resp.json()
        assert "imported" in body
        assert "source_count" in body


def _make_mock_importer(tmp_db: str):
    """Return an importer whose _fetch returns sample data."""
    imp = CisaKevImporter(db_path=tmp_db)

    def _fake_fetch():
        return SAMPLE_PAYLOAD

    imp._fetch = _fake_fetch  # type: ignore[method-assign]
    return imp


# ---------------------------------------------------------------------------
# Test 5: filter by knownRansomwareCampaignUse=true
# ---------------------------------------------------------------------------

def test_filter_ransomware_only(importer_with_fixture):
    importer_with_fixture.run(idempotent=True)

    result = importer_with_fixture.list_entries(ransomware_only=True)
    # CVE-2021-44228 and CVE-2023-23397 have "Known"; CVE-2022-30190 has "Unknown"
    assert result["total"] == 2
    cve_ids = {e["cve_id"] for e in result["entries"]}
    assert "CVE-2021-44228" in cve_ids
    assert "CVE-2023-23397" in cve_ids
    assert "CVE-2022-30190" not in cve_ids


# ---------------------------------------------------------------------------
# Helpers for kev/status endpoint tests
# ---------------------------------------------------------------------------

def _make_kev_status_client(tmp_db: str, preload: bool = False):
    """Return a TestClient wired to GET /api/v1/feeds/kev/status.

    When preload=True, seeds 3 entries (2 ransomware-marked, 1 Unknown)
    directly into the DB so the endpoint sees real rows.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from unittest.mock import MagicMock, patch
    import sqlite3

    # Ensure kev_entries table exists with the right schema
    Path(tmp_db).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(tmp_db)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kev_entries (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            short_description TEXT,
            required_action TEXT,
            due_date TEXT,
            known_ransomware_campaign_use TEXT,
            updated_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feed_metadata (
            feed_name TEXT PRIMARY KEY,
            last_refresh TEXT,
            records_count INTEGER,
            status TEXT
        )
    """)
    conn.commit()

    if preload:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            ("CVE-2021-44228", "Apache", "Log4j2", "RCE", "2021-12-10", "desc", "patch", "2021-12-24", "Known", now),
            ("CVE-2022-30190", "Microsoft", "Windows", "MSDT RCE", "2022-06-14", "desc", "patch", "2022-06-24", "Unknown", now),
            ("CVE-2023-23397", "Microsoft", "Outlook", "EoP", "2023-03-14", "desc", "patch", "2023-04-04", "Known", now),
        ]
        conn.executemany(
            "INSERT OR REPLACE INTO kev_entries VALUES (?,?,?,?,?,?,?,?,?,?)", rows
        )
        conn.execute(
            "INSERT OR REPLACE INTO feed_metadata VALUES (?,?,?,?)",
            ("kev", now, 3, "success"),
        )
        conn.commit()

    conn.close()

    # Build a FeedsService-compatible mock that reads the real tmp_db
    mock_service = MagicMock()
    mock_service.db_path = tmp_db

    def _fake_get_feed_stats():
        c = sqlite3.connect(tmp_db)
        total = c.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0]
        row = c.execute(
            "SELECT last_refresh FROM feed_metadata WHERE feed_name='kev'"
        ).fetchone()
        last_refresh = row[0] if row else None
        c.close()
        return {"kev": {"total_cves": total, "last_refresh": last_refresh}}

    mock_service.get_feed_stats.side_effect = _fake_get_feed_stats

    # Import the feeds router from suite-feeds directly (suite-feeds is first in sys.path
    # because this test file prepends it above).  We use importlib so we can target the
    # exact file regardless of any shadowing in suite-core/api/.
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location(
        "feeds_router_suite_feeds",
        str(Path(suite_feeds_path) / "api" / "feeds_router.py"),
    )
    fr_mod = _ilu.module_from_spec(_spec)
    # Pre-populate sys.modules dependencies the router needs
    import sys as _sys
    _sys.modules.setdefault("feeds_router_suite_feeds", fr_mod)
    _spec.loader.exec_module(fr_mod)

    app = FastAPI()
    # Directly replace get_feeds_service on the freshly-loaded module object
    fr_mod.get_feeds_service = lambda: mock_service  # type: ignore[attr-defined]

    app.include_router(fr_mod.router)
    client = TestClient(app)
    return client


# ---------------------------------------------------------------------------
# Test 6: empty DB → status = "empty"
# ---------------------------------------------------------------------------

def test_kev_status_empty_db(tmp_path):
    tmp_db = str(tmp_path / "kev_empty.db")
    client = _make_kev_status_client(tmp_db, preload=False)
    resp = client.get("/api/v1/feeds/kev/status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "empty"
    assert body["total_entries"] == 0
    assert body["last_poll"] is None


# ---------------------------------------------------------------------------
# Test 7: populated DB → status = "active", correct entry count
# ---------------------------------------------------------------------------

def test_kev_status_active(tmp_path):
    tmp_db = str(tmp_path / "kev_active.db")
    client = _make_kev_status_client(tmp_db, preload=True)
    resp = client.get("/api/v1/feeds/kev/status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "active"
    assert body["total_entries"] == 3
    assert body["last_poll"] is not None


# ---------------------------------------------------------------------------
# Test 8: ransomware counts — 2 "Known", 1 "Unknown" → pct = 66.67
# ---------------------------------------------------------------------------

def test_kev_status_ransomware_counts(tmp_path):
    tmp_db = str(tmp_path / "kev_ransomware.db")
    client = _make_kev_status_client(tmp_db, preload=True)
    resp = client.get("/api/v1/feeds/kev/status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ransomware_entries"] == 2
    assert body["ransomware_pct"] == pytest.approx(66.67, abs=0.01)


# ---------------------------------------------------------------------------
# Test 9: all required fields present in response
# ---------------------------------------------------------------------------

def test_kev_status_required_fields(tmp_path):
    tmp_db = str(tmp_path / "kev_fields.db")
    client = _make_kev_status_client(tmp_db, preload=False)
    resp = client.get("/api/v1/feeds/kev/status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    required = {"feed", "status", "total_entries", "last_poll",
                "ransomware_entries", "ransomware_pct", "source_url"}
    missing = required - set(body.keys())
    assert not missing, f"Missing fields: {missing}"


# ---------------------------------------------------------------------------
# Test 10: source_url is the canonical CISA feed URL
# ---------------------------------------------------------------------------

def test_kev_status_source_url(tmp_path):
    tmp_db = str(tmp_path / "kev_url.db")
    client = _make_kev_status_client(tmp_db, preload=False)
    resp = client.get("/api/v1/feeds/kev/status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source_url"] == (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    assert body["feed"] == "cisa_kev"
