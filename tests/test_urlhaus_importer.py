"""URLhaus importer — unit tests.

Tests:
  1. Parse 50-URL fixture CSV
  2. Comment-line skipping
  3. Threat-type filter
  4. URL-membership check endpoint logic
  5. Idempotent re-import
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure suite-feeds and suite-core are importable
# ---------------------------------------------------------------------------

_REPO = Path(__file__).resolve().parents[1]
for _sub in ("suite-feeds", "suite-core"):
    _p = str(_REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Minimal URLhaus CSV with real-looking structure.
# First lines are comments (start with #); followed by a header row; then data.
FIXTURE_CSV_50 = """\
# URLhaus CSV export - https://urlhaus.abuse.ch
# Timestamp: 2026-04-27 00:00:00 UTC
# Fields: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
1001,2026-04-26 12:00:00,http://evil.example.com/mal1.exe,online,2026-04-26 12:00:00,malware_download,"trojan,exe",https://urlhaus.abuse.ch/url/1001/,researcher1
1002,2026-04-26 11:59:00,http://bad.example.org/drop.bin,offline,2026-04-26 10:00:00,malware_download,"banker",https://urlhaus.abuse.ch/url/1002/,researcher2
1003,2026-04-26 11:58:00,http://malware.test/payload.zip,online,2026-04-26 11:58:00,malware_download,"zip,dropper",https://urlhaus.abuse.ch/url/1003/,researcher3
1004,2026-04-26 11:57:00,http://c2.example.net/gate.php,online,2026-04-26 11:57:00,botnet_cc,"gate",https://urlhaus.abuse.ch/url/1004/,researcher4
1005,2026-04-26 11:56:00,http://phish.example.io/login,offline,2026-04-26 09:00:00,phishing,"phish",https://urlhaus.abuse.ch/url/1005/,researcher5
""" + "\n".join(
    f"{1006 + i},2026-04-26 11:{55 - i:02d}:00,http://auto-{i}.example.com/x.exe,"
    f"{'online' if i % 2 == 0 else 'offline'},2026-04-26 11:00:00,malware_download,"
    f"\"auto\",https://urlhaus.abuse.ch/url/{1006 + i}/,auto_reporter"
    for i in range(45)
)


def _make_in_memory_store() -> Dict[str, Any]:
    """Simple dict that mimics PersistentDict's interface for testing."""
    return {}


# ---------------------------------------------------------------------------
# Test 1: Parse 50-URL fixture CSV
# ---------------------------------------------------------------------------

class TestParseCsvText:
    def test_parses_50_rows(self):
        from feeds.urlhaus.importer import parse_csv_text
        rows = parse_csv_text(FIXTURE_CSV_50)
        assert len(rows) == 50, f"Expected 50 rows, got {len(rows)}"

    def test_row_fields_present(self):
        from feeds.urlhaus.importer import parse_csv_text
        rows = parse_csv_text(FIXTURE_CSV_50)
        first = rows[0]
        for field in ("id", "dateadded", "url", "url_status", "last_online",
                      "threat", "tags", "urlhaus_link", "reporter", "imported_at"):
            assert field in first, f"Missing field: {field}"

    def test_tags_parsed_as_list(self):
        from feeds.urlhaus.importer import parse_csv_text
        rows = parse_csv_text(FIXTURE_CSV_50)
        # row 0 has tags "trojan,exe"
        assert rows[0]["tags"] == ["trojan", "exe"]

    def test_id_is_string(self):
        from feeds.urlhaus.importer import parse_csv_text
        rows = parse_csv_text(FIXTURE_CSV_50)
        assert isinstance(rows[0]["id"], str)
        assert rows[0]["id"] == "1001"


# ---------------------------------------------------------------------------
# Test 2: Comment-line skipping
# ---------------------------------------------------------------------------

class TestCommentSkipping:
    def test_comment_lines_not_parsed_as_data(self):
        from feeds.urlhaus.importer import parse_csv_text
        csv_with_comments = """\
# This is a comment
# Another comment
id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
9001,2026-04-27 00:00:00,http://evil.example.com/x.exe,online,2026-04-27 00:00:00,malware_download,"trojan",https://urlhaus.abuse.ch/url/9001/,tester
"""
        rows = parse_csv_text(csv_with_comments)
        assert len(rows) == 1
        assert rows[0]["id"] == "9001"

    def test_empty_body_returns_empty_list(self):
        from feeds.urlhaus.importer import parse_csv_text
        rows = parse_csv_text("# comment only\n# another\n")
        assert rows == []

    def test_no_comment_lines_still_parses(self):
        from feeds.urlhaus.importer import parse_csv_text
        plain = (
            "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
            "42,2026-01-01 00:00:00,http://x.example.com/y.exe,online,,malware_download,"
            "\"t\",https://urlhaus.abuse.ch/url/42/,bob\n"
        )
        rows = parse_csv_text(plain)
        assert len(rows) == 1
        assert rows[0]["id"] == "42"


# ---------------------------------------------------------------------------
# Test 3: Threat-type filter
# ---------------------------------------------------------------------------

class TestThreatFilter:
    def _load_store(self, rows: List[Dict[str, Any]], mock_store: Dict) -> None:
        for row in rows:
            mock_store[row["id"]] = row

    def test_filter_malware_download(self):
        from feeds.urlhaus.importer import parse_csv_text, list_urls
        rows = parse_csv_text(FIXTURE_CSV_50)
        mock_store = {r["id"]: r for r in rows}

        with patch("feeds.urlhaus.importer._get_store", return_value=mock_store):
            results = list_urls(threat="malware_download")

        assert all(r["threat"] == "malware_download" for r in results)
        assert len(results) > 0

    def test_filter_botnet_cc(self):
        from feeds.urlhaus.importer import parse_csv_text, list_urls
        rows = parse_csv_text(FIXTURE_CSV_50)
        mock_store = {r["id"]: r for r in rows}

        with patch("feeds.urlhaus.importer._get_store", return_value=mock_store):
            results = list_urls(threat="botnet_cc")

        assert all(r["threat"] == "botnet_cc" for r in results)
        assert len(results) == 1  # only row 1004

    def test_filter_status_online(self):
        from feeds.urlhaus.importer import parse_csv_text, list_urls
        rows = parse_csv_text(FIXTURE_CSV_50)
        mock_store = {r["id"]: r for r in rows}

        with patch("feeds.urlhaus.importer._get_store", return_value=mock_store):
            results = list_urls(url_status="online")

        assert all(r["url_status"] == "online" for r in results)

    def test_filter_nonexistent_threat_returns_empty(self):
        from feeds.urlhaus.importer import parse_csv_text, list_urls
        rows = parse_csv_text(FIXTURE_CSV_50)
        mock_store = {r["id"]: r for r in rows}

        with patch("feeds.urlhaus.importer._get_store", return_value=mock_store):
            results = list_urls(threat="nonexistent_threat_xyz")

        assert results == []


# ---------------------------------------------------------------------------
# Test 4: URL-membership check endpoint
# ---------------------------------------------------------------------------

class TestCheckUrl:
    def test_check_url_found(self):
        from feeds.urlhaus.importer import check_url
        mock_store = {
            "9001": {
                "id": "9001",
                "url": "http://evil.example.com/mal.exe",
                "threat": "malware_download",
                "url_status": "online",
                "tags": ["trojan"],
                "dateadded": "2026-04-27 00:00:00",
                "last_online": "2026-04-27 00:00:00",
                "urlhaus_link": "https://urlhaus.abuse.ch/url/9001/",
                "reporter": "tester",
                "imported_at": "2026-04-27T00:00:00+00:00",
            }
        }
        with patch("feeds.urlhaus.importer._get_store", return_value=mock_store):
            result = check_url("http://evil.example.com/mal.exe")
        assert result is not None
        assert result["id"] == "9001"

    def test_check_url_not_found(self):
        from feeds.urlhaus.importer import check_url
        mock_store: Dict = {}
        with patch("feeds.urlhaus.importer._get_store", return_value=mock_store):
            result = check_url("http://clean.example.com/safe.html")
        assert result is None

    def test_check_url_empty_string_returns_none(self):
        from feeds.urlhaus.importer import check_url
        with patch("feeds.urlhaus.importer._get_store", return_value={}):
            result = check_url("")
        assert result is None


# ---------------------------------------------------------------------------
# Test 5: Idempotent re-import
# ---------------------------------------------------------------------------

class TestIdempotentReimport:
    def test_reimport_does_not_duplicate(self):
        """Importing the same CSV twice should result in the same store size."""
        from feeds.urlhaus.importer import parse_csv_text

        csv_text = """\
id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
100,2026-04-27 00:00:00,http://dup.example.com/x.exe,online,,malware_download,"t",https://urlhaus.abuse.ch/url/100/,bot
101,2026-04-27 00:00:01,http://dup2.example.com/y.exe,offline,,malware_download,"t2",https://urlhaus.abuse.ch/url/101/,bot
"""
        in_memory: Dict[str, Any] = {}

        def _fake_store():
            return in_memory

        with patch("feeds.urlhaus.importer._get_store", side_effect=_fake_store), \
             patch("feeds.urlhaus.importer._fetch", return_value=csv_text):
            from feeds.urlhaus.importer import run_import
            result1 = run_import()
            result2 = run_import()

        assert result1["urls"] == 2
        assert result2["urls"] == 2  # no duplication
        assert len(in_memory) == 2

    def test_upsert_updates_existing_row(self):
        """Re-importing updated data for same id should overwrite the old record."""
        from feeds.urlhaus.importer import parse_csv_text

        first_csv = """\
id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
500,2026-04-27 00:00:00,http://change.example.com/x.exe,online,,malware_download,"t",https://urlhaus.abuse.ch/url/500/,bot
"""
        second_csv = """\
id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
500,2026-04-27 01:00:00,http://change.example.com/x.exe,offline,,malware_download,"t,updated",https://urlhaus.abuse.ch/url/500/,bot
"""
        in_memory: Dict[str, Any] = {}

        def _fake_store():
            return in_memory

        with patch("feeds.urlhaus.importer._get_store", side_effect=_fake_store), \
             patch("feeds.urlhaus.importer._fetch", return_value=first_csv):
            from feeds.urlhaus.importer import run_import
            run_import()

        assert in_memory["500"]["url_status"] == "online"

        with patch("feeds.urlhaus.importer._get_store", side_effect=_fake_store), \
             patch("feeds.urlhaus.importer._fetch", return_value=second_csv):
            run_import()

        assert in_memory["500"]["url_status"] == "offline"
        assert len(in_memory) == 1  # still only one entry
