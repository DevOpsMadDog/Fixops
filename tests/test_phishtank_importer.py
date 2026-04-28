"""Tests for the PhishTank phishing-URL importer.

Test plan:
1. Parse 50-phish fixture JSON
2. Target-brand filter (PayPal)
3. URL-membership check
4. Online-only filter
5. Idempotent re-import (no duplicates)
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure suite-feeds is importable
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SUITE_FEEDS = str(_PROJECT_ROOT / "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)

from feeds.phishtank.importer import PhishTankImporter, _DEFAULT_DB


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_fixture(count: int = 50) -> list:
    """Generate a synthetic PhishTank-shaped JSON list."""
    brands = ["PayPal", "Chase", "Apple", "Microsoft", "Netflix"]
    entries = []
    for i in range(1, count + 1):
        brand = brands[i % len(brands)]
        online_val = "yes" if i % 3 != 0 else "no"
        verified_val = "yes" if i % 4 != 0 else "no"
        entries.append({
            "phish_id": str(1000 + i),
            "url": f"http://phish-{i}.example.com/login",
            "phish_detail_url": f"https://phishtank.org/phish_detail.php?phish_id={1000+i}",
            "submission_time": "2026-04-01T00:00:00+00:00",
            "verified": verified_val,
            "verification_time": "2026-04-01T01:00:00+00:00",
            "online": online_val,
            "target": brand,
        })
    return entries


@pytest.fixture()
def tmp_db(tmp_path):
    return str(tmp_path / "phishtank_test.db")


@pytest.fixture()
def imp_with_fixture(tmp_db, tmp_path):
    """PhishTankImporter pre-loaded with 50 synthetic phishes via a local file URL."""
    fixture_data = _make_fixture(50)

    # Write fixture to a temp JSON file and build a file:// URL
    fixture_file = tmp_path / "fixture.json"
    fixture_file.write_text(json.dumps(fixture_data))

    # Use a subclass that overrides _fetch to return the fixture directly
    class FixtureImporter(PhishTankImporter):
        def _fetch(self):
            return fixture_data

    return FixtureImporter(db_path=tmp_db)


# ---------------------------------------------------------------------------
# Test 1: Parse 50-phish fixture JSON
# ---------------------------------------------------------------------------

def test_parse_fixture_50(imp_with_fixture):
    result = imp_with_fixture.run()
    assert result["phishes"] == 50, f"Expected 50 phishes, got {result['phishes']}"
    assert result["by_target"], "by_target should not be empty"
    # All 5 brands should appear
    assert "PayPal" in result["by_target"]
    assert "Chase" in result["by_target"]


# ---------------------------------------------------------------------------
# Test 2: Target-brand filter (PayPal)
# ---------------------------------------------------------------------------

def test_target_brand_filter(imp_with_fixture):
    imp_with_fixture.run()
    result = imp_with_fixture.list_phishes(target="PayPal")
    # Every returned entry must belong to PayPal
    for entry in result["entries"]:
        assert entry["target"].lower() == "paypal", (
            f"Expected PayPal, got {entry['target']}"
        )
    assert result["total"] > 0, "Expected at least one PayPal phish"


# ---------------------------------------------------------------------------
# Test 3: URL-membership check
# ---------------------------------------------------------------------------

def test_url_membership_check(imp_with_fixture):
    imp_with_fixture.run()

    # Known URL (phish #1)
    found = imp_with_fixture.check_url("http://phish-1.example.com/login")
    assert found["found"] is True
    assert found["phish_id"] == "1001"

    # Unknown URL
    not_found = imp_with_fixture.check_url("http://legit.example.com/")
    assert not_found["found"] is False


# ---------------------------------------------------------------------------
# Test 4: Online-only filter
# ---------------------------------------------------------------------------

def test_online_only_filter(imp_with_fixture):
    imp_with_fixture.run()
    online_result = imp_with_fixture.list_phishes(online_only=True, page_size=100)
    for entry in online_result["entries"]:
        assert entry["online"] == "yes", (
            f"Expected online=yes, got online={entry['online']}"
        )
    # With 50 entries and online=no every 3rd, we expect ~33-34 online entries
    assert online_result["total"] > 0


# ---------------------------------------------------------------------------
# Test 5: Idempotent re-import (no duplicates)
# ---------------------------------------------------------------------------

def test_idempotent_reimport(imp_with_fixture):
    result1 = imp_with_fixture.run()
    assert result1["phishes"] == 50

    # Second import — same fixture, same data
    result2 = imp_with_fixture.run()
    assert result2["phishes"] == 50, (
        f"Expected 50 after re-import, got {result2['phishes']}"
    )
    assert imp_with_fixture.total_count() == 50


# ---------------------------------------------------------------------------
# Test 6: _parse handles malformed / missing fields gracefully
# ---------------------------------------------------------------------------

def test_parse_skips_missing_id_or_url(tmp_db):
    imp = PhishTankImporter(db_path=tmp_db)
    raw = [
        {},                                      # no phish_id, no url
        {"phish_id": "9999"},                    # no url
        {"url": "http://x.com"},                 # no phish_id
        {"phish_id": "1", "url": "http://a.com", "target": "Apple"},  # valid
    ]
    parsed = imp._parse(raw)
    assert len(parsed) == 1
    assert parsed[0]["phish_id"] == "1"
