"""Tests for AbuseIPDB / EmergingThreats blocklist importer.

Tests:
1. Parse 100-IP fixture text (ET format)
2. List endpoint returns IPs after import
3. Filter by confidence_min=80
4. Single-IP lookup (check_ip)
5. Idempotent re-import (same IPs in -> same total, no duplicates)

Plus a guarded AbuseIPDB-payload parse test (only verifies parser shape, no network).
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Make suite-feeds importable
# ---------------------------------------------------------------------------

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_et_fixture(n: int = 100) -> str:
    """Build an ET compromised-ips.txt body with *n* unique IPv4 entries.

    Uses 192.0.2.0/22 (TEST-NET-1 / RFC 5737) so we never accidentally hit
    a real address. Includes a header comment + a blank line + an inline
    comment to exercise the parser's noise tolerance.
    """
    lines = [
        "# Emerging Threats — Compromised IPs (test fixture)",
        "# Format: one IP per line. Lines beginning with # are comments.",
        "",
    ]
    ips: List[str] = []
    count = 0
    for octet3 in range(0, 4):
        for octet4 in range(0, 256):
            if count >= n:
                break
            ip = f"192.0.{octet3}.{octet4}"
            ips.append(ip)
            count += 1
        if count >= n:
            break

    # Sprinkle in some inline comments and blank lines
    for idx, ip in enumerate(ips):
        if idx % 25 == 0 and idx != 0:
            lines.append("")
        if idx % 17 == 0 and idx != 0:
            lines.append(f"{ip}    # known scanner")
        else:
            lines.append(ip)

    # Some malformed lines that must be ignored
    lines.append("not-an-ip")
    lines.append("999.999.999.999")
    lines.append("# trailing comment")
    return "\n".join(lines) + "\n"


# AbuseIPDB-shaped sample payload (no network)
_ABUSEIPDB_SAMPLE_PAYLOAD: Dict[str, Any] = {
    "meta": {"generatedAt": "2026-04-28T12:00:00+00:00"},
    "data": [
        {
            "ipAddress": "203.0.113.1",
            "countryCode": "US",
            "abuseConfidenceScore": 100,
            "lastReportedAt": "2026-04-28T11:30:00+00:00",
            "categories": [18, 22],
        },
        {
            "ipAddress": "203.0.113.2",
            "countryCode": "DE",
            "abuseConfidenceScore": 85,
            "lastReportedAt": "2026-04-27T08:00:00+00:00",
            "categories": [14],
        },
        {
            "ipAddress": "203.0.113.3",
            "countryCode": "BR",
            "abuseConfidenceScore": 60,
            "lastReportedAt": "2026-04-25T19:00:00+00:00",
            "categories": [],
        },
    ],
}


# ---------------------------------------------------------------------------
# Patch the store with an in-memory dict so tests don't touch disk
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    """dict + persist() no-op (matches PersistentDict surface used by importer)."""

    def persist(self, key=None):  # noqa: D401
        pass


@pytest.fixture(autouse=True)
def _mock_store(monkeypatch):
    from feeds.abuseipdb import importer as imp
    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# ---------------------------------------------------------------------------
# Test 1: Parse 100-IP fixture
# ---------------------------------------------------------------------------

def test_parse_hundred_ip_fixture():
    from feeds.abuseipdb.importer import parse_emergingthreats_text

    text = _build_et_fixture(n=100)
    ips = parse_emergingthreats_text(text)

    assert len(ips) == 100, f"Expected 100 IPs parsed, got {len(ips)}"
    # Spot-check a known good entry and that malformed entries were dropped
    assert "192.0.0.0" in ips
    assert "999.999.999.999" not in ips
    assert "not-an-ip" not in ips


# ---------------------------------------------------------------------------
# Test 2: List endpoint returns IPs after import
# ---------------------------------------------------------------------------

def test_list_after_import():
    from feeds.abuseipdb.importer import import_emergingthreats_text, list_ips

    text = _build_et_fixture(n=100)
    upserted = import_emergingthreats_text(text)
    assert upserted == 100

    rows = list_ips(limit=500)
    assert len(rows) == 100
    # Every row carries the expected envelope
    sample = rows[0]
    assert sample["source"] == "et"
    assert sample["confidence_score"] == 100
    assert sample["categories"] == []
    assert sample["ip"].startswith("192.0.")


# ---------------------------------------------------------------------------
# Test 3: Filter by confidence_min=80
# ---------------------------------------------------------------------------

def test_filter_by_confidence_min():
    from feeds.abuseipdb.importer import (
        import_emergingthreats_text,
        import_abuseipdb_payload,
        list_ips,
    )

    # ET feed: confidence 100 (default)
    et_text = _build_et_fixture(n=20)
    import_emergingthreats_text(et_text)

    # AbuseIPDB feed: mixed confidences (100 / 85 / 60)
    import_abuseipdb_payload(_ABUSEIPDB_SAMPLE_PAYLOAD)

    # confidence_min=80 should include all 20 ET (=100) + 2 AbuseIPDB (100, 85)
    high = list_ips(confidence_min=80, limit=500)
    assert len(high) == 22

    # confidence_min=90 — drop the AbuseIPDB 85 entry
    very_high = list_ips(confidence_min=90, limit=500)
    assert len(very_high) == 21

    # confidence_min=70 — drop the AbuseIPDB 60 entry
    over_70 = list_ips(confidence_min=70, limit=500)
    assert len(over_70) == 22

    # All entries (no filter) include the 60-confidence one
    all_rows = list_ips(limit=500)
    assert len(all_rows) == 23


# ---------------------------------------------------------------------------
# Test 4: Single-IP lookup
# ---------------------------------------------------------------------------

def test_single_ip_lookup():
    from feeds.abuseipdb.importer import (
        import_emergingthreats_text,
        import_abuseipdb_payload,
        check_ip,
    )

    et_text = _build_et_fixture(n=10)
    import_emergingthreats_text(et_text)
    import_abuseipdb_payload(_ABUSEIPDB_SAMPLE_PAYLOAD)

    # Hit on an ET entry
    et_hit = check_ip("192.0.0.0")
    assert et_hit is not None
    assert et_hit["source"] == "et"
    assert et_hit["confidence_score"] == 100

    # Hit on an AbuseIPDB entry (richer metadata)
    aip_hit = check_ip("203.0.113.1")
    assert aip_hit is not None
    assert aip_hit["source"] == "abuseipdb"
    assert aip_hit["confidence_score"] == 100
    assert 18 in aip_hit["categories"]

    # Miss
    miss = check_ip("198.51.100.99")
    assert miss is None


# ---------------------------------------------------------------------------
# Test 5: Idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_reimport():
    from feeds.abuseipdb.importer import (
        import_emergingthreats_text,
        import_abuseipdb_payload,
        list_ips,
        total_count,
    )

    et_text = _build_et_fixture(n=50)

    import_emergingthreats_text(et_text)
    import_abuseipdb_payload(_ABUSEIPDB_SAMPLE_PAYLOAD)
    first_total = total_count()

    # Re-run both — same source data must produce same store size
    import_emergingthreats_text(et_text)
    import_abuseipdb_payload(_ABUSEIPDB_SAMPLE_PAYLOAD)
    second_total = total_count()

    assert first_total == second_total == 53  # 50 ET + 3 AbuseIPDB
    rows = list_ips(limit=500)
    assert len(rows) == 53


# ---------------------------------------------------------------------------
# Test 6: AbuseIPDB-over-ET precedence (richer metadata wins)
# ---------------------------------------------------------------------------

def test_abuseipdb_overrides_et_for_same_ip():
    from feeds.abuseipdb.importer import (
        import_emergingthreats_text,
        import_abuseipdb_payload,
        check_ip,
    )

    # Forge an ET entry that collides with one of the AbuseIPDB sample IPs
    overlap_text = "203.0.113.1\n"
    import_emergingthreats_text(overlap_text)

    # Pre-condition: ET wrote the row
    pre = check_ip("203.0.113.1")
    assert pre is not None and pre["source"] == "et"

    # AbuseIPDB import should overwrite with richer record
    import_abuseipdb_payload(_ABUSEIPDB_SAMPLE_PAYLOAD)
    post = check_ip("203.0.113.1")
    assert post is not None
    assert post["source"] == "abuseipdb"
    assert 18 in post["categories"]


# ---------------------------------------------------------------------------
# Test 7: AbuseIPDB payload parser (no network)
# ---------------------------------------------------------------------------

def test_parse_abuseipdb_payload():
    from feeds.abuseipdb.importer import parse_abuseipdb_payload

    rows = parse_abuseipdb_payload(_ABUSEIPDB_SAMPLE_PAYLOAD)
    assert len(rows) == 3
    assert rows[0]["ip"] == "203.0.113.1"
    assert rows[0]["confidence_score"] == 100
    assert rows[0]["categories"] == [18, 22]
    assert rows[1]["confidence_score"] == 85
    # Bad payload tolerated
    assert parse_abuseipdb_payload({}) == []
    assert parse_abuseipdb_payload({"data": [{"junk": "x"}]}) == []


# ---------------------------------------------------------------------------
# Test 8: last_seen_since filter
# ---------------------------------------------------------------------------

def test_last_seen_since_filter():
    from feeds.abuseipdb.importer import import_abuseipdb_payload, list_ips

    import_abuseipdb_payload(_ABUSEIPDB_SAMPLE_PAYLOAD)

    # All three sample rows are >= 2026-04-25
    rows = list_ips(last_seen_since="2026-04-25T00:00:00+00:00", limit=500)
    assert len(rows) == 3

    # Only the latest two are >= 2026-04-26
    rows = list_ips(last_seen_since="2026-04-26T00:00:00+00:00", limit=500)
    assert len(rows) == 2

    # None are after 2026-05-01
    rows = list_ips(last_seen_since="2026-05-01T00:00:00+00:00", limit=500)
    assert len(rows) == 0
