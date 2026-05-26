"""Tests for IOCEnrichmentEngine — covering all public methods.

enrich_ioc() is now REAL: it queries the abuse.ch Feodo Tracker C2 IP
blocklist (https://feodotracker.abuse.ch/downloads/ipblocklist.json).

Test strategy:
  - Integration tests (skipif feed unreachable): fetch the live blocklist,
    pick a known-malicious IP from it, assert verdict=malicious + source
    contains "abuse.ch". Also test a known-clean IP (8.8.8.8).
  - Error-path: monkeypatch _fetch_feodo_blocklist to raise -> IocEnrichmentError.
  - Non-IP types: assert verdict=unknown, no fabrication.
  - All existing CRUD/read tests preserved unchanged.
  - _seed_enrichment() helper retained for read-path tests that bypass enrich_ioc().
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from core.ioc_enrichment_engine import (
    IocEnrichmentError,
    IOCEnrichmentEngine,
    _fetch_feodo_blocklist,
)


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ioc_test.db")
    return IOCEnrichmentEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# Helper: seed an enrichment row directly into SQLite (bypasses enrich_ioc)
# Used by read-path tests that don't need to hit the live feed.
# ---------------------------------------------------------------------------

def _seed_enrichment(engine: IOCEnrichmentEngine, org_id: str, ioc_id: str, **kwargs) -> dict:
    """Insert a real enrichment row into ioc_enrichments.

    Returns the row dict (with lists decoded from JSON).
    """
    enrichment_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    row = {
        "enrichment_id": enrichment_id,
        "ioc_id": ioc_id,
        "org_id": org_id,
        "reputation_score": kwargs.get("reputation_score", 75),
        "geo_location": kwargs.get("geo_location", "RU"),
        "associated_campaigns": json.dumps(kwargs.get("associated_campaigns", ["APT29-Cozy Bear"])),
        "malware_families": json.dumps(kwargs.get("malware_families", ["Emotet"])),
        "threat_actor": kwargs.get("threat_actor", "APT29"),
        "verdict": kwargs.get("verdict", "malicious"),
        "enriched_at": kwargs.get("enriched_at", now),
    }
    conn = sqlite3.connect(engine.db_path)
    conn.execute(
        """
        INSERT OR REPLACE INTO ioc_enrichments
            (enrichment_id, ioc_id, org_id, reputation_score, geo_location,
             associated_campaigns, malware_families, threat_actor, verdict, enriched_at)
        VALUES (:enrichment_id, :ioc_id, :org_id, :reputation_score, :geo_location,
                :associated_campaigns, :malware_families, :threat_actor, :verdict, :enriched_at)
        """,
        row,
    )
    conn.commit()
    conn.close()
    row["associated_campaigns"] = json.loads(row["associated_campaigns"])
    row["malware_families"] = json.loads(row["malware_families"])
    return row


# ---------------------------------------------------------------------------
# Feed reachability probe — used by skipif markers
# ---------------------------------------------------------------------------

def _feed_reachable() -> bool:
    """Return True if the abuse.ch Feodo Tracker feed is reachable right now."""
    try:
        blocklist = _fetch_feodo_blocklist()
        return len(blocklist) > 0
    except Exception:
        return False


_FEED_UP = _feed_reachable()
_skip_if_feed_down = pytest.mark.skipif(
    not _FEED_UP,
    reason="abuse.ch Feodo Tracker feed unreachable from this host",
)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ioc_init.db")
    IOCEnrichmentEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ioc_idem.db")
    IOCEnrichmentEngine(db_path=db)
    IOCEnrichmentEngine(db_path=db)  # second init must not raise


# ---------------------------------------------------------------------------
# 2. add_ioc
# ---------------------------------------------------------------------------

def test_add_ioc_returns_dict(engine):
    ioc = engine.add_ioc(ORG_A, {"ioc_type": "ip", "value": "1.2.3.4", "source": "VirusTotal"})
    assert ioc["ioc_id"]
    assert ioc["value"] == "1.2.3.4"
    assert ioc["org_id"] == ORG_A


def test_add_ioc_defaults(engine):
    ioc = engine.add_ioc(ORG_A, {})
    assert ioc["ioc_type"] == "ip"
    assert ioc["severity"] == "medium"
    assert ioc["confidence"] == 50
    assert ioc["tags"] == []


def test_add_ioc_invalid_type_defaults(engine):
    ioc = engine.add_ioc(ORG_A, {"ioc_type": "banana"})
    assert ioc["ioc_type"] == "ip"


def test_add_ioc_invalid_severity_defaults(engine):
    ioc = engine.add_ioc(ORG_A, {"severity": "extreme"})
    assert ioc["severity"] == "medium"


def test_add_ioc_confidence_clamp(engine):
    ioc = engine.add_ioc(ORG_A, {"confidence": 999})
    assert ioc["confidence"] == 100
    ioc2 = engine.add_ioc(ORG_A, {"confidence": -5})
    assert ioc2["confidence"] == 0


def test_add_ioc_with_tags(engine):
    ioc = engine.add_ioc(ORG_A, {"tags": ["apt", "c2"]})
    assert "apt" in ioc["tags"]


# ---------------------------------------------------------------------------
# 3. list_iocs
# ---------------------------------------------------------------------------

def test_list_iocs_empty(engine):
    assert engine.list_iocs(ORG_A) == []


def test_list_iocs_all(engine):
    engine.add_ioc(ORG_A, {"ioc_type": "ip"})
    engine.add_ioc(ORG_A, {"ioc_type": "domain"})
    iocs = engine.list_iocs(ORG_A)
    assert len(iocs) == 2


def test_list_iocs_filter_type(engine):
    engine.add_ioc(ORG_A, {"ioc_type": "ip", "value": "1.1.1.1"})
    engine.add_ioc(ORG_A, {"ioc_type": "domain", "value": "evil.com"})
    ips = engine.list_iocs(ORG_A, ioc_type="ip")
    assert len(ips) == 1
    assert ips[0]["ioc_type"] == "ip"


def test_list_iocs_filter_severity(engine):
    engine.add_ioc(ORG_A, {"severity": "critical"})
    engine.add_ioc(ORG_A, {"severity": "low"})
    crits = engine.list_iocs(ORG_A, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# 4. enrich_ioc — REAL integration tests (abuse.ch Feodo Tracker)
# ---------------------------------------------------------------------------

@_skip_if_feed_down
def test_enrich_ioc_malicious_ip_real(engine):
    """A known C2 IP from the live Feodo Tracker blocklist is verdict=malicious.

    We fetch the live blocklist, pick the first listed IP, seed it as an IOC,
    then call enrich_ioc() and assert the real feed produced verdict=malicious.
    This proves the data is live — not hash-derived or fabricated.
    """
    blocklist = _fetch_feodo_blocklist()
    assert blocklist, "Feodo Tracker returned empty blocklist — test precondition failed"

    known_malicious_ip = next(iter(blocklist))  # first listed C2 IP
    ioc = engine.add_ioc(ORG_A, {"value": known_malicious_ip, "ioc_type": "ip"})

    result = engine.enrich_ioc(ORG_A, ioc["ioc_id"])

    assert result["verdict"] == "malicious", (
        f"Expected verdict=malicious for known C2 IP {known_malicious_ip!r}, "
        f"got {result['verdict']!r}"
    )
    assert result["reputation_score"] > 0
    assert "abuse.ch" in result.get("source", "").lower(), (
        f"Expected source to mention abuse.ch, got {result.get('source')!r}"
    )
    # Malware family must come from real feed data, not be fabricated
    assert isinstance(result["malware_families"], list)

    # Enrichment must be persisted — get_enrichment() should return it
    stored = engine.get_enrichment(ORG_A, ioc["ioc_id"])
    assert stored["ioc_id"] == ioc["ioc_id"]
    assert stored["verdict"] == "malicious"


@_skip_if_feed_down
def test_enrich_ioc_clean_ip_not_malicious(engine):
    """Google DNS (8.8.8.8) is not a Feodo Tracker C2 server — verdict must NOT be malicious.

    This proves the blocklist check is real: a well-known clean IP must not
    be flagged. verdict=unknown is the correct honest result for an unlisted IP.
    """
    ioc = engine.add_ioc(ORG_A, {"value": "8.8.8.8", "ioc_type": "ip"})
    result = engine.enrich_ioc(ORG_A, ioc["ioc_id"])

    assert result["verdict"] != "malicious", (
        "8.8.8.8 (Google DNS) should not be verdict=malicious on Feodo Tracker"
    )
    assert result["verdict"] == "unknown"
    assert "abuse.ch" in result.get("source", "").lower()


@_skip_if_feed_down
def test_enrich_ioc_result_reflects_blocklist_membership(engine):
    """Proves real data: listed IP is malicious; unlisted IP is not.

    Fetches the live blocklist, checks a listed IP gets malicious verdict and
    an unlisted IP gets unknown. The verdicts are determined by actual
    blocklist membership — not any hash or RNG.
    """
    blocklist = _fetch_feodo_blocklist()
    listed_ip = next(iter(blocklist))

    ioc_listed = engine.add_ioc(ORG_A, {"value": listed_ip, "ioc_type": "ip"})
    ioc_clean = engine.add_ioc(ORG_A, {"value": "192.0.2.1", "ioc_type": "ip"})

    r_listed = engine.enrich_ioc(ORG_A, ioc_listed["ioc_id"])
    r_clean = engine.enrich_ioc(ORG_A, ioc_clean["ioc_id"])

    assert r_listed["verdict"] == "malicious"
    assert r_clean["verdict"] == "unknown"
    # Malware family populated from real feed for the malicious IP
    assert len(r_listed["malware_families"]) > 0


def test_enrich_ioc_nonexistent_ioc_raises(engine):
    """enrich_ioc() raises IocEnrichmentError for a nonexistent IOC ID."""
    with pytest.raises(IocEnrichmentError, match="not found"):
        engine.enrich_ioc(ORG_A, "nonexistent-ioc-id")


def test_enrich_ioc_feed_unreachable_raises(engine):
    """When the feed fetch raises, enrich_ioc() propagates IocEnrichmentError.

    The monkeypatch simulates a network outage. No fabricated enrichment
    must be returned — the error must bubble up.
    """
    ioc = engine.add_ioc(ORG_A, {"value": "10.0.0.1", "ioc_type": "ip"})

    with patch(
        "core.ioc_enrichment_engine._fetch_feodo_blocklist",
        side_effect=IocEnrichmentError("abuse.ch Feodo Tracker feed unreachable: timeout"),
    ):
        # Also reset the module-level cache so _get_feodo_blocklist calls _fetch
        import core.ioc_enrichment_engine as _mod
        _mod._feodo_blocklist = None
        _mod._feodo_fetched_at = 0.0

        with pytest.raises(IocEnrichmentError, match="unreachable"):
            engine.enrich_ioc(ORG_A, ioc["ioc_id"])


def test_enrich_ioc_non_ip_type_returns_unknown(engine):
    """Non-IP IOC types get verdict=unknown — no fabrication from this feed."""
    for ioc_type in ("domain", "hash", "url", "email"):
        ioc = engine.add_ioc(ORG_A, {"value": f"test-{ioc_type}", "ioc_type": ioc_type})
        # Use a stub blocklist so we don't hit the network
        with patch(
            "core.ioc_enrichment_engine._get_feodo_blocklist",
            return_value={},
        ):
            result = engine.enrich_ioc(ORG_A, ioc["ioc_id"])
        assert result["verdict"] == "unknown", (
            f"Expected verdict=unknown for ioc_type={ioc_type!r}, got {result['verdict']!r}"
        )
        assert result["reputation_score"] == 0


def test_enrich_ioc_persists_result(engine):
    """enrich_ioc() stores the enrichment so get_enrichment() returns it immediately."""
    ioc = engine.add_ioc(ORG_A, {"value": "1.2.3.4", "ioc_type": "ip"})

    fake_blocklist = {"1.2.3.4": {"ip_address": "1.2.3.4", "malware": "Emotet", "country": "RU",
                                   "as_name": "TestASN", "port": 8080, "status": "online",
                                   "first_seen": "2025-01-01 00:00:00"}}
    with patch("core.ioc_enrichment_engine._get_feodo_blocklist", return_value=fake_blocklist):
        result = engine.enrich_ioc(ORG_A, ioc["ioc_id"])

    assert result["verdict"] == "malicious"
    stored = engine.get_enrichment(ORG_A, ioc["ioc_id"])
    assert stored["verdict"] == "malicious"
    assert stored["ioc_id"] == ioc["ioc_id"]


def test_enrich_ioc_malware_family_from_feed(engine):
    """malware_families is populated from the real feed entry — not hardcoded."""
    ioc = engine.add_ioc(ORG_A, {"value": "5.5.5.5", "ioc_type": "ip"})

    fake_blocklist = {"5.5.5.5": {"ip_address": "5.5.5.5", "malware": "QakBot",
                                   "country": "DE", "as_name": "TestASN",
                                   "port": 443, "status": "online",
                                   "first_seen": "2025-06-01 00:00:00"}}
    with patch("core.ioc_enrichment_engine._get_feodo_blocklist", return_value=fake_blocklist):
        result = engine.enrich_ioc(ORG_A, ioc["ioc_id"])

    assert "QakBot" in result["malware_families"]
    assert result["geo_location"] == "DE"


# ---------------------------------------------------------------------------
# 5. get_enrichment — real read path; seed via direct SQLite INSERT
# ---------------------------------------------------------------------------

def test_get_enrichment_not_enriched(engine):
    ioc = engine.add_ioc(ORG_A, {"value": "not-enriched.com"})
    result = engine.get_enrichment(ORG_A, ioc["ioc_id"])
    assert result == {}


def test_get_enrichment_after_direct_seed(engine):
    """get_enrichment() returns stored enrichment seeded via direct SQLite INSERT.

    Read-path preserved: get_enrichment() reads ioc_enrichments table directly.
    """
    ioc = engine.add_ioc(ORG_A, {"value": "enriched.com"})
    _seed_enrichment(engine, ORG_A, ioc["ioc_id"], verdict="malicious", reputation_score=90)

    stored = engine.get_enrichment(ORG_A, ioc["ioc_id"])
    assert stored["ioc_id"] == ioc["ioc_id"]
    assert "verdict" in stored
    assert stored["verdict"] == "malicious"
    assert stored["reputation_score"] == 90


# ---------------------------------------------------------------------------
# 6. Watchlist
# ---------------------------------------------------------------------------

def test_add_to_watchlist(engine):
    ioc = engine.add_ioc(ORG_A, {"value": "bad.com"})
    result = engine.add_to_watchlist(ORG_A, "critical-watch", ioc["ioc_id"])
    assert result is True


def test_get_watchlist_items(engine):
    ioc1 = engine.add_ioc(ORG_A, {"value": "bad1.com"})
    ioc2 = engine.add_ioc(ORG_A, {"value": "bad2.com"})
    engine.add_to_watchlist(ORG_A, "mylist", ioc1["ioc_id"])
    engine.add_to_watchlist(ORG_A, "mylist", ioc2["ioc_id"])
    items = engine.get_watchlist(ORG_A, "mylist")
    assert len(items) == 2


def test_get_watchlist_empty(engine):
    items = engine.get_watchlist(ORG_A, "no-such-list")
    assert items == []


def test_add_to_watchlist_idempotent(engine):
    ioc = engine.add_ioc(ORG_A, {"value": "idem.com"})
    engine.add_to_watchlist(ORG_A, "dedupe-list", ioc["ioc_id"])
    engine.add_to_watchlist(ORG_A, "dedupe-list", ioc["ioc_id"])  # duplicate ignored
    items = engine.get_watchlist(ORG_A, "dedupe-list")
    assert len(items) == 1


# ---------------------------------------------------------------------------
# 7. bulk_import
# ---------------------------------------------------------------------------

def test_bulk_import_success(engine):
    iocs = [
        {"ioc_type": "ip", "value": f"10.0.0.{i}", "source": "bulk"} for i in range(5)
    ]
    result = engine.bulk_import(ORG_A, iocs)
    assert result["imported"] == 5
    assert result["failed"] == 0


def test_bulk_import_empty(engine):
    result = engine.bulk_import(ORG_A, [])
    assert result["imported"] == 0
    assert result["failed"] == 0


def test_bulk_import_stored(engine):
    iocs = [{"value": "bulk.com", "ioc_type": "domain"}]
    engine.bulk_import(ORG_A, iocs)
    stored = engine.list_iocs(ORG_A)
    assert len(stored) == 1


# ---------------------------------------------------------------------------
# 8. get_ioc_stats — enriched_count reads from ioc_enrichments table (real)
# ---------------------------------------------------------------------------

def test_get_ioc_stats_empty(engine):
    stats = engine.get_ioc_stats(ORG_A)
    assert stats["total"] == 0
    assert stats["enriched_count"] == 0
    assert stats["watchlist_count"] == 0


def test_get_ioc_stats_counts(engine):
    """get_ioc_stats() accurately counts enriched IOCs from ioc_enrichments."""
    ioc1 = engine.add_ioc(ORG_A, {"ioc_type": "ip", "severity": "critical"})
    ioc2 = engine.add_ioc(ORG_A, {"ioc_type": "domain", "severity": "high"})

    _seed_enrichment(engine, ORG_A, ioc1["ioc_id"])
    engine.add_to_watchlist(ORG_A, "watch", ioc2["ioc_id"])

    stats = engine.get_ioc_stats(ORG_A)
    assert stats["total"] == 2
    assert stats["enriched_count"] == 1
    assert stats["watchlist_count"] == 1
    assert "ip" in stats["by_type"]
    assert "critical" in stats["by_severity"]


# ---------------------------------------------------------------------------
# 9. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_iocs(engine):
    engine.add_ioc(ORG_A, {"value": "a.com"})
    engine.add_ioc(ORG_B, {"value": "b.com"})
    assert len(engine.list_iocs(ORG_A)) == 1
    assert len(engine.list_iocs(ORG_B)) == 1
    assert engine.list_iocs(ORG_A)[0]["value"] == "a.com"
    assert engine.list_iocs(ORG_B)[0]["value"] == "b.com"


def test_org_isolation_enrichment(engine):
    """Enrichment seeded for ORG_A must not appear in ORG_B's stats."""
    ioc_a = engine.add_ioc(ORG_A, {"value": "a-ioc.com"})
    _seed_enrichment(engine, ORG_A, ioc_a["ioc_id"])

    stats_b = engine.get_ioc_stats(ORG_B)
    assert stats_b["enriched_count"] == 0


def test_org_isolation_watchlist(engine):
    ioc_a = engine.add_ioc(ORG_A, {"value": "a-watch.com"})
    engine.add_to_watchlist(ORG_A, "shared-name", ioc_a["ioc_id"])
    items = engine.get_watchlist(ORG_B, "shared-name")
    assert items == []
