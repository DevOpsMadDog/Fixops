"""Tests for IOCEnrichmentEngine — 30 tests covering all public methods.

NotImplementedError migration:
  - enrich_ioc() now raises NotImplementedError (requires THREAT_INTEL_API_KEY env var).
  - Tests that previously called enrich_ioc() to seed enrichment data now insert
    rows directly into ioc_enrichments via SQLite to preserve read-path coverage.
  - All other methods (add_ioc, list_iocs, get_enrichment, watchlist, bulk_import,
    get_ioc_stats) remain production-ready and are tested unchanged.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from core.ioc_enrichment_engine import IOCEnrichmentEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ioc_test.db")
    return IOCEnrichmentEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# Helper: seed an enrichment row directly into SQLite (bypasses enrich_ioc stub)
# ---------------------------------------------------------------------------

def _seed_enrichment(engine: IOCEnrichmentEngine, org_id: str, ioc_id: str, **kwargs) -> dict:
    """Insert a real enrichment row into ioc_enrichments.

    This is the canonical seeding path now that enrich_ioc() raises
    NotImplementedError. The row matches the exact schema used by get_enrichment()
    and get_ioc_stats(). Returns the row dict.
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
# 4. enrich_ioc — raises NotImplementedError (THREAT_INTEL_API_KEY not set)
# ---------------------------------------------------------------------------

def test_enrich_ioc_raises_not_implemented(engine):
    """enrich_ioc() must raise NotImplementedError when THREAT_INTEL_API_KEY is unset."""
    ioc = engine.add_ioc(ORG_A, {"value": "5.6.7.8", "ioc_type": "ip"})
    with pytest.raises(NotImplementedError):
        engine.enrich_ioc(ORG_A, ioc["ioc_id"])


def test_enrich_ioc_raises_for_nonexistent_ioc(engine):
    """enrich_ioc() raises NotImplementedError even for a nonexistent IOC ID
    (env-key guard fires before the DB lookup)."""
    with pytest.raises(NotImplementedError):
        engine.enrich_ioc(ORG_A, "nonexistent-id")


def test_enrich_ioc_raises_consistently(engine):
    """enrich_ioc() must raise NotImplementedError on every call (no intermittent behaviour)."""
    ioc = engine.add_ioc(ORG_A, {"value": "8.8.8.8"})
    with pytest.raises(NotImplementedError):
        engine.enrich_ioc(ORG_A, ioc["ioc_id"])
    with pytest.raises(NotImplementedError):
        engine.enrich_ioc(ORG_A, ioc["ioc_id"])


def test_enrich_ioc_error_message_references_api_key(engine):
    """NotImplementedError message must mention THREAT_INTEL_API_KEY or a real feed."""
    ioc = engine.add_ioc(ORG_A, {"value": "malware.example.com", "ioc_type": "domain"})
    with pytest.raises(NotImplementedError) as exc_info:
        engine.enrich_ioc(ORG_A, ioc["ioc_id"])
    msg = str(exc_info.value)
    assert "THREAT_INTEL_API_KEY" in msg or "threat intel" in msg.lower()


# ---------------------------------------------------------------------------
# 5. get_enrichment — real read path; seed via direct SQLite INSERT
# ---------------------------------------------------------------------------

def test_get_enrichment_not_enriched(engine):
    ioc = engine.add_ioc(ORG_A, {"value": "not-enriched.com"})
    result = engine.get_enrichment(ORG_A, ioc["ioc_id"])
    assert result == {}


def test_get_enrichment_after_direct_seed(engine):
    """get_enrichment() returns stored enrichment seeded via direct SQLite INSERT.

    Read-path preserved: enrich_ioc() is stubbed, but get_enrichment() reads
    ioc_enrichments table directly — real production path.
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
    """get_ioc_stats() accurately counts enriched IOCs from ioc_enrichments.

    Read-path preserved: enrich_ioc() is stubbed, so we seed the enrichment
    row directly via SQLite INSERT (same table get_ioc_stats reads from).
    """
    ioc1 = engine.add_ioc(ORG_A, {"ioc_type": "ip", "severity": "critical"})
    ioc2 = engine.add_ioc(ORG_A, {"ioc_type": "domain", "severity": "high"})

    # Seed enrichment for ioc1 directly (bypasses stubbed enrich_ioc)
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
    """Enrichment seeded for ORG_A must not appear in ORG_B's stats.

    Read-path preserved: seed ORG_A enrichment via direct SQLite INSERT,
    then verify get_ioc_stats for ORG_B shows enriched_count == 0.
    """
    ioc_a = engine.add_ioc(ORG_A, {"value": "a-ioc.com"})
    _seed_enrichment(engine, ORG_A, ioc_a["ioc_id"])

    # ORG_B must see zero enrichments (org isolation)
    stats_b = engine.get_ioc_stats(ORG_B)
    assert stats_b["enriched_count"] == 0


def test_org_isolation_watchlist(engine):
    ioc_a = engine.add_ioc(ORG_A, {"value": "a-watch.com"})
    engine.add_to_watchlist(ORG_A, "shared-name", ioc_a["ioc_id"])
    # ORG_B watchlist with same name should be empty
    items = engine.get_watchlist(ORG_B, "shared-name")
    assert items == []
