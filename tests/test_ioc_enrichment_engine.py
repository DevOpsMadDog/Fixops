"""Tests for IOCEnrichmentEngine — 20 tests covering all public methods."""

from __future__ import annotations

import os
import pytest

from core.ioc_enrichment_engine import IOCEnrichmentEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ioc_test.db")
    return IOCEnrichmentEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


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
# 4. enrich_ioc
# ---------------------------------------------------------------------------

def test_enrich_ioc_returns_dict(engine):
    ioc = engine.add_ioc(ORG_A, {"value": "5.6.7.8", "ioc_type": "ip"})
    result = engine.enrich_ioc(ORG_A, ioc["ioc_id"])
    assert result["ioc_id"] == ioc["ioc_id"]
    assert "reputation_score" in result
    assert result["verdict"] in {"malicious", "suspicious", "benign", "unknown"}


def test_enrich_ioc_not_found(engine):
    result = engine.enrich_ioc(ORG_A, "nonexistent-id")
    assert "error" in result


def test_enrich_ioc_deterministic(engine):
    ioc = engine.add_ioc(ORG_A, {"value": "8.8.8.8"})
    r1 = engine.enrich_ioc(ORG_A, ioc["ioc_id"])
    r2 = engine.enrich_ioc(ORG_A, ioc["ioc_id"])
    assert r1["reputation_score"] == r2["reputation_score"]
    assert r1["verdict"] == r2["verdict"]


def test_enrich_ioc_verdict_logic(engine):
    # Create IOCs with known deterministic values and verify verdict logic
    ioc = engine.add_ioc(ORG_A, {"value": "malware.example.com", "ioc_type": "domain"})
    result = engine.enrich_ioc(ORG_A, ioc["ioc_id"])
    score = result["reputation_score"]
    if score >= 70:
        assert result["verdict"] == "malicious"
    elif score >= 40:
        assert result["verdict"] == "suspicious"
    elif score >= 10:
        assert result["verdict"] == "benign"
    else:
        assert result["verdict"] == "unknown"


# ---------------------------------------------------------------------------
# 5. get_enrichment
# ---------------------------------------------------------------------------

def test_get_enrichment_not_enriched(engine):
    ioc = engine.add_ioc(ORG_A, {"value": "not-enriched.com"})
    result = engine.get_enrichment(ORG_A, ioc["ioc_id"])
    assert result == {}


def test_get_enrichment_after_enrich(engine):
    ioc = engine.add_ioc(ORG_A, {"value": "enriched.com"})
    engine.enrich_ioc(ORG_A, ioc["ioc_id"])
    stored = engine.get_enrichment(ORG_A, ioc["ioc_id"])
    assert stored["ioc_id"] == ioc["ioc_id"]
    assert "verdict" in stored


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
# 8. get_ioc_stats
# ---------------------------------------------------------------------------

def test_get_ioc_stats_empty(engine):
    stats = engine.get_ioc_stats(ORG_A)
    assert stats["total"] == 0
    assert stats["enriched_count"] == 0
    assert stats["watchlist_count"] == 0


def test_get_ioc_stats_counts(engine):
    ioc1 = engine.add_ioc(ORG_A, {"ioc_type": "ip", "severity": "critical"})
    ioc2 = engine.add_ioc(ORG_A, {"ioc_type": "domain", "severity": "high"})
    engine.enrich_ioc(ORG_A, ioc1["ioc_id"])
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
    ioc_a = engine.add_ioc(ORG_A, {"value": "a-ioc.com"})
    engine.enrich_ioc(ORG_A, ioc_a["ioc_id"])
    # ORG_B has no enrichments
    stats_b = engine.get_ioc_stats(ORG_B)
    assert stats_b["enriched_count"] == 0


def test_org_isolation_watchlist(engine):
    ioc_a = engine.add_ioc(ORG_A, {"value": "a-watch.com"})
    engine.add_to_watchlist(ORG_A, "shared-name", ioc_a["ioc_id"])
    # ORG_B watchlist with same name should be empty
    items = engine.get_watchlist(ORG_B, "shared-name")
    assert items == []
