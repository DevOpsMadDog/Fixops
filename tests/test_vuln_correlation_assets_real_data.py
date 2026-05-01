"""Test that /api/v1/vuln-correlation/assets surfaces real CISA KEV data.

Verifies the empty-endpoint fix: when the org has registered no assets, the
listing falls back to the imported CISA KEV catalog (real public-source data,
no mocks). Fixture builds a tiny KEV side-DB with 3 real-shaped rows and
points the engine at it.
"""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from core.vulnerability_correlation_engine import VulnerabilityCorrelationEngine


def _build_kev_db(path: Path, rows: list[tuple[str, str, str, str, str, str, str]]) -> None:
    """Materialise a real-shaped CISA KEV SQLite snapshot.

    rows = [(cve_id, vendor_project, product, vulnerability_name, date_added,
             short_description, known_ransomware_use), ...]
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS kev_entries (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                known_ransomware_use TEXT,
                notes TEXT,
                raw_json TEXT,
                imported_at TEXT
            )"""
        )
        for r in rows:
            c.execute(
                """INSERT OR REPLACE INTO kev_entries
                   (cve_id, vendor_project, product, vulnerability_name, date_added,
                    short_description, required_action, due_date, known_ransomware_use,
                    notes, raw_json, imported_at)
                   VALUES (?,?,?,?,?,?,'patch','2024-01-01',?,'', '{}', '2024-01-01T00:00:00Z')""",
                (r[0], r[1], r[2], r[3], r[4], r[5], r[6]),
            )
        c.commit()


@pytest.fixture
def engine(tmp_path):
    db_path = tmp_path / "vc.db"
    return VulnerabilityCorrelationEngine(db_path=str(db_path))


def test_empty_org_with_no_kev_returns_empty_with_hint(engine, tmp_path):
    """When neither org-assets nor KEV side-DB exist -> structured empty."""
    res = engine.list_assets_with_kev_fallback(
        "fresh-org",
        kev_db_path=str(tmp_path / "no_such.db"),
    )
    assert res["assets"] == []
    assert res["total"] == 0
    assert res["source"] == "empty"
    assert "hint" in res
    assert "import-kev" in res["hint"]


def test_empty_org_falls_back_to_cisa_kev(engine, tmp_path):
    """Empty org -> CISA KEV-derived asset library is returned (real data shape)."""
    kev_db = tmp_path / "cisa_kev.db"
    _build_kev_db(kev_db, [
        ("CVE-2024-0001", "Microsoft", "Exchange Server", "RCE in OWA", "2024-02-15",
         "Remote code execution via crafted SOAP envelope.", "Known"),
        ("CVE-2024-0002", "Apache", "Log4j", "Log4Shell variant", "2024-03-01",
         "JNDI lookup deserialisation.", "Unknown"),
        ("CVE-2024-0003", "Cisco", "ASA Firewall", "Privilege escalation", "2024-04-10",
         "Authenticated bypass of role checks.", ""),
    ])

    res = engine.list_assets_with_kev_fallback(
        "fresh-org-2",
        kev_db_path=str(kev_db),
    )
    assert res["source"] == "cisa-kev-derived"
    assert res["total"] == 3
    assert res["kev_total"] == 3
    names = {a["asset_name"] for a in res["assets"]}
    assert "Microsoft Exchange Server" in names
    assert "Apache Log4j" in names
    assert "Cisco ASA Firewall" in names
    # Critical when known_ransomware_use is "Known", high otherwise.
    by_name = {a["asset_name"]: a for a in res["assets"]}
    assert by_name["Microsoft Exchange Server"]["criticality"] == "critical"
    assert by_name["Apache Log4j"]["criticality"] == "high"
    # Source attribution is preserved on each derived asset.
    for a in res["assets"]:
        assert a["source"] == "cisa-kev"
        assert a["source_cve_id"].startswith("CVE-2024-")


def test_kev_fallback_dedupes_repeated_products(engine, tmp_path):
    """Multiple CVEs against the same product collapse to one library row."""
    kev_db = tmp_path / "cisa_kev_dup.db"
    _build_kev_db(kev_db, [
        ("CVE-2024-1001", "Acme", "WidgetServer", "RCE 1", "2024-01-01", "desc", "Known"),
        ("CVE-2024-1002", "Acme", "WidgetServer", "RCE 2", "2024-02-01", "desc", "Known"),
        ("CVE-2024-1003", "Acme", "OtherProduct", "Bypass", "2024-03-01", "desc", "Unknown"),
    ])
    res = engine.list_assets_with_kev_fallback("fresh-org-3", kev_db_path=str(kev_db))
    assert res["total"] == 2  # WidgetServer + OtherProduct
    assert res["kev_total"] == 3


def test_org_registered_assets_take_precedence_over_kev(engine, tmp_path):
    """When the org has registered its own assets, KEV fallback is bypassed."""
    kev_db = tmp_path / "cisa_kev_tier.db"
    _build_kev_db(kev_db, [
        ("CVE-2024-9001", "Some", "Product", "x", "2024-01-01", "desc", "Known"),
    ])
    engine.register_asset(
        "tiered-org",
        {"asset_name": "Tenant DB cluster", "asset_type": "database", "criticality": "high"},
    )
    res = engine.list_assets_with_kev_fallback("tiered-org", kev_db_path=str(kev_db))
    assert res["source"] == "org_registered"
    assert res["total"] == 1
    assert res["assets"][0]["asset_name"] == "Tenant DB cluster"


def test_kev_fallback_filters_apply(engine, tmp_path):
    """asset_type and criticality filters apply against the derived rows too."""
    kev_db = tmp_path / "cisa_kev_filter.db"
    _build_kev_db(kev_db, [
        ("CVE-2024-2001", "V1", "P1", "x", "2024-01-01", "d", "Known"),  # critical
        ("CVE-2024-2002", "V2", "P2", "y", "2024-02-01", "d", "Unknown"),  # high
    ])
    res = engine.list_assets_with_kev_fallback(
        "filt-org", criticality="critical", kev_db_path=str(kev_db)
    )
    assert res["source"] == "cisa-kev-derived"
    assert res["total"] == 1
    assert res["assets"][0]["criticality"] == "critical"
