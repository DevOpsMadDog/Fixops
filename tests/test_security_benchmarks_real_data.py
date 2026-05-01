"""Test that /api/v1/security-benchmarks/benchmarks surfaces real DBIR data.

Verifies the empty-endpoint fix: when the org has registered no industry
benchmarks, the listing falls back to the imported Verizon DBIR / VCDB incident
corpus (real public-source breach data, no mocks). Fixture builds a tiny DBIR
side-DB with real-shaped rows and points the engine at it.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.security_benchmark_engine import SecurityBenchmarkEngine


def _build_dbir_db(path: Path, incidents: list[dict]) -> None:
    """Materialise a real-shaped DBIR/VCDB SQLite snapshot using the
    PersistentDict layout: table [dbir_incidents] with (key TEXT, value TEXT)
    where value is the JSON-serialised parsed VERIS incident.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS [dbir_incidents] "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        for inc in incidents:
            c.execute(
                "INSERT OR REPLACE INTO [dbir_incidents] (key, value) VALUES (?, ?)",
                (inc["incident_id"], json.dumps(inc)),
            )
        c.commit()


def _make_inc(
    incident_id: str, naics: str, primary_pattern: str
) -> dict:
    return {
        "incident_id": incident_id,
        "summary": "",
        "action_patterns": [primary_pattern],
        "primary_action_pattern": primary_pattern,
        "actors": ["external"],
        "primary_actor": "external",
        "asset_categories": [],
        "attributes": ["confidentiality"],
        "discovery_method": "log-review",
        "victim": {"industry_naics": naics, "employee_count": "", "country": []},
        "timeline": {},
        "raw_action": {},
        "imported_at": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def engine(tmp_path):
    db_path = tmp_path / "sbe.db"
    return SecurityBenchmarkEngine(db_path=str(db_path))


def test_empty_org_with_no_dbir_returns_empty_with_hint(engine, tmp_path):
    """When neither org-benchmarks nor DBIR side-DB exist -> structured empty."""
    res = engine.list_benchmarks_with_dbir_fallback(
        "fresh-org",
        dbir_db_path=str(tmp_path / "no_such.db"),
    )
    assert res["benchmarks"] == []
    assert res["total"] == 0
    assert res["source"] == "empty"
    assert "hint" in res
    assert "import-dbir" in res["hint"]


def test_empty_org_falls_back_to_dbir(engine, tmp_path):
    """Empty org -> DBIR-derived benchmark library is returned (real data shape)."""
    dbir_db = tmp_path / "dbir.db"
    _build_dbir_db(dbir_db, [
        # finance/52 — 4 hacking incidents
        _make_inc("inc-1", "52", "hacking"),
        _make_inc("inc-2", "52", "hacking"),
        _make_inc("inc-3", "52", "hacking"),
        _make_inc("inc-4", "52", "hacking"),
        # finance/52 — 2 malware incidents
        _make_inc("inc-5", "52", "malware"),
        _make_inc("inc-6", "52", "malware"),
        # healthcare/62 — 1 social incident
        _make_inc("inc-7", "62", "social"),
        # tech/51 — 3 misuse incidents
        _make_inc("inc-8", "51", "misuse"),
        _make_inc("inc-9", "51", "misuse"),
        _make_inc("inc-10", "51", "misuse"),
        # NAICS we don't recognise -> dropped
        _make_inc("inc-11", "99", "hacking"),
        # primary_action_pattern=unknown -> dropped
        _make_inc("inc-12", "52", "unknown"),
    ])

    res = engine.list_benchmarks_with_dbir_fallback(
        "fresh-org-2",
        dbir_db_path=str(dbir_db),
    )
    assert res["source"] == "dbir-derived"
    assert res["dbir_total_incidents"] == 12
    # 4 valid (sector, pattern) buckets: finance/hacking, finance/malware,
    # healthcare/social, technology/misuse.
    assert res["total"] == 4
    sectors = {b["sector"] for b in res["benchmarks"]}
    assert {"finance", "healthcare", "technology"}.issubset(sectors)
    by_name = {b["benchmark_name"]: b for b in res["benchmarks"]}
    assert "DBIR Finance — Hacking Incidents" in by_name
    fin_hack = by_name["DBIR Finance — Hacking Incidents"]
    assert fin_hack["benchmark_source"] == "Verizon-DBIR"
    assert fin_hack["metric_category"] == "incident-response"
    assert fin_hack["metric_name"] == "breach_count_hacking"
    assert fin_hack["unit"] == "incidents"
    assert fin_hack["higher_is_better"] == 0
    assert fin_hack["source"] == "dbir"
    assert fin_hack["source_action_pattern"] == "hacking"
    assert fin_hack["source_bucket_count"] == 4
    # Percentile anchors are populated and ordered.
    for k in ("p25_value", "p50_value", "p75_value", "p90_value"):
        assert isinstance(fin_hack[k], float)
    assert fin_hack["p25_value"] <= fin_hack["p50_value"] <= fin_hack["p75_value"] <= fin_hack["p90_value"]


def test_org_registered_takes_precedence_over_dbir(engine, tmp_path):
    """When the org has its own benchmark, DBIR fallback is bypassed."""
    dbir_db = tmp_path / "dbir_tier.db"
    _build_dbir_db(dbir_db, [_make_inc("inc-x", "52", "hacking")])
    engine.create_benchmark(
        org_id="tiered-org",
        benchmark_name="Custom",
        benchmark_source="custom",
        sector="finance",
        metric_name="x",
        metric_category="vulnerability",
        p25=1.0, p50=2.0, p75=3.0, p90=4.0,
    )
    res = engine.list_benchmarks_with_dbir_fallback(
        "tiered-org", dbir_db_path=str(dbir_db)
    )
    assert res["source"] == "org_registered"
    assert res["total"] == 1
    assert res["benchmarks"][0]["benchmark_name"] == "Custom"


def test_dbir_fallback_filter_sector(engine, tmp_path):
    """sector filter applies against derived rows."""
    dbir_db = tmp_path / "dbir_sector.db"
    _build_dbir_db(dbir_db, [
        _make_inc("inc-1", "52", "hacking"),  # finance
        _make_inc("inc-2", "62", "malware"),  # healthcare
    ])
    res = engine.list_benchmarks_with_dbir_fallback(
        "filt-org", sector="finance", dbir_db_path=str(dbir_db)
    )
    assert res["source"] == "dbir-derived"
    assert res["total"] == 1
    assert res["benchmarks"][0]["sector"] == "finance"


def test_dbir_fallback_filter_metric_category_non_match(engine, tmp_path):
    """All DBIR rows are metric_category=incident-response; other filters yield empty."""
    dbir_db = tmp_path / "dbir_cat.db"
    _build_dbir_db(dbir_db, [
        _make_inc("inc-1", "52", "hacking"),
    ])
    res = engine.list_benchmarks_with_dbir_fallback(
        "cat-org", metric_category="patch", dbir_db_path=str(dbir_db)
    )
    assert res["source"] == "dbir-derived"
    assert res["total"] == 0
