"""Test that /api/v1/posture-benchmarking/benchmarks surfaces real CIS Benchmark data.

Verifies the empty-endpoint fix: when the org has registered no benchmarks,
the listing falls back to the imported CIS Benchmark catalog (real public-source
XCCDF data, no mocks). Fixture builds a tiny CIS side-DB with real-shaped rows
and points the engine at it.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from core.security_posture_benchmarking_engine import SecurityPostureBenchmarkingEngine


def _build_cis_db(path: Path, controls: list[tuple[str, str, str, str, str, str]]) -> None:
    """Materialise a real-shaped CIS Benchmark SQLite snapshot.

    controls = [(benchmark_id, benchmark_version, benchmark_title, control_id,
                 control_title, severity), ...]
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS cis_controls (
                benchmark_id TEXT NOT NULL,
                benchmark_version TEXT,
                benchmark_title TEXT,
                control_id TEXT NOT NULL,
                control_title TEXT,
                audit TEXT,
                remediation TEXT,
                severity TEXT,
                profiles TEXT,
                nist_references TEXT,
                iso_references TEXT,
                all_references TEXT,
                imported_at TEXT,
                PRIMARY KEY (benchmark_id, control_id)
            )"""
        )
        for r in controls:
            c.execute(
                """INSERT OR REPLACE INTO cis_controls
                   (benchmark_id, benchmark_version, benchmark_title, control_id,
                    control_title, audit, remediation, severity, profiles,
                    nist_references, iso_references, all_references, imported_at)
                   VALUES (?,?,?,?,?,'check','fix',?,'[]','[]','[]','[]','2024-01-01T00:00:00Z')""",
                (r[0], r[1], r[2], r[3], r[4], r[5]),
            )
        c.commit()


@pytest.fixture
def engine(tmp_path):
    db_path = tmp_path / "spb.db"
    return SecurityPostureBenchmarkingEngine(db_path=str(db_path))


def test_empty_org_with_no_cis_returns_empty_with_hint(engine, tmp_path):
    """When neither org-benchmarks nor CIS side-DB exist -> structured empty."""
    res = engine.list_benchmarks_with_cis_fallback(
        "fresh-org",
        cis_db_path=str(tmp_path / "no_such.db"),
    )
    assert res["benchmarks"] == []
    assert res["total"] == 0
    assert res["source"] == "empty"
    assert "hint" in res
    assert "import-cis" in res["hint"]


def test_empty_org_falls_back_to_cis(engine, tmp_path):
    """Empty org -> CIS-derived benchmark library is returned (real data shape)."""
    cis_db = tmp_path / "cis_benchmark.db"
    _build_cis_db(cis_db, [
        ("xccdf_org.cisecurity.benchmarks_benchmark_8.0.0_CIS_Controls",
         "8.0.0", "CIS Critical Security Controls v8",
         "rule_1.1", "Establish and Maintain Detailed Asset Inventory", "high"),
        ("xccdf_org.cisecurity.benchmarks_benchmark_8.0.0_CIS_Controls",
         "8.0.0", "CIS Critical Security Controls v8",
         "rule_1.2", "Address Unauthorized Assets", "medium"),
        ("xccdf_org.cisecurity.benchmarks_benchmark_1.5.0_AWS_Foundations",
         "1.5.0", "CIS AWS Foundations Benchmark",
         "rule_1.1", "Maintain current contact details", "low"),
    ])

    res = engine.list_benchmarks_with_cis_fallback(
        "fresh-org-2",
        cis_db_path=str(cis_db),
    )
    assert res["source"] == "cis-benchmark-derived"
    assert res["total"] == 2  # two distinct benchmark_ids
    assert res["cis_total_controls"] == 3
    titles = {b["benchmark_name"] for b in res["benchmarks"]}
    assert "CIS Critical Security Controls v8" in titles
    assert "CIS AWS Foundations Benchmark" in titles
    # Each derived row shaped like a real spb_benchmark
    by_title = {b["benchmark_name"]: b for b in res["benchmarks"]}
    cis8 = by_title["CIS Critical Security Controls v8"]
    assert cis8["framework"] == "cis"
    assert cis8["category"] == "compliance"
    assert cis8["total_controls"] == 2
    assert cis8["status"] == "draft"
    assert cis8["score"] == 0.0
    assert cis8["source"] == "cis-benchmark"
    assert cis8["source_benchmark_id"].startswith("xccdf_")


def test_org_registered_benchmarks_take_precedence_over_cis(engine, tmp_path):
    """When the org has registered its own benchmark, CIS fallback is bypassed."""
    cis_db = tmp_path / "cis_tier.db"
    _build_cis_db(cis_db, [
        ("xccdf_dummy", "1.0", "Dummy CIS", "r1", "x", "high"),
    ])
    engine.create_benchmark(
        "tiered-org",
        {
            "benchmark_name": "Tenant custom benchmark",
            "framework": "nist",
            "category": "compliance",
        },
    )
    res = engine.list_benchmarks_with_cis_fallback(
        "tiered-org", cis_db_path=str(cis_db)
    )
    assert res["source"] == "org_registered"
    assert res["total"] == 1
    assert res["benchmarks"][0]["benchmark_name"] == "Tenant custom benchmark"


def test_cis_fallback_filter_non_cis_framework_returns_empty(engine, tmp_path):
    """If caller filters to a non-cis framework, fallback declines."""
    cis_db = tmp_path / "cis_filter.db"
    _build_cis_db(cis_db, [
        ("xccdf_x", "1.0", "X", "r1", "T", "low"),
    ])
    res = engine.list_benchmarks_with_cis_fallback(
        "filt-org", framework="nist", cis_db_path=str(cis_db)
    )
    assert res["source"] == "empty"
    assert res["total"] == 0
    assert "framework='nist'" in res["hint"]


def test_cis_fallback_filter_status_active_returns_empty(engine, tmp_path):
    """Derived rows are status=draft; filtering for 'active' yields empty list."""
    cis_db = tmp_path / "cis_status.db"
    _build_cis_db(cis_db, [
        ("xccdf_y", "1.0", "Y", "r1", "T", "medium"),
    ])
    res = engine.list_benchmarks_with_cis_fallback(
        "status-org", status="active", cis_db_path=str(cis_db)
    )
    # All derived rows skipped because status filter doesn't match draft.
    assert res["source"] == "cis-benchmark-derived"
    assert res["total"] == 0
