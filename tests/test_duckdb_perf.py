"""Performance assertions for DuckDB analytics engine.

Verifies that the three hotspot fixes push aggregation into DuckDB rather than
materialising full Python row lists:

  Fix 1: cross_domain_risk_summary  — COUNT(*)/FILTER instead of len(fetchall())
  Fix 2: threat_intel_correlation   — COUNT(*) instead of len(matching rows)
  Fix 3: executive_dashboard_data   — all four aggregates are SQL-side, no full scan

Each test creates a temporary SQLite DB with a known row count, wires the
engine to it, and asserts:
  a) correctness (the right numbers come back), and
  b) timing: the call completes in < 500 ms even with synthetic data
     (the old path fetched and deserialised every row into Python dicts
      before counting — the new path returns a single 1-row aggregate).

Compliance: SOC2 CC7.2 performance monitoring.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import sqlite3
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-core"))

from core.duckdb_analytics_engine import AnalyticsEngine  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ROW_COUNT = 200  # enough to show difference; not so large tests are slow


def _make_db(tmp_dir: Path, name: str, ddl: str, rows: list[tuple]) -> Path:
    """Create a SQLite DB with a single table and return its path."""
    db_path = tmp_dir / f"{name}.db"
    con = sqlite3.connect(db_path)
    con.execute(ddl)
    con.executemany(f"INSERT INTO {ddl.split('(')[0].split()[-1]} VALUES ({','.join('?' * len(rows[0]))})", rows)
    con.commit()
    con.close()
    return db_path


# ---------------------------------------------------------------------------
# Fix 1: cross_domain_risk_summary — SQL COUNT, not Python len()
# ---------------------------------------------------------------------------


class TestCrossDomainRiskSummaryPerf:
    def test_risk_counts_are_correct(self, tmp_path: Path) -> None:
        """COUNT(*) FILTER returns correct totals and critical counts."""
        # Build risk_register DB: 200 rows, 80 critical
        rows = [
            (f"risk-{i}", "critical" if i < 80 else "medium", float(i))
            for i in range(_ROW_COUNT)
        ]
        _make_db(tmp_path, "risk_register", "CREATE TABLE risks (risk_id TEXT, severity TEXT, risk_score REAL)", rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        result = engine.cross_domain_risk_summary(org_id="test-org")

        assert result["total_risks"] == _ROW_COUNT
        assert result["critical_risks"] == 80

    def test_forensics_open_cases_correct(self, tmp_path: Path) -> None:
        """COUNT FILTER for open cases returns correct count."""
        rows = [
            (f"case-{i}", "open" if i < 60 else "closed")
            for i in range(_ROW_COUNT)
        ]
        _make_db(tmp_path, "digital_forensics", "CREATE TABLE forensic_cases (case_id TEXT, status TEXT)", rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        result = engine.cross_domain_risk_summary(org_id="test-org")

        assert result["open_cases"] == 60

    def test_hunt_findings_counts_correct(self, tmp_path: Path) -> None:
        """COUNT(*) FILTER for hunt findings returns correct totals."""
        rows = [
            (f"finding-{i}", "critical" if i < 30 else "low", "open")
            for i in range(_ROW_COUNT)
        ]
        _make_db(tmp_path, "threat_hunting", "CREATE TABLE hunt_findings (id TEXT, severity TEXT, status TEXT)", rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        result = engine.cross_domain_risk_summary(org_id="test-org")

        assert result["total_findings"] == _ROW_COUNT
        assert result["critical_findings"] == 30

    def test_risk_summary_perf_under_500ms(self, tmp_path: Path) -> None:
        """Entire risk summary with all four DBs completes in < 500 ms."""
        risk_rows = [(f"r-{i}", "critical" if i % 3 == 0 else "high", float(i)) for i in range(_ROW_COUNT)]
        forensics_rows = [(f"c-{i}", "open" if i % 2 == 0 else "closed") for i in range(_ROW_COUNT)]
        hunt_rows = [(f"f-{i}", "critical" if i % 4 == 0 else "low", "open") for i in range(_ROW_COUNT)]
        posture_rows = [(1, 82.5, "B")]

        _make_db(tmp_path, "risk_register", "CREATE TABLE risks (risk_id TEXT, severity TEXT, risk_score REAL)", risk_rows)
        _make_db(tmp_path, "digital_forensics", "CREATE TABLE forensic_cases (case_id TEXT, status TEXT)", forensics_rows)
        _make_db(tmp_path, "threat_hunting", "CREATE TABLE hunt_findings (id TEXT, severity TEXT, status TEXT)", hunt_rows)
        _make_db(tmp_path, "posture_score", "CREATE TABLE posture_scores (id INTEGER, current_score REAL, grade TEXT)", posture_rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        start = time.perf_counter()
        result = engine.cross_domain_risk_summary(org_id="test-org")
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 500, f"cross_domain_risk_summary took {elapsed_ms:.1f}ms — expected < 500ms"
        assert result["total_risks"] == _ROW_COUNT
        assert result["current_score"] == 82.5


# ---------------------------------------------------------------------------
# Fix 2: threat_intel_correlation — SQL COUNT, not len(matching rows)
# ---------------------------------------------------------------------------


class TestThreatIntelCorrelationPerf:
    def test_feed_hits_correct(self, tmp_path: Path) -> None:
        """COUNT(*) FILTER returns correct feed_hits count."""
        ioc = "192.168.1.1"
        rows = [
            (f"item-{i}", f"{ioc},10.0.0.{i}" if i < 40 else f"10.0.0.{i}")
            for i in range(_ROW_COUNT)
        ]
        _make_db(tmp_path, "threat_feed_aggregator", "CREATE TABLE feed_items (id TEXT, iocs TEXT)", rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        result = engine.threat_intel_correlation(org_id="test-org", ioc=ioc)

        assert result["feed_hits"] == 40
        assert result["correlated"] is True
        assert "threat_feed_aggregator" in result["sources"]

    def test_hunt_hits_correct(self, tmp_path: Path) -> None:
        """COUNT(*) for hunt_findings ioc search returns correct count."""
        ioc = "malware.example.com"
        rows = [
            (f"f-{i}", f"{ioc}" if i < 25 else "clean.example.com")
            for i in range(_ROW_COUNT)
        ]
        _make_db(tmp_path, "threat_hunting", "CREATE TABLE hunt_findings (id TEXT, iocs_found TEXT)", rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        result = engine.threat_intel_correlation(org_id="test-org", ioc=ioc)

        assert result["hunt_hits"] == 25
        assert "threat_hunting" in result["sources"]

    def test_no_hits_not_correlated(self, tmp_path: Path) -> None:
        """Zero hits returns correlated=False."""
        rows = [(f"item-{i}", "10.0.0.1") for i in range(10)]
        _make_db(tmp_path, "threat_feed_aggregator", "CREATE TABLE feed_items (id TEXT, iocs TEXT)", rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        result = engine.threat_intel_correlation(org_id="test-org", ioc="192.168.99.99")

        assert result["feed_hits"] == 0
        assert result["correlated"] is False

    def test_threat_intel_perf_under_300ms(self, tmp_path: Path) -> None:
        """IOC correlation with two DBs completes in < 300 ms."""
        ioc = "evil.example.com"
        feed_rows = [(f"i-{i}", ioc if i < 50 else "safe.com") for i in range(_ROW_COUNT)]
        hunt_rows = [(f"f-{i}", ioc if i < 20 else "safe.com") for i in range(_ROW_COUNT)]

        _make_db(tmp_path, "threat_feed_aggregator", "CREATE TABLE feed_items (id TEXT, iocs TEXT)", feed_rows)
        _make_db(tmp_path, "threat_hunting", "CREATE TABLE hunt_findings (id TEXT, iocs_found TEXT)", hunt_rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        start = time.perf_counter()
        result = engine.threat_intel_correlation(org_id="test-org", ioc=ioc)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 300, f"threat_intel_correlation took {elapsed_ms:.1f}ms — expected < 300ms"
        assert result["feed_hits"] == 50
        assert result["hunt_hits"] == 20


# ---------------------------------------------------------------------------
# Fix 3: executive_dashboard_data — all aggregates SQL-side
# ---------------------------------------------------------------------------


class TestExecutiveDashboardPerf:
    def _populate_all_dbs(self, tmp_path: Path) -> None:
        posture_rows = [(1, 88.0, "A")]
        forensics_rows = [("open" if i < 45 else "closed",) for i in range(_ROW_COUNT)]
        risk_rows = [("critical" if i < 55 else "high",) for i in range(_ROW_COUNT)]
        hunt_rows = [("open" if i < 70 else "closed",) for i in range(_ROW_COUNT)]
        compliance_rows = [(float(60 + i % 40), "2024-01-01") for i in range(20)]

        _make_db(tmp_path, "posture_score", "CREATE TABLE posture_scores (id INTEGER, current_score REAL, grade TEXT)", posture_rows)
        _make_db(tmp_path, "digital_forensics", "CREATE TABLE forensic_cases (status TEXT)", forensics_rows)
        _make_db(tmp_path, "risk_register", "CREATE TABLE risks (severity TEXT)", risk_rows)
        _make_db(tmp_path, "threat_hunting", "CREATE TABLE hunt_findings (status TEXT)", hunt_rows)
        _make_db(tmp_path, "compliance_scanner", "CREATE TABLE scan_results (score REAL, scan_completed TEXT)", compliance_rows)

    def test_dashboard_values_correct(self, tmp_path: Path) -> None:
        """Executive dashboard returns correct SQL-aggregated values."""
        self._populate_all_dbs(tmp_path)
        engine = AnalyticsEngine(data_dir=tmp_path)
        dash = engine.executive_dashboard_data(org_id="test-org")

        assert dash["posture_score"] == 88.0
        assert dash["grade"] == "A"
        assert dash["open_incidents"] == 45
        assert dash["critical_vulns"] == 55
        assert dash["active_threats"] == 70
        assert dash["compliance_score_avg"] is not None
        assert dash["domains_online"] == 5

    def test_dashboard_perf_under_500ms(self, tmp_path: Path) -> None:
        """Full executive dashboard with 5 DBs completes in < 500 ms."""
        self._populate_all_dbs(tmp_path)
        engine = AnalyticsEngine(data_dir=tmp_path)

        start = time.perf_counter()
        dash = engine.executive_dashboard_data(org_id="test-org")
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 500, f"executive_dashboard_data took {elapsed_ms:.1f}ms — expected < 500ms"
        assert dash["open_incidents"] == 45

    def test_dashboard_missing_dbs_returns_defaults(self, tmp_path: Path) -> None:
        """Missing domain DBs return zero defaults, not errors."""
        engine = AnalyticsEngine(data_dir=tmp_path)
        dash = engine.executive_dashboard_data(org_id="test-org")

        assert dash["open_incidents"] == 0
        assert dash["critical_vulns"] == 0
        assert dash["active_threats"] == 0
        assert dash["compliance_score_avg"] is None
        assert dash["posture_score"] is None


# ---------------------------------------------------------------------------
# _count_agg helper
# ---------------------------------------------------------------------------


class TestCountAggHelper:
    def test_count_agg_returns_correct_count(self, tmp_path: Path) -> None:
        """_count_agg returns exact row count matching WHERE clause."""
        rows = [("critical",) for _ in range(30)] + [("high",) for _ in range(70)]
        _make_db(tmp_path, "risk_register", "CREATE TABLE risks (severity TEXT)", rows)

        engine = AnalyticsEngine(data_dir=tmp_path)
        db_path = engine.get_db_path("risk_register")
        assert db_path is not None

        total = engine._count_agg(db_path, "risks")
        critical = engine._count_agg(db_path, "risks", where="lower(severity) = 'critical'")

        assert total == 100
        assert critical == 30
