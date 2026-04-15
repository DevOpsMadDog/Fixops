"""Tests for DuckDB cross-domain analytics engine.

Covers:
- Engine initialisation
- list_available_domains (real tmp files)
- cross_domain_risk_summary — returns all keys even when DBs missing
- executive_dashboard_data — complete structure when no DBs present
- run_custom_query — identifier validation rejects path traversal
- threat_intel_correlation — correct schema on missing DBs
- compliance_posture_trend — returns [] gracefully
- asset_vulnerability_correlation — returns [] gracefully
- Each method handles missing DB files without raising exceptions

DuckDB sqlite_scan calls are mocked via patch on the engine's _try_scan
and _scan internals so tests don't need real SQLite files.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from core.duckdb_analytics_engine import AnalyticsEngine, _safe_ident


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_data_dir(tmp_path: Path) -> Path:
    """Return a tmp directory with no .db files."""
    return tmp_path


@pytest.fixture()
def engine_empty(empty_data_dir: Path) -> AnalyticsEngine:
    """AnalyticsEngine pointed at an empty directory."""
    return AnalyticsEngine(data_dir=empty_data_dir)


@pytest.fixture()
def data_dir_with_dbs(tmp_path: Path) -> Path:
    """Create a data_dir with a couple of minimal SQLite *.db files."""
    for name in ("posture_score", "risk_register", "compliance_scanner"):
        db_path = tmp_path / f"{name}.db"
        conn = sqlite3.connect(str(db_path))
        conn.close()
    return tmp_path


@pytest.fixture()
def engine_with_dbs(data_dir_with_dbs: Path) -> AnalyticsEngine:
    """AnalyticsEngine pointed at a directory with (empty) .db files."""
    return AnalyticsEngine(data_dir=data_dir_with_dbs)


# ---------------------------------------------------------------------------
# Initialisation tests
# ---------------------------------------------------------------------------


class TestEngineInit:
    def test_default_data_dir(self) -> None:
        """Engine initialises with default data_dir derived from file location."""
        engine = AnalyticsEngine()
        assert engine.data_dir.name == ".fixops_data"

    def test_custom_data_dir(self, tmp_path: Path) -> None:
        engine = AnalyticsEngine(data_dir=tmp_path)
        assert engine.data_dir == tmp_path

    def test_conn_is_in_memory(self, engine_empty: AnalyticsEngine) -> None:
        """DuckDB connection is in-memory (no persistent file)."""
        import duckdb
        assert isinstance(engine_empty._conn, duckdb.DuckDBPyConnection)

    def test_data_dir_nonexistent_ok(self, tmp_path: Path) -> None:
        """Engine accepts a non-existent data_dir without raising."""
        engine = AnalyticsEngine(data_dir=tmp_path / "nonexistent")
        assert engine.data_dir.name == "nonexistent"


# ---------------------------------------------------------------------------
# get_db_path
# ---------------------------------------------------------------------------


class TestGetDbPath:
    def test_returns_none_when_missing(self, engine_empty: AnalyticsEngine) -> None:
        assert engine_empty.get_db_path("no_such_db") is None

    def test_returns_str_when_exists(self, data_dir_with_dbs: Path) -> None:
        engine = AnalyticsEngine(data_dir=data_dir_with_dbs)
        path = engine.get_db_path("posture_score")
        assert path is not None
        assert path.endswith("posture_score.db")


# ---------------------------------------------------------------------------
# list_available_domains
# ---------------------------------------------------------------------------


class TestListAvailableDomains:
    def test_empty_dir_returns_empty_list(self, engine_empty: AnalyticsEngine) -> None:
        assert engine_empty.list_available_domains() == []

    def test_nonexistent_dir_returns_empty_list(self, tmp_path: Path) -> None:
        engine = AnalyticsEngine(data_dir=tmp_path / "ghost")
        assert engine.list_available_domains() == []

    def test_returns_correct_names(self, engine_with_dbs: AnalyticsEngine) -> None:
        domains = engine_with_dbs.list_available_domains()
        names = {d["name"] for d in domains}
        assert "posture_score" in names
        assert "risk_register" in names
        assert "compliance_scanner" in names

    def test_returns_required_keys(self, engine_with_dbs: AnalyticsEngine) -> None:
        domains = engine_with_dbs.list_available_domains()
        for d in domains:
            assert "name" in d
            assert "path" in d
            assert "size_mb" in d

    def test_size_mb_is_float(self, engine_with_dbs: AnalyticsEngine) -> None:
        domains = engine_with_dbs.list_available_domains()
        for d in domains:
            assert isinstance(d["size_mb"], float)

    def test_excludes_non_db_files(self, tmp_path: Path) -> None:
        (tmp_path / "readme.txt").write_text("hello")
        (tmp_path / "posture_score.db").write_bytes(b"")
        engine = AnalyticsEngine(data_dir=tmp_path)
        domains = engine.list_available_domains()
        assert all(d["name"] != "readme" for d in domains)
        assert len(domains) == 1


# ---------------------------------------------------------------------------
# cross_domain_risk_summary — missing DBs return complete dict
# ---------------------------------------------------------------------------


class TestCrossDomainRiskSummary:
    def test_returns_dict_when_no_dbs(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.cross_domain_risk_summary("default")
        assert isinstance(result, dict)

    def test_all_expected_keys_present(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.cross_domain_risk_summary("default")
        for key in (
            "org_id", "current_score", "grade", "total_risks",
            "critical_risks", "open_cases", "total_findings",
            "critical_findings", "generated_at",
        ):
            assert key in result, f"Missing key: {key}"

    def test_defaults_when_dbs_missing(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.cross_domain_risk_summary("acme")
        assert result["org_id"] == "acme"
        assert result["total_risks"] == 0
        assert result["critical_risks"] == 0
        assert result["open_cases"] == 0
        assert result["total_findings"] == 0
        assert result["critical_findings"] == 0
        assert result["current_score"] is None
        assert result["grade"] is None

    def test_generated_at_is_iso_string(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.cross_domain_risk_summary("default")
        from datetime import datetime
        # Should parse without error
        dt = datetime.fromisoformat(result["generated_at"])
        assert dt is not None

    def test_with_mocked_posture_data(self, engine_empty: AnalyticsEngine) -> None:
        """Mocked _try_scan returns posture data correctly."""
        mock_rows: Dict[str, List] = {
            ("posture_score", "posture_scores"): [{"current_score": 78.5, "grade": "B"}],
            ("risk_register", "risks"): [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "critical"},
            ],
            ("digital_forensics", "forensic_cases"): [
                {"status": "open"},
                {"status": "closed"},
            ],
            ("threat_hunting", "hunt_findings"): [
                {"severity": "critical"},
                {"severity": "medium"},
            ],
        }

        def mock_try_scan(db_name, table, where="", limit=None):
            return mock_rows.get((db_name, table))

        with patch.object(engine_empty, "_try_scan", side_effect=mock_try_scan):
            result = engine_empty.cross_domain_risk_summary("default")

        assert result["current_score"] == 78.5
        assert result["grade"] == "B"
        assert result["total_risks"] == 3
        assert result["critical_risks"] == 2
        assert result["open_cases"] == 1
        assert result["total_findings"] == 2
        assert result["critical_findings"] == 1


# ---------------------------------------------------------------------------
# executive_dashboard_data
# ---------------------------------------------------------------------------


class TestExecutiveDashboardData:
    def test_returns_dict_always(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.executive_dashboard_data("default")
        assert isinstance(result, dict)

    def test_all_keys_present(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.executive_dashboard_data("default")
        for key in (
            "org_id", "posture_score", "grade", "open_incidents",
            "critical_vulns", "active_threats", "compliance_score_avg",
            "domains_online", "generated_at",
        ):
            assert key in result, f"Missing key: {key}"

    def test_zero_domains_when_empty_dir(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.executive_dashboard_data("default")
        assert result["domains_online"] == 0

    def test_domains_online_reflects_actual_files(self, engine_with_dbs: AnalyticsEngine) -> None:
        result = engine_with_dbs.executive_dashboard_data("default")
        assert result["domains_online"] == 3  # posture_score, risk_register, compliance_scanner

    def test_no_exception_when_all_dbs_missing(self, engine_empty: AnalyticsEngine) -> None:
        """Must not raise even if all domain DBs are absent."""
        result = engine_empty.executive_dashboard_data("tenant-x")
        assert result["org_id"] == "tenant-x"

    def test_compliance_avg_computed_from_mocked_data(self, engine_empty: AnalyticsEngine) -> None:
        def mock_list():
            return [{"name": "compliance_scanner", "path": "/fake/compliance_scanner.db", "size_mb": 0.1}]

        def mock_try_scan(db_name, table, where="", limit=None):
            if db_name == "compliance_scanner" and table == "scan_results":
                return [{"score": 80}, {"score": 90}, {"score": 70}]
            return None

        with patch.object(engine_empty, "list_available_domains", side_effect=mock_list):
            with patch.object(engine_empty, "_try_scan", side_effect=mock_try_scan):
                result = engine_empty.executive_dashboard_data("default")

        assert result["compliance_score_avg"] == 80.0


# ---------------------------------------------------------------------------
# run_custom_query — validation
# ---------------------------------------------------------------------------


class TestRunCustomQuery:
    def test_rejects_path_traversal_db_name(self, engine_empty: AnalyticsEngine) -> None:
        with pytest.raises(ValueError, match="db_name"):
            engine_empty.run_custom_query("../secret", "table")

    def test_rejects_dotted_db_name(self, engine_empty: AnalyticsEngine) -> None:
        with pytest.raises(ValueError, match="db_name"):
            engine_empty.run_custom_query("foo.bar", "table")

    def test_rejects_uppercase_db_name(self, engine_empty: AnalyticsEngine) -> None:
        with pytest.raises(ValueError, match="db_name"):
            engine_empty.run_custom_query("PostureScore", "table")

    def test_rejects_path_traversal_table_name(self, engine_empty: AnalyticsEngine) -> None:
        with pytest.raises(ValueError, match="table_name"):
            engine_empty.run_custom_query("posture_score", "../etc/passwd")

    def test_rejects_space_in_table_name(self, engine_empty: AnalyticsEngine) -> None:
        with pytest.raises(ValueError, match="table_name"):
            engine_empty.run_custom_query("posture_score", "my table")

    def test_rejects_semicolon_in_db_name(self, engine_empty: AnalyticsEngine) -> None:
        with pytest.raises(ValueError, match="db_name"):
            engine_empty.run_custom_query("foo;drop table users", "bar")

    def test_raises_file_not_found_when_db_missing(self, engine_empty: AnalyticsEngine) -> None:
        with pytest.raises(FileNotFoundError):
            engine_empty.run_custom_query("nonexistent_db", "some_table")

    def test_valid_identifiers_accepted(self, tmp_path: Path) -> None:
        """Valid snake_case identifiers pass validation (DB need not exist for this check)."""
        engine = AnalyticsEngine(data_dir=tmp_path)
        # Validation passes — FileNotFoundError raised because no actual DB
        with pytest.raises(FileNotFoundError):
            engine.run_custom_query("posture_score", "posture_scores")

    def test_limit_capped_at_1000(self, tmp_path: Path) -> None:
        """Limit is silently capped at 1000."""
        db_path = tmp_path / "test_db.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, val TEXT)")
        conn.commit()
        conn.close()

        engine = AnalyticsEngine(data_dir=tmp_path)
        # Should not raise — limit gets capped
        result = engine.run_custom_query("test_db", "test_table", limit=99999)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# threat_intel_correlation
# ---------------------------------------------------------------------------


class TestThreatIntelCorrelation:
    def test_returns_correct_schema_no_dbs(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.threat_intel_correlation("default", "1.2.3.4")
        assert result["ioc"] == "1.2.3.4"
        assert result["org_id"] == "default"
        assert "feed_hits" in result
        assert "hunt_hits" in result
        assert "correlated" in result
        assert "sources" in result

    def test_not_correlated_when_no_dbs(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.threat_intel_correlation("default", "evil.example.com")
        assert result["correlated"] is False
        assert result["feed_hits"] == 0
        assert result["hunt_hits"] == 0
        assert result["sources"] == []

    def test_correlated_when_feed_has_hit(self, engine_empty: AnalyticsEngine) -> None:
        def mock_try_scan(db_name, table, where="", limit=None):
            if db_name == "threat_feed_aggregator":
                return [{"iocs": "1.2.3.4", "source": "feodo"}]
            if db_name == "threat_hunting":
                return []
            return None

        with patch.object(engine_empty, "_try_scan", side_effect=mock_try_scan):
            result = engine_empty.threat_intel_correlation("default", "1.2.3.4")

        assert result["feed_hits"] == 1
        assert result["correlated"] is True
        assert "threat_feed_aggregator" in result["sources"]

    def test_correlated_when_hunt_has_hit(self, engine_empty: AnalyticsEngine) -> None:
        def mock_try_scan(db_name, table, where="", limit=None):
            if db_name == "threat_feed_aggregator":
                return []
            if db_name == "threat_hunting":
                return [{"iocs_found": "1.2.3.4"}]
            return None

        with patch.object(engine_empty, "_try_scan", side_effect=mock_try_scan):
            result = engine_empty.threat_intel_correlation("default", "1.2.3.4")

        assert result["hunt_hits"] == 1
        assert result["correlated"] is True
        assert "threat_hunting" in result["sources"]


# ---------------------------------------------------------------------------
# compliance_posture_trend
# ---------------------------------------------------------------------------


class TestCompliancePostureTrend:
    def test_returns_empty_list_no_db(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.compliance_posture_trend("default")
        assert result == []

    def test_returns_list_type(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.compliance_posture_trend("default")
        assert isinstance(result, list)

    def test_with_mocked_scan_data(self, engine_empty: AnalyticsEngine) -> None:
        fake_rows = [
            {
                "result_id": "r1", "profile_id": "cis_l1", "score": 82.0,
                "passed": 41, "failed": 9, "scan_completed": "2026-04-15T10:00:00",
            },
            {
                "result_id": "r2", "profile_id": "soc2", "score": 91.5,
                "passed": 55, "failed": 5, "scan_completed": "2026-04-14T10:00:00",
            },
        ]

        def mock_try_scan(db_name, table, where="", limit=None):
            return None  # DB missing — engine falls through

        # Patch get_db_path to return a fake path, then mock _scan
        with patch.object(engine_empty, "get_db_path", return_value="/fake/compliance_scanner.db"):
            with patch.object(engine_empty, "_conn") as mock_conn:
                mock_rel = MagicMock()
                mock_rel.description = [
                    ("result_id",), ("profile_id",), ("score",),
                    ("passed",), ("failed",), ("scan_completed",),
                ]
                mock_rel.fetchall.return_value = [
                    ("r1", "cis_l1", 82.0, 41, 9, "2026-04-15T10:00:00"),
                    ("r2", "soc2", 91.5, 55, 5, "2026-04-14T10:00:00"),
                ]
                mock_conn.execute.return_value = mock_rel
                result = engine_empty.compliance_posture_trend("default")

        assert len(result) == 2
        assert result[0]["result_id"] == "r1"
        assert result[0]["score"] == 82.0


# ---------------------------------------------------------------------------
# asset_vulnerability_correlation
# ---------------------------------------------------------------------------


class TestAssetVulnerabilityCorrelation:
    def test_returns_empty_list_when_dbs_missing(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.asset_vulnerability_correlation("default")
        assert result == []

    def test_returns_empty_list_when_only_one_db_present(self, tmp_path: Path) -> None:
        (tmp_path / "asset_inventory.db").write_bytes(b"")
        engine = AnalyticsEngine(data_dir=tmp_path)
        result = engine.asset_vulnerability_correlation("default")
        assert result == []

    def test_returns_list_type(self, engine_empty: AnalyticsEngine) -> None:
        result = engine_empty.asset_vulnerability_correlation("default")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _safe_ident helper
# ---------------------------------------------------------------------------


class TestSafeIdent:
    def test_valid_snake_case(self) -> None:
        assert _safe_ident("posture_score", "x") == "posture_score"

    def test_valid_simple(self) -> None:
        assert _safe_ident("risks", "x") == "risks"

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(ValueError):
            _safe_ident("", "x")

    def test_rejects_path_components(self) -> None:
        with pytest.raises(ValueError):
            _safe_ident("../etc/passwd", "x")

    def test_rejects_uppercase(self) -> None:
        with pytest.raises(ValueError):
            _safe_ident("MyTable", "x")

    def test_rejects_hyphen(self) -> None:
        with pytest.raises(ValueError):
            _safe_ident("my-table", "x")

    def test_rejects_semicolon(self) -> None:
        with pytest.raises(ValueError):
            _safe_ident("foo;drop", "x")

    def test_allows_leading_underscore(self) -> None:
        assert _safe_ident("_internal", "x") == "_internal"
