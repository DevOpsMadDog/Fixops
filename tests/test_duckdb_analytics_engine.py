"""Smoke tests for DuckDB AnalyticsEngine — baseline coverage."""
import tempfile
from pathlib import Path

import pytest

from core.duckdb_analytics_engine import AnalyticsEngine


@pytest.fixture()
def engine(tmp_path):
    """AnalyticsEngine pointing at an empty temp dir (no .db files present)."""
    return AnalyticsEngine(data_dir=tmp_path)


# ── Instantiation ─────────────────────────────────────────────────────────────

def test_instantiation_default():
    """Engine can be created with default data_dir."""
    eng = AnalyticsEngine()
    assert eng is not None


def test_instantiation_custom_dir(tmp_path):
    eng = AnalyticsEngine(data_dir=tmp_path)
    assert eng.data_dir == tmp_path


# ── get_db_path() ─────────────────────────────────────────────────────────────

def test_get_db_path_missing_returns_none(engine, tmp_path):
    result = engine.get_db_path("nonexistent")
    assert result is None


def test_get_db_path_existing_returns_str(engine, tmp_path):
    db_file = tmp_path / "mydb.db"
    db_file.touch()
    result = engine.get_db_path("mydb")
    assert result is not None
    assert "mydb.db" in result


# ── list_available_domains() ──────────────────────────────────────────────────

def test_list_available_domains_returns_list(engine):
    result = engine.list_available_domains()
    assert isinstance(result, list)


def test_list_available_domains_empty_dir(engine):
    """Returns empty list when no .db files exist."""
    result = engine.list_available_domains()
    assert result == []


def test_list_available_domains_with_db_file(tmp_path):
    db_file = tmp_path / "vulns.db"
    db_file.touch()
    eng = AnalyticsEngine(data_dir=tmp_path)
    result = eng.list_available_domains()
    assert any(d.get("name") == "vulns" for d in result)


# ── cross_domain_risk_summary() ───────────────────────────────────────────────

def test_cross_domain_risk_summary_returns_dict(engine):
    result = engine.cross_domain_risk_summary("org1")
    assert isinstance(result, dict)


def test_cross_domain_risk_summary_has_org_id(engine):
    result = engine.cross_domain_risk_summary("org1")
    assert result.get("org_id") == "org1"


# ── asset_vulnerability_correlation() ────────────────────────────────────────

def test_asset_vulnerability_correlation_returns_list(engine):
    result = engine.asset_vulnerability_correlation("org1")
    assert isinstance(result, list)


# ── threat_intel_correlation() ────────────────────────────────────────────────

def test_threat_intel_correlation_returns_dict(engine):
    result = engine.threat_intel_correlation("org1", "1.2.3.4")
    assert isinstance(result, dict)


# ── compliance_posture_trend() ────────────────────────────────────────────────

def test_compliance_posture_trend_returns_list(engine):
    result = engine.compliance_posture_trend("org1")
    assert isinstance(result, list)


# ── executive_dashboard_data() ────────────────────────────────────────────────

def test_executive_dashboard_data_returns_dict(engine):
    result = engine.executive_dashboard_data("org1")
    assert isinstance(result, dict)


# ── run_custom_query() ────────────────────────────────────────────────────────

def test_run_custom_query_missing_db_raises(engine):
    """run_custom_query raises FileNotFoundError when .db file doesn't exist."""
    with pytest.raises(FileNotFoundError):
        engine.run_custom_query("nonexistent_db", "some_table")


# ── org isolation ─────────────────────────────────────────────────────────────

def test_different_orgs_dont_cross_contaminate(engine):
    r1 = engine.cross_domain_risk_summary("org-a")
    r2 = engine.cross_domain_risk_summary("org-b")
    assert r1.get("org_id") != r2.get("org_id")
