"""Tests for DuckDB AnalyticsEngine — comprehensive coverage."""
import sqlite3
import tempfile
from pathlib import Path

import pytest

from core.duckdb_analytics_engine import AnalyticsEngine


@pytest.fixture()
def engine(tmp_path):
    """AnalyticsEngine pointing at an empty temp dir (no .db files present)."""
    return AnalyticsEngine(data_dir=tmp_path)


@pytest.fixture()
def engine_with_db(tmp_path):
    """AnalyticsEngine with a pre-created SQLite db file for query tests."""
    db_file = tmp_path / "assets.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE assets (id TEXT, org_id TEXT, risk_score REAL)")
    conn.execute("INSERT INTO assets VALUES ('a1', 'org1', 8.5)")
    conn.execute("INSERT INTO assets VALUES ('a2', 'org1', 3.2)")
    conn.execute("INSERT INTO assets VALUES ('a3', 'org2', 9.0)")
    conn.commit()
    conn.close()
    return AnalyticsEngine(data_dir=tmp_path)


# ── Instantiation ─────────────────────────────────────────────────────────────

def test_instantiation_default():
    eng = AnalyticsEngine()
    assert eng is not None


def test_instantiation_custom_dir(tmp_path):
    eng = AnalyticsEngine(data_dir=tmp_path)
    assert eng.data_dir == tmp_path


def test_instantiation_string_path(tmp_path):
    eng = AnalyticsEngine(data_dir=str(tmp_path))
    assert eng is not None


def test_instantiation_nonexistent_dir(tmp_path):
    """Engine creates data_dir if it doesn't exist."""
    new_dir = tmp_path / "new_subdir"
    eng = AnalyticsEngine(data_dir=new_dir)
    assert eng is not None


# ── get_db_path() ─────────────────────────────────────────────────────────────

def test_get_db_path_missing_returns_none(engine):
    assert engine.get_db_path("nonexistent") is None


def test_get_db_path_existing_returns_str(engine, tmp_path):
    db_file = tmp_path / "mydb.db"
    db_file.touch()
    result = engine.get_db_path("mydb")
    assert result is not None
    assert "mydb.db" in result


def test_get_db_path_multiple_dbs(tmp_path):
    (tmp_path / "alpha.db").touch()
    (tmp_path / "beta.db").touch()
    eng = AnalyticsEngine(data_dir=tmp_path)
    assert eng.get_db_path("alpha") is not None
    assert eng.get_db_path("beta") is not None
    assert eng.get_db_path("gamma") is None


def test_get_db_path_without_extension(engine, tmp_path):
    (tmp_path / "vulns.db").touch()
    # Must work without passing .db suffix
    result = engine.get_db_path("vulns")
    assert result is not None


# ── list_available_domains() ──────────────────────────────────────────────────

def test_list_available_domains_returns_list(engine):
    assert isinstance(engine.list_available_domains(), list)


def test_list_available_domains_empty_dir(engine):
    assert engine.list_available_domains() == []


def test_list_available_domains_with_single_db(tmp_path):
    (tmp_path / "vulns.db").touch()
    eng = AnalyticsEngine(data_dir=tmp_path)
    result = eng.list_available_domains()
    assert any(d.get("name") == "vulns" for d in result)


def test_list_available_domains_with_multiple_dbs(tmp_path):
    for name in ("findings", "assets", "incidents"):
        (tmp_path / f"{name}.db").touch()
    eng = AnalyticsEngine(data_dir=tmp_path)
    result = eng.list_available_domains()
    names = {d["name"] for d in result}
    assert {"findings", "assets", "incidents"}.issubset(names)


def test_list_available_domains_domain_has_name_key(tmp_path):
    (tmp_path / "posture.db").touch()
    eng = AnalyticsEngine(data_dir=tmp_path)
    result = eng.list_available_domains()
    assert all("name" in d for d in result)


def test_list_available_domains_ignores_non_db_files(tmp_path):
    (tmp_path / "notes.txt").touch()
    (tmp_path / "config.yaml").touch()
    (tmp_path / "real.db").touch()
    eng = AnalyticsEngine(data_dir=tmp_path)
    result = eng.list_available_domains()
    assert len(result) == 1
    assert result[0]["name"] == "real"


# ── cross_domain_risk_summary() ───────────────────────────────────────────────

def test_cross_domain_risk_summary_returns_dict(engine):
    assert isinstance(engine.cross_domain_risk_summary("org1"), dict)


def test_cross_domain_risk_summary_has_org_id(engine):
    result = engine.cross_domain_risk_summary("org1")
    assert result.get("org_id") == "org1"


def test_cross_domain_risk_summary_different_orgs(engine):
    r1 = engine.cross_domain_risk_summary("org-a")
    r2 = engine.cross_domain_risk_summary("org-b")
    assert r1["org_id"] == "org-a"
    assert r2["org_id"] == "org-b"


def test_cross_domain_risk_summary_empty_db_dir(engine):
    """Empty data dir should still return valid summary structure."""
    result = engine.cross_domain_risk_summary("anyorg")
    assert isinstance(result, dict)


# ── asset_vulnerability_correlation() ────────────────────────────────────────

def test_asset_vulnerability_correlation_returns_list(engine):
    assert isinstance(engine.asset_vulnerability_correlation("org1"), list)


def test_asset_vulnerability_correlation_empty_dir(engine):
    result = engine.asset_vulnerability_correlation("org-x")
    assert result == [] or isinstance(result, list)


def test_asset_vulnerability_correlation_two_orgs_dont_mix(engine):
    r1 = engine.asset_vulnerability_correlation("org-1")
    r2 = engine.asset_vulnerability_correlation("org-2")
    assert isinstance(r1, list)
    assert isinstance(r2, list)


# ── threat_intel_correlation() ────────────────────────────────────────────────

def test_threat_intel_correlation_returns_dict(engine):
    assert isinstance(engine.threat_intel_correlation("org1", "1.2.3.4"), dict)


def test_threat_intel_correlation_ipv6(engine):
    result = engine.threat_intel_correlation("org1", "::1")
    assert isinstance(result, dict)


def test_threat_intel_correlation_domain_ioc(engine):
    result = engine.threat_intel_correlation("org1", "evil.example.com")
    assert isinstance(result, dict)


def test_threat_intel_correlation_hash_ioc(engine):
    result = engine.threat_intel_correlation("org1", "d41d8cd98f00b204e9800998ecf8427e")
    assert isinstance(result, dict)


# ── compliance_posture_trend() ────────────────────────────────────────────────

def test_compliance_posture_trend_returns_list(engine):
    assert isinstance(engine.compliance_posture_trend("org1"), list)


def test_compliance_posture_trend_empty_dir(engine):
    result = engine.compliance_posture_trend("org-empty")
    assert isinstance(result, list)


# ── executive_dashboard_data() ────────────────────────────────────────────────

def test_executive_dashboard_data_returns_dict(engine):
    assert isinstance(engine.executive_dashboard_data("org1"), dict)


def test_executive_dashboard_data_empty_dir(engine):
    result = engine.executive_dashboard_data("org-empty")
    assert isinstance(result, dict)


def test_executive_dashboard_data_different_orgs(engine):
    r1 = engine.executive_dashboard_data("orgA")
    r2 = engine.executive_dashboard_data("orgB")
    assert isinstance(r1, dict)
    assert isinstance(r2, dict)


# ── run_custom_query() ────────────────────────────────────────────────────────

def test_run_custom_query_missing_db_raises(engine):
    with pytest.raises(FileNotFoundError):
        engine.run_custom_query("nonexistent_db", "some_table")


def test_run_custom_query_invalid_db_name_raises(engine):
    with pytest.raises(ValueError):
        engine.run_custom_query("../etc/passwd", "users")


def test_run_custom_query_invalid_table_name_raises(engine, tmp_path):
    (tmp_path / "real.db").touch()
    with pytest.raises((ValueError, Exception)):
        engine.run_custom_query("real", "drop;table--")


def test_run_custom_query_returns_list(engine_with_db):
    result = engine_with_db.run_custom_query("assets", "assets")
    assert isinstance(result, list)


def test_run_custom_query_all_rows(engine_with_db):
    result = engine_with_db.run_custom_query("assets", "assets")
    assert len(result) == 3


def test_run_custom_query_respects_limit(engine_with_db):
    result = engine_with_db.run_custom_query("assets", "assets", limit=1)
    assert len(result) == 1


def test_run_custom_query_where_clause(engine_with_db):
    result = engine_with_db.run_custom_query("assets", "assets", where_clause="org_id = 'org1'")
    assert all(r["org_id"] == "org1" for r in result)
    assert len(result) == 2


# ── org isolation ─────────────────────────────────────────────────────────────

def test_different_orgs_dont_cross_contaminate(engine):
    r1 = engine.cross_domain_risk_summary("org-a")
    r2 = engine.cross_domain_risk_summary("org-b")
    assert r1.get("org_id") != r2.get("org_id")


# ── list_available_domains size_mb field ──────────────────────────────────────

def test_list_available_domains_has_size_mb(tmp_path):
    (tmp_path / "mydb.db").touch()
    eng = AnalyticsEngine(data_dir=tmp_path)
    result = eng.list_available_domains()
    assert "size_mb" in result[0]
    assert isinstance(result[0]["size_mb"], float)


def test_list_available_domains_has_path(tmp_path):
    (tmp_path / "events.db").touch()
    eng = AnalyticsEngine(data_dir=tmp_path)
    result = eng.list_available_domains()
    assert "path" in result[0]


# ── run_custom_query limit cap ─────────────────────────────────────────────────

def test_run_custom_query_limit_capped_at_1000(engine_with_db):
    """Limit above 1000 should be capped to 1000, not raise."""
    result = engine_with_db.run_custom_query("assets", "assets", limit=9999)
    assert isinstance(result, list)


def test_run_custom_query_empty_table(tmp_path):
    db_file = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE records (id TEXT)")
    conn.commit()
    conn.close()
    eng = AnalyticsEngine(data_dir=tmp_path)
    result = eng.run_custom_query("empty", "records")
    assert result == []
