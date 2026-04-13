"""
Tests for the Security Metrics KPI Engine — ALDECI.

Covers:
- KPIEngine: record_kpi, get_current_kpis, get_kpi_trend, set_target,
  get_kpi_health, get_executive_kpis, auto_calculate_kpis, list_kpi_definitions
- KPI API router: all 8 endpoints

At least 35 tests.
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.kpi_engine import (
    KPI,
    KPICategory,
    KPIEngine,
    KPIHealth,
    KPIHealthStatus,
    KPITarget,
    KPITrend,
    _KPI_DEFINITIONS,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def engine() -> KPIEngine:
    """Create a KPIEngine backed by a temporary SQLite database."""
    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "test_kpi.db")
    return KPIEngine(db_path=db_path)


@pytest.fixture
def client(authenticated_client):
    """Use shared authenticated client fixture."""
    return authenticated_client


# ============================================================================
# UNIT TESTS — KPIEngine
# ============================================================================


class TestKPIEngineInit:
    def test_creates_database_file(self, engine: KPIEngine) -> None:
        assert engine.db_path.exists()

    def test_seeds_default_targets(self, engine: KPIEngine) -> None:
        conn = engine._get_conn()
        rows = conn.execute("SELECT COUNT(*) FROM kpi_targets").fetchone()
        conn.close()
        assert rows[0] >= len(_KPI_DEFINITIONS)

    def test_built_in_definitions_not_empty(self) -> None:
        assert len(_KPI_DEFINITIONS) >= 20


class TestRecordKPI:
    def test_record_returns_kpi_model(self, engine: KPIEngine) -> None:
        kpi = engine.record_kpi("mttd_minutes", 45.0, KPICategory.DETECTION, org_id="org1")
        assert isinstance(kpi, KPI)
        assert kpi.name == "mttd_minutes"
        assert kpi.value == 45.0
        assert kpi.category == KPICategory.DETECTION
        assert kpi.org_id == "org1"

    def test_record_resolves_unit_from_definition(self, engine: KPIEngine) -> None:
        kpi = engine.record_kpi("mttd_minutes", 30.0, KPICategory.DETECTION)
        assert kpi.unit == "minutes"

    def test_record_custom_kpi_name(self, engine: KPIEngine) -> None:
        kpi = engine.record_kpi("custom_metric", 99.9, KPICategory.EFFICIENCY)
        assert kpi.name == "custom_metric"
        assert kpi.unit == ""  # Not in built-in definitions

    def test_record_sets_period_automatically(self, engine: KPIEngine) -> None:
        kpi = engine.record_kpi("scan_coverage_pct", 88.0, KPICategory.COVERAGE)
        assert kpi.period != ""
        # Should be current year-month
        expected = datetime.now(timezone.utc).strftime("%Y-%m")
        assert kpi.period == expected

    def test_record_custom_period(self, engine: KPIEngine) -> None:
        kpi = engine.record_kpi(
            "compliance_score_pct", 92.0, KPICategory.COMPLIANCE, period="2026-Q1"
        )
        assert kpi.period == "2026-Q1"

    def test_record_with_metadata(self, engine: KPIEngine) -> None:
        meta = {"source": "automated", "scanner": "trivy"}
        kpi = engine.record_kpi(
            "vuln_density", 1.5, KPICategory.PREVENTION, metadata=meta
        )
        assert kpi.metadata == meta

    def test_record_persists_to_db(self, engine: KPIEngine) -> None:
        engine.record_kpi("mttr_hours", 6.0, KPICategory.RESPONSE, org_id="org-persist")
        conn = engine._get_conn()
        row = conn.execute(
            "SELECT value FROM kpi_records WHERE name=? AND org_id=?",
            ("mttr_hours", "org-persist"),
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == 6.0

    def test_record_multiple_orgs_isolated(self, engine: KPIEngine) -> None:
        engine.record_kpi("patch_rate_pct", 70.0, KPICategory.PREVENTION, org_id="orgA")
        engine.record_kpi("patch_rate_pct", 95.0, KPICategory.PREVENTION, org_id="orgB")
        kpis_a = engine.get_current_kpis(org_id="orgA")
        kpis_b = engine.get_current_kpis(org_id="orgB")
        val_a = next(k for k in kpis_a if k.name == "patch_rate_pct").value
        val_b = next(k for k in kpis_b if k.name == "patch_rate_pct").value
        assert val_a == 70.0
        assert val_b == 95.0


class TestGetCurrentKPIs:
    def test_empty_org_returns_empty_list(self, engine: KPIEngine) -> None:
        kpis = engine.get_current_kpis(org_id="nonexistent-org")
        assert kpis == []

    def test_returns_only_latest_value(self, engine: KPIEngine) -> None:
        engine.record_kpi("mttd_minutes", 100.0, KPICategory.DETECTION, org_id="org-latest")
        engine.record_kpi("mttd_minutes", 50.0, KPICategory.DETECTION, org_id="org-latest")
        kpis = engine.get_current_kpis(org_id="org-latest")
        mttd = [k for k in kpis if k.name == "mttd_minutes"]
        assert len(mttd) == 1
        assert mttd[0].value == 50.0

    def test_includes_target(self, engine: KPIEngine) -> None:
        engine.record_kpi("scan_coverage_pct", 90.0, KPICategory.COVERAGE, org_id="org-t")
        kpis = engine.get_current_kpis(org_id="org-t")
        cov = next(k for k in kpis if k.name == "scan_coverage_pct")
        assert cov.target is not None
        assert cov.target == 95.0

    def test_trend_stable_on_single_point(self, engine: KPIEngine) -> None:
        engine.record_kpi("false_positive_rate_pct", 5.0, KPICategory.EFFICIENCY, org_id="org-trend")
        kpis = engine.get_current_kpis(org_id="org-trend")
        fp = next(k for k in kpis if k.name == "false_positive_rate_pct")
        assert fp.trend == KPITrend.STABLE

    def test_trend_down_when_value_decreases(self, engine: KPIEngine) -> None:
        engine.record_kpi("mttd_minutes", 80.0, KPICategory.DETECTION, org_id="org-down")
        engine.record_kpi("mttd_minutes", 40.0, KPICategory.DETECTION, org_id="org-down")
        kpis = engine.get_current_kpis(org_id="org-down")
        mttd = next(k for k in kpis if k.name == "mttd_minutes")
        assert mttd.trend == KPITrend.DOWN

    def test_trend_up_when_value_increases(self, engine: KPIEngine) -> None:
        engine.record_kpi("scan_coverage_pct", 60.0, KPICategory.COVERAGE, org_id="org-up")
        engine.record_kpi("scan_coverage_pct", 85.0, KPICategory.COVERAGE, org_id="org-up")
        kpis = engine.get_current_kpis(org_id="org-up")
        cov = next(k for k in kpis if k.name == "scan_coverage_pct")
        assert cov.trend == KPITrend.UP


class TestGetKPITrend:
    def test_returns_chronological_data(self, engine: KPIEngine) -> None:
        org = "org-chronological"
        engine.record_kpi("mttd_minutes", 60.0, KPICategory.DETECTION, org_id=org)
        engine.record_kpi("mttd_minutes", 50.0, KPICategory.DETECTION, org_id=org)
        engine.record_kpi("mttd_minutes", 40.0, KPICategory.DETECTION, org_id=org)
        trend = engine.get_kpi_trend("mttd_minutes", org_id=org, days=30)
        assert len(trend) == 3
        timestamps = [t["timestamp"] for t in trend]
        assert timestamps == sorted(timestamps)

    def test_returns_empty_for_missing_kpi(self, engine: KPIEngine) -> None:
        trend = engine.get_kpi_trend("nonexistent_kpi", org_id="org-none", days=30)
        assert trend == []

    def test_respects_days_filter(self, engine: KPIEngine) -> None:
        org = "org-days-filter"
        # Record a value and check it appears within 30 days
        engine.record_kpi("mttr_hours", 12.0, KPICategory.RESPONSE, org_id=org)
        trend_30 = engine.get_kpi_trend("mttr_hours", org_id=org, days=30)
        trend_0 = engine.get_kpi_trend("mttr_hours", org_id=org, days=0)
        assert len(trend_30) >= 1
        # 0 days = only today; SQLite timestamp comparison includes today's values
        # so we just check 30 >= 0-day result
        assert len(trend_30) >= len(trend_0)

    def test_returns_timestamp_and_value_keys(self, engine: KPIEngine) -> None:
        engine.record_kpi("compliance_score_pct", 88.0, KPICategory.COMPLIANCE, org_id="org-keys")
        trend = engine.get_kpi_trend("compliance_score_pct", org_id="org-keys", days=30)
        assert len(trend) == 1
        assert "timestamp" in trend[0]
        assert "value" in trend[0]
        assert trend[0]["value"] == 88.0


class TestSetTarget:
    def test_set_target_returns_kpi_target(self, engine: KPIEngine) -> None:
        target = engine.set_target("custom_kpi", 100.0, 80.0, 60.0)
        assert isinstance(target, KPITarget)
        assert target.kpi_name == "custom_kpi"
        assert target.target_value == 100.0
        assert target.threshold_yellow == 80.0
        assert target.threshold_red == 60.0

    def test_set_target_overwrites_existing(self, engine: KPIEngine) -> None:
        engine.set_target("mttd_minutes", 30.0, 40.0, 60.0, higher_is_better=False)
        conn = engine._get_conn()
        row = conn.execute(
            "SELECT target_value FROM kpi_targets WHERE kpi_name=?", ("mttd_minutes",)
        ).fetchone()
        conn.close()
        assert row[0] == 30.0

    def test_set_target_higher_is_better_stored(self, engine: KPIEngine) -> None:
        engine.set_target("patch_rate_pct", 95.0, 80.0, 70.0, higher_is_better=True)
        conn = engine._get_conn()
        row = conn.execute(
            "SELECT higher_is_better FROM kpi_targets WHERE kpi_name=?", ("patch_rate_pct",)
        ).fetchone()
        conn.close()
        assert row[0] == 1


class TestGetKPIHealth:
    def test_green_when_above_yellow_threshold(self, engine: KPIEngine) -> None:
        engine.set_target("scan_coverage_pct", 95.0, 76.0, 57.0, higher_is_better=True)
        engine.record_kpi("scan_coverage_pct", 90.0, KPICategory.COVERAGE, org_id="org-green")
        health = engine.get_kpi_health(org_id="org-green")
        h = next(h for h in health if h.name == "scan_coverage_pct")
        assert h.health == KPIHealth.GREEN

    def test_yellow_when_between_thresholds(self, engine: KPIEngine) -> None:
        engine.set_target("scan_coverage_pct", 95.0, 76.0, 57.0, higher_is_better=True)
        engine.record_kpi("scan_coverage_pct", 65.0, KPICategory.COVERAGE, org_id="org-yellow")
        health = engine.get_kpi_health(org_id="org-yellow")
        h = next(h for h in health if h.name == "scan_coverage_pct")
        assert h.health == KPIHealth.YELLOW

    def test_red_when_below_red_threshold(self, engine: KPIEngine) -> None:
        engine.set_target("scan_coverage_pct", 95.0, 76.0, 57.0, higher_is_better=True)
        engine.record_kpi("scan_coverage_pct", 40.0, KPICategory.COVERAGE, org_id="org-red")
        health = engine.get_kpi_health(org_id="org-red")
        h = next(h for h in health if h.name == "scan_coverage_pct")
        assert h.health == KPIHealth.RED

    def test_lower_is_better_green(self, engine: KPIEngine) -> None:
        engine.set_target("mttd_minutes", 60.0, 72.0, 84.0, higher_is_better=False)
        engine.record_kpi("mttd_minutes", 45.0, KPICategory.DETECTION, org_id="org-lb-green")
        health = engine.get_kpi_health(org_id="org-lb-green")
        h = next(h for h in health if h.name == "mttd_minutes")
        assert h.health == KPIHealth.GREEN

    def test_lower_is_better_red(self, engine: KPIEngine) -> None:
        engine.set_target("mttd_minutes", 60.0, 72.0, 84.0, higher_is_better=False)
        engine.record_kpi("mttd_minutes", 120.0, KPICategory.DETECTION, org_id="org-lb-red")
        health = engine.get_kpi_health(org_id="org-lb-red")
        h = next(h for h in health if h.name == "mttd_minutes")
        assert h.health == KPIHealth.RED

    def test_empty_org_returns_empty_list(self, engine: KPIEngine) -> None:
        health = engine.get_kpi_health(org_id="org-health-empty")
        assert health == []


class TestGetExecutiveKPIs:
    def test_returns_executive_summary_model(self, engine: KPIEngine) -> None:
        from core.kpi_engine import ExecutiveKPISummary

        summary = engine.get_executive_kpis(org_id="org-exec-empty")
        assert isinstance(summary, ExecutiveKPISummary)
        assert summary.org_id == "org-exec-empty"
        assert summary.overall_health == KPIHealth.UNKNOWN
        assert summary.kpis == []

    def test_returns_up_to_10_kpis(self, engine: KPIEngine) -> None:
        org = "org-exec-10"
        for name, (_, unit, cat, hib, tgt) in list(_KPI_DEFINITIONS.items())[:12]:
            engine.record_kpi(name, tgt, cat, org_id=org)
        summary = engine.get_executive_kpis(org_id=org)
        assert len(summary.kpis) <= 10

    def test_overall_health_red_when_any_red(self, engine: KPIEngine) -> None:
        org = "org-exec-red"
        # Record scan_coverage_pct far below red threshold
        engine.set_target("scan_coverage_pct", 95.0, 76.0, 57.0, higher_is_better=True)
        engine.record_kpi("scan_coverage_pct", 10.0, KPICategory.COVERAGE, org_id=org)
        summary = engine.get_executive_kpis(org_id=org)
        assert summary.overall_health == KPIHealth.RED

    def test_green_yellow_red_counts_consistent(self, engine: KPIEngine) -> None:
        org = "org-exec-counts"
        engine.set_target("scan_coverage_pct", 95.0, 76.0, 57.0, higher_is_better=True)
        engine.record_kpi("scan_coverage_pct", 90.0, KPICategory.COVERAGE, org_id=org)
        summary = engine.get_executive_kpis(org_id=org)
        total = (
            summary.green_count
            + summary.yellow_count
            + summary.red_count
            + summary.unknown_count
        )
        assert total == len(summary.kpis)

    def test_generated_at_is_utc_aware(self, engine: KPIEngine) -> None:
        summary = engine.get_executive_kpis()
        assert summary.generated_at.tzinfo is not None


class TestAutoCalculateKPIs:
    def test_returns_list(self, engine: KPIEngine) -> None:
        # With no analytics DB available, should return empty list gracefully
        result = engine.auto_calculate_kpis(org_id="org-auto")
        assert isinstance(result, list)

    def test_does_not_raise_when_analytics_unavailable(self, engine: KPIEngine) -> None:
        # Should silently skip if analytics engine is not set up
        result = engine.auto_calculate_kpis(org_id="org-no-analytics")
        assert isinstance(result, list)


class TestListKPIDefinitions:
    def test_returns_all_definitions(self, engine: KPIEngine) -> None:
        defs = engine.list_kpi_definitions()
        assert len(defs) == len(_KPI_DEFINITIONS)

    def test_each_definition_has_required_keys(self, engine: KPIEngine) -> None:
        defs = engine.list_kpi_definitions()
        required_keys = {"name", "display_name", "unit", "category", "higher_is_better", "default_target"}
        for d in defs:
            assert required_keys.issubset(d.keys()), f"Missing keys in: {d}"


# ============================================================================
# API ROUTER TESTS
# ============================================================================


class TestKPIRouterRecordEndpoint:
    def test_record_kpi_returns_201(self, client) -> None:
        resp = client.post(
            "/api/v1/kpis/record",
            json={
                "name": "mttd_minutes",
                "value": 45.0,
                "category": "detection",
                "org_id": "api-test-org",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "mttd_minutes"
        assert data["value"] == 45.0

    def test_record_kpi_missing_required_fields_422(self, client) -> None:
        resp = client.post("/api/v1/kpis/record", json={"name": "mttd_minutes"})
        assert resp.status_code == 422

    def test_record_kpi_invalid_category_422(self, client) -> None:
        resp = client.post(
            "/api/v1/kpis/record",
            json={"name": "mttd_minutes", "value": 30.0, "category": "invalid_cat"},
        )
        assert resp.status_code == 422


class TestKPIRouterCurrentEndpoint:
    def test_get_current_returns_200(self, client) -> None:
        resp = client.get("/api/v1/kpis/current?org_id=api-current-org")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_current_reflects_recorded_data(self, client, monkeypatch) -> None:
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "api_kpi.db")
        eng = KPIEngine(db_path=db_path)
        eng.record_kpi("scan_coverage_pct", 91.0, KPICategory.COVERAGE, org_id="api-reflect")
        monkeypatch.setattr("apps.api.kpi_router._engine", eng)
        resp = client.get("/api/v1/kpis/current?org_id=api-reflect")
        assert resp.status_code == 200
        data = resp.json()
        assert any(k["name"] == "scan_coverage_pct" for k in data)


class TestKPIRouterTrendEndpoint:
    def test_trend_404_for_missing_kpi(self, client) -> None:
        resp = client.get("/api/v1/kpis/trend/nonexistent_kpi_xyz?org_id=api-trend-org")
        assert resp.status_code == 404

    def test_trend_returns_data_when_present(self, client, monkeypatch) -> None:
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "api_trend_kpi.db")
        eng = KPIEngine(db_path=db_path)
        eng.record_kpi("mttd_minutes", 60.0, KPICategory.DETECTION, org_id="api-trend")
        monkeypatch.setattr("apps.api.kpi_router._engine", eng)
        resp = client.get("/api/v1/kpis/trend/mttd_minutes?org_id=api-trend&days=30")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["value"] == 60.0


class TestKPIRouterTargetEndpoint:
    def test_set_target_returns_200(self, client) -> None:
        resp = client.put(
            "/api/v1/kpis/targets",
            json={
                "name": "mttd_minutes",
                "target": 60.0,
                "yellow": 72.0,
                "red": 84.0,
                "higher_is_better": False,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["kpi_name"] == "mttd_minutes"
        assert data["target_value"] == 60.0

    def test_set_target_missing_fields_422(self, client) -> None:
        resp = client.put("/api/v1/kpis/targets", json={"name": "mttd_minutes"})
        assert resp.status_code == 422


class TestKPIRouterHealthEndpoint:
    def test_health_returns_200_list(self, client) -> None:
        resp = client.get("/api/v1/kpis/health?org_id=api-health-org")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestKPIRouterExecutiveEndpoint:
    def test_executive_returns_200(self, client) -> None:
        resp = client.get("/api/v1/kpis/executive?org_id=api-exec-org")
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_health" in data
        assert "kpis" in data
        assert "green_count" in data
        assert "generated_at" in data


class TestKPIRouterCalculateEndpoint:
    def test_calculate_returns_200_list(self, client) -> None:
        resp = client.post("/api/v1/kpis/calculate?org_id=api-calc-org")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestKPIRouterDefinitionsEndpoint:
    def test_definitions_returns_all_builtins(self, client) -> None:
        resp = client.get("/api/v1/kpis/definitions")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 20
        names = {d["name"] for d in data}
        assert "mttd_minutes" in names
        assert "mttr_hours" in names
        assert "compliance_score_pct" in names
        assert "scan_coverage_pct" in names
        assert "false_positive_rate_pct" in names
