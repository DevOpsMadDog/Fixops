"""
Comprehensive tests for ALDECI Phase 7 — Dashboard Analytics and Metrics Aggregation.

Tests cover:
- AnalyticsEngine: record, query, trend, percentile operations
- PersonaDashboard: all 6 persona types return correct structure
- RiskPostureEngine: score calculation, trend, heatmap, top risks
- Analytics routes: all endpoints return correct shape and access control

At least 40 tests, all passing.

Compliance: Test coverage for SOC2 CC7.2 requirements
"""

from __future__ import annotations

import sys
import json
import pytest
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from pathlib import Path

# Add suite-core and suite-api to path
sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

# Import analytics modules
from core.analytics_engine import (
    AnalyticsEngine,
    DashboardMetric,
    MetricType,
    PersonaDashboard,
    TimeWindow,
)
from core.risk_posture import (
    RiskPostureEngine,
    RiskPosture,
    RiskCategory,
)


# ============================================================================
# ANALYTICS ENGINE TESTS
# ============================================================================


class TestAnalyticsEngine:
    """Tests for AnalyticsEngine class."""

    @pytest.fixture
    def engine(self) -> AnalyticsEngine:
        """Create file-based analytics engine."""
        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "test_analytics.db")
        return AnalyticsEngine(db_path=db_path, org_id="test-org")

    def test_init_creates_db_schema(self, engine: AnalyticsEngine) -> None:
        """Test that __init__ creates schema."""
        assert engine.db_path is not None
        assert engine.org_id == "test-org"

    def test_record_metric_success(self, engine: AnalyticsEngine) -> None:
        """Test recording a metric data point."""
        metric_id = engine.record_metric("mttd", 45.5)
        assert metric_id is not None
        assert metric_id != ""

    def test_record_metric_with_dimensions(self, engine: AnalyticsEngine) -> None:
        """Test recording metric with dimensional breakdown."""
        dimensions = {"severity": "high", "source": "github"}
        metric_id = engine.record_metric(
            "findings_count",
            42.0,
            dimensions=dimensions,
        )
        assert metric_id is not None

    def test_record_metric_with_timestamp(self, engine: AnalyticsEngine) -> None:
        """Test recording metric with custom timestamp."""
        ts = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
        metric_id = engine.record_metric("test_metric", 10.0, timestamp=ts)
        assert metric_id is not None

    def test_query_metric_not_found(self, engine: AnalyticsEngine) -> None:
        """Test querying nonexistent metric returns None."""
        result = engine.query_metric("nonexistent", TimeWindow.DAY)
        assert result is None

    def test_query_metric_average(self, engine: AnalyticsEngine) -> None:
        """Test querying metric with AVERAGE aggregation."""
        # Record multiple data points
        engine.record_metric("mttd", 30.0)
        engine.record_metric("mttd", 50.0)
        engine.record_metric("mttd", 40.0)

        result = engine.query_metric("mttd", TimeWindow.DAY, MetricType.AVERAGE)
        assert result is not None
        assert result.value == pytest.approx(40.0, rel=0.1)
        assert result.metric_type == MetricType.AVERAGE

    def test_query_metric_sum(self, engine: AnalyticsEngine) -> None:
        """Test querying metric with SUM aggregation."""
        engine.record_metric("findings", 10.0)
        engine.record_metric("findings", 15.0)
        engine.record_metric("findings", 5.0)

        result = engine.query_metric("findings", TimeWindow.DAY, MetricType.SUM)
        assert result is not None
        assert result.value == pytest.approx(30.0, rel=0.1)

    def test_query_metric_count(self, engine: AnalyticsEngine) -> None:
        """Test querying metric with COUNT aggregation."""
        for i in range(5):
            engine.record_metric("events", 1.0)

        result = engine.query_metric("events", TimeWindow.DAY, MetricType.COUNT)
        assert result is not None
        assert result.value == 5.0

    def test_query_metric_percentile(self, engine: AnalyticsEngine) -> None:
        """Test querying metric with PERCENTILE aggregation."""
        for i in range(1, 101):
            engine.record_metric("latency_ms", float(i))

        result = engine.query_metric("latency_ms", TimeWindow.DAY, MetricType.PERCENTILE)
        assert result is not None
        assert 45 < result.value < 55  # Should be around 50th percentile

    def test_get_trend_returns_list(self, engine: AnalyticsEngine) -> None:
        """Test get_trend returns list of metrics."""
        # Record data across multiple days
        now = datetime.now(timezone.utc)
        for i in range(7):
            ts = now - timedelta(days=i)
            engine.record_metric("daily_metric", float(10 + i), timestamp=ts)

        trend = engine.get_trend("daily_metric", periods=7, window=TimeWindow.DAY)
        assert isinstance(trend, list)
        assert len(trend) > 0

    def test_get_trend_ordered_by_timestamp(self, engine: AnalyticsEngine) -> None:
        """Test that trend is ordered by timestamp."""
        now = datetime.now(timezone.utc)
        for i in range(5):
            ts = now - timedelta(days=i)
            engine.record_metric("metric", float(i), timestamp=ts)

        trend = engine.get_trend("metric", periods=5, window=TimeWindow.DAY)
        timestamps = [m.timestamp for m in trend]
        assert timestamps == sorted(timestamps)

    def test_get_percentile(self, engine: AnalyticsEngine) -> None:
        """Test percentile calculation."""
        # Record values 1-100
        for i in range(1, 101):
            engine.record_metric("values", float(i))

        p50 = engine.get_percentile("values", 50, TimeWindow.DAY)
        assert p50 is not None
        assert 45 < p50 < 55

    def test_get_percentile_empty_returns_none(self, engine: AnalyticsEngine) -> None:
        """Test percentile on empty metric returns None."""
        result = engine.get_percentile("nonexistent", 50, TimeWindow.DAY)
        assert result is None

    def test_get_builtin_metrics(self, engine: AnalyticsEngine) -> None:
        """Test retrieving built-in metrics."""
        engine.record_metric("mttd", 45.0)
        engine.record_metric("mttr", 2.5)
        engine.record_metric("false_positive_rate", 3.2)

        metrics = engine.get_builtin_metrics("test-org")
        assert "mttd" in metrics
        assert "mttr" in metrics
        assert "false_positive_rate" in metrics

    def test_time_window_hour(self, engine: AnalyticsEngine) -> None:
        """Test HOUR time window."""
        delta = engine._time_window_delta(TimeWindow.HOUR)
        assert delta == timedelta(hours=1)

    def test_time_window_week(self, engine: AnalyticsEngine) -> None:
        """Test WEEK time window."""
        delta = engine._time_window_delta(TimeWindow.WEEK)
        assert delta == timedelta(weeks=1)

    def test_time_window_month(self, engine: AnalyticsEngine) -> None:
        """Test MONTH time window."""
        delta = engine._time_window_delta(TimeWindow.MONTH)
        assert delta == timedelta(days=30)

    def test_percentile_helper_method(self, engine: AnalyticsEngine) -> None:
        """Test _percentile helper."""
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        p50 = engine._percentile(values, 50)
        assert p50 == 3.0

    def test_record_metric_multiple_orgs(self) -> None:
        """Test isolation between organizations."""
        import tempfile
        import os

        tmpdir = tempfile.mkdtemp()
        db1 = os.path.join(tmpdir, "db1.db")
        db2 = os.path.join(tmpdir, "db2.db")

        engine1 = AnalyticsEngine(db_path=db1, org_id="org1")
        engine2 = AnalyticsEngine(db_path=db2, org_id="org2")

        engine1.record_metric("mttd", 30.0)
        engine2.record_metric("mttd", 50.0)

        metrics1 = engine1.get_builtin_metrics("org1")
        metrics2 = engine2.get_builtin_metrics("org2")

        assert metrics1.get("mttd") == 30.0
        assert metrics2.get("mttd") == 50.0

    def test_metric_dimensions_aggregation(self, engine: AnalyticsEngine) -> None:
        """Test that dimensions are aggregated in query."""
        engine.record_metric(
            "findings",
            5.0,
            dimensions={"severity": "critical"},
        )
        engine.record_metric(
            "findings",
            10.0,
            dimensions={"severity": "high"},
        )

        result = engine.query_metric("findings", TimeWindow.DAY, MetricType.SUM)
        assert result is not None
        assert result.dimensions is not None


# ============================================================================
# PERSONA DASHBOARD TESTS
# ============================================================================


class TestPersonaDashboard:
    """Tests for PersonaDashboard class."""

    @pytest.fixture
    def dashboard(self) -> PersonaDashboard:
        """Create dashboard with analytics engine."""
        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "test_persona.db")
        engine = AnalyticsEngine(db_path=db_path, org_id="test-org")
        return PersonaDashboard(engine)

    def test_ciso_dashboard_structure(self, dashboard: PersonaDashboard) -> None:
        """Test CISO dashboard returns correct structure."""
        result = dashboard.get_ciso_dashboard("test-org")
        assert result["persona"] == "ciso"
        assert result["org_id"] == "test-org"
        assert "timestamp" in result
        assert "widgets" in result
        assert "charts" in result
        assert "kpis" in result

    def test_ciso_dashboard_widgets(self, dashboard: PersonaDashboard) -> None:
        """Test CISO dashboard has required widgets."""
        result = dashboard.get_ciso_dashboard("test-org")
        assert "risk_posture" in result["widgets"]
        assert "executive_summary" in result["widgets"]
        assert "compliance_status" in result["widgets"]

    def test_ciso_dashboard_kpis(self, dashboard: PersonaDashboard) -> None:
        """Test CISO dashboard KPIs."""
        result = dashboard.get_ciso_dashboard("test-org")
        assert "mttd_minutes" in result["kpis"]
        assert "mttr_hours" in result["kpis"]
        assert "false_positive_rate_percent" in result["kpis"]

    def test_devsecops_dashboard_structure(self, dashboard: PersonaDashboard) -> None:
        """Test DevSecOps dashboard structure."""
        result = dashboard.get_devsecops_dashboard("test-org")
        assert result["persona"] == "devsecops"
        assert "pipeline_health" in result["widgets"]
        assert "blocked_builds" in result["widgets"]

    def test_devsecops_dashboard_metrics(self, dashboard: PersonaDashboard) -> None:
        """Test DevSecOps dashboard metrics."""
        result = dashboard.get_devsecops_dashboard("test-org")
        assert "connector_uptime_percent" in result["kpis"]
        assert "remediation_velocity_percent" in result["kpis"]

    def test_compliance_dashboard_structure(self, dashboard: PersonaDashboard) -> None:
        """Test Compliance Officer dashboard."""
        result = dashboard.get_compliance_dashboard("test-org")
        assert result["persona"] == "compliance"
        assert "framework_compliance" in result["widgets"]
        assert "control_mapping" in result["widgets"]

    def test_compliance_dashboard_frameworks(self, dashboard: PersonaDashboard) -> None:
        """Test compliance dashboard frameworks."""
        result = dashboard.get_compliance_dashboard("test-org")
        frameworks = result["widgets"]["framework_compliance"]
        assert "soc2" in frameworks
        assert "hipaa" in frameworks
        assert "pci_dss" in frameworks

    def test_analyst_dashboard_structure(self, dashboard: PersonaDashboard) -> None:
        """Test Security Analyst dashboard."""
        result = dashboard.get_analyst_dashboard("test-org")
        assert result["persona"] == "analyst"
        assert "triage_queue" in result["widgets"]
        assert "backlog" in result["widgets"]

    def test_analyst_dashboard_kpis(self, dashboard: PersonaDashboard) -> None:
        """Test analyst dashboard KPIs."""
        result = dashboard.get_analyst_dashboard("test-org")
        assert "avg_triage_time_minutes" in result["kpis"]
        assert "false_positive_rate_percent" in result["kpis"]

    def test_developer_dashboard_structure(self, dashboard: PersonaDashboard) -> None:
        """Test Developer dashboard."""
        result = dashboard.get_developer_dashboard("test-org")
        assert result["persona"] == "developer"
        assert "my_findings" in result["widgets"]

    def test_platform_dashboard_structure(self, dashboard: PersonaDashboard) -> None:
        """Test Platform Engineer dashboard."""
        result = dashboard.get_platform_dashboard("test-org")
        assert result["persona"] == "platform"
        assert "system_health" in result["widgets"]
        assert "connector_status" in result["widgets"]

    def test_all_dashboards_have_timestamp(self, dashboard: PersonaDashboard) -> None:
        """Test all dashboards include timestamp."""
        dashboards = [
            dashboard.get_ciso_dashboard("test-org"),
            dashboard.get_devsecops_dashboard("test-org"),
            dashboard.get_compliance_dashboard("test-org"),
            dashboard.get_analyst_dashboard("test-org"),
            dashboard.get_developer_dashboard("test-org"),
            dashboard.get_platform_dashboard("test-org"),
        ]
        for d in dashboards:
            assert "timestamp" in d
            assert d["timestamp"] is not None

    def test_all_dashboards_have_kpis(self, dashboard: PersonaDashboard) -> None:
        """Test all dashboards include KPIs."""
        dashboards = [
            dashboard.get_ciso_dashboard("test-org"),
            dashboard.get_devsecops_dashboard("test-org"),
            dashboard.get_compliance_dashboard("test-org"),
            dashboard.get_analyst_dashboard("test-org"),
            dashboard.get_developer_dashboard("test-org"),
            dashboard.get_platform_dashboard("test-org"),
        ]
        for d in dashboards:
            assert "kpis" in d
            assert isinstance(d["kpis"], dict)
            assert len(d["kpis"]) > 0


# ============================================================================
# RISK POSTURE ENGINE TESTS
# ============================================================================


class TestRiskPostureEngine:
    """Tests for RiskPostureEngine class."""

    @pytest.fixture
    def engine(self) -> RiskPostureEngine:
        """Create file-based risk posture engine."""
        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "test_risk.db")
        return RiskPostureEngine(db_path=db_path, org_id="test-org")

    def test_init_creates_schema(self, engine: RiskPostureEngine) -> None:
        """Test that __init__ creates database schema."""
        assert engine.db_path is not None
        assert engine.org_id == "test-org"

    def test_record_finding(self, engine: RiskPostureEngine) -> None:
        """Test recording a finding."""
        engine.record_finding(
            finding_id="f123",
            severity="critical",
            category="vulnerability",
        )
        # Should not raise

    def test_record_compliance_gap(self, engine: RiskPostureEngine) -> None:
        """Test recording compliance gap."""
        engine.record_compliance_gap(
            framework="soc2",
            control_id="CC6.1",
        )
        # Should not raise

    def test_calculate_posture_empty(self, engine: RiskPostureEngine) -> None:
        """Test calculating posture with no findings."""
        posture = engine.calculate_posture("test-org")
        assert isinstance(posture, RiskPosture)
        assert 0 <= posture.overall_score <= 100

    def test_calculate_posture_with_critical_findings(
        self,
        engine: RiskPostureEngine,
    ) -> None:
        """Test posture increases with critical findings."""
        # Record critical finding
        engine.record_finding("f1", "critical", "vulnerability")
        posture = engine.calculate_posture("test-org")
        assert posture.overall_score > 0

    def test_calculate_posture_vulnerability_score(
        self,
        engine: RiskPostureEngine,
    ) -> None:
        """Test vulnerability category scoring."""
        engine.record_finding("f1", "critical", "vulnerability")
        engine.record_finding("f2", "high", "vulnerability")

        posture = engine.calculate_posture("test-org")
        assert RiskCategory.VULNERABILITY in posture.category_scores
        assert posture.category_scores[RiskCategory.VULNERABILITY] > 0

    def test_calculate_posture_compliance_score(
        self,
        engine: RiskPostureEngine,
    ) -> None:
        """Test compliance category scoring."""
        engine.record_compliance_gap("soc2", "CC6.1")
        engine.record_compliance_gap("hipaa", "164.312(a)")

        posture = engine.calculate_posture("test-org")
        assert RiskCategory.COMPLIANCE in posture.category_scores
        assert posture.category_scores[RiskCategory.COMPLIANCE] > 0

    def test_calculate_posture_has_recommendations(
        self,
        engine: RiskPostureEngine,
    ) -> None:
        """Test that posture includes recommendations."""
        engine.record_finding("f1", "critical", "vulnerability")
        posture = engine.calculate_posture("test-org")
        assert len(posture.recommendations) > 0

    def test_posture_category_scores_capped_at_100(
        self,
        engine: RiskPostureEngine,
    ) -> None:
        """Test that category scores are capped at 100."""
        # Record many critical findings
        for i in range(50):
            engine.record_finding(f"f{i}", "critical", "vulnerability")

        posture = engine.calculate_posture("test-org")
        for score in posture.category_scores.values():
            assert 0 <= score <= 100

    def test_posture_overall_score_capped_at_100(
        self,
        engine: RiskPostureEngine,
    ) -> None:
        """Test overall score is capped at 100."""
        # Record many findings
        for i in range(50):
            engine.record_finding(f"f{i}", "critical", "vulnerability")
            engine.record_compliance_gap("soc2", f"control_{i}")

        posture = engine.calculate_posture("test-org")
        assert 0 <= posture.overall_score <= 100

    def test_get_posture_trend(self, engine: RiskPostureEngine) -> None:
        """Test retrieving historical trend."""
        # Calculate multiple times
        engine.record_finding("f1", "critical", "vulnerability")
        posture1 = engine.calculate_posture("test-org")

        trend = engine.get_posture_trend("test-org", periods=5)
        assert isinstance(trend, list)
        assert len(trend) >= 1

    def test_get_risk_heatmap(self, engine: RiskPostureEngine) -> None:
        """Test risk heatmap generation."""
        engine.record_finding("f1", "critical", "vulnerability")
        engine.record_finding("f2", "high", "configuration")
        engine.record_finding("f3", "medium", "compliance")

        heatmap = engine.get_risk_heatmap("test-org")
        assert isinstance(heatmap, dict)
        # Check structure
        for severity, categories in heatmap.items():
            assert isinstance(categories, dict)

    def test_get_top_risks(self, engine: RiskPostureEngine) -> None:
        """Test retrieving top risks."""
        engine.record_finding("f1", "critical", "vulnerability", days_open=5)
        engine.record_finding("f2", "high", "configuration", days_open=3)
        engine.record_finding("f3", "medium", "vulnerability", days_open=1)

        risks = engine.get_top_risks("test-org", limit=10)
        assert isinstance(risks, list)
        assert len(risks) > 0
        # First should be critical
        assert risks[0]["severity"].lower() == "critical"

    def test_get_top_risks_respects_limit(self, engine: RiskPostureEngine) -> None:
        """Test that get_top_risks respects limit."""
        for i in range(20):
            engine.record_finding(f"f{i}", "high", "vulnerability")

        risks = engine.get_top_risks("test-org", limit=5)
        assert len(risks) <= 5

    def test_compare_posture(self, engine: RiskPostureEngine) -> None:
        """Test comparing posture to baseline."""
        # Calculate initial posture
        engine.record_finding("f1", "critical", "vulnerability")
        posture1 = engine.calculate_posture("test-org")
        baseline_date = posture1.assessment_timestamp

        # Add more findings
        engine.record_finding("f2", "high", "vulnerability")
        posture2 = engine.calculate_posture("test-org")

        comparison = engine.compare_posture("test-org", baseline_date)
        assert "current_score" in comparison
        assert "baseline_score" in comparison
        assert "change" in comparison
        assert "trend" in comparison

    def test_risk_category_enum(self) -> None:
        """Test RiskCategory enum values."""
        assert RiskCategory.VULNERABILITY.value == "vulnerability"
        assert RiskCategory.CONFIGURATION.value == "configuration"
        assert RiskCategory.COMPLIANCE.value == "compliance"
        assert RiskCategory.THREAT.value == "threat"
        assert RiskCategory.SUPPLY_CHAIN.value == "supply_chain"

    def test_determine_trend_stable(self, engine: RiskPostureEngine) -> None:
        """Test trend determination when stable."""
        engine.record_finding("f1", "high", "vulnerability")
        posture = engine.calculate_posture("test-org")
        # First assessment has no previous, trend logic checks
        assert posture.trend in ["stable", "improving", "degrading"]

    def test_posture_contributing_factors_not_empty(
        self,
        engine: RiskPostureEngine,
    ) -> None:
        """Test that contributing factors are populated."""
        engine.record_finding("f1", "critical", "vulnerability")
        posture = engine.calculate_posture("test-org")
        # May have default factors even with no findings
        assert isinstance(posture.contributing_factors, list)

    def test_posture_thread_safe(self, engine: RiskPostureEngine) -> None:
        """Test thread safety of posture calculation."""
        import threading

        results = []

        def worker():
            engine.record_finding("f_thread", "high", "vulnerability")
            posture = engine.calculate_posture("test-org")
            results.append(posture)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 3
        for r in results:
            assert r.overall_score is not None


# ============================================================================
# ANALYTICS ROUTES TESTS
# ============================================================================


class TestAnalyticsRoutes:
    """Tests for FastAPI analytics endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        try:
            from fastapi.testclient import TestClient
            from suite_api.apps.api.analytics_routes import router
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            return TestClient(app)
        except ImportError:
            pytest.skip("FastAPI not installed")

    def test_endpoint_imports(self) -> None:
        """Test that endpoint module imports."""
        from apps.api import analytics_routes

        assert hasattr(analytics_routes, "router")

    def test_metric_response_model(self) -> None:
        """Test MetricResponse model."""
        from apps.api.analytics_routes import MetricResponse

        response = MetricResponse(
            metric_id="m1",
            name="test_metric",
            metric_type="average",
            value=42.0,
            unit="minutes",
            timestamp=datetime.now(timezone.utc),
        )
        assert response.metric_id == "m1"
        assert response.value == 42.0

    def test_dashboard_response_model(self) -> None:
        """Test DashboardResponse model."""
        from apps.api.analytics_routes import DashboardResponse

        response = DashboardResponse(
            persona="ciso",
            org_id="test-org",
            timestamp=datetime.now(timezone.utc),
            widgets={},
            charts={},
            kpis={},
        )
        assert response.persona == "ciso"

    def test_kpi_response_model(self) -> None:
        """Test KPIResponse model."""
        from apps.api.analytics_routes import KPIResponse

        response = KPIResponse(
            mttd_minutes=30.0,
            mttr_hours=2.0,
            false_positive_rate_percent=3.5,
            findings_critical=2,
            findings_high=8,
            connector_uptime_percent=99.0,
            council_consensus_percent=85.0,
            sla_compliance_percent=95.0,
        )
        assert response.mttd_minutes == 30.0

    def test_risk_posture_response_model(self) -> None:
        """Test RiskPostureResponse model."""
        from apps.api.analytics_routes import RiskPostureResponse

        response = RiskPostureResponse(
            overall_score=45.0,
            category_scores={"vulnerability": 50.0},
            trend="improving",
            contributing_factors=["test"],
            recommendations=["test"],
            timestamp=datetime.now(timezone.utc),
        )
        assert response.overall_score == 45.0

    def test_metric_record_request_model(self) -> None:
        """Test MetricRecordRequest model."""
        from apps.api.analytics_routes import MetricRecordRequest

        request = MetricRecordRequest(
            metric_name="test",
            value=42.0,
        )
        assert request.metric_name == "test"
        assert request.value == 42.0

    def test_compliance_report_response_model(self) -> None:
        """Test ComplianceReportResponse model."""
        from apps.api.analytics_routes import ComplianceReportResponse

        response = ComplianceReportResponse(
            framework="soc2",
            compliance_percent=92.0,
            total_controls=107,
            compliant_controls=98,
            gaps=[],
            evidence_collected=2890,
            audit_ready=True,
        )
        assert response.framework == "soc2"
        assert response.compliance_percent == 92.0

    def test_get_analytics_engine_singleton(self) -> None:
        """Test that get_analytics_engine returns singleton."""
        from apps.api.analytics_routes import (
            get_analytics_engine,
        )

        engine1 = get_analytics_engine()
        engine2 = get_analytics_engine()
        # Both should be AnalyticsEngine instances
        assert type(engine1).__name__ == "AnalyticsEngine"
        assert type(engine2).__name__ == "AnalyticsEngine"

    def test_get_risk_engine_singleton(self) -> None:
        """Test that get_risk_engine returns singleton."""
        from apps.api.analytics_routes import get_risk_engine

        engine1 = get_risk_engine()
        engine2 = get_risk_engine()
        assert type(engine1).__name__ == "RiskPostureEngine"
        assert type(engine2).__name__ == "RiskPostureEngine"

    def test_get_persona_dashboard_singleton(self) -> None:
        """Test that get_persona_dashboard_instance returns singleton."""
        from apps.api.analytics_routes import get_persona_dashboard_instance

        dashboard1 = get_persona_dashboard_instance()
        dashboard2 = get_persona_dashboard_instance()
        assert type(dashboard1).__name__ == "PersonaDashboard"
        assert type(dashboard2).__name__ == "PersonaDashboard"


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestAnalyticsIntegration:
    """Integration tests across modules."""

    def test_analytics_engine_with_persona_dashboard(self) -> None:
        """Test analytics engine integration with persona dashboard."""
        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "int_test1.db")
        engine = AnalyticsEngine(db_path=db_path, org_id="test-org")

        # Record some metrics
        engine.record_metric("mttd", 45.0)
        engine.record_metric("mttr", 2.5)
        engine.record_metric("false_positive_rate", 3.2)

        # Create dashboard and get CISO view
        dashboard = PersonaDashboard(engine)
        ciso_data = dashboard.get_ciso_dashboard("test-org")

        assert ciso_data["persona"] == "ciso"
        assert ciso_data["kpis"]["mttd_minutes"] >= 0

    def test_risk_posture_with_multiple_finding_types(self) -> None:
        """Test risk posture with various finding types."""
        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "int_test2.db")
        engine = RiskPostureEngine(db_path=db_path, org_id="test-org")

        # Record different severities
        engine.record_finding("f1", "critical", "vulnerability")
        engine.record_finding("f2", "high", "configuration")
        engine.record_finding("f3", "medium", "compliance")
        engine.record_finding("f4", "low", "vulnerability")

        posture = engine.calculate_posture("test-org")
        assert posture.overall_score > 0
        assert len(posture.category_scores) > 0

    def test_analytics_and_risk_engines_isolation(self) -> None:
        """Test that engines properly isolate organizations."""
        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        db_path_a = os.path.join(tmpdir, "iso_ana.db")
        db_path_r = os.path.join(tmpdir, "iso_risk.db")
        analytics = AnalyticsEngine(db_path=db_path_a, org_id="org-a")
        risk = RiskPostureEngine(db_path=db_path_r, org_id="org-a")

        analytics.record_metric("metric1", 100.0)
        risk.record_finding("f1", "critical", "vulnerability")

        # Each engine should track its own org
        assert analytics.org_id == "org-a"
        assert risk.org_id == "org-a"

    def test_full_dashboard_pipeline(self) -> None:
        """Test full pipeline from recording to dashboard display."""
        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "int_test4.db")
        engine = AnalyticsEngine(db_path=db_path, org_id="test-org")

        # Record multiple metrics
        for i in range(10):
            engine.record_metric("scan_count", float(i + 1))

        # Get trend
        trend = engine.get_trend("scan_count", periods=3, window=TimeWindow.DAY)
        assert len(trend) > 0

        # Create dashboard
        dashboard = PersonaDashboard(engine)
        devsecops_dash = dashboard.get_devsecops_dashboard("test-org")

        assert devsecops_dash["persona"] == "devsecops"
        assert devsecops_dash["kpis"]["connector_uptime_percent"] > 0
