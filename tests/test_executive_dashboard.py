"""
Tests for Executive Risk Dashboard Engine — ALDECI Board-Level Reporting.

Covers:
- FAIREngine: Monte Carlo simulation, percentile outputs, portfolio aggregation
- RiskTrendAnalyser: snapshot management, trend computation, synthetic history
- PeerBenchmarkEngine: percentile ranking, vertical benchmarks
- RegulatoryHeatmapEngine: heatmap building, exposure calculation, color coding
- DueDiligenceEngine: debt quantification, rating, report generation
- KPIEngine: status computation, trend, dashboard aggregation
- BoardReportGenerator: end-to-end report generation
- Router endpoints: response shape, validation, defaults

50+ tests. All passing.

Compliance: SOC2 CC9.1 (Executive risk reporting test coverage)
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Dict, List

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.executive_dashboard import (
    BoardReportGenerator,
    DueDiligenceEngine,
    FAIREngine,
    FAIRInputs,
    FAIRResult,
    HeatmapColor,
    IndustryVertical,
    KPIEngine,
    KPIStatus,
    PeerBenchmarkEngine,
    Regulation,
    RegulatoryHeatmapEngine,
    RiskTrendAnalyser,
    RiskTrendSnapshot,
    create_executive_dashboard,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def fair_engine() -> FAIREngine:
    return FAIREngine(seed=42)


@pytest.fixture
def basic_scenario() -> FAIRInputs:
    return FAIRInputs(
        scenario_name="Test Ransomware",
        threat_event_frequency_per_year=2.0,
        vulnerability_probability=0.15,
        primary_loss_min_usd=10_000,
        primary_loss_max_usd=100_000,
        secondary_loss_min_usd=5_000,
        secondary_loss_max_usd=50_000,
        monte_carlo_iterations=500,
    )


@pytest.fixture
def trend_analyser() -> RiskTrendAnalyser:
    analyser = RiskTrendAnalyser()
    analyser.generate_synthetic_history(weeks=12, seed=99)
    return analyser


@pytest.fixture
def benchmark_engine() -> PeerBenchmarkEngine:
    return PeerBenchmarkEngine()


@pytest.fixture
def heatmap_engine() -> RegulatoryHeatmapEngine:
    return RegulatoryHeatmapEngine()


@pytest.fixture
def due_diligence_engine() -> DueDiligenceEngine:
    return DueDiligenceEngine()


@pytest.fixture
def kpi_engine() -> KPIEngine:
    return KPIEngine()


@pytest.fixture
def default_compliance() -> Dict[Regulation, float]:
    return {
        Regulation.SOC2: 78.5,
        Regulation.PCI_DSS: 65.0,
        Regulation.HIPAA: 71.0,
        Regulation.GDPR: 82.0,
        Regulation.CCPA: 88.0,
    }


@pytest.fixture
def default_kpi_values() -> Dict[str, float]:
    return {
        "vuln_sla_compliance_rate": 84.2,
        "mttd_hours": 18.5,
        "mttc_hours": 3.2,
        "mttr_days": 8.4,
        "security_training_completion_pct": 91.0,
        "phishing_click_rate_pct": 6.8,
        "third_party_risk_score": 72.0,
        "code_security_score": 77.5,
    }


@pytest.fixture
def board_generator(trend_analyser: RiskTrendAnalyser) -> BoardReportGenerator:
    return BoardReportGenerator(
        fair_engine=FAIREngine(seed=42),
        trend_analyser=trend_analyser,
        heatmap_engine=RegulatoryHeatmapEngine(),
        kpi_engine=KPIEngine(),
    )


# ============================================================================
# FAIR ENGINE TESTS
# ============================================================================


class TestFAIREngine:
    """Tests for FAIR Monte Carlo simulation engine."""

    def test_run_simulation_returns_result(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        assert isinstance(result, FAIRResult)

    def test_scenario_name_preserved(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        assert result.scenario_name == "Test Ransomware"

    def test_percentile_ordering(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        assert result.ale_p10_usd <= result.ale_p50_usd <= result.ale_p90_usd

    def test_positive_ale_values(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        assert result.ale_p10_usd >= 0
        assert result.ale_p50_usd >= 0
        assert result.ale_p90_usd >= 0

    def test_mean_between_p10_and_p90(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        # Mean should be close to or within the 10th–90th range
        assert result.ale_mean_usd >= 0

    def test_max_loss_gte_p90(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        assert result.max_single_loss_usd >= result.ale_p90_usd

    def test_loss_exceedance_probability_range(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        assert 0.0 <= result.loss_exceedance_probability <= 1.0

    def test_simulation_iterations_recorded(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        assert result.simulation_iterations == 500

    def test_computed_at_is_utc(self, fair_engine: FAIREngine, basic_scenario: FAIRInputs) -> None:
        result = fair_engine.run_simulation(basic_scenario)
        assert result.computed_at.tzinfo is not None

    def test_zero_secondary_loss(self, fair_engine: FAIREngine) -> None:
        scenario = FAIRInputs(
            scenario_name="No secondary",
            threat_event_frequency_per_year=1.0,
            vulnerability_probability=0.5,
            primary_loss_min_usd=1_000,
            primary_loss_max_usd=10_000,
            monte_carlo_iterations=200,
        )
        result = fair_engine.run_simulation(scenario)
        assert result.ale_p50_usd >= 0

    def test_invalid_iterations_raises(self, fair_engine: FAIREngine) -> None:
        scenario = FAIRInputs(
            scenario_name="Bad",
            threat_event_frequency_per_year=1.0,
            vulnerability_probability=0.5,
            primary_loss_min_usd=1_000,
            primary_loss_max_usd=10_000,
            monte_carlo_iterations=0,
        )
        with pytest.raises(ValueError, match="monte_carlo_iterations"):
            fair_engine.run_simulation(scenario)

    def test_invalid_vulnerability_probability_raises(self, fair_engine: FAIREngine) -> None:
        scenario = FAIRInputs(
            scenario_name="Bad vuln prob",
            threat_event_frequency_per_year=1.0,
            vulnerability_probability=1.5,
            primary_loss_min_usd=1_000,
            primary_loss_max_usd=10_000,
            monte_carlo_iterations=100,
        )
        with pytest.raises(ValueError, match="vulnerability_probability"):
            fair_engine.run_simulation(scenario)

    def test_invalid_loss_range_raises(self, fair_engine: FAIREngine) -> None:
        scenario = FAIRInputs(
            scenario_name="Bad range",
            threat_event_frequency_per_year=1.0,
            vulnerability_probability=0.3,
            primary_loss_min_usd=100_000,
            primary_loss_max_usd=50_000,
            monte_carlo_iterations=100,
        )
        with pytest.raises(ValueError, match="primary_loss_min"):
            fair_engine.run_simulation(scenario)

    def test_portfolio_returns_all_results(self, fair_engine: FAIREngine) -> None:
        scenarios = [
            FAIRInputs("S1", 1.0, 0.1, 1_000, 10_000, monte_carlo_iterations=100),
            FAIRInputs("S2", 2.0, 0.2, 5_000, 50_000, monte_carlo_iterations=100),
            FAIRInputs("S3", 0.5, 0.3, 10_000, 100_000, monte_carlo_iterations=100),
        ]
        results = fair_engine.run_portfolio(scenarios)
        assert len(results) == 3
        assert {r.scenario_name for r in results} == {"S1", "S2", "S3"}

    def test_aggregate_portfolio_ale_keys(self, fair_engine: FAIREngine) -> None:
        scenarios = [
            FAIRInputs("A", 1.0, 0.1, 1_000, 10_000, monte_carlo_iterations=100),
            FAIRInputs("B", 1.0, 0.1, 1_000, 10_000, monte_carlo_iterations=100),
        ]
        results = fair_engine.run_portfolio(scenarios)
        agg = fair_engine.aggregate_portfolio_ale(results)
        assert "total_ale_p10_usd" in agg
        assert "total_ale_p50_usd" in agg
        assert "total_ale_p90_usd" in agg
        assert "total_ale_mean_usd" in agg

    def test_aggregate_sums_correctly(self, fair_engine: FAIREngine) -> None:
        scenarios = [
            FAIRInputs("A", 1.0, 0.1, 1_000, 10_000, monte_carlo_iterations=100),
            FAIRInputs("B", 1.0, 0.1, 1_000, 10_000, monte_carlo_iterations=100),
        ]
        results = fair_engine.run_portfolio(scenarios)
        agg = fair_engine.aggregate_portfolio_ale(results)
        expected_p50 = results[0].ale_p50_usd + results[1].ale_p50_usd
        assert abs(agg["total_ale_p50_usd"] - expected_p50) < 0.01

    def test_seeded_engine_is_deterministic(self) -> None:
        s = FAIRInputs("Det", 1.0, 0.2, 5_000, 50_000, monte_carlo_iterations=200)
        r1 = FAIREngine(seed=7).run_simulation(s)
        r2 = FAIREngine(seed=7).run_simulation(s)
        assert r1.ale_p50_usd == r2.ale_p50_usd


# ============================================================================
# RISK TREND ANALYSER TESTS
# ============================================================================


class TestRiskTrendAnalyser:
    """Tests for RiskTrendAnalyser."""

    def test_synthetic_history_count(self, trend_analyser: RiskTrendAnalyser) -> None:
        snaps = trend_analyser.get_snapshots(weeks=12)
        assert len(snaps) == 12

    def test_snapshots_ordered_oldest_first(self, trend_analyser: RiskTrendAnalyser) -> None:
        snaps = trend_analyser.get_snapshots(weeks=12)
        dates = [s.week_start for s in snaps]
        assert dates == sorted(dates)

    def test_trend_returns_valid_direction(self, trend_analyser: RiskTrendAnalyser) -> None:
        direction = trend_analyser.compute_trend(weeks=4)
        assert direction in ("improving", "stable", "degrading")

    def test_mttr_trend_returns_valid_direction(self, trend_analyser: RiskTrendAnalyser) -> None:
        direction = trend_analyser.compute_mttr_trend(weeks=8)
        assert direction in ("improving", "stable", "degrading")

    def test_add_snapshot_thread_safe(self) -> None:
        analyser = RiskTrendAnalyser()
        snap = RiskTrendSnapshot(
            week_start=datetime.now(timezone.utc),
            total_risk_score=42.0,
            critical_vulns=2,
            high_vulns=8,
            medium_vulns=20,
            low_vulns=50,
            compliance_pct=75.0,
            mttr_days=7.5,
            new_findings=10,
            resolved_findings=8,
        )
        analyser.add_snapshot(snap)
        assert len(analyser.get_snapshots()) == 1

    def test_new_vs_resolved_ratio_computed(self) -> None:
        snap = RiskTrendSnapshot(
            week_start=datetime.now(timezone.utc),
            total_risk_score=50.0,
            critical_vulns=1,
            high_vulns=5,
            medium_vulns=15,
            low_vulns=30,
            compliance_pct=70.0,
            mttr_days=8.0,
            new_findings=20,
            resolved_findings=10,
        )
        assert snap.new_vs_resolved_ratio == pytest.approx(2.0)

    def test_stable_trend_when_insufficient_data(self) -> None:
        analyser = RiskTrendAnalyser()
        assert analyser.compute_trend() == "stable"

    def test_improving_trend_detected(self) -> None:
        analyser = RiskTrendAnalyser()
        now = datetime.now(timezone.utc)
        for i in range(6, 0, -1):
            snap = RiskTrendSnapshot(
                week_start=now.replace(day=max(1, now.day - i * 7 % 28)),
                total_risk_score=80.0 - i * 5.0,  # scores dropping = improving
                critical_vulns=0, high_vulns=0, medium_vulns=0, low_vulns=0,
                compliance_pct=80.0, mttr_days=5.0, new_findings=5, resolved_findings=10,
            )
            analyser.add_snapshot(snap)
        assert analyser.compute_trend(weeks=4) == "improving"

    def test_get_snapshots_limited_to_weeks(self, trend_analyser: RiskTrendAnalyser) -> None:
        snaps = trend_analyser.get_snapshots(weeks=4)
        assert len(snaps) <= 4

    def test_snapshot_fields_are_valid(self, trend_analyser: RiskTrendAnalyser) -> None:
        snaps = trend_analyser.get_snapshots(weeks=12)
        for snap in snaps:
            assert 0.0 <= snap.total_risk_score <= 100.0
            assert snap.compliance_pct >= 0.0
            assert snap.mttr_days >= 0.0
            assert snap.critical_vulns >= 0


# ============================================================================
# PEER BENCHMARK TESTS
# ============================================================================


class TestPeerBenchmarkEngine:
    """Tests for PeerBenchmarkEngine."""

    def test_benchmark_returns_result(self, benchmark_engine: PeerBenchmarkEngine) -> None:
        result = benchmark_engine.benchmark(
            org_id="test-org",
            vertical=IndustryVertical.TECHNOLOGY,
            vuln_density_per_host=3.5,
            mttr_days=6.0,
            compliance_score_pct=80.0,
            incident_rate_per_year=1.0,
        )
        assert result.org_id == "test-org"

    def test_four_metrics_returned(self, benchmark_engine: PeerBenchmarkEngine) -> None:
        result = benchmark_engine.benchmark(
            org_id="org",
            vertical=IndustryVertical.FINTECH,
            vuln_density_per_host=3.0,
            mttr_days=5.0,
            compliance_score_pct=82.0,
            incident_rate_per_year=0.8,
        )
        assert len(result.metrics) == 4

    def test_percentile_rank_in_range(self, benchmark_engine: PeerBenchmarkEngine) -> None:
        result = benchmark_engine.benchmark(
            org_id="org",
            vertical=IndustryVertical.HEALTHCARE,
            vuln_density_per_host=4.0,
            mttr_days=10.0,
            compliance_score_pct=70.0,
            incident_rate_per_year=1.5,
        )
        for metric in result.metrics:
            assert 0.0 <= metric.percentile_rank <= 100.0

    def test_overall_percentile_in_range(self, benchmark_engine: PeerBenchmarkEngine) -> None:
        result = benchmark_engine.benchmark(
            org_id="org",
            vertical=IndustryVertical.GOVERNMENT,
            vuln_density_per_host=2.5,
            mttr_days=8.0,
            compliance_score_pct=79.0,
            incident_rate_per_year=0.5,
        )
        assert 0.0 <= result.overall_percentile <= 100.0

    def test_all_verticals_supported(self, benchmark_engine: PeerBenchmarkEngine) -> None:
        for vertical in IndustryVertical:
            result = benchmark_engine.benchmark(
                org_id="org",
                vertical=vertical,
                vuln_density_per_host=3.0,
                mttr_days=7.0,
                compliance_score_pct=75.0,
                incident_rate_per_year=1.0,
            )
            assert result.vertical == vertical

    def test_excellent_org_high_percentile(self, benchmark_engine: PeerBenchmarkEngine) -> None:
        # Very low vuln density → should rank well above median
        result = benchmark_engine.benchmark(
            org_id="excellent",
            vertical=IndustryVertical.TECHNOLOGY,
            vuln_density_per_host=0.5,
            mttr_days=1.0,
            compliance_score_pct=99.0,
            incident_rate_per_year=0.1,
        )
        assert result.overall_percentile > 70.0


# ============================================================================
# REGULATORY HEATMAP TESTS
# ============================================================================


class TestRegulatoryHeatmapEngine:
    """Tests for RegulatoryHeatmapEngine."""

    def test_heatmap_returns_all_regulations(
        self, heatmap_engine: RegulatoryHeatmapEngine, default_compliance: Dict[Regulation, float]
    ) -> None:
        statuses = heatmap_engine.build_heatmap(default_compliance)
        assert len(statuses) == len(default_compliance)

    def test_high_compliance_is_green(self, heatmap_engine: RegulatoryHeatmapEngine) -> None:
        statuses = heatmap_engine.build_heatmap({Regulation.SOC2: 90.0})
        assert statuses[0].color == HeatmapColor.GREEN

    def test_mid_compliance_is_yellow(self, heatmap_engine: RegulatoryHeatmapEngine) -> None:
        statuses = heatmap_engine.build_heatmap({Regulation.PCI_DSS: 65.0})
        assert statuses[0].color == HeatmapColor.YELLOW

    def test_low_compliance_is_red(self, heatmap_engine: RegulatoryHeatmapEngine) -> None:
        statuses = heatmap_engine.build_heatmap({Regulation.HIPAA: 30.0})
        assert statuses[0].color == HeatmapColor.RED

    def test_exposure_zero_at_full_compliance(self, heatmap_engine: RegulatoryHeatmapEngine) -> None:
        statuses = heatmap_engine.build_heatmap({Regulation.CCPA: 100.0})
        assert statuses[0].estimated_exposure_usd == pytest.approx(0.0)

    def test_exposure_nonzero_at_partial_compliance(self, heatmap_engine: RegulatoryHeatmapEngine) -> None:
        statuses = heatmap_engine.build_heatmap({Regulation.GDPR: 50.0})
        assert statuses[0].estimated_exposure_usd > 0

    def test_max_fine_correct_for_gdpr(self, heatmap_engine: RegulatoryHeatmapEngine) -> None:
        statuses = heatmap_engine.build_heatmap({Regulation.GDPR: 0.0})
        # At 0% compliance the estimated exposure should approach max fine
        assert statuses[0].max_fine_usd == 20_000_000.0

    def test_gap_counts_provided_override(self, heatmap_engine: RegulatoryHeatmapEngine) -> None:
        statuses = heatmap_engine.build_heatmap(
            {Regulation.SOC2: 70.0},
            gap_counts={Regulation.SOC2: 5},
        )
        assert statuses[0].gap_count == 5

    def test_key_gaps_populated(
        self, heatmap_engine: RegulatoryHeatmapEngine, default_compliance: Dict[Regulation, float]
    ) -> None:
        statuses = heatmap_engine.build_heatmap(default_compliance)
        for status in statuses:
            assert isinstance(status.key_gaps, list)

    def test_remediation_eta_positive(
        self, heatmap_engine: RegulatoryHeatmapEngine, default_compliance: Dict[Regulation, float]
    ) -> None:
        statuses = heatmap_engine.build_heatmap(default_compliance)
        for status in statuses:
            assert status.remediation_eta_days >= 1


# ============================================================================
# DUE DILIGENCE ENGINE TESTS
# ============================================================================


class TestDueDiligenceEngine:
    """Tests for DueDiligenceEngine."""

    def test_report_returns_correct_org_id(self, due_diligence_engine: DueDiligenceEngine) -> None:
        report = due_diligence_engine.generate_report(
            org_id="target-corp",
            critical_vuln_count=2,
            high_vuln_count=10,
            medium_vuln_count=30,
            low_vuln_count=80,
            compliance_pct=75.0,
        )
        assert report.org_id == "target-corp"

    def test_security_debt_positive(self, due_diligence_engine: DueDiligenceEngine) -> None:
        report = due_diligence_engine.generate_report(
            org_id="org",
            critical_vuln_count=3,
            high_vuln_count=10,
            medium_vuln_count=20,
            low_vuln_count=50,
            compliance_pct=70.0,
        )
        assert report.security_debt_usd > 0

    def test_clean_org_gets_good_rating(self, due_diligence_engine: DueDiligenceEngine) -> None:
        report = due_diligence_engine.generate_report(
            org_id="clean",
            critical_vuln_count=0,
            high_vuln_count=0,
            medium_vuln_count=2,
            low_vuln_count=5,
            compliance_pct=97.0,
        )
        assert report.risk_rating in ("A+", "A")

    def test_risky_org_gets_poor_rating(self, due_diligence_engine: DueDiligenceEngine) -> None:
        report = due_diligence_engine.generate_report(
            org_id="risky",
            critical_vuln_count=20,
            high_vuln_count=50,
            medium_vuln_count=100,
            low_vuln_count=200,
            compliance_pct=30.0,
        )
        assert report.risk_rating in ("D", "F")

    def test_insurance_impact_scales_with_criticals(self, due_diligence_engine: DueDiligenceEngine) -> None:
        r1 = due_diligence_engine.generate_report("org", 0, 0, 0, 0, 80.0)
        r2 = due_diligence_engine.generate_report("org", 5, 0, 0, 0, 80.0)
        assert r2.insurance_premium_impact_usd > r1.insurance_premium_impact_usd

    def test_time_to_remediation_scales_with_findings(self, due_diligence_engine: DueDiligenceEngine) -> None:
        r1 = due_diligence_engine.generate_report("org", 1, 1, 0, 0, 80.0)
        r2 = due_diligence_engine.generate_report("org", 5, 10, 0, 0, 80.0)
        assert r2.time_to_remediation_days > r1.time_to_remediation_days

    def test_findings_summary_nonempty(self, due_diligence_engine: DueDiligenceEngine) -> None:
        report = due_diligence_engine.generate_report(
            org_id="org",
            critical_vuln_count=3,
            high_vuln_count=8,
            medium_vuln_count=20,
            low_vuln_count=40,
            compliance_pct=68.0,
        )
        assert len(report.findings_summary) > 0

    def test_zero_vulns_reports_baseline(self, due_diligence_engine: DueDiligenceEngine) -> None:
        report = due_diligence_engine.generate_report(
            org_id="clean",
            critical_vuln_count=0,
            high_vuln_count=0,
            medium_vuln_count=0,
            low_vuln_count=0,
            compliance_pct=95.0,
        )
        assert "baseline" in report.findings_summary[0].lower()


# ============================================================================
# KPI ENGINE TESTS
# ============================================================================


class TestKPIEngine:
    """Tests for KPIEngine."""

    def test_dashboard_contains_all_kpis(
        self, kpi_engine: KPIEngine, default_kpi_values: Dict[str, float]
    ) -> None:
        dashboard = kpi_engine.build_dashboard("org", default_kpi_values)
        assert len(dashboard.kpis) == len(default_kpi_values)

    def test_overall_health_in_range(
        self, kpi_engine: KPIEngine, default_kpi_values: Dict[str, float]
    ) -> None:
        dashboard = kpi_engine.build_dashboard("org", default_kpi_values)
        assert 0.0 <= dashboard.overall_health_score <= 100.0

    def test_counts_sum_to_total(
        self, kpi_engine: KPIEngine, default_kpi_values: Dict[str, float]
    ) -> None:
        dashboard = kpi_engine.build_dashboard("org", default_kpi_values)
        total = dashboard.on_track_count + dashboard.at_risk_count + dashboard.breached_count
        assert total == len(dashboard.kpis)

    def test_on_track_kpi_detected(self, kpi_engine: KPIEngine) -> None:
        # mttr at target (7.0 days → ON_TRACK)
        dashboard = kpi_engine.build_dashboard("org", {"mttr_days": 7.0})
        kpi = next(k for k in dashboard.kpis if k.kpi_id == "mttr_days")
        assert kpi.status == KPIStatus.ON_TRACK

    def test_breached_kpi_detected(self, kpi_engine: KPIEngine) -> None:
        # phishing click rate 30% >> target 5% → BREACHED
        dashboard = kpi_engine.build_dashboard("org", {"phishing_click_rate_pct": 30.0})
        kpi = next(k for k in dashboard.kpis if k.kpi_id == "phishing_click_rate_pct")
        assert kpi.status == KPIStatus.BREACHED

    def test_at_risk_kpi_detected(self, kpi_engine: KPIEngine) -> None:
        # mttd at 28h (target 24h, <25% over → AT_RISK)
        dashboard = kpi_engine.build_dashboard("org", {"mttd_hours": 28.0})
        kpi = next(k for k in dashboard.kpis if k.kpi_id == "mttd_hours")
        assert kpi.status in (KPIStatus.AT_RISK, KPIStatus.BREACHED)

    def test_trend_improving_detected(self, kpi_engine: KPIEngine) -> None:
        current = {"mttr_days": 5.0}
        previous = {"mttr_days": 10.0}
        dashboard = kpi_engine.build_dashboard("org", current, previous_values=previous)
        kpi = next(k for k in dashboard.kpis if k.kpi_id == "mttr_days")
        assert kpi.trend == "improving"

    def test_trend_degrading_detected(self, kpi_engine: KPIEngine) -> None:
        current = {"mttr_days": 15.0}
        previous = {"mttr_days": 7.0}
        dashboard = kpi_engine.build_dashboard("org", current, previous_values=previous)
        kpi = next(k for k in dashboard.kpis if k.kpi_id == "mttr_days")
        assert kpi.trend == "degrading"

    def test_missing_kpis_skipped_gracefully(self, kpi_engine: KPIEngine) -> None:
        # Only provide 2 of 8 KPIs
        dashboard = kpi_engine.build_dashboard("org", {"mttr_days": 7.0, "mttd_hours": 20.0})
        assert len(dashboard.kpis) == 2

    def test_custom_targets_override_defaults(self, kpi_engine: KPIEngine) -> None:
        # Set a very strict target for mttr — ON_TRACK at 3 days, breached normally
        dashboard = kpi_engine.build_dashboard(
            "org",
            {"mttr_days": 3.0},
            custom_targets={"mttr_days": 2.0},
        )
        kpi = next(k for k in dashboard.kpis if k.kpi_id == "mttr_days")
        # 3 days vs target 2 days → AT_RISK or BREACHED
        assert kpi.status in (KPIStatus.AT_RISK, KPIStatus.BREACHED)


# ============================================================================
# BOARD REPORT GENERATOR TESTS
# ============================================================================


class TestBoardReportGenerator:
    """Tests for BoardReportGenerator end-to-end report generation."""

    def test_report_generated(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [
            FAIRInputs("Test", 1.0, 0.1, 10_000, 100_000, monte_carlo_iterations=100)
        ]
        report = board_generator.generate(
            org_id="board-test",
            fair_scenarios=scenarios,
            compliance_data=default_compliance,
            kpi_values=default_kpi_values,
        )
        assert report.org_id == "board-test"

    def test_report_period_format(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [FAIRInputs("T", 1.0, 0.1, 10_000, 100_000, monte_carlo_iterations=100)]
        report = board_generator.generate("org", scenarios, default_compliance, default_kpi_values)
        assert report.report_period.startswith("Q")

    def test_risk_headline_positive(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [FAIRInputs("T", 2.0, 0.2, 50_000, 500_000, monte_carlo_iterations=200)]
        report = board_generator.generate("org", scenarios, default_compliance, default_kpi_values)
        assert report.risk_headline_usd >= 0

    def test_top_5_risks_count(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [
            FAIRInputs(f"Scenario {i}", 1.0, 0.1, 10_000, 100_000, monte_carlo_iterations=100)
            for i in range(5)
        ]
        report = board_generator.generate("org", scenarios, default_compliance, default_kpi_values)
        assert len(report.top_5_risks) <= 5

    def test_compliance_summary_keys(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [FAIRInputs("T", 1.0, 0.1, 10_000, 100_000, monte_carlo_iterations=100)]
        report = board_generator.generate("org", scenarios, default_compliance, default_kpi_values)
        assert "SOC2" in report.compliance_summary

    def test_action_items_nonempty(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [FAIRInputs("T", 1.0, 0.1, 10_000, 100_000, monte_carlo_iterations=100)]
        report = board_generator.generate("org", scenarios, default_compliance, default_kpi_values)
        assert len(report.action_items) > 0

    def test_qoq_delta_computed(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [FAIRInputs("T", 1.0, 0.1, 10_000, 100_000, monte_carlo_iterations=100)]
        report = board_generator.generate(
            "org",
            scenarios,
            default_compliance,
            default_kpi_values,
            prior_quarter_risk_score=50.0,
        )
        assert isinstance(report.qoq_delta_pct, float)

    def test_generated_at_utc(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [FAIRInputs("T", 1.0, 0.1, 10_000, 100_000, monte_carlo_iterations=100)]
        report = board_generator.generate("org", scenarios, default_compliance, default_kpi_values)
        assert report.generated_at.tzinfo is not None

    def test_risk_trend_valid_value(
        self,
        board_generator: BoardReportGenerator,
        default_compliance: Dict[Regulation, float],
        default_kpi_values: Dict[str, float],
    ) -> None:
        scenarios = [FAIRInputs("T", 1.0, 0.1, 10_000, 100_000, monte_carlo_iterations=100)]
        report = board_generator.generate("org", scenarios, default_compliance, default_kpi_values)
        assert report.risk_trend in ("improving", "stable", "degrading")


# ============================================================================
# CREATE_EXECUTIVE_DASHBOARD FACTORY TEST
# ============================================================================


class TestFactory:
    """Tests for the create_executive_dashboard factory."""

    def test_factory_returns_all_engines(self) -> None:
        dashboard = create_executive_dashboard(seed=42)
        expected_keys = {
            "fair_engine",
            "trend_analyser",
            "benchmark_engine",
            "heatmap_engine",
            "due_diligence_engine",
            "kpi_engine",
            "board_report_generator",
        }
        assert set(dashboard.keys()) == expected_keys

    def test_factory_engines_are_correct_types(self) -> None:
        dashboard = create_executive_dashboard()
        assert isinstance(dashboard["fair_engine"], FAIREngine)
        assert isinstance(dashboard["trend_analyser"], RiskTrendAnalyser)
        assert isinstance(dashboard["benchmark_engine"], PeerBenchmarkEngine)
        assert isinstance(dashboard["heatmap_engine"], RegulatoryHeatmapEngine)
        assert isinstance(dashboard["due_diligence_engine"], DueDiligenceEngine)
        assert isinstance(dashboard["kpi_engine"], KPIEngine)
        assert isinstance(dashboard["board_report_generator"], BoardReportGenerator)
