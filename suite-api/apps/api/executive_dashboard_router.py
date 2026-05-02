"""
Executive Dashboard API — Board-Level Risk Reporting Endpoints.

Exposes FAIR risk quantification, trend analysis, peer benchmarking,
regulatory heatmap, M&A due diligence, KPI tracking, and board report
generation for executive and board consumption.

Protected with API key authentication via ``api_key_auth`` dependency.

Compliance: SOC2 CC9.1 (Board-level risk reporting)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.executive_dashboard import (
    BoardReportGenerator,
    DueDiligenceEngine,
    FAIREngine,
    FAIRInputs,
    FAIRResult,
    HeatmapColor,
    IndustryVertical,
    KPIEngine,
    PeerBenchmark,
    PeerBenchmarkEngine,
    Regulation,
    RegulatoryHeatmapEngine,
    RegulatoryStatus,
    RiskTrendAnalyser,
    RiskTrendSnapshot,
    create_executive_dashboard,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

router = APIRouter(
    prefix="/api/v1/executive",
    tags=["Executive Dashboard"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Module-level engine instances (shared across requests)
# ---------------------------------------------------------------------------

_dashboard = create_executive_dashboard()
_fair_engine: FAIREngine = _dashboard["fair_engine"]
_trend_analyser: RiskTrendAnalyser = _dashboard["trend_analyser"]
_benchmark_engine: PeerBenchmarkEngine = _dashboard["benchmark_engine"]
_heatmap_engine: RegulatoryHeatmapEngine = _dashboard["heatmap_engine"]
_due_diligence_engine: DueDiligenceEngine = _dashboard["due_diligence_engine"]
_kpi_engine: KPIEngine = _dashboard["kpi_engine"]
_board_report_generator: BoardReportGenerator = _dashboard["board_report_generator"]

# Seed synthetic trend history on startup (for demo / development)
_trend_analyser.generate_synthetic_history(weeks=12, seed=42)


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class FAIRScenarioRequest(BaseModel):
    """Input for a single FAIR risk scenario."""

    scenario_name: str = Field(..., description="Human-readable scenario label")
    threat_event_frequency_per_year: float = Field(
        ..., gt=0, description="Expected threat events per year"
    )
    vulnerability_probability: float = Field(
        ..., ge=0.0, le=1.0, description="Probability of successful exploit [0.0, 1.0]"
    )
    primary_loss_min_usd: float = Field(
        ..., ge=0, description="Minimum primary loss magnitude (USD)"
    )
    primary_loss_max_usd: float = Field(
        ..., ge=0, description="Maximum primary loss magnitude (USD)"
    )
    secondary_loss_min_usd: float = Field(
        0.0, ge=0, description="Minimum secondary loss (regulatory, reputational) (USD)"
    )
    secondary_loss_max_usd: float = Field(
        0.0, ge=0, description="Maximum secondary loss magnitude (USD)"
    )
    monte_carlo_iterations: int = Field(
        1000, ge=100, le=10000, description="Monte Carlo sample count (100–10000)"
    )

    @field_validator("primary_loss_max_usd")
    @classmethod
    def max_gte_min(cls, v: float, info: Any) -> float:
        min_val = info.data.get("primary_loss_min_usd", 0.0)
        if v < min_val:
            raise ValueError("primary_loss_max_usd must be >= primary_loss_min_usd")
        return v


class FAIRResultResponse(BaseModel):
    """FAIR simulation output."""

    scenario_name: str
    ale_p10_usd: float
    ale_p50_usd: float
    ale_p90_usd: float
    ale_mean_usd: float
    max_single_loss_usd: float
    loss_exceedance_probability: float
    simulation_iterations: int
    computed_at: datetime


class FAIRRiskSummaryResponse(BaseModel):
    """Aggregated FAIR portfolio risk summary."""

    scenarios: List[FAIRResultResponse]
    total_ale_p10_usd: float
    total_ale_p50_usd: float
    total_ale_p90_usd: float
    total_ale_mean_usd: float
    computed_at: datetime


class TrendSnapshotResponse(BaseModel):
    """Single weekly risk posture snapshot."""

    week_start: datetime
    total_risk_score: float
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int
    compliance_pct: float
    mttr_days: float
    new_findings: int
    resolved_findings: int
    new_vs_resolved_ratio: float


class TrendResponse(BaseModel):
    """Risk trend data with snapshots and direction."""

    snapshots: List[TrendSnapshotResponse]
    trend_direction: str
    mttr_trend: str
    weeks_analysed: int


class BenchmarkMetricResponse(BaseModel):
    """Single benchmark metric comparison."""

    metric_name: str
    org_value: float
    industry_p25: float
    industry_p50: float
    industry_p75: float
    unit: str
    percentile_rank: float
    is_lower_better: bool


class PeerBenchmarkResponse(BaseModel):
    """Peer benchmarking result."""

    vertical: str
    org_id: str
    metrics: List[BenchmarkMetricResponse]
    overall_percentile: float
    computed_at: datetime


class RegulatoryStatusResponse(BaseModel):
    """Regulatory compliance status and exposure."""

    regulation: str
    compliance_pct: float
    max_fine_usd: float
    estimated_exposure_usd: float
    gap_count: int
    remediation_eta_days: int
    color: str
    key_gaps: List[str]


class RegulatoryHeatmapResponse(BaseModel):
    """Full regulatory risk heatmap."""

    regulations: List[RegulatoryStatusResponse]
    total_estimated_exposure_usd: float
    red_count: int
    yellow_count: int
    green_count: int
    computed_at: datetime


class DueDiligenceResponse(BaseModel):
    """M&A due diligence security report."""

    org_id: str
    security_debt_usd: float
    compliance_readiness_pct: float
    critical_vuln_count: int
    high_vuln_count: int
    time_to_remediation_days: int
    insurance_premium_impact_usd: float
    risk_rating: str
    findings_summary: List[str]
    computed_at: datetime


class KPIMetricResponse(BaseModel):
    """Single KPI metric."""

    kpi_id: str
    name: str
    value: float
    target: float
    unit: str
    status: str
    trend: str
    description: str


class KPIDashboardResponse(BaseModel):
    """KPI dashboard response."""

    org_id: str
    kpis: List[KPIMetricResponse]
    overall_health_score: float
    on_track_count: int
    at_risk_count: int
    breached_count: int
    computed_at: datetime


class BoardReportRequest(BaseModel):
    """Request body for board report generation."""

    org_id: str = Field("default", description="Organisation identifier")
    fair_scenarios: List[FAIRScenarioRequest] = Field(
        default_factory=list,
        description="FAIR risk scenarios to simulate",
    )
    compliance_data: Dict[str, float] = Field(
        default_factory=dict,
        description="Regulation → compliance % mapping (e.g. {\"soc2\": 78.5})",
    )
    kpi_values: Dict[str, float] = Field(
        default_factory=dict,
        description="KPI ID → current value mapping",
    )
    previous_kpi_values: Optional[Dict[str, float]] = Field(
        None,
        description="Prior-period KPI values for trend computation",
    )
    prior_quarter_risk_score: Optional[float] = Field(
        None, ge=0, le=100,
        description="Last quarter's risk score for QoQ delta calculation",
    )


class BoardReportResponse(BaseModel):
    """Board-level executive risk report."""

    org_id: str
    report_period: str
    risk_headline_usd: float
    risk_trend: str
    top_5_risks: List[Dict[str, Any]]
    compliance_summary: Dict[str, float]
    kpi_summary: Dict[str, Any]
    qoq_delta_pct: float
    action_items: List[str]
    generated_at: datetime


# ---------------------------------------------------------------------------
# Helper: convert domain objects to response models
# ---------------------------------------------------------------------------


def _fair_result_to_response(result: FAIRResult) -> FAIRResultResponse:
    return FAIRResultResponse(
        scenario_name=result.scenario_name,
        ale_p10_usd=result.ale_p10_usd,
        ale_p50_usd=result.ale_p50_usd,
        ale_p90_usd=result.ale_p90_usd,
        ale_mean_usd=result.ale_mean_usd,
        max_single_loss_usd=result.max_single_loss_usd,
        loss_exceedance_probability=result.loss_exceedance_probability,
        simulation_iterations=result.simulation_iterations,
        computed_at=result.computed_at,
    )


def _snapshot_to_response(snap: RiskTrendSnapshot) -> TrendSnapshotResponse:
    return TrendSnapshotResponse(
        week_start=snap.week_start,
        total_risk_score=snap.total_risk_score,
        critical_vulns=snap.critical_vulns,
        high_vulns=snap.high_vulns,
        medium_vulns=snap.medium_vulns,
        low_vulns=snap.low_vulns,
        compliance_pct=snap.compliance_pct,
        mttr_days=snap.mttr_days,
        new_findings=snap.new_findings,
        resolved_findings=snap.resolved_findings,
        new_vs_resolved_ratio=snap.new_vs_resolved_ratio,
    )


def _reg_status_to_response(status: RegulatoryStatus) -> RegulatoryStatusResponse:
    return RegulatoryStatusResponse(
        regulation=status.regulation.value,
        compliance_pct=status.compliance_pct,
        max_fine_usd=status.max_fine_usd,
        estimated_exposure_usd=status.estimated_exposure_usd,
        gap_count=status.gap_count,
        remediation_eta_days=status.remediation_eta_days,
        color=status.color.value,
        key_gaps=status.key_gaps,
    )


def _benchmark_to_response(bm: PeerBenchmark) -> PeerBenchmarkResponse:
    return PeerBenchmarkResponse(
        vertical=bm.vertical.value,
        org_id=bm.org_id,
        metrics=[
            BenchmarkMetricResponse(
                metric_name=m.metric_name,
                org_value=m.org_value,
                industry_p25=m.industry_p25,
                industry_p50=m.industry_p50,
                industry_p75=m.industry_p75,
                unit=m.unit,
                percentile_rank=m.percentile_rank,
                is_lower_better=m.is_lower_better,
            )
            for m in bm.metrics
        ],
        overall_percentile=bm.overall_percentile,
        computed_at=bm.computed_at,
    )


# ---------------------------------------------------------------------------
# Default FAIR scenarios (used when no body is provided to risk-summary)
# ---------------------------------------------------------------------------

_DEFAULT_FAIR_SCENARIOS = [
    FAIRInputs(
        scenario_name="Ransomware Attack",
        threat_event_frequency_per_year=2.0,
        vulnerability_probability=0.15,
        primary_loss_min_usd=50_000,
        primary_loss_max_usd=500_000,
        secondary_loss_min_usd=100_000,
        secondary_loss_max_usd=1_000_000,
    ),
    FAIRInputs(
        scenario_name="Data Breach (PII)",
        threat_event_frequency_per_year=1.5,
        vulnerability_probability=0.10,
        primary_loss_min_usd=200_000,
        primary_loss_max_usd=2_000_000,
        secondary_loss_min_usd=500_000,
        secondary_loss_max_usd=5_000_000,
    ),
    FAIRInputs(
        scenario_name="Supply Chain Compromise",
        threat_event_frequency_per_year=0.5,
        vulnerability_probability=0.20,
        primary_loss_min_usd=100_000,
        primary_loss_max_usd=800_000,
        secondary_loss_min_usd=50_000,
        secondary_loss_max_usd=400_000,
    ),
]

_DEFAULT_COMPLIANCE_DATA: Dict[Regulation, float] = {
    Regulation.SOC2: 78.5,
    Regulation.PCI_DSS: 65.0,
    Regulation.HIPAA: 71.0,
    Regulation.GDPR: 82.0,
    Regulation.CCPA: 88.0,
}

_DEFAULT_KPI_VALUES: Dict[str, float] = {
    "vuln_sla_compliance_rate": 84.2,
    "mttd_hours": 18.5,
    "mttc_hours": 3.2,
    "mttr_days": 8.4,
    "security_training_completion_pct": 91.0,
    "phishing_click_rate_pct": 6.8,
    "third_party_risk_score": 72.0,
    "code_security_score": 77.5,
}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/risk-summary",
    response_model=FAIRRiskSummaryResponse,
    summary="FAIR risk quantification summary",
    description=(
        "Run Monte Carlo FAIR simulation across default risk scenarios and return "
        "10th/50th/90th percentile ALE estimates in USD."
    ),
)
async def get_risk_summary(
    org_id: str = Query("default", description="Organisation identifier"),
    iterations: int = Query(1000, ge=100, le=10000, description="Monte Carlo iterations"),
) -> FAIRRiskSummaryResponse:
    """Return FAIR risk quantification for default scenarios."""
    scenarios = [
        FAIRInputs(
            scenario_name=s.scenario_name,
            threat_event_frequency_per_year=s.threat_event_frequency_per_year,
            vulnerability_probability=s.vulnerability_probability,
            primary_loss_min_usd=s.primary_loss_min_usd,
            primary_loss_max_usd=s.primary_loss_max_usd,
            secondary_loss_min_usd=s.secondary_loss_min_usd,
            secondary_loss_max_usd=s.secondary_loss_max_usd,
            monte_carlo_iterations=iterations,
        )
        for s in _DEFAULT_FAIR_SCENARIOS
    ]

    results = _fair_engine.run_portfolio(scenarios)
    portfolio = _fair_engine.aggregate_portfolio_ale(results)

    return FAIRRiskSummaryResponse(
        scenarios=[_fair_result_to_response(r) for r in results],
        total_ale_p10_usd=portfolio["total_ale_p10_usd"],
        total_ale_p50_usd=portfolio["total_ale_p50_usd"],
        total_ale_p90_usd=portfolio["total_ale_p90_usd"],
        total_ale_mean_usd=portfolio["total_ale_mean_usd"],
        computed_at=datetime.now(timezone.utc),
    )


@router.get(
    "/trends",
    response_model=TrendResponse,
    summary="Risk trend data (weekly snapshots)",
    description="Return weekly risk posture snapshots with trend direction analysis.",
)
async def get_trends(
    weeks: int = Query(12, ge=1, le=52, description="Number of weeks of history to return"),
) -> TrendResponse:
    """Return risk trend data from weekly posture snapshots."""
    snapshots = _trend_analyser.get_snapshots(weeks=weeks)
    trend = _trend_analyser.compute_trend(weeks=min(4, weeks))
    mttr_trend = _trend_analyser.compute_mttr_trend(weeks=min(8, weeks))

    return TrendResponse(
        snapshots=[_snapshot_to_response(s) for s in snapshots],
        trend_direction=trend,
        mttr_trend=mttr_trend,
        weeks_analysed=len(snapshots),
    )


@router.get(
    "/benchmarks",
    response_model=PeerBenchmarkResponse,
    summary="Peer benchmarking comparison",
    description=(
        "Compare organisation security posture against industry vertical benchmarks "
        "across vulnerability density, MTTR, compliance score, and incident rate."
    ),
)
async def get_benchmarks(
    org_id: str = Query("default", description="Organisation identifier"),
    vertical: IndustryVertical = Query(IndustryVertical.TECHNOLOGY, description="Industry vertical"),
    vuln_density: float = Query(4.2, ge=0, description="Vulnerabilities per host"),
    mttr_days: float = Query(9.1, ge=0, description="Mean time to remediate (days)"),
    compliance_score: float = Query(76.0, ge=0, le=100, description="Compliance score (0–100)"),
    incident_rate: float = Query(1.3, ge=0, description="Security incidents per year"),
) -> PeerBenchmarkResponse:
    """Return peer benchmarking comparison for the specified industry vertical."""
    result = _benchmark_engine.benchmark(
        org_id=org_id,
        vertical=vertical,
        vuln_density_per_host=vuln_density,
        mttr_days=mttr_days,
        compliance_score_pct=compliance_score,
        incident_rate_per_year=incident_rate,
    )
    return _benchmark_to_response(result)


@router.get(
    "/regulatory-heatmap",
    response_model=RegulatoryHeatmapResponse,
    summary="Regulatory compliance heatmap",
    description=(
        "Return colour-coded regulatory compliance status with penalty exposure "
        "estimates for SOC2, PCI DSS, HIPAA, FedRAMP, GDPR, and CCPA."
    ),
)
async def get_regulatory_heatmap(
    org_id: str = Query("default", description="Organisation identifier"),
) -> RegulatoryHeatmapResponse:
    """Return regulatory risk heatmap with penalty exposure per framework."""
    statuses = _heatmap_engine.build_heatmap(_DEFAULT_COMPLIANCE_DATA)

    total_exposure = sum(s.estimated_exposure_usd for s in statuses)
    red = sum(1 for s in statuses if s.color == HeatmapColor.RED)
    yellow = sum(1 for s in statuses if s.color == HeatmapColor.YELLOW)
    green = sum(1 for s in statuses if s.color == HeatmapColor.GREEN)

    return RegulatoryHeatmapResponse(
        regulations=[_reg_status_to_response(s) for s in statuses],
        total_estimated_exposure_usd=round(total_exposure, 2),
        red_count=red,
        yellow_count=yellow,
        green_count=green,
        computed_at=datetime.now(timezone.utc),
    )


@router.get(
    "/due-diligence",
    response_model=DueDiligenceResponse,
    summary="M&A due diligence view",
    description=(
        "Generate security due diligence assessment for acquisition targets or "
        "investor reporting: security debt in dollars, compliance readiness, "
        "critical findings, and insurance premium impact."
    ),
)
async def get_due_diligence(
    org_id: str = Query("default", description="Target organisation identifier"),
    critical_vulns: int = Query(3, ge=0, description="Open critical vulnerabilities"),
    high_vulns: int = Query(12, ge=0, description="Open high vulnerabilities"),
    medium_vulns: int = Query(45, ge=0, description="Open medium vulnerabilities"),
    low_vulns: int = Query(120, ge=0, description="Open low vulnerabilities"),
    compliance_pct: float = Query(74.0, ge=0, le=100, description="Compliance readiness (%)"),
    avg_days_per_finding: float = Query(5.0, gt=0, description="Avg remediation days per finding"),
) -> DueDiligenceResponse:
    """Return M&A security due diligence report."""
    report = _due_diligence_engine.generate_report(
        org_id=org_id,
        critical_vuln_count=critical_vulns,
        high_vuln_count=high_vulns,
        medium_vuln_count=medium_vulns,
        low_vuln_count=low_vulns,
        compliance_pct=compliance_pct,
        avg_days_per_finding=avg_days_per_finding,
    )

    return DueDiligenceResponse(
        org_id=report.org_id,
        security_debt_usd=report.security_debt_usd,
        compliance_readiness_pct=report.compliance_readiness_pct,
        critical_vuln_count=report.critical_vuln_count,
        high_vuln_count=report.high_vuln_count,
        time_to_remediation_days=report.time_to_remediation_days,
        insurance_premium_impact_usd=report.insurance_premium_impact_usd,
        risk_rating=report.risk_rating,
        findings_summary=report.findings_summary,
        computed_at=report.computed_at,
    )


@router.get(
    "/kpis",
    response_model=KPIDashboardResponse,
    summary="KPI dashboard",
    description=(
        "Return executive security KPI dashboard: SLA compliance rate, "
        "MTTD/MTTC/MTTR, training completion, phishing click rate, "
        "third-party risk score, and code security score."
    ),
)
async def get_kpis(
    org_id: str = Query("default", description="Organisation identifier"),
) -> KPIDashboardResponse:
    """Return KPI dashboard with status and trend for each metric."""
    dashboard = _kpi_engine.build_dashboard(org_id=org_id, values=_DEFAULT_KPI_VALUES)

    return KPIDashboardResponse(
        org_id=dashboard.org_id,
        kpis=[
            KPIMetricResponse(
                kpi_id=k.kpi_id,
                name=k.name,
                value=k.value,
                target=k.target,
                unit=k.unit,
                status=k.status.value,
                trend=k.trend,
                description=k.description,
            )
            for k in dashboard.kpis
        ],
        overall_health_score=dashboard.overall_health_score,
        on_track_count=dashboard.on_track_count,
        at_risk_count=dashboard.at_risk_count,
        breached_count=dashboard.breached_count,
        computed_at=dashboard.computed_at,
    )


@router.post(
    "/board-report",
    response_model=BoardReportResponse,
    summary="Generate board report",
    description=(
        "Generate a one-page board-level executive risk report: risk-in-dollars "
        "headline, top 5 risks with business impact, compliance summary, KPI "
        "summary, quarter-over-quarter trend, and board action items."
    ),
)
async def generate_board_report(body: BoardReportRequest) -> BoardReportResponse:
    """Generate a complete board-level risk report."""
    # Convert request FAIR scenarios to domain objects
    fair_scenarios = [
        FAIRInputs(
            scenario_name=s.scenario_name,
            threat_event_frequency_per_year=s.threat_event_frequency_per_year,
            vulnerability_probability=s.vulnerability_probability,
            primary_loss_min_usd=s.primary_loss_min_usd,
            primary_loss_max_usd=s.primary_loss_max_usd,
            secondary_loss_min_usd=s.secondary_loss_min_usd,
            secondary_loss_max_usd=s.secondary_loss_max_usd,
            monte_carlo_iterations=s.monte_carlo_iterations,
        )
        for s in body.fair_scenarios
    ] or _DEFAULT_FAIR_SCENARIOS

    # Convert compliance data keys (strings) to Regulation enum
    compliance_data: Dict[Regulation, float] = {}
    for key, pct in body.compliance_data.items():
        try:
            reg = Regulation(key.lower())
            compliance_data[reg] = pct
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown regulation: '{key}'. Valid values: {[r.value for r in Regulation]}",
            )
    if not compliance_data:
        compliance_data = _DEFAULT_COMPLIANCE_DATA

    kpi_values = body.kpi_values or _DEFAULT_KPI_VALUES

    try:
        report = _board_report_generator.generate(
            org_id=body.org_id,
            fair_scenarios=fair_scenarios,
            compliance_data=compliance_data,
            kpi_values=kpi_values,
            previous_kpi_values=body.previous_kpi_values,
            prior_quarter_risk_score=body.prior_quarter_risk_score,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}") from exc

    return BoardReportResponse(
        org_id=report.org_id,
        report_period=report.report_period,
        risk_headline_usd=report.risk_headline_usd,
        risk_trend=report.risk_trend,
        top_5_risks=report.top_5_risks,
        compliance_summary=report.compliance_summary,
        kpi_summary=report.kpi_summary,
        qoq_delta_pct=report.qoq_delta_pct,
        action_items=report.action_items,
        generated_at=report.generated_at,
    )
