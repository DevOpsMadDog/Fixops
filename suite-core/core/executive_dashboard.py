"""
Executive Risk Dashboard Engine — ALDECI Board-Level Reporting.

Provides board-level security intelligence with:
- FAIR Risk Quantification: Monte Carlo ALE simulation (1000 iterations)
- Risk Trend Analysis: weekly posture snapshots (score, vulns, MTTR, compliance)
- Peer Benchmarking: vuln density, MTTR, compliance vs. industry verticals
- Regulatory Risk Heatmap: SOC2, PCI, HIPAA, FedRAMP, GDPR, CCPA exposure
- M&A Due Diligence: security debt, readiness, insurance impact in dollars
- KPI Tracking: SLA compliance, MTTD/MTTC/MTTR, training, phishing, third-party
- Board Report Generation: one-page JSON summary, risk-in-dollars, QoQ trend

Compliance: SOC2 CC9.1 (Risk assessment for board-level reporting)
"""

from __future__ import annotations

import logging
import random
import statistics
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    Hub-level emit so this engine module participates in second-brain coverage.
    Downstream callers are AQUA via blast-radius (depth ≤ 2).
    """
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat — fires once per process so this file is observable
# in the TrustGraph second-brain, even if no public method is called yet.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class IndustryVertical(Enum):
    """Industry verticals for peer benchmarking."""

    FINTECH = "fintech"
    HEALTHCARE = "healthcare"
    GOVERNMENT = "government"
    TECHNOLOGY = "technology"
    RETAIL = "retail"
    ENERGY = "energy"
    MANUFACTURING = "manufacturing"


class Regulation(Enum):
    """Applicable regulatory frameworks."""

    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    FEDRAMP = "fedramp"
    GDPR = "gdpr"
    CCPA = "ccpa"


class HeatmapColor(Enum):
    """Traffic-light color coding for regulatory heatmap."""

    GREEN = "green"    # >= 80% compliant
    YELLOW = "yellow"  # 50–79% compliant
    RED = "red"        # < 50% compliant


class KPIStatus(Enum):
    """KPI health status."""

    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    BREACHED = "breached"


# ============================================================================
# DATACLASSES — FAIR RISK QUANTIFICATION
# ============================================================================


@dataclass
class FAIRInputs:
    """
    Inputs for a single FAIR risk scenario.

    Attributes:
        scenario_name: Human-readable scenario label
        threat_event_frequency_per_year: Expected number of threat events/year
        vulnerability_probability: Probability [0.0, 1.0] an event exploits a vuln
        primary_loss_min_usd: Minimum primary loss magnitude (USD)
        primary_loss_max_usd: Maximum primary loss magnitude (USD)
        secondary_loss_min_usd: Minimum secondary loss (regulatory, reputational)
        secondary_loss_max_usd: Maximum secondary loss magnitude (USD)
        monte_carlo_iterations: Number of Monte Carlo samples (default 1000)
    """

    scenario_name: str
    threat_event_frequency_per_year: float
    vulnerability_probability: float
    primary_loss_min_usd: float
    primary_loss_max_usd: float
    secondary_loss_min_usd: float = 0.0
    secondary_loss_max_usd: float = 0.0
    monte_carlo_iterations: int = 1000


@dataclass
class FAIRResult:
    """
    Output of a FAIR Monte Carlo risk simulation.

    Attributes:
        scenario_name: Scenario identifier
        ale_p10_usd: 10th-percentile Annual Loss Expectancy (USD)
        ale_p50_usd: 50th-percentile (median) ALE (USD)
        ale_p90_usd: 90th-percentile ALE (USD)
        ale_mean_usd: Mean ALE across all iterations (USD)
        max_single_loss_usd: Largest single-year loss observed in simulation
        loss_exceedance_probability: Fraction of years where loss > mean (0–1)
        simulation_iterations: Number of Monte Carlo runs performed
        computed_at: Timestamp of computation
    """

    scenario_name: str
    ale_p10_usd: float
    ale_p50_usd: float
    ale_p90_usd: float
    ale_mean_usd: float
    max_single_loss_usd: float
    loss_exceedance_probability: float
    simulation_iterations: int
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# DATACLASSES — RISK TREND
# ============================================================================


@dataclass
class RiskTrendSnapshot:
    """
    Weekly risk posture snapshot.

    Attributes:
        week_start: Monday of the measurement week (UTC)
        total_risk_score: Overall risk score 0–100 (higher = riskier)
        critical_vulns: Open critical vulnerabilities
        high_vulns: Open high vulnerabilities
        medium_vulns: Open medium vulnerabilities
        low_vulns: Open low vulnerabilities
        compliance_pct: Compliance percentage across all frameworks (0–100)
        mttr_days: Mean time to remediate (days)
        new_findings: Findings opened this week
        resolved_findings: Findings closed this week
        new_vs_resolved_ratio: new_findings / max(resolved_findings, 1)
    """

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
    new_vs_resolved_ratio: float = 0.0

    def __post_init__(self) -> None:
        self.new_vs_resolved_ratio = self.new_findings / max(self.resolved_findings, 1)


# ============================================================================
# DATACLASSES — PEER BENCHMARKING
# ============================================================================


@dataclass
class BenchmarkMetric:
    """Single benchmark metric comparison."""

    metric_name: str
    org_value: float
    industry_p25: float
    industry_p50: float
    industry_p75: float
    unit: str
    percentile_rank: float  # Where org sits vs. peers (0–100, higher = better)
    is_lower_better: bool = True  # True for MTTR, vuln density; False for compliance score


@dataclass
class PeerBenchmark:
    """
    Peer benchmarking comparison for one industry vertical.

    Attributes:
        vertical: Industry vertical used for comparison
        org_id: Organisation being assessed
        metrics: List of benchmark metric comparisons
        overall_percentile: Composite percentile rank vs. peers
        computed_at: Timestamp
    """

    vertical: IndustryVertical
    org_id: str
    metrics: List[BenchmarkMetric]
    overall_percentile: float
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# DATACLASSES — REGULATORY HEATMAP
# ============================================================================


@dataclass
class RegulatoryStatus:
    """
    Compliance status and exposure for one regulation.

    Attributes:
        regulation: Regulatory framework
        compliance_pct: Current compliance percentage (0–100)
        max_fine_usd: Maximum regulatory fine (USD)
        estimated_exposure_usd: Estimated penalty given current compliance gap
        gap_count: Number of open control gaps
        remediation_eta_days: Estimated days to full compliance
        color: Traffic-light status (red/yellow/green)
        key_gaps: Top 3 gap descriptions
    """

    regulation: Regulation
    compliance_pct: float
    max_fine_usd: float
    estimated_exposure_usd: float
    gap_count: int
    remediation_eta_days: int
    color: HeatmapColor
    key_gaps: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.compliance_pct >= 80:
            self.color = HeatmapColor.GREEN
        elif self.compliance_pct >= 50:
            self.color = HeatmapColor.YELLOW
        else:
            self.color = HeatmapColor.RED


# ============================================================================
# DATACLASSES — M&A DUE DILIGENCE
# ============================================================================


@dataclass
class DueDiligenceReport:
    """
    M&A / investor due diligence security assessment.

    Attributes:
        org_id: Target organisation identifier
        security_debt_usd: Quantified technical security debt (USD)
        compliance_readiness_pct: Percentage ready for compliance audit
        critical_vuln_count: Open critical vulnerabilities
        high_vuln_count: Open high vulnerabilities
        time_to_remediation_days: Estimated days to clear all critical/high findings
        insurance_premium_impact_usd: Annual cyber-insurance premium delta
        risk_rating: Letter rating (A–F)
        findings_summary: Key findings for acquirer review
        computed_at: Timestamp
    """

    org_id: str
    security_debt_usd: float
    compliance_readiness_pct: float
    critical_vuln_count: int
    high_vuln_count: int
    time_to_remediation_days: int
    insurance_premium_impact_usd: float
    risk_rating: str
    findings_summary: List[str] = field(default_factory=list)
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# DATACLASSES — KPI TRACKING
# ============================================================================


@dataclass
class KPIMetric:
    """Single KPI data point."""

    kpi_id: str
    name: str
    value: float
    target: float
    unit: str
    status: KPIStatus
    trend: str  # "improving", "stable", "degrading"
    description: str


@dataclass
class KPIDashboard:
    """
    Aggregated KPI dashboard for executive consumption.

    Attributes:
        org_id: Organisation identifier
        kpis: List of individual KPI metrics
        overall_health_score: Weighted health score 0–100
        on_track_count: KPIs meeting target
        at_risk_count: KPIs approaching threshold
        breached_count: KPIs exceeding threshold
        computed_at: Timestamp
    """

    org_id: str
    kpis: List[KPIMetric]
    overall_health_score: float
    on_track_count: int
    at_risk_count: int
    breached_count: int
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# DATACLASSES — BOARD REPORT
# ============================================================================


@dataclass
class BoardReport:
    """
    One-page board-level risk report.

    Attributes:
        org_id: Organisation identifier
        report_period: Human-readable quarter label (e.g. "Q2 2025")
        risk_headline_usd: Risk-in-dollars headline number (median ALE)
        risk_trend: "improving", "stable", or "degrading" QoQ
        top_5_risks: Top 5 business-impact risks with dollar estimates
        compliance_summary: Per-framework compliance percentage
        kpi_summary: Key KPI values for board slide
        qoq_delta_pct: Quarter-over-quarter risk score change (%)
        action_items: Recommended board-level actions
        generated_at: Timestamp
    """

    org_id: str
    report_period: str
    risk_headline_usd: float
    risk_trend: str
    top_5_risks: List[Dict[str, Any]]
    compliance_summary: Dict[str, float]
    kpi_summary: Dict[str, Any]
    qoq_delta_pct: float
    action_items: List[str]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# INDUSTRY BENCHMARK DATABASE (static reference data)
# ============================================================================

# Benchmark reference values per vertical.
# Keys: vuln_density_per_host, mttr_days, compliance_score_pct, incident_rate_per_year
# Values: (p25, p50, p75)
_BENCHMARK_DB: Dict[IndustryVertical, Dict[str, Tuple[float, float, float]]] = {
    IndustryVertical.FINTECH: {
        "vuln_density_per_host": (2.1, 3.8, 6.5),
        "mttr_days": (4.2, 7.1, 14.3),
        "compliance_score_pct": (72.0, 81.0, 91.0),
        "incident_rate_per_year": (0.4, 1.1, 2.8),
    },
    IndustryVertical.HEALTHCARE: {
        "vuln_density_per_host": (3.5, 5.9, 9.2),
        "mttr_days": (6.8, 12.4, 21.7),
        "compliance_score_pct": (61.0, 74.0, 86.0),
        "incident_rate_per_year": (0.7, 1.8, 4.1),
    },
    IndustryVertical.GOVERNMENT: {
        "vuln_density_per_host": (2.8, 4.6, 7.3),
        "mttr_days": (8.1, 15.2, 28.6),
        "compliance_score_pct": (68.0, 78.0, 89.0),
        "incident_rate_per_year": (0.3, 0.9, 2.2),
    },
    IndustryVertical.TECHNOLOGY: {
        "vuln_density_per_host": (1.8, 3.1, 5.7),
        "mttr_days": (2.9, 5.4, 10.8),
        "compliance_score_pct": (75.0, 84.0, 93.0),
        "incident_rate_per_year": (0.5, 1.4, 3.3),
    },
    IndustryVertical.RETAIL: {
        "vuln_density_per_host": (3.2, 5.4, 8.8),
        "mttr_days": (5.6, 10.3, 19.4),
        "compliance_score_pct": (59.0, 71.0, 83.0),
        "incident_rate_per_year": (0.9, 2.1, 5.0),
    },
    IndustryVertical.ENERGY: {
        "vuln_density_per_host": (2.5, 4.2, 7.0),
        "mttr_days": (7.3, 13.8, 25.1),
        "compliance_score_pct": (64.0, 76.0, 87.0),
        "incident_rate_per_year": (0.2, 0.7, 1.9),
    },
    IndustryVertical.MANUFACTURING: {
        "vuln_density_per_host": (4.1, 6.7, 10.5),
        "mttr_days": (9.2, 17.6, 31.4),
        "compliance_score_pct": (55.0, 68.0, 80.0),
        "incident_rate_per_year": (0.6, 1.6, 3.8),
    },
}

# Maximum regulatory fines (USD) per framework
_REGULATION_MAX_FINES: Dict[Regulation, float] = {
    Regulation.SOC2: 100_000.0,          # Audit failure / breach penalty
    Regulation.PCI_DSS: 500_000.0,       # Per incident
    Regulation.HIPAA: 1_900_000.0,       # Annual maximum per violation category
    Regulation.FEDRAMP: 2_000_000.0,     # Contract loss + fines
    Regulation.GDPR: 20_000_000.0,       # 4% global revenue or €20M, whichever higher
    Regulation.CCPA: 7_500.0,            # Per intentional violation (scaled to 10K violations)
}

# Typical remediation days per gap for each framework
_REGULATION_DAYS_PER_GAP: Dict[Regulation, float] = {
    Regulation.SOC2: 14.0,
    Regulation.PCI_DSS: 10.0,
    Regulation.HIPAA: 18.0,
    Regulation.FEDRAMP: 21.0,
    Regulation.GDPR: 12.0,
    Regulation.CCPA: 8.0,
}

# Common gap descriptions per framework
_REGULATION_COMMON_GAPS: Dict[Regulation, List[str]] = {
    Regulation.SOC2: [
        "CC6.1: Logical access controls not fully documented",
        "CC7.2: Anomaly detection alerting not implemented",
        "CC9.1: Risk assessment not updated within 12 months",
        "CC2.3: Internal communication of control changes missing",
    ],
    Regulation.PCI_DSS: [
        "Req 6.3: Vulnerability management process gaps",
        "Req 10.5: Audit log integrity controls incomplete",
        "Req 12.3: Risk assessment documentation outdated",
        "Req 8.3: MFA not enforced for all admin access",
    ],
    Regulation.HIPAA: [
        "§164.312(a)(1): Access control policy gaps",
        "§164.308(a)(1): Risk analysis not completed annually",
        "§164.312(e)(2)(ii): Encryption at rest not enforced",
        "§164.308(a)(5): Security training not current",
    ],
    Regulation.FEDRAMP: [
        "AC-2: Account management procedures incomplete",
        "SI-2: Flaw remediation SLA not met",
        "CA-7: Continuous monitoring gaps",
        "IR-4: Incident handling process not documented",
    ],
    Regulation.GDPR: [
        "Art.25: Privacy by design not implemented",
        "Art.30: Records of processing incomplete",
        "Art.32: Security measures not documented",
        "Art.35: DPIA not completed for high-risk processing",
    ],
    Regulation.CCPA: [
        "§1798.100: Consumer data request process missing",
        "§1798.115: Data sharing disclosures incomplete",
        "§1798.120: Opt-out mechanism not implemented",
        "§1798.150: Security safeguards audit outstanding",
    ],
}


# ============================================================================
# FAIR RISK QUANTIFICATION ENGINE
# ============================================================================


class FAIREngine:
    """
    FAIR (Factor Analysis of Information Risk) Monte Carlo simulation engine.

    Runs configurable iterations sampling threat event frequency and loss
    magnitude to produce 10th/50th/90th percentile ALE estimates.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)

    def run_simulation(self, inputs: FAIRInputs) -> FAIRResult:
        """
        Execute Monte Carlo FAIR simulation.

        Args:
            inputs: FAIRInputs specifying scenario parameters.

        Returns:
            FAIRResult with percentile ALE estimates.
        """
        if inputs.monte_carlo_iterations < 1:
            raise ValueError("monte_carlo_iterations must be >= 1")
        if not 0.0 <= inputs.vulnerability_probability <= 1.0:
            raise ValueError("vulnerability_probability must be in [0.0, 1.0]")
        if inputs.primary_loss_min_usd > inputs.primary_loss_max_usd:
            raise ValueError("primary_loss_min_usd must be <= primary_loss_max_usd")

        annual_losses: List[float] = []
        n = inputs.monte_carlo_iterations

        for _ in range(n):
            # Sample threat event frequency using Poisson-like approximation
            freq = self._rng.gauss(
                mu=inputs.threat_event_frequency_per_year,
                sigma=inputs.threat_event_frequency_per_year * 0.3,
            )
            freq = max(0.0, freq)

            # Sample vulnerability (contact × probability of action)
            vuln = self._rng.betavariate(
                alpha=max(0.5, inputs.vulnerability_probability * 10),
                beta=max(0.5, (1.0 - inputs.vulnerability_probability) * 10),
            )

            # Loss event frequency = TEF × Vulnerability
            lef = freq * vuln

            # Sample primary loss magnitude (PERT-like using beta)
            p_loss = self._rng.uniform(
                inputs.primary_loss_min_usd,
                inputs.primary_loss_max_usd,
            )

            # Sample secondary loss magnitude
            if inputs.secondary_loss_max_usd > 0:
                s_loss = self._rng.uniform(
                    inputs.secondary_loss_min_usd,
                    inputs.secondary_loss_max_usd,
                )
            else:
                s_loss = 0.0

            total_loss_per_event = p_loss + s_loss
            annual_loss = lef * total_loss_per_event
            annual_losses.append(annual_loss)

        annual_losses.sort()
        mean_loss = statistics.mean(annual_losses) if annual_losses else 0.0
        above_mean = sum(1 for x in annual_losses if x > mean_loss)
        exceedance_prob = above_mean / n if n > 0 else 0.0

        def _percentile(data: List[float], pct: float) -> float:
            idx = int(len(data) * pct / 100)
            idx = min(idx, len(data) - 1)
            return data[idx]

        return FAIRResult(
            scenario_name=inputs.scenario_name,
            ale_p10_usd=_percentile(annual_losses, 10),
            ale_p50_usd=_percentile(annual_losses, 50),
            ale_p90_usd=_percentile(annual_losses, 90),
            ale_mean_usd=mean_loss,
            max_single_loss_usd=max(annual_losses) if annual_losses else 0.0,
            loss_exceedance_probability=exceedance_prob,
            simulation_iterations=n,
        )

    def run_portfolio(self, scenarios: List[FAIRInputs]) -> List[FAIRResult]:
        """Run multiple FAIR scenarios and return all results."""
        return [self.run_simulation(s) for s in scenarios]

    def aggregate_portfolio_ale(self, results: List[FAIRResult]) -> Dict[str, float]:
        """Sum ALE percentiles across all scenarios for total exposure."""
        return {
            "total_ale_p10_usd": sum(r.ale_p10_usd for r in results),
            "total_ale_p50_usd": sum(r.ale_p50_usd for r in results),
            "total_ale_p90_usd": sum(r.ale_p90_usd for r in results),
            "total_ale_mean_usd": sum(r.ale_mean_usd for r in results),
        }


# ============================================================================
# RISK TREND ANALYSER
# ============================================================================


class RiskTrendAnalyser:
    """
    Tracks and analyses risk posture trends over weekly snapshots.

    Snapshots are held in memory (no persistence required for board reporting).
    For production, inject a list of historical snapshots.
    """

    def __init__(self) -> None:
        self._snapshots: List[RiskTrendSnapshot] = []
        self._lock = threading.Lock()

    def add_snapshot(self, snapshot: RiskTrendSnapshot) -> None:
        """Add a weekly snapshot (thread-safe)."""
        with self._lock:
            self._snapshots.append(snapshot)
            self._snapshots.sort(key=lambda s: s.week_start)

    def get_snapshots(
        self,
        weeks: int = 12,
    ) -> List[RiskTrendSnapshot]:
        """Return the most recent N weekly snapshots."""
        with self._lock:
            return list(self._snapshots[-weeks:])

    def compute_trend(self, weeks: int = 4) -> str:
        """
        Compute trend direction from recent snapshots.

        Returns "improving", "stable", or "degrading".
        """
        recent = self.get_snapshots(weeks)
        if len(recent) < 2:
            return "stable"
        first_score = recent[0].total_risk_score
        last_score = recent[-1].total_risk_score
        delta_pct = ((last_score - first_score) / max(first_score, 1.0)) * 100
        if delta_pct <= -5.0:
            return "improving"
        if delta_pct >= 5.0:
            return "degrading"
        return "stable"

    def compute_mttr_trend(self, weeks: int = 8) -> str:
        """Compute MTTR trend direction."""
        recent = self.get_snapshots(weeks)
        if len(recent) < 2:
            return "stable"
        first = recent[0].mttr_days
        last = recent[-1].mttr_days
        delta_pct = ((last - first) / max(first, 0.1)) * 100
        if delta_pct <= -10.0:
            return "improving"
        if delta_pct >= 10.0:
            return "degrading"
        return "stable"

    def generate_synthetic_history(
        self,
        weeks: int = 12,
        base_risk_score: float = 45.0,
        base_compliance_pct: float = 72.0,
        seed: Optional[int] = None,
    ) -> List[RiskTrendSnapshot]:
        """
        Generate synthetic weekly snapshots for demonstration / testing.

        Args:
            weeks: Number of historical weeks to generate
            base_risk_score: Starting risk score
            base_compliance_pct: Starting compliance percentage
            seed: Optional RNG seed for reproducibility

        Returns:
            List of RiskTrendSnapshot ordered oldest-first.
        """
        rng = random.Random(seed)
        snapshots: List[RiskTrendSnapshot] = []
        now = datetime.now(timezone.utc)
        risk = base_risk_score
        compliance = base_compliance_pct
        mttr = 9.5

        for i in range(weeks, 0, -1):
            week_start = now - timedelta(weeks=i)
            week_start = week_start.replace(hour=0, minute=0, second=0, microsecond=0)

            risk += rng.uniform(-3.0, 2.5)
            risk = max(10.0, min(95.0, risk))
            compliance += rng.uniform(-1.5, 2.0)
            compliance = max(30.0, min(99.0, compliance))
            mttr += rng.uniform(-0.8, 1.0)
            mttr = max(1.0, min(45.0, mttr))

            new_f = rng.randint(5, 35)
            resolved_f = rng.randint(3, 30)

            snap = RiskTrendSnapshot(
                week_start=week_start,
                total_risk_score=round(risk, 2),
                critical_vulns=rng.randint(0, 8),
                high_vulns=rng.randint(2, 25),
                medium_vulns=rng.randint(10, 60),
                low_vulns=rng.randint(20, 100),
                compliance_pct=round(compliance, 2),
                mttr_days=round(mttr, 2),
                new_findings=new_f,
                resolved_findings=resolved_f,
            )
            snapshots.append(snap)
            self.add_snapshot(snap)

        return snapshots


# ============================================================================
# PEER BENCHMARKING ENGINE
# ============================================================================


class PeerBenchmarkEngine:
    """Compares org security metrics against industry vertical benchmarks."""

    def __init__(self) -> None:
        self._db = _BENCHMARK_DB

    def compute_percentile_rank(
        self,
        org_value: float,
        p25: float,
        p50: float,
        p75: float,
        is_lower_better: bool,
    ) -> float:
        """
        Estimate org percentile rank (0–100) given benchmark quartiles.

        For lower-is-better metrics (MTTR, vuln density) a lower org value
        means a better rank. For higher-is-better metrics (compliance score)
        it is reversed.

        Returns:
            Percentile rank where 100 = best possible.
        """
        if is_lower_better:
            if org_value <= p25:
                return 90.0 + min(10.0, (p25 - org_value) / max(p25, 0.01) * 20)
            if org_value <= p50:
                t = (org_value - p25) / max(p50 - p25, 0.01)
                return 90.0 - t * 30.0
            if org_value <= p75:
                t = (org_value - p50) / max(p75 - p50, 0.01)
                return 60.0 - t * 30.0
            return max(5.0, 30.0 - (org_value - p75) / max(p75, 0.01) * 20)
        else:
            # Higher is better (compliance score)
            if org_value >= p75:
                return 90.0 + min(10.0, (org_value - p75) / max(100 - p75, 0.01) * 10)
            if org_value >= p50:
                t = (p75 - org_value) / max(p75 - p50, 0.01)
                return 90.0 - t * 30.0
            if org_value >= p25:
                t = (p50 - org_value) / max(p50 - p25, 0.01)
                return 60.0 - t * 30.0
            return max(5.0, 30.0 - (p25 - org_value) / max(p25, 0.01) * 20)

    def benchmark(
        self,
        org_id: str,
        vertical: IndustryVertical,
        vuln_density_per_host: float,
        mttr_days: float,
        compliance_score_pct: float,
        incident_rate_per_year: float,
    ) -> PeerBenchmark:
        """
        Generate a full peer benchmarking report.

        Args:
            org_id: Organisation identifier.
            vertical: Industry vertical for benchmark selection.
            vuln_density_per_host: Org's vulnerability density (vulns / host).
            mttr_days: Org's mean time to remediate (days).
            compliance_score_pct: Org's compliance score (0–100).
            incident_rate_per_year: Org's security incidents per year.

        Returns:
            PeerBenchmark with metric-level and overall comparison.
        """
        ref = self._db.get(vertical, self._db[IndustryVertical.TECHNOLOGY])

        def _metric(
            name: str,
            org_val: float,
            key: str,
            unit: str,
            lower_better: bool,
        ) -> BenchmarkMetric:
            p25, p50, p75 = ref[key]
            rank = self.compute_percentile_rank(org_val, p25, p50, p75, lower_better)
            return BenchmarkMetric(
                metric_name=name,
                org_value=org_val,
                industry_p25=p25,
                industry_p50=p50,
                industry_p75=p75,
                unit=unit,
                percentile_rank=round(rank, 1),
                is_lower_better=lower_better,
            )

        metrics = [
            _metric("Vulnerability Density", vuln_density_per_host, "vuln_density_per_host", "vulns/host", True),
            _metric("Mean Time to Remediate", mttr_days, "mttr_days", "days", True),
            _metric("Compliance Score", compliance_score_pct, "compliance_score_pct", "%", False),
            _metric("Incident Rate", incident_rate_per_year, "incident_rate_per_year", "incidents/year", True),
        ]

        overall = statistics.mean(m.percentile_rank for m in metrics)

        return PeerBenchmark(
            vertical=vertical,
            org_id=org_id,
            metrics=metrics,
            overall_percentile=round(overall, 1),
        )


# ============================================================================
# REGULATORY HEATMAP ENGINE
# ============================================================================


class RegulatoryHeatmapEngine:
    """Generates regulatory compliance heatmap with penalty exposure estimates."""

    def __init__(self) -> None:
        self._max_fines = _REGULATION_MAX_FINES
        self._days_per_gap = _REGULATION_DAYS_PER_GAP
        self._common_gaps = _REGULATION_COMMON_GAPS

    def _estimate_exposure(self, regulation: Regulation, compliance_pct: float, gap_count: int) -> float:
        """
        Estimate regulatory exposure in USD.

        Linear interpolation: 0% compliance → max fine; 100% → $0.
        Scaled by gap_count to account for per-violation exposure.
        """
        max_fine = self._max_fines.get(regulation, 100_000.0)
        gap_fraction = 1.0 - (compliance_pct / 100.0)
        base_exposure = max_fine * gap_fraction
        # PCI and GDPR are per-violation — scale by gap count (capped at max_fine)
        if regulation in (Regulation.PCI_DSS, Regulation.GDPR, Regulation.CCPA):
            base_exposure = min(base_exposure * max(1, gap_count // 2), max_fine)
        return round(base_exposure, 2)

    def _remediation_eta(self, regulation: Regulation, gap_count: int) -> int:
        """Estimate days to full compliance given gap count."""
        days_per_gap = self._days_per_gap.get(regulation, 14.0)
        return max(1, int(gap_count * days_per_gap))

    def build_heatmap(
        self,
        compliance_data: Dict[Regulation, float],
        gap_counts: Optional[Dict[Regulation, int]] = None,
    ) -> List[RegulatoryStatus]:
        """
        Build regulatory risk heatmap.

        Args:
            compliance_data: Mapping of regulation → compliance % (0–100).
            gap_counts: Optional mapping of regulation → open gap count.
                        Defaults to estimating from compliance %.

        Returns:
            List of RegulatoryStatus (one per regulation in compliance_data).
        """
        results: List[RegulatoryStatus] = []
        gap_counts = gap_counts or {}

        for regulation, compliance_pct in compliance_data.items():
            compliance_pct = max(0.0, min(100.0, compliance_pct))
            gaps = gap_counts.get(regulation)
            if gaps is None:
                # Estimate: every 5% gap ≈ 1 control gap
                gaps = max(0, int((100.0 - compliance_pct) / 5.0))

            exposure = self._estimate_exposure(regulation, compliance_pct, gaps)
            eta_days = self._remediation_eta(regulation, gaps)
            max_fine = self._max_fines.get(regulation, 100_000.0)
            known_gaps = self._common_gaps.get(regulation, [])[:3]

            status = RegulatoryStatus(
                regulation=regulation,
                compliance_pct=round(compliance_pct, 2),
                max_fine_usd=max_fine,
                estimated_exposure_usd=exposure,
                gap_count=gaps,
                remediation_eta_days=eta_days,
                color=HeatmapColor.GREEN,  # __post_init__ will set correct value
                key_gaps=known_gaps,
            )
            results.append(status)

        return results


# ============================================================================
# M&A DUE DILIGENCE ENGINE
# ============================================================================


class DueDiligenceEngine:
    """Generates M&A / investor due diligence security assessment reports."""

    # Cost estimates (USD) per unresolved vulnerability
    _COST_PER_CRITICAL = 25_000.0
    _COST_PER_HIGH = 8_000.0
    _COST_PER_MEDIUM = 1_500.0
    _COST_PER_LOW = 200.0

    # Insurance premium uplift per unresolved critical
    _INSURANCE_UPLIFT_PER_CRITICAL = 5_000.0
    _INSURANCE_UPLIFT_PER_HIGH = 1_200.0

    _RATING_THRESHOLDS = [
        (95.0, "A+"),
        (85.0, "A"),
        (75.0, "B"),
        (60.0, "C"),
        (45.0, "D"),
        (0.0, "F"),
    ]

    def compute_risk_rating(self, compliance_pct: float, critical_count: int, high_count: int) -> str:
        """Compute letter rating based on compliance and vulnerability counts."""
        score = compliance_pct
        score -= critical_count * 5.0
        score -= high_count * 1.0
        score = max(0.0, min(100.0, score))
        for threshold, rating in self._RATING_THRESHOLDS:
            if score >= threshold:
                return rating
        return "F"

    def generate_report(
        self,
        org_id: str,
        critical_vuln_count: int,
        high_vuln_count: int,
        medium_vuln_count: int,
        low_vuln_count: int,
        compliance_pct: float,
        avg_days_per_finding: float = 5.0,
    ) -> DueDiligenceReport:
        """
        Generate a due diligence security report.

        Args:
            org_id: Target organisation identifier.
            critical_vuln_count: Count of open critical vulnerabilities.
            high_vuln_count: Count of open high vulnerabilities.
            medium_vuln_count: Count of open medium vulnerabilities.
            low_vuln_count: Count of open low vulnerabilities.
            compliance_pct: Overall compliance readiness percentage (0–100).
            avg_days_per_finding: Average days to remediate one finding.

        Returns:
            DueDiligenceReport suitable for investor / acquirer review.
        """
        security_debt = (
            critical_vuln_count * self._COST_PER_CRITICAL
            + high_vuln_count * self._COST_PER_HIGH
            + medium_vuln_count * self._COST_PER_MEDIUM
            + low_vuln_count * self._COST_PER_LOW
        )

        total_critical_high = critical_vuln_count + high_vuln_count
        time_to_remediation = int(total_critical_high * avg_days_per_finding)

        insurance_impact = (
            critical_vuln_count * self._INSURANCE_UPLIFT_PER_CRITICAL
            + high_vuln_count * self._INSURANCE_UPLIFT_PER_HIGH
        )

        rating = self.compute_risk_rating(compliance_pct, critical_vuln_count, high_vuln_count)

        findings_summary: List[str] = []
        if critical_vuln_count > 0:
            findings_summary.append(
                f"{critical_vuln_count} critical vulnerabilities requiring immediate remediation "
                f"(estimated ${critical_vuln_count * self._COST_PER_CRITICAL:,.0f} exposure)"
            )
        if high_vuln_count > 0:
            findings_summary.append(
                f"{high_vuln_count} high-severity findings "
                f"(${high_vuln_count * self._COST_PER_HIGH:,.0f} remediation cost)"
            )
        if compliance_pct < 70:
            findings_summary.append(
                f"Compliance readiness at {compliance_pct:.1f}% — material gap for regulated industries"
            )
        if insurance_impact > 0:
            findings_summary.append(
                f"Estimated cyber-insurance premium uplift: ${insurance_impact:,.0f}/year"
            )
        if not findings_summary:
            findings_summary.append("Security posture meets acquisition baseline criteria")

        return DueDiligenceReport(
            org_id=org_id,
            security_debt_usd=round(security_debt, 2),
            compliance_readiness_pct=round(compliance_pct, 2),
            critical_vuln_count=critical_vuln_count,
            high_vuln_count=high_vuln_count,
            time_to_remediation_days=time_to_remediation,
            insurance_premium_impact_usd=round(insurance_impact, 2),
            risk_rating=rating,
            findings_summary=findings_summary,
        )


# ============================================================================
# KPI ENGINE
# ============================================================================


class KPIEngine:
    """Tracks and evaluates executive security KPIs."""

    _DEFAULT_TARGETS: Dict[str, Dict[str, Any]] = {
        "vuln_sla_compliance_rate": {"target": 90.0, "unit": "%", "lower_better": False},
        "mttd_hours": {"target": 24.0, "unit": "hours", "lower_better": True},
        "mttc_hours": {"target": 4.0, "unit": "hours", "lower_better": True},
        "mttr_days": {"target": 7.0, "unit": "days", "lower_better": True},
        "security_training_completion_pct": {"target": 95.0, "unit": "%", "lower_better": False},
        "phishing_click_rate_pct": {"target": 5.0, "unit": "%", "lower_better": True},
        "third_party_risk_score": {"target": 70.0, "unit": "score (0–100)", "lower_better": False},
        "code_security_score": {"target": 80.0, "unit": "score (0–100)", "lower_better": False},
    }

    def _compute_status(
        self,
        kpi_id: str,
        value: float,
        target: float,
        lower_better: bool,
    ) -> KPIStatus:
        """Determine KPI health status with 15% tolerance for AT_RISK band."""
        if lower_better:
            if value <= target:
                return KPIStatus.ON_TRACK
            if value <= target * 1.25:
                return KPIStatus.AT_RISK
            return KPIStatus.BREACHED
        else:
            if value >= target:
                return KPIStatus.ON_TRACK
            if value >= target * 0.80:
                return KPIStatus.AT_RISK
            return KPIStatus.BREACHED

    def build_dashboard(
        self,
        org_id: str,
        values: Dict[str, float],
        previous_values: Optional[Dict[str, float]] = None,
        custom_targets: Optional[Dict[str, float]] = None,
    ) -> KPIDashboard:
        """
        Build a KPI dashboard from current metric values.

        Args:
            org_id: Organisation identifier.
            values: Current KPI values keyed by KPI ID.
            previous_values: Optional prior-period values for trend computation.
            custom_targets: Override default targets per KPI ID.

        Returns:
            KPIDashboard with status and trend for each KPI.
        """
        custom_targets = custom_targets or {}
        previous_values = previous_values or {}
        kpis: List[KPIMetric] = []
        descriptions = {
            "vuln_sla_compliance_rate": "Percentage of vulnerabilities remediated within SLA",
            "mttd_hours": "Mean Time to Detect a security incident",
            "mttc_hours": "Mean Time to Contain an active incident",
            "mttr_days": "Mean Time to Remediate a vulnerability",
            "security_training_completion_pct": "Security awareness training completion rate",
            "phishing_click_rate_pct": "Phishing simulation click-through rate",
            "third_party_risk_score": "Aggregated third-party vendor risk score",
            "code_security_score": "Code security posture score (SAST + SCA)",
        }

        for kpi_id, cfg in self._DEFAULT_TARGETS.items():
            if kpi_id not in values:
                continue
            current = values[kpi_id]
            target = custom_targets.get(kpi_id, cfg["target"])
            lower_better = cfg["lower_better"]
            status = self._compute_status(kpi_id, current, target, lower_better)

            # Compute trend
            trend = "stable"
            if kpi_id in previous_values:
                prev = previous_values[kpi_id]
                delta_pct = ((current - prev) / max(abs(prev), 0.001)) * 100
                if lower_better:
                    trend = "improving" if delta_pct <= -5 else ("degrading" if delta_pct >= 5 else "stable")
                else:
                    trend = "improving" if delta_pct >= 5 else ("degrading" if delta_pct <= -5 else "stable")

            kpis.append(KPIMetric(
                kpi_id=kpi_id,
                name=kpi_id.replace("_", " ").title(),
                value=round(current, 2),
                target=target,
                unit=cfg["unit"],
                status=status,
                trend=trend,
                description=descriptions.get(kpi_id, ""),
            ))

        on_track = sum(1 for k in kpis if k.status == KPIStatus.ON_TRACK)
        at_risk = sum(1 for k in kpis if k.status == KPIStatus.AT_RISK)
        breached = sum(1 for k in kpis if k.status == KPIStatus.BREACHED)
        total = len(kpis)

        health = 100.0
        if total > 0:
            health = ((on_track * 100 + at_risk * 60 + breached * 10) / (total * 100)) * 100

        return KPIDashboard(
            org_id=org_id,
            kpis=kpis,
            overall_health_score=round(health, 1),
            on_track_count=on_track,
            at_risk_count=at_risk,
            breached_count=breached,
        )


# ============================================================================
# BOARD REPORT GENERATOR
# ============================================================================


class BoardReportGenerator:
    """
    Generates one-page board-level executive risk reports.

    Aggregates FAIR ALE, trend data, compliance status, and KPIs into a
    single JSON-serialisable structure for React rendering.
    """

    def __init__(
        self,
        fair_engine: Optional[FAIREngine] = None,
        trend_analyser: Optional[RiskTrendAnalyser] = None,
        heatmap_engine: Optional[RegulatoryHeatmapEngine] = None,
        kpi_engine: Optional[KPIEngine] = None,
    ) -> None:
        self._fair = fair_engine or FAIREngine()
        self._trend = trend_analyser or RiskTrendAnalyser()
        self._heatmap = heatmap_engine or RegulatoryHeatmapEngine()
        self._kpi = kpi_engine or KPIEngine()

    def _current_quarter(self) -> str:
        now = datetime.now(timezone.utc)
        q = (now.month - 1) // 3 + 1
        return f"Q{q} {now.year}"

    def _build_top_5_risks(
        self,
        fair_results: List[FAIRResult],
        regulatory_statuses: List[RegulatoryStatus],
    ) -> List[Dict[str, Any]]:
        """Build top 5 risks sorted by dollar impact."""
        risks: List[Dict[str, Any]] = []

        for result in fair_results:
            risks.append({
                "risk_name": result.scenario_name,
                "category": "operational",
                "ale_p50_usd": result.ale_p50_usd,
                "ale_p90_usd": result.ale_p90_usd,
                "business_impact": f"Expected annual loss: ${result.ale_p50_usd:,.0f} (90th pct: ${result.ale_p90_usd:,.0f})",
            })

        for reg_status in regulatory_statuses:
            if reg_status.estimated_exposure_usd > 0:
                risks.append({
                    "risk_name": f"Regulatory: {reg_status.regulation.value.upper()} compliance gap",
                    "category": "regulatory",
                    "ale_p50_usd": reg_status.estimated_exposure_usd,
                    "ale_p90_usd": reg_status.max_fine_usd,
                    "business_impact": (
                        f"{reg_status.gap_count} gaps, ${reg_status.estimated_exposure_usd:,.0f} exposure, "
                        f"ETA {reg_status.remediation_eta_days}d"
                    ),
                })

        risks.sort(key=lambda r: r["ale_p50_usd"], reverse=True)
        return risks[:5]

    def generate(
        self,
        org_id: str,
        fair_scenarios: List[FAIRInputs],
        compliance_data: Dict[Regulation, float],
        kpi_values: Dict[str, float],
        previous_kpi_values: Optional[Dict[str, float]] = None,
        prior_quarter_risk_score: Optional[float] = None,
    ) -> BoardReport:
        """
        Generate a complete board report.

        Args:
            org_id: Organisation identifier.
            fair_scenarios: FAIR scenario inputs for ALE simulation.
            compliance_data: Per-regulation compliance percentages.
            kpi_values: Current KPI values.
            previous_kpi_values: Optional prior-period KPI values for trend.
            prior_quarter_risk_score: Optional last quarter's risk score for QoQ delta.

        Returns:
            BoardReport ready for JSON serialization.
        """
        # FAIR simulation
        fair_results = self._fair.run_portfolio(fair_scenarios)
        portfolio_ale = self._fair.aggregate_portfolio_ale(fair_results)

        # Regulatory heatmap
        reg_statuses = self._heatmap.build_heatmap(compliance_data)

        # KPI dashboard
        kpi_dashboard = self._kpi.build_dashboard(
            org_id=org_id,
            values=kpi_values,
            previous_values=previous_kpi_values,
        )

        # Top 5 risks
        top_5 = self._build_top_5_risks(fair_results, reg_statuses)

        # Trend
        snapshots = self._trend.get_snapshots(weeks=8)
        trend = self._trend.compute_trend(weeks=4)

        # QoQ delta
        current_score = snapshots[-1].total_risk_score if snapshots else 50.0
        if prior_quarter_risk_score is not None and prior_quarter_risk_score > 0:
            qoq_delta = ((current_score - prior_quarter_risk_score) / prior_quarter_risk_score) * 100
        else:
            qoq_delta = 0.0

        # Compliance summary
        compliance_summary = {
            reg.value.upper(): pct for reg, pct in compliance_data.items()
        }

        # KPI summary
        kpi_summary = {
            "overall_health_score": kpi_dashboard.overall_health_score,
            "on_track": kpi_dashboard.on_track_count,
            "at_risk": kpi_dashboard.at_risk_count,
            "breached": kpi_dashboard.breached_count,
            "metrics": {k.kpi_id: k.value for k in kpi_dashboard.kpis},
        }

        # Action items
        action_items: List[str] = []
        red_regs = [s for s in reg_statuses if s.color == HeatmapColor.RED]
        if red_regs:
            names = ", ".join(s.regulation.value.upper() for s in red_regs[:3])
            action_items.append(f"Immediate remediation required for {names} compliance gaps")
        breached_kpis = [k for k in kpi_dashboard.kpis if k.status == KPIStatus.BREACHED]
        if breached_kpis:
            names = ", ".join(k.name for k in breached_kpis[:2])
            action_items.append(f"KPI breach remediation plan needed for: {names}")
        if trend == "degrading":
            action_items.append("Risk posture trending upward — board-approved remediation sprint recommended")
        if portfolio_ale["total_ale_p90_usd"] > 1_000_000:
            action_items.append(
                f"Cyber-insurance coverage review: P90 ALE is "
                f"${portfolio_ale['total_ale_p90_usd']:,.0f}"
            )
        if not action_items:
            action_items.append("Continue monitoring — security posture within acceptable parameters")

        _logger.info(
            "Board report generated for %s: ALE P50=$%s, QoQ delta=%.1f%%",
            org_id,
            f"{portfolio_ale['total_ale_p50_usd']:,.0f}",
            qoq_delta,
        )

        return BoardReport(
            org_id=org_id,
            report_period=self._current_quarter(),
            risk_headline_usd=round(portfolio_ale["total_ale_p50_usd"], 2),
            risk_trend=trend,
            top_5_risks=top_5,
            compliance_summary=compliance_summary,
            kpi_summary=kpi_summary,
            qoq_delta_pct=round(qoq_delta, 2),
            action_items=action_items,
        )


# ============================================================================
# CONVENIENCE FACTORY
# ============================================================================


def create_executive_dashboard(seed: Optional[int] = None) -> Dict[str, Any]:
    """
    Factory returning all executive dashboard engine instances.

    Returns:
        Dict with keys: fair_engine, trend_analyser, benchmark_engine,
        heatmap_engine, due_diligence_engine, kpi_engine, board_report_generator.
    """
    fair_engine = FAIREngine(seed=seed)
    trend_analyser = RiskTrendAnalyser()
    benchmark_engine = PeerBenchmarkEngine()
    heatmap_engine = RegulatoryHeatmapEngine()
    due_diligence_engine = DueDiligenceEngine()
    kpi_engine = KPIEngine()
    board_report_generator = BoardReportGenerator(
        fair_engine=fair_engine,
        trend_analyser=trend_analyser,
        heatmap_engine=heatmap_engine,
        kpi_engine=kpi_engine,
    )

    return {
        "fair_engine": fair_engine,
        "trend_analyser": trend_analyser,
        "benchmark_engine": benchmark_engine,
        "heatmap_engine": heatmap_engine,
        "due_diligence_engine": due_diligence_engine,
        "kpi_engine": kpi_engine,
        "board_report_generator": board_report_generator,
    }
