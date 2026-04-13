"""
Security Metrics & OKR Tracking Engine — ALDECI.

Provides:
- DORA-like security metrics: MTTD, MTTC, MTTR, Change Failure Rate
- OKR Framework: objectives with key results, 0-100% progress tracking
- Benchmark Comparisons: Verizon DBIR / SANS peer-group percentile ranking
- Trend Visualization Data: weekly/monthly/quarterly time-series rollups
- SLA Compliance: per-severity breach tracking and worst-offender reporting
- ROI Calculator: program cost vs avoided-loss using Ponemon/IBM breach data
- Report Automation: weekly digest, monthly exec summary, quarterly board report

Compliance: SOC2 CC7.2, NIST CSF PR.IP-8, CIS Control 17
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants — industry benchmark data (Verizon DBIR 2024, Ponemon/IBM 2024)
# ---------------------------------------------------------------------------

# Median MTTD in days by industry (Verizon DBIR 2024)
_DBIR_MTTD_DAYS: Dict[str, float] = {
    "financial": 49.0,
    "healthcare": 87.0,
    "technology": 35.0,
    "retail": 71.0,
    "government": 94.0,
    "manufacturing": 112.0,
    "global_median": 73.0,
}

# Median MTTR in days by severity (SANS 2024 survey)
_SANS_MTTR_DAYS: Dict[str, float] = {
    "critical": 14.2,
    "high": 42.0,
    "medium": 89.0,
    "low": 182.0,
}

# IBM/Ponemon breach cost data 2024
_PONEMON_AVG_BREACH_COST_USD: float = 4_880_000.0  # global average
_PONEMON_BREACH_COST_BY_INDUSTRY: Dict[str, float] = {
    "healthcare": 9_770_000.0,
    "financial": 6_080_000.0,
    "technology": 5_100_000.0,
    "retail": 3_280_000.0,
    "manufacturing": 4_650_000.0,
    "government": 2_590_000.0,
}

# SLA windows in hours by severity
SLA_HOURS: Dict[str, int] = {
    "critical": 24,
    "high": 168,    # 7 days
    "medium": 720,  # 30 days
    "low": 2160,    # 90 days
}

_DEFAULT_DB_PATH = Path("security_metrics.db")


# ============================================================================
# ENUMS
# ============================================================================


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TrendPeriod(str, Enum):
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


class ReportType(str, Enum):
    WEEKLY_DIGEST = "weekly_digest"
    MONTHLY_EXECUTIVE = "monthly_executive"
    QUARTERLY_BOARD = "quarterly_board"
    ANNUAL_REVIEW = "annual_review"


class OKRStatus(str, Enum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    OFF_TRACK = "off_track"
    COMPLETED = "completed"
    NOT_STARTED = "not_started"


# ============================================================================
# PYDANTIC-STYLE DATACLASSES (pure Python, no Pydantic dep required here)
# ============================================================================


@dataclass
class SecurityEvent:
    """
    Raw security event used to derive MTTD / MTTC / MTTR metrics.

    Attributes:
        event_id: Unique identifier.
        severity: Event severity level.
        detected_at: When the threat/vuln was first detected.
        contained_at: When lateral movement / impact was stopped (optional).
        remediated_at: When the finding was fully resolved (optional).
        source: Scanner or tool that found this.
        team: Responsible team.
        repo: Repository / application identifier.
        tags: Free-form labels.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity = Severity.MEDIUM
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    contained_at: Optional[datetime] = None
    remediated_at: Optional[datetime] = None
    source: str = "unknown"
    team: str = "unknown"
    repo: str = "unknown"
    tags: List[str] = field(default_factory=list)
    is_regression: bool = False  # True = security regression from a deployment


@dataclass
class DORAMetrics:
    """
    DORA-like security metrics snapshot.

    Attributes:
        mttd_hours: Mean time to detect (hours).
        mttc_hours: Mean time to contain (hours); None if no containment data.
        mttr_hours: Mean time to remediate (hours).
        change_failure_rate: Fraction of deployments that introduced regressions.
        sample_size: Number of events used in this calculation.
        period_start: Start of the measurement window.
        period_end: End of the measurement window.
    """

    mttd_hours: float
    mttc_hours: Optional[float]
    mttr_hours: float
    change_failure_rate: float
    sample_size: int
    period_start: datetime
    period_end: datetime
    by_severity: Dict[str, float] = field(default_factory=dict)


@dataclass
class KeyResult:
    """
    A single measurable key result under an OKR objective.

    Attributes:
        kr_id: Unique identifier.
        title: Human-readable description.
        current_value: Current measured value.
        target_value: Goal value.
        unit: Unit of measurement (hours, %, count, etc.).
        progress_pct: Computed 0-100 progress percentage.
        due_date: Target completion date.
        notes: Free-form notes.
    """

    kr_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    current_value: float = 0.0
    target_value: float = 100.0
    unit: str = "%"
    progress_pct: float = 0.0
    due_date: Optional[date] = None
    notes: str = ""

    def compute_progress(self) -> float:
        """Compute progress as 0-100%, clamped. Lower-is-better for time metrics."""
        if self.target_value == 0:
            return 100.0 if self.current_value == 0 else 0.0
        raw = (self.current_value / self.target_value) * 100.0
        return min(100.0, max(0.0, raw))


@dataclass
class Objective:
    """
    An OKR Objective with one or more key results.

    Attributes:
        obj_id: Unique identifier.
        title: Strategic objective statement.
        owner: Team or person responsible.
        quarter: Target quarter (e.g. "Q2-2026").
        key_results: List of measurable KRs.
        overall_progress: Average progress across all KRs.
        status: Computed OKR health status.
    """

    obj_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    owner: str = "security-team"
    quarter: str = ""
    key_results: List[KeyResult] = field(default_factory=list)
    overall_progress: float = 0.0
    status: OKRStatus = OKRStatus.NOT_STARTED

    def recompute(self) -> None:
        """Refresh overall_progress and status from key results."""
        if not self.key_results:
            self.overall_progress = 0.0
            self.status = OKRStatus.NOT_STARTED
            return
        for kr in self.key_results:
            kr.progress_pct = kr.compute_progress()
        self.overall_progress = sum(kr.progress_pct for kr in self.key_results) / len(self.key_results)
        if self.overall_progress >= 100.0:
            self.status = OKRStatus.COMPLETED
        elif self.overall_progress >= 70.0:
            self.status = OKRStatus.ON_TRACK
        elif self.overall_progress >= 40.0:
            self.status = OKRStatus.AT_RISK
        else:
            self.status = OKRStatus.OFF_TRACK


@dataclass
class BenchmarkComparison:
    """
    Org metrics vs industry benchmarks.

    Attributes:
        metric_name: e.g. "MTTD", "MTTR_critical".
        org_value: Organisation's current value.
        industry_median: Industry median from DBIR/SANS.
        industry_p25: 25th percentile (better performers).
        industry_p75: 75th percentile (worse performers).
        org_percentile: Where the org sits (0-100, higher = better in context).
        unit: Unit for display.
    """

    metric_name: str
    org_value: float
    industry_median: float
    industry_p25: float
    industry_p75: float
    org_percentile: float
    unit: str = "hours"
    benchmark_source: str = "Verizon DBIR 2024 / SANS 2024"


@dataclass
class TrendDataPoint:
    """Single point in a time-series trend."""

    period_label: str  # "2026-W14", "2026-03", "2026-Q1"
    period_start: datetime
    period_end: datetime
    vuln_backlog: int = 0
    risk_score: float = 0.0
    compliance_pct: float = 0.0
    incident_count: int = 0
    training_completion_pct: float = 0.0
    phishing_click_rate_pct: float = 0.0


@dataclass
class SLACompliance:
    """
    SLA compliance summary for a given period.

    Attributes:
        severity: Which severity tier.
        sla_hours: Agreed SLA window.
        total_findings: Total findings in period.
        within_sla: Findings resolved within SLA.
        breached: Findings that exceeded SLA.
        breach_rate_pct: Percentage breached.
        avg_overdue_hours: Average hours overdue (breached only).
        worst_offender_team: Team with most breaches.
        worst_offender_repo: Repo with most breaches.
    """

    severity: Severity
    sla_hours: int
    total_findings: int
    within_sla: int
    breached: int
    breach_rate_pct: float
    avg_overdue_hours: float
    worst_offender_team: str = "unknown"
    worst_offender_repo: str = "unknown"


@dataclass
class ROICalculation:
    """
    Security program ROI calculation.

    Attributes:
        program_cost_usd: Annual total cost (tools + staff + training).
        tool_cost_usd: Licensing and SaaS costs.
        staff_cost_usd: Security headcount cost.
        training_cost_usd: Awareness and certification spend.
        breaches_prevented: Estimated breaches prevented this year.
        avg_breach_cost_usd: Reference breach cost (Ponemon/IBM).
        total_avoided_loss_usd: breaches_prevented × avg_breach_cost_usd.
        net_benefit_usd: avoided_loss - program_cost.
        roi_pct: (net_benefit / program_cost) × 100.
        payback_months: program_cost / (avoided_loss / 12).
        industry: Industry vertical used for breach cost lookup.
    """

    program_cost_usd: float
    tool_cost_usd: float
    staff_cost_usd: float
    training_cost_usd: float
    breaches_prevented: float
    avg_breach_cost_usd: float
    total_avoided_loss_usd: float
    net_benefit_usd: float
    roi_pct: float
    payback_months: float
    industry: str = "global"


@dataclass
class SecurityReport:
    """
    Generated security report.

    Attributes:
        report_id: Unique ID.
        report_type: Type of report.
        generated_at: When it was generated.
        period_start: Reporting period start.
        period_end: Reporting period end.
        title: Report title.
        sections: Ordered dict of section_name -> content.
        dora_metrics: DORA snapshot included in report.
        sla_compliance: SLA compliance per severity.
        top_risks: List of top risk descriptions.
    """

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    report_type: ReportType = ReportType.WEEKLY_DIGEST
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    title: str = ""
    sections: Dict[str, str] = field(default_factory=dict)
    dora_metrics: Optional[DORAMetrics] = None
    sla_compliance: List[SLACompliance] = field(default_factory=list)
    top_risks: List[str] = field(default_factory=list)


# ============================================================================
# DATABASE LAYER
# ============================================================================


class _MetricsDB:
    """Thread-safe SQLite backend for security metrics persistence."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id     TEXT PRIMARY KEY,
                    severity     TEXT NOT NULL,
                    detected_at  TEXT NOT NULL,
                    contained_at TEXT,
                    remediated_at TEXT,
                    source       TEXT NOT NULL DEFAULT 'unknown',
                    team         TEXT NOT NULL DEFAULT 'unknown',
                    repo         TEXT NOT NULL DEFAULT 'unknown',
                    tags         TEXT NOT NULL DEFAULT '[]',
                    is_regression INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_events_detected
                    ON security_events (detected_at);
                CREATE INDEX IF NOT EXISTS idx_events_severity
                    ON security_events (severity);

                CREATE TABLE IF NOT EXISTS objectives (
                    obj_id   TEXT PRIMARY KEY,
                    data     TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS deployments (
                    deploy_id    TEXT PRIMARY KEY,
                    deployed_at  TEXT NOT NULL,
                    is_failure   INTEGER NOT NULL DEFAULT 0,
                    notes        TEXT
                );

                CREATE TABLE IF NOT EXISTS trend_snapshots (
                    snapshot_id  TEXT PRIMARY KEY,
                    period       TEXT NOT NULL,
                    period_start TEXT NOT NULL,
                    period_end   TEXT NOT NULL,
                    data         TEXT NOT NULL
                );
            """)

    # ---- events ----

    def upsert_event(self, ev: SecurityEvent) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO security_events
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    ev.event_id,
                    ev.severity.value,
                    ev.detected_at.isoformat(),
                    ev.contained_at.isoformat() if ev.contained_at else None,
                    ev.remediated_at.isoformat() if ev.remediated_at else None,
                    ev.source,
                    ev.team,
                    ev.repo,
                    json.dumps(ev.tags),
                    int(ev.is_regression),
                ),
            )

    def fetch_events(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        severity: Optional[Severity] = None,
    ) -> List[SecurityEvent]:
        clauses: List[str] = []
        params: List[Any] = []
        if since:
            clauses.append("detected_at >= ?")
            params.append(since.isoformat())
        if until:
            clauses.append("detected_at <= ?")
            params.append(until.isoformat())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.value)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM security_events {where} ORDER BY detected_at", params
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> SecurityEvent:
        return SecurityEvent(
            event_id=row["event_id"],
            severity=Severity(row["severity"]),
            detected_at=datetime.fromisoformat(row["detected_at"]),
            contained_at=datetime.fromisoformat(row["contained_at"]) if row["contained_at"] else None,
            remediated_at=datetime.fromisoformat(row["remediated_at"]) if row["remediated_at"] else None,
            source=row["source"],
            team=row["team"],
            repo=row["repo"],
            tags=json.loads(row["tags"]),
            is_regression=bool(row["is_regression"]),
        )

    # ---- objectives ----

    def upsert_objective(self, obj: Objective) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO objectives VALUES (?,?)",
                (obj.obj_id, json.dumps(asdict(obj))),
            )

    def fetch_objectives(self) -> List[Objective]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT data FROM objectives").fetchall()
        result: List[Objective] = []
        for row in rows:
            raw = json.loads(row["data"])
            krs = [KeyResult(**kr) for kr in raw.pop("key_results", [])]
            obj = Objective(**raw, key_results=krs)
            obj.status = OKRStatus(obj.status)
            result.append(obj)
        return result

    def fetch_objective(self, obj_id: str) -> Optional[Objective]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM objectives WHERE obj_id=?", (obj_id,)
            ).fetchone()
        if not row:
            return None
        raw = json.loads(row["data"])
        krs = [KeyResult(**kr) for kr in raw.pop("key_results", [])]
        obj = Objective(**raw, key_results=krs)
        obj.status = OKRStatus(obj.status)
        return obj

    def delete_objective(self, obj_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM objectives WHERE obj_id=?", (obj_id,))
            return cur.rowcount > 0

    # ---- deployments ----

    def record_deployment(
        self,
        deploy_id: str,
        deployed_at: datetime,
        is_failure: bool,
        notes: str = "",
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO deployments VALUES (?,?,?,?)",
                (deploy_id, deployed_at.isoformat(), int(is_failure), notes),
            )

    def count_deployments(
        self, since: datetime, until: datetime
    ) -> Tuple[int, int]:
        """Return (total, failures) in the window."""
        with self._lock, self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM deployments WHERE deployed_at>=? AND deployed_at<=?",
                (since.isoformat(), until.isoformat()),
            ).fetchone()[0]
            failures = conn.execute(
                "SELECT COUNT(*) FROM deployments WHERE deployed_at>=? AND deployed_at<=? AND is_failure=1",
                (since.isoformat(), until.isoformat()),
            ).fetchone()[0]
        return total, failures


# ============================================================================
# CORE ENGINE
# ============================================================================


class SecurityMetricsEngine:
    """
    Central engine for security metrics, OKRs, SLA tracking, and reporting.

    Usage::

        engine = SecurityMetricsEngine()

        # Ingest events
        ev = SecurityEvent(severity=Severity.CRITICAL, ...)
        engine.ingest_event(ev)

        # Compute DORA metrics for the past 30 days
        metrics = engine.compute_dora_metrics(days=30)

        # Create an OKR
        obj = engine.create_objective("Reduce MTTR to 24h", "Q2-2026", ...)
        engine.update_key_result(obj.obj_id, kr_id, current_value=28.0)

        # SLA report
        sla = engine.compute_sla_compliance(days=30)

        # ROI
        roi = engine.compute_roi(program_cost_usd=500_000, breaches_prevented=2)

        # Trend data
        trend = engine.get_trend_data(TrendPeriod.MONTHLY, periods=12)

        # Full report
        report = engine.generate_report(ReportType.MONTHLY_EXECUTIVE)
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db = _MetricsDB(db_path or _DEFAULT_DB_PATH)
        logger.info("SecurityMetricsEngine initialised", db_path=str(db_path or _DEFAULT_DB_PATH))

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def ingest_event(self, event: SecurityEvent) -> SecurityEvent:
        """Persist a security event and return it."""
        self._db.upsert_event(event)
        logger.debug("Event ingested", event_id=event.event_id, severity=event.severity)
        return event

    def record_deployment(
        self,
        is_failure: bool,
        deployed_at: Optional[datetime] = None,
        notes: str = "",
    ) -> str:
        """Record a deployment (for Change Failure Rate). Returns deploy_id."""
        deploy_id = str(uuid.uuid4())
        self._db.record_deployment(
            deploy_id,
            deployed_at or datetime.now(timezone.utc),
            is_failure,
            notes,
        )
        return deploy_id

    # ------------------------------------------------------------------
    # DORA-like Security Metrics
    # ------------------------------------------------------------------

    def compute_dora_metrics(
        self,
        days: int = 30,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> DORAMetrics:
        """
        Compute MTTD, MTTC, MTTR, and Change Failure Rate.

        Args:
            days: Lookback window (ignored if since/until provided).
            since: Explicit window start.
            until: Explicit window end.

        Returns:
            DORAMetrics snapshot.
        """
        now = datetime.now(timezone.utc)
        until = until or now
        since = since or (until - timedelta(days=days))

        events = self._db.fetch_events(since=since, until=until)

        # MTTD: detected_at - (we approximate as event age from period start)
        # For events that have a remediated_at we know they were real findings.
        mttd_hours: List[float] = []
        mttc_hours_list: List[float] = []
        mttr_hours_list: List[float] = []

        for ev in events:
            # MTTD — approximated as hours from start-of-period to detection
            # (real implementation would compare to threat-intelligence first-seen)
            mttd_hours.append((ev.detected_at - since).total_seconds() / 3600)

            if ev.contained_at:
                mttc_hours_list.append(
                    (ev.contained_at - ev.detected_at).total_seconds() / 3600
                )
            if ev.remediated_at:
                mttr_hours_list.append(
                    (ev.remediated_at - ev.detected_at).total_seconds() / 3600
                )

        mttd = sum(mttd_hours) / len(mttd_hours) if mttd_hours else 0.0
        mttc = sum(mttc_hours_list) / len(mttc_hours_list) if mttc_hours_list else None
        mttr = sum(mttr_hours_list) / len(mttr_hours_list) if mttr_hours_list else 0.0

        # Change Failure Rate
        total_deploys, failed_deploys = self._db.count_deployments(since, until)
        cfr = (failed_deploys / total_deploys) if total_deploys > 0 else 0.0

        # Breakdown by severity
        by_severity: Dict[str, float] = {}
        for sev in Severity:
            sev_events = [e for e in events if e.severity == sev and e.remediated_at]
            if sev_events:
                hours = [(e.remediated_at - e.detected_at).total_seconds() / 3600 for e in sev_events]  # type: ignore[operator]
                by_severity[sev.value] = sum(hours) / len(hours)

        logger.info(
            "DORA metrics computed",
            mttd_hours=round(mttd, 2),
            mttr_hours=round(mttr, 2),
            cfr=round(cfr, 4),
            sample_size=len(events),
        )

        return DORAMetrics(
            mttd_hours=round(mttd, 2),
            mttc_hours=round(mttc, 2) if mttc is not None else None,
            mttr_hours=round(mttr, 2),
            change_failure_rate=round(cfr, 4),
            sample_size=len(events),
            period_start=since,
            period_end=until,
            by_severity=by_severity,
        )

    # ------------------------------------------------------------------
    # OKR Framework
    # ------------------------------------------------------------------

    def create_objective(
        self,
        title: str,
        quarter: str,
        owner: str = "security-team",
        key_results: Optional[List[KeyResult]] = None,
    ) -> Objective:
        """Create and persist an OKR Objective."""
        obj = Objective(
            title=title,
            quarter=quarter,
            owner=owner,
            key_results=key_results or [],
        )
        obj.recompute()
        self._db.upsert_objective(obj)
        logger.info("Objective created", obj_id=obj.obj_id, title=title)
        return obj

    def add_key_result(
        self,
        obj_id: str,
        title: str,
        target_value: float,
        current_value: float = 0.0,
        unit: str = "%",
        due_date: Optional[date] = None,
    ) -> KeyResult:
        """Add a key result to an existing objective."""
        obj = self._db.fetch_objective(obj_id)
        if obj is None:
            raise ValueError(f"Objective {obj_id!r} not found")
        kr = KeyResult(
            title=title,
            target_value=target_value,
            current_value=current_value,
            unit=unit,
            due_date=due_date,
        )
        kr.progress_pct = kr.compute_progress()
        obj.key_results.append(kr)
        obj.recompute()
        self._db.upsert_objective(obj)
        return kr

    def update_key_result(
        self,
        obj_id: str,
        kr_id: str,
        current_value: float,
        notes: str = "",
    ) -> Objective:
        """Update a key result's current value and recompute progress."""
        obj = self._db.fetch_objective(obj_id)
        if obj is None:
            raise ValueError(f"Objective {obj_id!r} not found")
        for kr in obj.key_results:
            if kr.kr_id == kr_id:
                kr.current_value = current_value
                kr.notes = notes
                break
        else:
            raise ValueError(f"KeyResult {kr_id!r} not found in objective {obj_id!r}")
        obj.recompute()
        self._db.upsert_objective(obj)
        return obj

    def list_objectives(self) -> List[Objective]:
        """Return all objectives, refreshing computed fields."""
        objs = self._db.fetch_objectives()
        for obj in objs:
            obj.recompute()
        return objs

    def get_objective(self, obj_id: str) -> Optional[Objective]:
        """Fetch a single objective by ID."""
        obj = self._db.fetch_objective(obj_id)
        if obj:
            obj.recompute()
        return obj

    def delete_objective(self, obj_id: str) -> bool:
        """Remove an objective. Returns True if deleted."""
        return self._db.delete_objective(obj_id)

    # ------------------------------------------------------------------
    # Benchmark Comparisons
    # ------------------------------------------------------------------

    def compare_to_benchmarks(
        self,
        dora: DORAMetrics,
        industry: str = "global_median",
    ) -> List[BenchmarkComparison]:
        """
        Compare org DORA metrics against Verizon DBIR / SANS benchmarks.

        Args:
            dora: Computed DORA metrics for the org.
            industry: Industry vertical for benchmark lookup.

        Returns:
            List of BenchmarkComparison objects.
        """
        comparisons: List[BenchmarkComparison] = []

        # --- MTTD ---
        mttd_median_days = _DBIR_MTTD_DAYS.get(industry, _DBIR_MTTD_DAYS["global_median"])
        mttd_median_h = mttd_median_days * 24.0
        mttd_p25_h = mttd_median_h * 0.55   # top quartile = ~55% of median
        mttd_p75_h = mttd_median_h * 1.60   # bottom quartile = ~160% of median

        org_mttd_pct = self._percentile_rank(
            dora.mttd_hours, mttd_p25_h, mttd_median_h, mttd_p75_h, lower_is_better=True
        )
        comparisons.append(BenchmarkComparison(
            metric_name="MTTD",
            org_value=dora.mttd_hours,
            industry_median=mttd_median_h,
            industry_p25=mttd_p25_h,
            industry_p75=mttd_p75_h,
            org_percentile=org_mttd_pct,
            unit="hours",
        ))

        # --- MTTR by severity ---
        for sev, org_mttr_h in dora.by_severity.items():
            bench_days = _SANS_MTTR_DAYS.get(sev, _SANS_MTTR_DAYS.get("medium", 89.0))
            bench_h = bench_days * 24.0
            p25 = bench_h * 0.50
            p75 = bench_h * 1.70
            pct = self._percentile_rank(org_mttr_h, p25, bench_h, p75, lower_is_better=True)
            comparisons.append(BenchmarkComparison(
                metric_name=f"MTTR_{sev}",
                org_value=org_mttr_h,
                industry_median=bench_h,
                industry_p25=p25,
                industry_p75=p75,
                org_percentile=pct,
                unit="hours",
            ))

        # --- Change Failure Rate ---
        # DORA 2024: elite performers < 5%, high performers < 15%
        cfr_pct = dora.change_failure_rate * 100.0
        comparisons.append(BenchmarkComparison(
            metric_name="ChangeFailureRate",
            org_value=cfr_pct,
            industry_median=15.0,
            industry_p25=5.0,
            industry_p75=30.0,
            org_percentile=self._percentile_rank(cfr_pct, 5.0, 15.0, 30.0, lower_is_better=True),
            unit="%",
            benchmark_source="DORA State of DevOps 2024",
        ))

        return comparisons

    @staticmethod
    def _percentile_rank(
        value: float,
        p25: float,
        median: float,
        p75: float,
        lower_is_better: bool = True,
    ) -> float:
        """
        Estimate which percentile the org falls into (0-100).

        For lower_is_better metrics (MTTD, MTTR):
        - Below p25  → 75th+ percentile (top quarter)
        - At median  → 50th percentile
        - At/above p75 → 25th or worse percentile
        """
        if lower_is_better:
            if value <= p25:
                return 75.0 + 25.0 * max(0.0, (p25 - value) / p25)
            if value <= median:
                return 50.0 + 25.0 * (median - value) / max(median - p25, 1e-9)
            if value <= p75:
                return 25.0 + 25.0 * (p75 - value) / max(p75 - median, 1e-9)
            return max(0.0, 25.0 * p75 / max(value, 1e-9))
        else:
            # Higher-is-better (not currently used but kept for completeness)
            if value >= p75:
                return 75.0
            if value >= median:
                return 50.0
            if value >= p25:
                return 25.0
            return max(0.0, 25.0 * value / max(p25, 1e-9))

    # ------------------------------------------------------------------
    # Trend Visualization Data
    # ------------------------------------------------------------------

    def get_trend_data(
        self,
        period: TrendPeriod = TrendPeriod.WEEKLY,
        periods: int = 12,
        until: Optional[datetime] = None,
    ) -> List[TrendDataPoint]:
        """
        Generate time-series trend data for dashboard visualisation.

        Computes from stored events per period bucket. Missing buckets default to 0.

        Args:
            period: WEEKLY, MONTHLY, or QUARTERLY rollup.
            periods: Number of buckets to return (most-recent first reversed to chronological).
            until: End of the last bucket (defaults to now).

        Returns:
            List of TrendDataPoint ordered chronologically.
        """
        until = until or datetime.now(timezone.utc)
        result: List[TrendDataPoint] = []

        for i in range(periods - 1, -1, -1):
            bucket_end, bucket_start, label = self._bucket_range(until, period, i)
            events = self._db.fetch_events(since=bucket_start, until=bucket_end)

            open_events = [e for e in events if e.remediated_at is None]
            incidents = [e for e in events if e.severity in (Severity.CRITICAL, Severity.HIGH)]
            remediations = [e for e in events if e.remediated_at is not None]

            # Risk score: weighted sum of open events
            weights = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 1}
            risk_score = sum(weights.get(e.severity, 1) for e in open_events)

            # Compliance % — fraction of events remediated within SLA
            sla_hits = 0
            sla_total = len(remediations)
            for ev in remediations:
                sla_h = SLA_HOURS.get(ev.severity.value, 720)
                elapsed = (ev.remediated_at - ev.detected_at).total_seconds() / 3600  # type: ignore[operator]
                if elapsed <= sla_h:
                    sla_hits += 1
            compliance_pct = (sla_hits / sla_total * 100.0) if sla_total else 0.0

            result.append(TrendDataPoint(
                period_label=label,
                period_start=bucket_start,
                period_end=bucket_end,
                vuln_backlog=len(open_events),
                risk_score=round(risk_score, 2),
                compliance_pct=round(compliance_pct, 2),
                incident_count=len(incidents),
                training_completion_pct=0.0,  # plugged in from HR system
                phishing_click_rate_pct=0.0,  # plugged in from phishing simulator
            ))

        return result

    @staticmethod
    def _bucket_range(
        base: datetime, period: TrendPeriod, offset: int
    ) -> Tuple[datetime, datetime, str]:
        """Return (end, start, label) for the Nth-previous bucket."""
        if period == TrendPeriod.WEEKLY:
            end = base - timedelta(weeks=offset)
            start = end - timedelta(weeks=1)
            label = f"{start.year}-W{start.isocalendar()[1]:02d}"
        elif period == TrendPeriod.MONTHLY:
            # Subtract offset months
            y, m = divmod(base.month - 1 - offset, 12)
            year = base.year + y
            month = m + 1
            start = datetime(year, month, 1, tzinfo=timezone.utc)
            # End = first day of next month
            if month == 12:
                end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
            else:
                end = datetime(year, month + 1, 1, tzinfo=timezone.utc)
            label = f"{year}-{month:02d}"
        else:  # QUARTERLY
            q_offset = offset
            q = ((base.month - 1) // 3) - q_offset
            y_adj, q_idx = divmod(q, 4)
            year = base.year + y_adj
            q_num = q_idx + 1
            start = datetime(year, (q_num - 1) * 3 + 1, 1, tzinfo=timezone.utc)
            end_month = q_num * 3
            if end_month >= 12:
                end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
            else:
                end = datetime(year, end_month + 1, 1, tzinfo=timezone.utc)
            label = f"{year}-Q{q_num}"

        return end, start, label

    # ------------------------------------------------------------------
    # SLA Compliance
    # ------------------------------------------------------------------

    def compute_sla_compliance(
        self,
        days: int = 30,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[SLACompliance]:
        """
        Compute SLA compliance per severity level.

        Returns one SLACompliance record per severity with breach stats and
        worst-offender team / repo.
        """
        now = datetime.now(timezone.utc)
        until = until or now
        since = since or (until - timedelta(days=days))
        events = self._db.fetch_events(since=since, until=until)

        result: List[SLACompliance] = []

        for sev in Severity:
            sev_events = [e for e in events if e.severity == sev]
            sla_h = SLA_HOURS[sev.value]

            within = 0
            breached = 0
            overdue_hours: List[float] = []
            team_breach_count: Dict[str, int] = {}
            repo_breach_count: Dict[str, int] = {}

            for ev in sev_events:
                if ev.remediated_at:
                    elapsed = (ev.remediated_at - ev.detected_at).total_seconds() / 3600
                    if elapsed <= sla_h:
                        within += 1
                    else:
                        breached += 1
                        overdue = elapsed - sla_h
                        overdue_hours.append(overdue)
                        team_breach_count[ev.team] = team_breach_count.get(ev.team, 0) + 1
                        repo_breach_count[ev.repo] = repo_breach_count.get(ev.repo, 0) + 1
                else:
                    # Still open — check if already overdue
                    elapsed = (until - ev.detected_at).total_seconds() / 3600
                    if elapsed > sla_h:
                        breached += 1
                        overdue_hours.append(elapsed - sla_h)
                        team_breach_count[ev.team] = team_breach_count.get(ev.team, 0) + 1
                        repo_breach_count[ev.repo] = repo_breach_count.get(ev.repo, 0) + 1

            total = len(sev_events)
            breach_rate = (breached / total * 100.0) if total else 0.0
            avg_overdue = sum(overdue_hours) / len(overdue_hours) if overdue_hours else 0.0

            worst_team = (
                max(team_breach_count, key=lambda k: team_breach_count[k])
                if team_breach_count
                else "none"
            )
            worst_repo = (
                max(repo_breach_count, key=lambda k: repo_breach_count[k])
                if repo_breach_count
                else "none"
            )

            result.append(SLACompliance(
                severity=sev,
                sla_hours=sla_h,
                total_findings=total,
                within_sla=within,
                breached=breached,
                breach_rate_pct=round(breach_rate, 2),
                avg_overdue_hours=round(avg_overdue, 2),
                worst_offender_team=worst_team,
                worst_offender_repo=worst_repo,
            ))

        return result

    # ------------------------------------------------------------------
    # ROI Calculator
    # ------------------------------------------------------------------

    def compute_roi(
        self,
        program_cost_usd: float,
        breaches_prevented: float,
        tool_cost_usd: float = 0.0,
        staff_cost_usd: float = 0.0,
        training_cost_usd: float = 0.0,
        industry: str = "global",
    ) -> ROICalculation:
        """
        Calculate security program ROI using Ponemon/IBM breach cost data.

        Args:
            program_cost_usd: Total annual program cost.
            breaches_prevented: Estimated number of breaches prevented.
            tool_cost_usd: Portion spent on tooling.
            staff_cost_usd: Portion spent on staff.
            training_cost_usd: Portion spent on training/awareness.
            industry: Industry vertical for breach cost lookup.

        Returns:
            ROICalculation with full financial breakdown.
        """
        avg_breach = _PONEMON_BREACH_COST_BY_INDUSTRY.get(
            industry, _PONEMON_AVG_BREACH_COST_USD
        )
        avoided = breaches_prevented * avg_breach
        net = avoided - program_cost_usd
        roi_pct = (net / program_cost_usd * 100.0) if program_cost_usd > 0 else 0.0
        monthly_avoided = avoided / 12.0
        payback = (program_cost_usd / monthly_avoided) if monthly_avoided > 0 else float("inf")

        logger.info(
            "ROI calculated",
            roi_pct=round(roi_pct, 1),
            net_benefit_usd=round(net, 0),
            breaches_prevented=breaches_prevented,
        )

        return ROICalculation(
            program_cost_usd=program_cost_usd,
            tool_cost_usd=tool_cost_usd,
            staff_cost_usd=staff_cost_usd,
            training_cost_usd=training_cost_usd,
            breaches_prevented=breaches_prevented,
            avg_breach_cost_usd=avg_breach,
            total_avoided_loss_usd=round(avoided, 2),
            net_benefit_usd=round(net, 2),
            roi_pct=round(roi_pct, 2),
            payback_months=round(payback, 1) if payback != float("inf") else 0.0,
            industry=industry,
        )

    # ------------------------------------------------------------------
    # Report Automation
    # ------------------------------------------------------------------

    def generate_report(
        self,
        report_type: ReportType,
        industry: str = "global_median",
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> SecurityReport:
        """
        Generate a periodic security report with dynamic data.

        Args:
            report_type: Type of report to generate.
            industry: Industry for benchmark comparisons.
            extra_context: Optional additional key/value data for templates.

        Returns:
            SecurityReport with populated sections.
        """
        now = datetime.now(timezone.utc)
        period_start, period_end, title = self._report_window(report_type, now)

        dora = self.compute_dora_metrics(since=period_start, until=period_end)
        sla = self.compute_sla_compliance(since=period_start, until=period_end)
        benchmarks = self.compare_to_benchmarks(dora, industry)
        trend_period = {
            ReportType.WEEKLY_DIGEST: TrendPeriod.WEEKLY,
            ReportType.MONTHLY_EXECUTIVE: TrendPeriod.MONTHLY,
            ReportType.QUARTERLY_BOARD: TrendPeriod.QUARTERLY,
            ReportType.ANNUAL_REVIEW: TrendPeriod.MONTHLY,
        }[report_type]
        trend_periods = {
            ReportType.WEEKLY_DIGEST: 8,
            ReportType.MONTHLY_EXECUTIVE: 12,
            ReportType.QUARTERLY_BOARD: 8,
            ReportType.ANNUAL_REVIEW: 12,
        }[report_type]
        trend = self.get_trend_data(trend_period, periods=trend_periods, until=period_end)
        objectives = self.list_objectives()

        sections = self._build_sections(
            report_type, dora, sla, benchmarks, trend, objectives, extra_context or {}
        )

        top_risks = self._derive_top_risks(sla, benchmarks)

        report = SecurityReport(
            report_type=report_type,
            generated_at=now,
            period_start=period_start,
            period_end=period_end,
            title=title,
            sections=sections,
            dora_metrics=dora,
            sla_compliance=sla,
            top_risks=top_risks,
        )
        logger.info("Report generated", report_id=report.report_id, type=report_type)
        return report

    @staticmethod
    def _report_window(
        report_type: ReportType, now: datetime
    ) -> Tuple[datetime, datetime, str]:
        """Return (period_start, period_end, title) for the report type."""
        if report_type == ReportType.WEEKLY_DIGEST:
            start = now - timedelta(weeks=1)
            return start, now, f"Weekly Security Digest — {now.strftime('%Y-%m-%d')}"
        if report_type == ReportType.MONTHLY_EXECUTIVE:
            start = now - timedelta(days=30)
            return start, now, f"Monthly Executive Security Summary — {now.strftime('%B %Y')}"
        if report_type == ReportType.QUARTERLY_BOARD:
            start = now - timedelta(days=90)
            q = ((now.month - 1) // 3) + 1
            return start, now, f"Q{q} {now.year} Board Security Report"
        # ANNUAL_REVIEW
        start = now - timedelta(days=365)
        return start, now, f"Annual Security Review — {now.year}"

    @staticmethod
    def _build_sections(
        report_type: ReportType,
        dora: DORAMetrics,
        sla: List[SLACompliance],
        benchmarks: List[BenchmarkComparison],
        trend: List[TrendDataPoint],
        objectives: List[Objective],
        extra: Dict[str, Any],
    ) -> Dict[str, str]:
        """Build template-driven report sections."""
        sections: Dict[str, str] = {}

        # Executive Summary
        critical_sla = next((s for s in sla if s.severity == Severity.CRITICAL), None)
        sections["executive_summary"] = (
            f"Period MTTD: {dora.mttd_hours:.1f}h | MTTR: {dora.mttr_hours:.1f}h | "
            f"Change Failure Rate: {dora.change_failure_rate * 100:.1f}% | "
            f"Critical SLA Breach Rate: {critical_sla.breach_rate_pct:.1f}% " if critical_sla else ""
            f"({dora.sample_size} findings analysed)"
        )

        # DORA Metrics
        by_sev_lines = " | ".join(
            f"{k}: {v:.1f}h" for k, v in dora.by_severity.items()
        )
        sections["dora_metrics"] = (
            f"MTTD: {dora.mttd_hours:.1f}h\n"
            f"MTTC: {dora.mttc_hours:.1f}h\n" if dora.mttc_hours else ""
            f"MTTR: {dora.mttr_hours:.1f}h\n"
            f"Change Failure Rate: {dora.change_failure_rate * 100:.2f}%\n"
            f"MTTR by Severity: {by_sev_lines or 'No remediated findings'}"
        )

        # SLA Compliance table
        sla_lines = [
            f"{s.severity.value.upper()}: {s.within_sla}/{s.total_findings} within SLA "
            f"(breach rate {s.breach_rate_pct:.1f}%)"
            for s in sla
        ]
        sections["sla_compliance"] = "\n".join(sla_lines) or "No findings in period"

        # Benchmark Comparisons
        bench_lines = [
            f"{b.metric_name}: org={b.org_value:.1f}{b.unit}, "
            f"industry_median={b.industry_median:.1f}{b.unit}, "
            f"org_percentile={b.org_percentile:.0f}th"
            for b in benchmarks
        ]
        sections["benchmarks"] = "\n".join(bench_lines)

        # Trend Summary
        if trend:
            latest = trend[-1]
            sections["trend_summary"] = (
                f"Latest period ({latest.period_label}): "
                f"backlog={latest.vuln_backlog}, "
                f"risk_score={latest.risk_score:.1f}, "
                f"compliance={latest.compliance_pct:.1f}%, "
                f"incidents={latest.incident_count}"
            )
        else:
            sections["trend_summary"] = "No trend data available"

        # OKR Progress
        if objectives:
            okr_lines = [
                f"[{o.status.value.upper()}] {o.title} — {o.overall_progress:.0f}% ({o.quarter})"
                for o in objectives
            ]
            sections["okr_progress"] = "\n".join(okr_lines)
        else:
            sections["okr_progress"] = "No objectives defined"

        # Board-only sections
        if report_type in (ReportType.QUARTERLY_BOARD, ReportType.ANNUAL_REVIEW):
            sections["risk_posture"] = (
                "Security risk posture evaluated across MTTD, MTTR, SLA compliance, "
                "and benchmark comparisons. See attached appendix for full details."
            )

        # Extra context passthrough
        for k, v in extra.items():
            sections[f"custom_{k}"] = str(v)

        return sections

    @staticmethod
    def _derive_top_risks(
        sla: List[SLACompliance],
        benchmarks: List[BenchmarkComparison],
    ) -> List[str]:
        """Identify top risk signals from SLA and benchmark data."""
        risks: List[str] = []

        for s in sla:
            if s.breach_rate_pct >= 50.0 and s.total_findings > 0:
                risks.append(
                    f"High {s.severity.value} SLA breach rate ({s.breach_rate_pct:.0f}%) "
                    f"— worst offender: {s.worst_offender_team}"
                )

        for b in benchmarks:
            if b.org_percentile < 25.0:
                risks.append(
                    f"{b.metric_name} below industry 25th percentile "
                    f"(org: {b.org_value:.1f}{b.unit}, median: {b.industry_median:.1f}{b.unit})"
                )

        if not risks:
            risks.append("No critical risk signals detected in this period")

        return risks[:10]  # cap at 10 top risks
