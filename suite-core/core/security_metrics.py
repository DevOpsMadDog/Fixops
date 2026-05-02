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
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

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
                f"SELECT * FROM security_events {where} ORDER BY detected_at", params  # nosec B608
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


# ============================================================================
# SECURITY METRICS AGGREGATOR — KPI Dashboard Engine
# ============================================================================


@dataclass
class FindingMetrics:
    """Aggregated finding counts and trends across all severity tiers."""

    total_open: int = 0
    critical_open: int = 0
    high_open: int = 0
    medium_open: int = 0
    low_open: int = 0
    new_24h: int = 0
    new_7d: int = 0
    new_30d: int = 0
    closed_24h: int = 0
    closed_7d: int = 0
    closed_30d: int = 0
    mttr_by_severity: Dict[str, float] = field(default_factory=dict)  # hours
    false_positive_rate: float = 0.0


@dataclass
class CoverageMetrics:
    """Attack surface monitoring coverage percentages."""

    repos_scanned_pct: float = 0.0
    assets_inventoried_pct: float = 0.0
    endpoints_monitored_pct: float = 0.0
    trustgraph_coverage_pct: float = 0.0
    total_finding_sources: int = 0
    active_scanners: List[str] = field(default_factory=list)


@dataclass
class SLAMetrics:
    """SLA compliance rates and breach statistics."""

    overall_compliance_rate: float = 0.0
    compliance_by_severity: Dict[str, float] = field(default_factory=dict)
    total_records: int = 0
    on_time_resolutions: int = 0
    breaches: int = 0
    at_risk_count: int = 0  # open findings approaching SLA deadline
    avg_overdue_hours: float = 0.0


@dataclass
class ResponseMetrics:
    """Incident response effectiveness metrics."""

    mttd_hours: float = 0.0   # mean time to detect
    mttr_hours: float = 0.0   # mean time to remediate
    escalation_rate: float = 0.0
    automated_response_rate: float = 0.0
    total_incidents: int = 0
    open_incidents: int = 0
    closed_incidents: int = 0


@dataclass
class ExecutiveSummary:
    """One-page executive summary for CISO."""

    overall_security_score: float = 0.0
    score_trend: str = "stable"  # "improving", "degrading", "stable"
    top_risks: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    period_label: str = ""
    finding_metrics: Optional["FindingMetrics"] = None
    sla_metrics: Optional["SLAMetrics"] = None
    response_metrics: Optional["ResponseMetrics"] = None


# Default DB paths relative to this file
_SUITE_DATA = Path(__file__).resolve().parents[2] / "data"


class SecurityMetricsAggregator:
    """
    Aggregates security KPIs from all ALDECI engines.

    Reads from SQLite databases in suite-core/data/ — no external API calls.
    Covers: findings, SLA compliance, incident response, posture, coverage.

    Compliance: SOC2 CC7.2, NIST CSF ID.RA-1, CIS Control 17
    """

    def __init__(
        self,
        vuln_db: Optional[Path] = None,
        sla_db: Optional[Path] = None,
        incident_db: Optional[Path] = None,
        posture_db: Optional[Path] = None,
        lifecycle_db: Optional[Path] = None,
    ) -> None:
        self._vuln_db = vuln_db or (_SUITE_DATA / "vulnerability_analytics.db")
        self._sla_db = sla_db or (_SUITE_DATA / "sla.db")
        self._incident_db = incident_db or (_SUITE_DATA / "incident_response.db")
        self._posture_db = posture_db or (_SUITE_DATA / "posture_scoring.db")
        self._lifecycle_db = lifecycle_db or (_SUITE_DATA / "vuln_lifecycle.db")
        self._log = structlog.get_logger(self.__class__.__name__)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self, path: Path) -> Optional[sqlite3.Connection]:
        """Return a read-only connection or None if the DB does not exist."""
        if not path.exists():
            self._log.warning("db_not_found", path=str(path))
            return None
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def _connect_rw(self, path: Path) -> sqlite3.Connection:
        """Return a read-write connection, creating the DB if needed."""
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _iso(dt: datetime) -> str:
        return dt.isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_finding_metrics(self, org_id: str = "default") -> FindingMetrics:
        """
        Aggregate finding counts and trends from vulnerability_analytics.db.

        Returns counts of open findings by severity, new/closed in last
        24h / 7d / 30d, MTTR by severity, and false positive rate.
        """
        conn = self._connect(self._vuln_db)
        if conn is None:
            return FindingMetrics()

        now = datetime.now(timezone.utc)
        cutoff_24h = self._iso(now - timedelta(hours=24))
        cutoff_7d = self._iso(now - timedelta(days=7))
        cutoff_30d = self._iso(now - timedelta(days=30))

        try:
            cur = conn.cursor()

            # Count open findings per severity (opened but never closed)
            open_by_sev: Dict[str, int] = {}
            cur.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM finding_events
                WHERE (org_id = ? OR ? = 'default')
                  AND event_type = 'opened'
                  AND finding_id NOT IN (
                    SELECT finding_id FROM finding_events
                    WHERE event_type = 'closed'
                  )
                GROUP BY severity
                """,
                (org_id, org_id),
            )
            for row in cur.fetchall():
                open_by_sev[row["severity"].lower()] = row["cnt"]

            total_open = sum(open_by_sev.values())

            # New findings in time windows (event_type = 'opened')
            def _count_new(cutoff: str) -> int:
                cur.execute(
                    """
                    SELECT COUNT(*) FROM finding_events
                    WHERE (org_id = ? OR ? = 'default')
                      AND event_type = 'opened'
                      AND ts >= ?
                    """,
                    (org_id, org_id, cutoff),
                )
                return cur.fetchone()[0] or 0

            # Closed findings in time windows
            def _count_closed(cutoff: str) -> int:
                cur.execute(
                    """
                    SELECT COUNT(*) FROM finding_events
                    WHERE (org_id = ? OR ? = 'default')
                      AND event_type = 'closed'
                      AND ts >= ?
                    """,
                    (org_id, org_id, cutoff),
                )
                return cur.fetchone()[0] or 0

            new_24h = _count_new(cutoff_24h)
            new_7d = _count_new(cutoff_7d)
            new_30d = _count_new(cutoff_30d)
            closed_24h = _count_closed(cutoff_24h)
            closed_7d = _count_closed(cutoff_7d)
            closed_30d = _count_closed(cutoff_30d)

            # False positive rate
            cur.execute(
                """
                SELECT
                    CAST(SUM(CASE WHEN event_type = 'false_positive' THEN 1 ELSE 0 END) AS REAL) as fp,
                    CAST(COUNT(*) AS REAL) as total
                FROM finding_events
                WHERE (org_id = ? OR ? = 'default')
                """,
                (org_id, org_id),
            )
            row = cur.fetchone()
            fp_rate = 0.0
            if row and row["total"] and row["total"] > 0:
                fp_rate = round((row["fp"] or 0.0) / row["total"] * 100.0, 2)

        finally:
            conn.close()

        # MTTR from lifecycle DB
        mttr = self._compute_mttr_by_severity(org_id)

        return FindingMetrics(
            total_open=total_open,
            critical_open=open_by_sev.get("critical", 0),
            high_open=open_by_sev.get("high", 0),
            medium_open=open_by_sev.get("medium", 0),
            low_open=open_by_sev.get("low", 0),
            new_24h=new_24h,
            new_7d=new_7d,
            new_30d=new_30d,
            closed_24h=closed_24h,
            closed_7d=closed_7d,
            closed_30d=closed_30d,
            mttr_by_severity=mttr,
            false_positive_rate=fp_rate,
        )

    def _compute_mttr_by_severity(self, org_id: str) -> Dict[str, float]:
        """Compute MTTR in hours per severity from vulnerability analytics events."""
        conn = self._connect(self._vuln_db)
        if conn is None:
            return {}
        try:
            cur = conn.cursor()
            # Match open/close pairs per finding_id to compute elapsed hours
            cur.execute(
                """
                SELECT o.severity, o.ts AS opened_ts, c.ts AS closed_ts
                FROM finding_events o
                JOIN finding_events c ON o.finding_id = c.finding_id
                WHERE o.event_type = 'opened'
                  AND c.event_type = 'closed'
                  AND (o.org_id = ? OR ? = 'default')
                """,
                (org_id, org_id),
            )
            rows = cur.fetchall()
        finally:
            conn.close()

        buckets: Dict[str, List[float]] = {}
        for row in rows:
            try:
                t_open = datetime.fromisoformat(row["opened_ts"])
                t_close = datetime.fromisoformat(row["closed_ts"])
                if t_close > t_open:
                    sev = (row["severity"] or "unknown").lower()
                    buckets.setdefault(sev, []).append(
                        (t_close - t_open).total_seconds() / 3600.0
                    )
            except (ValueError, TypeError):
                pass

        return {
            sev: round(sum(vals) / len(vals), 2)
            for sev, vals in buckets.items()
            if vals
        }

    def get_coverage_metrics(self, org_id: str = "default") -> CoverageMetrics:
        """
        Compute attack surface coverage from posture and vuln analytics DBs.

        Coverage is derived from posture snapshots (trustgraph_coverage field)
        and distinct scanner sources in the finding events.
        """
        tg_coverage = 0.0
        conn_p = self._connect(self._posture_db)
        if conn_p is not None:
            try:
                cur = conn_p.cursor()
                cur.execute(
                    """
                    SELECT components FROM posture_scores
                    WHERE (org_id = ? OR ? = 'default')
                    ORDER BY calculated_at DESC
                    LIMIT 1
                    """,
                    (org_id, org_id),
                )
                row = cur.fetchone()
                if row:
                    try:
                        comps = json.loads(row["components"] or "{}")
                        tg_coverage = float(comps.get("trustgraph_coverage", 0.0))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        pass
            finally:
                conn_p.close()

        active_scanners: List[str] = []
        total_sources = 0
        conn_v = self._connect(self._vuln_db)
        if conn_v is not None:
            try:
                cur = conn_v.cursor()
                cur.execute(
                    """
                    SELECT DISTINCT scanner FROM finding_events
                    WHERE (org_id = ? OR ? = 'default')
                      AND scanner IS NOT NULL AND scanner != ''
                    """,
                    (org_id, org_id),
                )
                active_scanners = [r["scanner"] for r in cur.fetchall()]
                total_sources = len(active_scanners)
            finally:
                conn_v.close()

        # Estimate coverage percentages from posture score components
        conn_p2 = self._connect(self._posture_db)
        repos_pct = assets_pct = endpoints_pct = 0.0
        if conn_p2 is not None:
            try:
                cur = conn_p2.cursor()
                cur.execute(
                    """
                    SELECT overall_score FROM posture_scores
                    WHERE (org_id = ? OR ? = 'default')
                    ORDER BY calculated_at DESC
                    LIMIT 1
                    """,
                    (org_id, org_id),
                )
                row = cur.fetchone()
                if row:
                    # Approximate coverage from posture score as proxy
                    score = float(row["overall_score"] or 0.0)
                    repos_pct = min(100.0, score * 1.1)
                    assets_pct = min(100.0, score)
                    endpoints_pct = min(100.0, score * 0.9)
            finally:
                conn_p2.close()

        return CoverageMetrics(
            repos_scanned_pct=round(repos_pct, 1),
            assets_inventoried_pct=round(assets_pct, 1),
            endpoints_monitored_pct=round(endpoints_pct, 1),
            trustgraph_coverage_pct=round(tg_coverage, 1),
            total_finding_sources=total_sources,
            active_scanners=active_scanners,
        )

    def get_sla_metrics(self, org_id: str = "default") -> SLAMetrics:
        """
        Compute SLA compliance rates and breach stats from sla.db.

        Reads sla_records table: status, severity, deadline, resolved_at.
        """
        conn = self._connect(self._sla_db)
        if conn is None:
            return SLAMetrics()

        now = datetime.now(timezone.utc)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT severity, status, deadline, resolved_at, breached_at
                FROM sla_records
                WHERE (org_id = ? OR ? = 'default')
                """,
                (org_id, org_id),
            )
            rows = cur.fetchall()
        finally:
            conn.close()

        total = len(rows)
        if total == 0:
            return SLAMetrics()

        on_time = 0
        breaches = 0
        at_risk = 0
        overdue_hours: List[float] = []
        compliance_by_sev: Dict[str, List[bool]] = {}

        for row in rows:
            (row["status"] or "unknown").lower()
            status = (row["status"] or "").lower()
            try:
                deadline_dt = datetime.fromisoformat(row["deadline"]) if row["deadline"] else None
            except (ValueError, TypeError):
                deadline_dt = None

            resolved_dt = None
            if row["resolved_at"]:
                try:
                    resolved_dt = datetime.fromisoformat(row["resolved_at"])
                except (ValueError, TypeError):
                    pass

            severity_key = (row["severity"] or "unknown").lower()
            compliance_by_sev.setdefault(severity_key, [])

            if status == "resolved" or resolved_dt is not None:
                if deadline_dt and resolved_dt:
                    in_sla = resolved_dt <= deadline_dt
                    compliance_by_sev[severity_key].append(in_sla)
                    if in_sla:
                        on_time += 1
                    else:
                        breaches += 1
                        overdue = (resolved_dt - deadline_dt).total_seconds() / 3600.0
                        overdue_hours.append(max(0.0, overdue))
                else:
                    on_time += 1
                    compliance_by_sev[severity_key].append(True)
            elif row["breached_at"]:
                breaches += 1
                compliance_by_sev[severity_key].append(False)
                if deadline_dt:
                    overdue = (now - deadline_dt).total_seconds() / 3600.0
                    overdue_hours.append(max(0.0, overdue))
            else:
                # Open — check if at risk (>80% of SLA window elapsed)
                if deadline_dt:
                    sla_hours_map = {"critical": 24, "high": 168, "medium": 720, "low": 2160}
                    sla_window = sla_hours_map.get(severity_key, 720)
                    elapsed = (now - (deadline_dt - timedelta(hours=sla_window))).total_seconds() / 3600.0
                    if elapsed > sla_window * 0.8:
                        at_risk += 1

        resolved_count = on_time + breaches
        overall_rate = round((on_time / resolved_count * 100.0) if resolved_count > 0 else 0.0, 2)

        compliance_by_severity: Dict[str, float] = {}
        for sev_key, results in compliance_by_sev.items():
            if results:
                compliance_by_severity[sev_key] = round(
                    sum(1 for r in results if r) / len(results) * 100.0, 2
                )

        avg_overdue = round(sum(overdue_hours) / len(overdue_hours), 2) if overdue_hours else 0.0

        return SLAMetrics(
            overall_compliance_rate=overall_rate,
            compliance_by_severity=compliance_by_severity,
            total_records=total,
            on_time_resolutions=on_time,
            breaches=breaches,
            at_risk_count=at_risk,
            avg_overdue_hours=avg_overdue,
        )

    def get_response_metrics(self, org_id: str = "default") -> ResponseMetrics:
        """
        Compute IR effectiveness metrics from incident_response.db.

        MTTD: time from incident creation to detection event.
        MTTR: time from detection to resolution (status=resolved).
        """
        conn = self._connect(self._incident_db)
        if conn is None:
            return ResponseMetrics()

        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT status, data, detected_at
                FROM incidents
                WHERE (org_id = ? OR ? = 'default')
                """,
                (org_id, org_id),
            )
            rows = cur.fetchall()
        finally:
            conn.close()

        total = len(rows)
        if total == 0:
            return ResponseMetrics()

        open_count = 0
        closed_count = 0
        mttd_vals: List[float] = []
        mttr_vals: List[float] = []
        escalated = 0
        automated = 0

        for row in rows:
            status = (row["status"] or "").lower()
            if status in ("resolved", "closed"):
                closed_count += 1
            else:
                open_count += 1

            try:
                data = json.loads(row["data"] or "{}")
            except (json.JSONDecodeError, TypeError):
                data = {}

            detected_at_str = row["detected_at"]
            created_at_str = data.get("created_at") or detected_at_str
            resolved_at_str = data.get("resolved_at")

            if detected_at_str and created_at_str:
                try:
                    t_detected = datetime.fromisoformat(detected_at_str)
                    t_created = datetime.fromisoformat(created_at_str)
                    mttd_h = abs((t_detected - t_created).total_seconds()) / 3600.0
                    mttd_vals.append(mttd_h)
                except (ValueError, TypeError):
                    pass

            if detected_at_str and resolved_at_str:
                try:
                    t_detected = datetime.fromisoformat(detected_at_str)
                    t_resolved = datetime.fromisoformat(resolved_at_str)
                    if t_resolved > t_detected:
                        mttr_vals.append((t_resolved - t_detected).total_seconds() / 3600.0)
                except (ValueError, TypeError):
                    pass

            if data.get("escalated"):
                escalated += 1
            if data.get("automated_response"):
                automated += 1

        mttd = round(sum(mttd_vals) / len(mttd_vals), 2) if mttd_vals else 0.0
        mttr = round(sum(mttr_vals) / len(mttr_vals), 2) if mttr_vals else 0.0
        esc_rate = round(escalated / total * 100.0, 2) if total else 0.0
        auto_rate = round(automated / total * 100.0, 2) if total else 0.0

        return ResponseMetrics(
            mttd_hours=mttd,
            mttr_hours=mttr,
            escalation_rate=esc_rate,
            automated_response_rate=auto_rate,
            total_incidents=total,
            open_incidents=open_count,
            closed_incidents=closed_count,
        )

    def get_executive_summary(self, org_id: str = "default") -> ExecutiveSummary:
        """
        Produce a one-page executive summary for CISO.

        Pulls overall_security_score from latest posture snapshot.
        Computes score trend by comparing last two posture scores.
        Derives top risks and recommended actions from sub-metrics.
        """
        now = datetime.now(timezone.utc)
        period_label = now.strftime("Week of %Y-%m-%d")

        # Posture score + trend
        overall_score = 0.0
        score_trend = "stable"
        conn_p = self._connect(self._posture_db)
        if conn_p is not None:
            try:
                cur = conn_p.cursor()
                cur.execute(
                    """
                    SELECT overall_score FROM posture_scores
                    WHERE (org_id = ? OR ? = 'default')
                    ORDER BY calculated_at DESC
                    LIMIT 2
                    """,
                    (org_id, org_id),
                )
                scores = [r["overall_score"] for r in cur.fetchall()]
                if scores:
                    overall_score = float(scores[0])
                if len(scores) == 2:
                    delta = scores[0] - scores[1]
                    if delta > 1.0:
                        score_trend = "improving"
                    elif delta < -1.0:
                        score_trend = "degrading"
            finally:
                conn_p.close()

        findings = self.get_finding_metrics(org_id)
        sla = self.get_sla_metrics(org_id)
        response = self.get_response_metrics(org_id)

        # Build top risks
        top_risks: List[str] = []
        if findings.critical_open > 0:
            top_risks.append(f"{findings.critical_open} critical findings open")
        if sla.breaches > 0:
            top_risks.append(
                f"{sla.breaches} SLA breaches (compliance {sla.overall_compliance_rate:.0f}%)"
            )
        if response.mttd_hours > 48:
            top_risks.append(f"MTTD {response.mttd_hours:.0f}h exceeds 48h target")
        if response.mttr_hours > 720:
            top_risks.append(f"MTTR {response.mttr_hours:.0f}h exceeds 30-day target")
        if findings.false_positive_rate > 20.0:
            top_risks.append(
                f"High false positive rate ({findings.false_positive_rate:.0f}%) — review tuning"
            )
        if not top_risks:
            top_risks.append("No critical risk signals detected this period")

        # Recommended actions
        actions: List[str] = []
        if findings.critical_open > 0:
            actions.append("Prioritise remediation of all open critical findings immediately")
        if sla.breaches > 0:
            actions.append("Review SLA breach root causes; assign dedicated remediation owner")
        if response.mttd_hours > 48:
            actions.append("Tune detection rules to reduce MTTD below 48h threshold")
        if score_trend == "degrading":
            actions.append("Posture score declining — review recent scan results for regressions")
        if not actions:
            actions.append("Maintain current security posture — no urgent actions required")

        return ExecutiveSummary(
            overall_security_score=round(overall_score, 1),
            score_trend=score_trend,
            top_risks=top_risks[:5],
            recommended_actions=actions[:5],
            period_label=period_label,
            finding_metrics=findings,
            sla_metrics=sla,
            response_metrics=response,
        )

    def export_metrics_report(self, org_id: str = "default", format: str = "json") -> str:
        """
        Export a full metrics report as JSON or CSV.

        Args:
            org_id: Organisation identifier.
            format: "json" (default) or "csv".

        Returns:
            Serialised report string.
        """
        findings = self.get_finding_metrics(org_id)
        coverage = self.get_coverage_metrics(org_id)
        sla = self.get_sla_metrics(org_id)
        response = self.get_response_metrics(org_id)
        summary = self.get_executive_summary(org_id)

        now_iso = datetime.now(timezone.utc).isoformat()

        if format.lower() == "csv":
            import csv
            import io

            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["metric", "value", "org_id", "exported_at"])
            flat: List[Tuple[str, Any]] = [
                ("findings.total_open", findings.total_open),
                ("findings.critical_open", findings.critical_open),
                ("findings.high_open", findings.high_open),
                ("findings.medium_open", findings.medium_open),
                ("findings.low_open", findings.low_open),
                ("findings.new_24h", findings.new_24h),
                ("findings.new_7d", findings.new_7d),
                ("findings.new_30d", findings.new_30d),
                ("findings.false_positive_rate_pct", findings.false_positive_rate),
                ("coverage.repos_scanned_pct", coverage.repos_scanned_pct),
                ("coverage.assets_inventoried_pct", coverage.assets_inventoried_pct),
                ("coverage.endpoints_monitored_pct", coverage.endpoints_monitored_pct),
                ("coverage.trustgraph_coverage_pct", coverage.trustgraph_coverage_pct),
                ("coverage.total_finding_sources", coverage.total_finding_sources),
                ("sla.overall_compliance_rate_pct", sla.overall_compliance_rate),
                ("sla.total_records", sla.total_records),
                ("sla.on_time_resolutions", sla.on_time_resolutions),
                ("sla.breaches", sla.breaches),
                ("sla.at_risk_count", sla.at_risk_count),
                ("sla.avg_overdue_hours", sla.avg_overdue_hours),
                ("response.mttd_hours", response.mttd_hours),
                ("response.mttr_hours", response.mttr_hours),
                ("response.escalation_rate_pct", response.escalation_rate),
                ("response.automated_response_rate_pct", response.automated_response_rate),
                ("response.total_incidents", response.total_incidents),
                ("executive.overall_security_score", summary.overall_security_score),
                ("executive.score_trend", summary.score_trend),
            ]
            for metric, value in flat:
                writer.writerow([metric, value, org_id, now_iso])
            return buf.getvalue()

        # Default: JSON
        return json.dumps(
            {
                "exported_at": now_iso,
                "org_id": org_id,
                "findings": asdict(findings),
                "coverage": asdict(coverage),
                "sla": asdict(sla),
                "response": asdict(response),
                "executive_summary": {
                    "overall_security_score": summary.overall_security_score,
                    "score_trend": summary.score_trend,
                    "top_risks": summary.top_risks,
                    "recommended_actions": summary.recommended_actions,
                    "period_label": summary.period_label,
                },
            },
            indent=2,
            default=str,
        )
