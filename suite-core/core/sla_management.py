"""
SLA Management Engine for ALDECI — Advanced Vulnerability Remediation SLA Tracking.

Extends the basic sla_manager with:
- Business-hours-only SLA policies
- Asset criticality-based SLA assignment
- Compliance framework overrides (PCI-DSS, SOC2, HIPAA, ISO27001)
- Exception management (risk acceptance, extended deadline, false positive)
- Per-team performance metrics and leaderboard
- Severity-based escalation rules (team lead → director → CISO)
- Compliance reports (per-team, per-severity, per-framework, per-asset-tier)

Compliance: SOC2 CC7.2, ISO27001 A.12.6.1, NIST SP 800-40, PCI-DSS Req 6.3
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import structlog
from pydantic import BaseModel, Field, field_validator

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
# Constants
# ---------------------------------------------------------------------------

_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "sla_management.db"

# Default SLA deadlines in hours per severity
_DEFAULT_DEADLINES: Dict[str, int] = {
    "critical": 24,
    "high": 168,    # 7 days
    "medium": 720,  # 30 days
    "low": 2160,    # 90 days
}

# Compliance framework overrides — stricter deadlines (hours)
_FRAMEWORK_OVERRIDES: Dict[str, Dict[str, int]] = {
    "pci-dss": {
        "critical": 24,
        "high": 72,   # PCI requires faster remediation
        "medium": 168,
        "low": 720,
    },
    "hipaa": {
        "critical": 24,
        "high": 120,
        "medium": 480,
        "low": 1440,
    },
    "soc2": {
        "critical": 24,
        "high": 168,
        "medium": 720,
        "low": 2160,
    },
    "iso27001": {
        "critical": 24,
        "high": 168,
        "medium": 720,
        "low": 2160,
    },
    "nist-csf": {
        "critical": 24,
        "high": 168,
        "medium": 720,
        "low": 2160,
    },
    "cis-benchmark": {
        "critical": 24,
        "high": 120,
        "medium": 480,
        "low": 1440,
    },
}

# Asset tier multipliers — lower = faster SLA (e.g. tier1 prod = 0.5x deadline)
_ASSET_TIER_MULTIPLIERS: Dict[str, float] = {
    "tier1": 0.5,   # Production critical — half the time
    "tier2": 0.75,  # Production supporting
    "tier3": 1.0,   # Staging / pre-prod (default)
    "tier4": 1.5,   # Dev / test
    "tier5": 2.0,   # Non-critical internal
}

# Business hours: Mon–Fri 09:00–17:00 (configurable)
_BIZ_HOURS_START = 9   # 09:00
_BIZ_HOURS_END = 17    # 17:00
_BIZ_DAYS = {0, 1, 2, 3, 4}  # Monday=0 … Friday=4

# Escalation thresholds
_ESCALATION_APPROACHING_PCT = 0.80  # 80% elapsed → notify team lead
_ESCALATION_BREACHED_MULT = 1.0     # 100% = deadline passed → notify director
_ESCALATION_SEVERE_MULT = 2.0       # 2x deadline → notify CISO

# Schema SQL
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sla_policies_v2 (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL,
    team_id             TEXT,
    asset_tier          TEXT,
    name                TEXT NOT NULL,
    severity_deadlines  TEXT NOT NULL DEFAULT '{}',
    framework_overrides TEXT NOT NULL DEFAULT '{}',
    business_hours_only INTEGER NOT NULL DEFAULT 0,
    tz_name             TEXT NOT NULL DEFAULT 'UTC',
    escalation_rules    TEXT NOT NULL DEFAULT '{}',
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uidx_pol_org_team_tier
    ON sla_policies_v2(org_id, COALESCE(team_id,''), COALESCE(asset_tier,''));

CREATE TABLE IF NOT EXISTS sla_assignments (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL UNIQUE,
    org_id          TEXT NOT NULL,
    team_id         TEXT,
    asset_tier      TEXT NOT NULL DEFAULT 'tier3',
    severity        TEXT NOT NULL,
    frameworks      TEXT NOT NULL DEFAULT '[]',
    discovered_at   TEXT NOT NULL,
    deadline        TEXT NOT NULL,
    business_hours  INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'within_sla',
    pct_elapsed     REAL NOT NULL DEFAULT 0.0,
    escalation_level TEXT NOT NULL DEFAULT 'none',
    breached_at     TEXT,
    resolved_at     TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asgn_org     ON sla_assignments(org_id);
CREATE INDEX IF NOT EXISTS idx_asgn_team    ON sla_assignments(org_id, team_id);
CREATE INDEX IF NOT EXISTS idx_asgn_status  ON sla_assignments(org_id, status);

CREATE TABLE IF NOT EXISTS sla_exceptions (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL,
    org_id          TEXT NOT NULL,
    exception_type  TEXT NOT NULL,
    justification   TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    approved_by     TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    expiry_date     TEXT,
    evidence        TEXT NOT NULL DEFAULT '{}',
    new_deadline    TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exc_finding  ON sla_exceptions(finding_id);
CREATE INDEX IF NOT EXISTS idx_exc_org      ON sla_exceptions(org_id, status);

CREATE TABLE IF NOT EXISTS sla_team_metrics (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    team_id         TEXT NOT NULL,
    period_start    TEXT NOT NULL,
    period_end      TEXT NOT NULL,
    total_assigned  INTEGER NOT NULL DEFAULT 0,
    resolved_within INTEGER NOT NULL DEFAULT 0,
    breached        INTEGER NOT NULL DEFAULT 0,
    avg_resolution_hours REAL NOT NULL DEFAULT 0.0,
    compliance_rate REAL NOT NULL DEFAULT 0.0,
    trend           TEXT NOT NULL DEFAULT 'stable',
    computed_at     TEXT NOT NULL,
    UNIQUE(org_id, team_id, period_start)
);
CREATE INDEX IF NOT EXISTS idx_team_org  ON sla_team_metrics(org_id, team_id);
"""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SLAStatusV2(str, Enum):
    """SLA lifecycle states with breach severity."""

    WITHIN_SLA = "within_sla"
    APPROACHING = "approaching"     # ≥80% elapsed
    BREACHED = "breached"           # deadline passed
    SEVERELY_BREACHED = "severely_breached"  # 2x deadline
    RESOLVED = "resolved"
    EXEMPT = "exempt"


class ExceptionType(str, Enum):
    """Types of SLA exception requests."""

    RISK_ACCEPTANCE = "risk_acceptance"
    EXTENDED_DEADLINE = "extended_deadline"
    FALSE_POSITIVE = "false_positive"
    COMPENSATING_CONTROL = "compensating_control"


class ExceptionStatus(str, Enum):
    """Approval workflow states for exceptions."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class EscalationLevel(str, Enum):
    """Escalation tiers for SLA notifications."""

    NONE = "none"
    TEAM_LEAD = "team_lead"
    DIRECTOR = "director"
    CISO = "ciso"


class TrendDirection(str, Enum):
    """Team performance trend direction."""

    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"


# ---------------------------------------------------------------------------
# Pydantic v2 models
# ---------------------------------------------------------------------------


class EscalationRule(BaseModel):
    """Escalation targets per severity level."""

    severity: str
    team_lead_email: Optional[str] = None
    director_email: Optional[str] = None
    ciso_email: Optional[str] = None

    model_config = {"use_enum_values": True}


class SLAPolicyV2(BaseModel):
    """Extended SLA policy with business hours and framework support."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    team_id: Optional[str] = None
    asset_tier: Optional[str] = None
    name: str
    severity_deadlines: Dict[str, int] = Field(
        default_factory=lambda: dict(_DEFAULT_DEADLINES)
    )
    framework_overrides: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    business_hours_only: bool = False
    tz_name: str = "UTC"
    escalation_rules: List[EscalationRule] = Field(default_factory=list)
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}

    @field_validator("asset_tier")
    @classmethod
    def validate_asset_tier(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _ASSET_TIER_MULTIPLIERS:
            raise ValueError(
                f"asset_tier must be one of {list(_ASSET_TIER_MULTIPLIERS)}"
            )
        return v


class SLAAssignment(BaseModel):
    """SLA assignment record for a finding."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    org_id: str
    team_id: Optional[str] = None
    asset_tier: str = "tier3"
    severity: str
    frameworks: List[str] = Field(default_factory=list)
    discovered_at: datetime
    deadline: datetime
    business_hours: bool = False
    status: SLAStatusV2 = SLAStatusV2.WITHIN_SLA
    pct_elapsed: float = 0.0
    escalation_level: EscalationLevel = EscalationLevel.NONE
    breached_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}


class SLAException(BaseModel):
    """Exception request for an SLA assignment."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    org_id: str
    exception_type: ExceptionType
    justification: str
    requested_by: str
    approved_by: Optional[str] = None
    status: ExceptionStatus = ExceptionStatus.PENDING
    expiry_date: Optional[datetime] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    new_deadline: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}


class TeamMetrics(BaseModel):
    """Per-team SLA performance metrics for a reporting period."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    team_id: str
    period_start: datetime
    period_end: datetime
    total_assigned: int = 0
    resolved_within: int = 0
    breached: int = 0
    avg_resolution_hours: float = 0.0
    compliance_rate: float = 0.0
    trend: TrendDirection = TrendDirection.STABLE
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}


class SLAReport(BaseModel):
    """Compiled SLA compliance report."""

    org_id: str
    generated_at: datetime
    period_days: int
    overall_compliance_rate: float
    by_severity: Dict[str, Dict[str, Any]]
    by_team: List[Dict[str, Any]]
    by_framework: Dict[str, Dict[str, Any]]
    by_asset_tier: Dict[str, Dict[str, Any]]
    escalation_summary: Dict[str, int]
    exception_summary: Dict[str, int]
    leaderboard: List[Dict[str, Any]]

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _biz_hours_delta(start: datetime, hours: float) -> datetime:
    """Advance *start* by *hours* of business time (Mon–Fri 09:00–17:00 UTC)."""
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)

    remaining = timedelta(hours=hours)
    current = start

    # Advance to next business hour if currently outside
    while True:
        wd = current.weekday()
        h = current.hour + current.minute / 60.0
        if wd in _BIZ_DAYS and _BIZ_HOURS_START <= h < _BIZ_HOURS_END:
            break
        # Skip to next day's open
        current = current.replace(hour=_BIZ_HOURS_START, minute=0, second=0, microsecond=0)
        if wd not in _BIZ_DAYS or h >= _BIZ_HOURS_END:
            days_ahead = 1
            while (current + timedelta(days=days_ahead)).weekday() not in _BIZ_DAYS:
                days_ahead += 1
            current += timedelta(days=days_ahead)

    while remaining.total_seconds() > 0:
        wd = current.weekday()
        h = current.hour + current.minute / 60.0
        # End of current biz day
        end_of_day = current.replace(
            hour=_BIZ_HOURS_END, minute=0, second=0, microsecond=0
        )
        available = end_of_day - current
        if available >= remaining:
            current += remaining
            remaining = timedelta()
        else:
            remaining -= available
            # Move to next biz day
            next_day = current + timedelta(days=1)
            while next_day.weekday() not in _BIZ_DAYS:
                next_day += timedelta(days=1)
            current = next_day.replace(
                hour=_BIZ_HOURS_START, minute=0, second=0, microsecond=0
            )

    return current


def _compute_pct_elapsed(
    discovered: datetime, deadline: datetime, now: Optional[datetime] = None
) -> float:
    """Return 0.0–N.N fraction of SLA window elapsed (>1.0 = breached)."""
    if now is None:
        now = _now()
    total = (deadline - discovered).total_seconds()
    if total <= 0:
        return 1.0
    elapsed = (now - discovered).total_seconds()
    return max(0.0, elapsed / total)


def _resolve_deadline(
    discovered_at: datetime,
    severity: str,
    asset_tier: str = "tier3",
    frameworks: Optional[List[str]] = None,
    policy: Optional[SLAPolicyV2] = None,
    business_hours: bool = False,
) -> Tuple[datetime, int]:
    """Compute the remediation deadline for a finding.

    Precedence: framework override (strictest) > policy override > default.
    Then apply asset tier multiplier.

    Returns:
        (deadline datetime, effective_sla_hours)
    """
    sev = severity.lower()
    base_hours = _DEFAULT_DEADLINES.get(sev, 720)

    # Apply policy-level overrides first
    if policy and policy.severity_deadlines:
        base_hours = policy.severity_deadlines.get(sev, base_hours)

    # Apply compliance framework override — pick strictest (smallest hours)
    active_frameworks = [f.lower() for f in (frameworks or [])]
    for fw in active_frameworks:
        fw_deadlines = _FRAMEWORK_OVERRIDES.get(fw, {})
        if fw_deadlines:
            fw_hours = fw_deadlines.get(sev, base_hours)
            base_hours = min(base_hours, fw_hours)

    # Also check policy-level framework_overrides
    if policy and policy.framework_overrides:
        for fw, fw_deadlines in policy.framework_overrides.items():
            if fw.lower() in active_frameworks:
                fw_hours = fw_deadlines.get(sev, base_hours)
                base_hours = min(base_hours, fw_hours)

    # Apply asset tier multiplier
    tier_mult = _ASSET_TIER_MULTIPLIERS.get(asset_tier, 1.0)
    effective_hours = max(1, int(base_hours * tier_mult))

    if business_hours:
        deadline = _biz_hours_delta(discovered_at, effective_hours)
    else:
        deadline = discovered_at + timedelta(hours=effective_hours)

    return deadline, effective_hours


def _compute_status(
    pct: float,
    deadline: datetime,
    now: Optional[datetime] = None,
) -> SLAStatusV2:
    """Map elapsed percentage to SLA status enum."""
    if now is None:
        now = _now()
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)

    if pct >= _ESCALATION_SEVERE_MULT:
        return SLAStatusV2.SEVERELY_BREACHED
    if pct >= _ESCALATION_BREACHED_MULT:
        return SLAStatusV2.BREACHED
    if pct >= _ESCALATION_APPROACHING_PCT:
        return SLAStatusV2.APPROACHING
    return SLAStatusV2.WITHIN_SLA


def _escalation_level_for_pct(pct: float) -> EscalationLevel:
    """Map elapsed pct to escalation level."""
    if pct >= _ESCALATION_SEVERE_MULT:
        return EscalationLevel.CISO
    if pct >= _ESCALATION_BREACHED_MULT:
        return EscalationLevel.DIRECTOR
    if pct >= _ESCALATION_APPROACHING_PCT:
        return EscalationLevel.TEAM_LEAD
    return EscalationLevel.NONE


# ---------------------------------------------------------------------------
# SLAManagement — main engine
# ---------------------------------------------------------------------------


class SLAManagement:
    """Advanced SLA management engine with SQLite persistence.

    Args:
        db_path: Path to SQLite DB, or ``:memory:`` for testing.
    """

    def __init__(self, db_path: Union[str, Path] = ":memory:") -> None:
        self._db_path = str(db_path)
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_db()
        logger.info("sla_management: engine initialised", db=self._db_path)

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._db_path == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(
                    ":memory:", check_same_thread=False
                )
                self._mem_conn.row_factory = sqlite3.Row
                self._mem_conn.executescript(_SCHEMA)
                self._mem_conn.commit()
            return self._mem_conn
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            if self._db_path != ":memory:":
                conn.executescript(_SCHEMA)
                conn.commit()
                conn.close()

    def _close(self, conn: sqlite3.Connection) -> None:
        if self._db_path != ":memory:":
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        return self._connect()

    # ------------------------------------------------------------------
    # Policy management
    # ------------------------------------------------------------------

    def create_policy(self, policy: SLAPolicyV2) -> SLAPolicyV2:
        """Persist a new (or replace existing) SLA policy."""
        now_iso = _now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO sla_policies_v2
                        (id, org_id, team_id, asset_tier, name, severity_deadlines,
                         framework_overrides, business_hours_only, tz_name,
                         escalation_rules, enabled, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        policy.id,
                        policy.org_id,
                        policy.team_id,
                        policy.asset_tier,
                        policy.name,
                        json.dumps(policy.severity_deadlines),
                        json.dumps(policy.framework_overrides),
                        1 if policy.business_hours_only else 0,
                        policy.tz_name,
                        json.dumps(
                            [r.model_dump() for r in policy.escalation_rules]
                        ),
                        1 if policy.enabled else 0,
                        policy.created_at.isoformat(),
                        now_iso,
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)
        logger.info(
            "sla_management: policy upserted",
            org=policy.org_id,
            team=policy.team_id,
            tier=policy.asset_tier,
        )
        return policy

    def get_policy(
        self,
        org_id: str,
        team_id: Optional[str] = None,
        asset_tier: Optional[str] = None,
    ) -> Optional[SLAPolicyV2]:
        """Return the most-specific SLA policy matching the given scope.

        Lookup order: (org, team, tier) → (org, team, None) → (org, None, tier)
        → (org, None, None).
        """
        candidates = [
            (org_id, team_id, asset_tier),
            (org_id, team_id, None),
            (org_id, None, asset_tier),
            (org_id, None, None),
        ]
        with self._lock:
            conn = self._get_conn()
            try:
                for o, t, a in candidates:
                    row = conn.execute(
                        """
                        SELECT * FROM sla_policies_v2
                        WHERE org_id=?
                          AND (team_id IS ? OR (? IS NULL AND team_id IS NULL))
                          AND (asset_tier IS ? OR (? IS NULL AND asset_tier IS NULL))
                          AND enabled=1
                        LIMIT 1
                        """,
                        (o, t, t, a, a),
                    ).fetchone()
                    if row:
                        return self._policy_from_row(row)
            finally:
                self._close(conn)
        return None

    def list_policies(self, org_id: str) -> List[SLAPolicyV2]:
        """List all policies for an org."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM sla_policies_v2 WHERE org_id=?", (org_id,)
                ).fetchall()
            finally:
                self._close(conn)
        return [self._policy_from_row(r) for r in rows]

    @staticmethod
    def _policy_from_row(row: sqlite3.Row) -> SLAPolicyV2:
        d = dict(row)
        d["severity_deadlines"] = json.loads(d.get("severity_deadlines") or "{}")
        d["framework_overrides"] = json.loads(d.get("framework_overrides") or "{}")
        d["escalation_rules"] = [
            EscalationRule(**r)
            for r in json.loads(d.get("escalation_rules") or "[]")
        ]
        d["business_hours_only"] = bool(d.get("business_hours_only", 0))
        d["enabled"] = bool(d.get("enabled", 1))
        return SLAPolicyV2(**d)

    # ------------------------------------------------------------------
    # SLA Assignment
    # ------------------------------------------------------------------

    def assign_sla(
        self,
        finding_id: str,
        severity: str,
        discovered_at: datetime,
        org_id: str,
        team_id: Optional[str] = None,
        asset_tier: str = "tier3",
        frameworks: Optional[List[str]] = None,
    ) -> SLAAssignment:
        """Auto-assign SLA to a finding based on severity + asset criticality.

        Idempotent — returns existing assignment if already tracked.
        """
        # Check for existing
        existing = self.get_assignment(finding_id)
        if existing is not None:
            return existing

        if discovered_at.tzinfo is None:
            discovered_at = discovered_at.replace(tzinfo=timezone.utc)

        policy = self.get_policy(org_id, team_id=team_id, asset_tier=asset_tier)
        use_biz_hours = policy.business_hours_only if policy else False
        active_frameworks = frameworks or []

        deadline, sla_hours = _resolve_deadline(
            discovered_at,
            severity,
            asset_tier=asset_tier,
            frameworks=active_frameworks,
            policy=policy,
            business_hours=use_biz_hours,
        )

        assignment = SLAAssignment(
            finding_id=finding_id,
            org_id=org_id,
            team_id=team_id,
            asset_tier=asset_tier,
            severity=severity.lower(),
            frameworks=active_frameworks,
            discovered_at=discovered_at,
            deadline=deadline,
            business_hours=use_biz_hours,
            status=SLAStatusV2.WITHIN_SLA,
            pct_elapsed=0.0,
            escalation_level=EscalationLevel.NONE,
        )

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO sla_assignments
                        (id, finding_id, org_id, team_id, asset_tier, severity,
                         frameworks, discovered_at, deadline, business_hours,
                         status, pct_elapsed, escalation_level,
                         breached_at, resolved_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        assignment.id,
                        assignment.finding_id,
                        assignment.org_id,
                        assignment.team_id,
                        assignment.asset_tier,
                        assignment.severity,
                        json.dumps(assignment.frameworks),
                        assignment.discovered_at.isoformat(),
                        assignment.deadline.isoformat(),
                        1 if assignment.business_hours else 0,
                        assignment.status if isinstance(assignment.status, str)
                        else assignment.status.value,
                        assignment.pct_elapsed,
                        assignment.escalation_level if isinstance(assignment.escalation_level, str)
                        else assignment.escalation_level.value,
                        None,
                        None,
                        assignment.created_at.isoformat(),
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)

        logger.info(
            "sla_management: assigned",
            finding=finding_id,
            severity=severity,
            deadline=deadline.isoformat(),
            tier=asset_tier,
            biz_hours=use_biz_hours,
        )
        return assignment

    def get_assignment(self, finding_id: str) -> Optional[SLAAssignment]:
        """Return the SLA assignment for a finding, or None."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM sla_assignments WHERE finding_id=?",
                    (finding_id,),
                ).fetchone()
            finally:
                self._close(conn)
        return self._assignment_from_row(row) if row else None

    @staticmethod
    def _assignment_from_row(row: sqlite3.Row) -> SLAAssignment:
        d = dict(row)
        d["frameworks"] = json.loads(d.get("frameworks") or "[]")
        d["business_hours"] = bool(d.get("business_hours", 0))
        return SLAAssignment(**d)

    # ------------------------------------------------------------------
    # Breach Detection
    # ------------------------------------------------------------------

    def check_and_update_status(self, finding_id: str) -> SLAAssignment:
        """Recompute SLA status for a finding and persist the update.

        Returns the updated SLAAssignment.
        """
        assignment = self.get_assignment(finding_id)
        if assignment is None:
            raise ValueError(f"No SLA assignment found for finding '{finding_id}'")

        # Terminal states
        if assignment.status in (
            SLAStatusV2.RESOLVED, SLAStatusV2.EXEMPT,
            "resolved", "exempt",
        ):
            return assignment

        now = _now()
        disc = assignment.discovered_at
        if disc.tzinfo is None:
            disc = disc.replace(tzinfo=timezone.utc)
        deadline = assignment.deadline
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)

        pct = _compute_pct_elapsed(disc, deadline, now)
        status = _compute_status(pct, deadline, now)
        esc_level = _escalation_level_for_pct(pct)

        breached_at_iso = assignment.breached_at.isoformat() if assignment.breached_at else None
        if status in (SLAStatusV2.BREACHED, SLAStatusV2.SEVERELY_BREACHED) and not assignment.breached_at:
            breached_at_iso = now.isoformat()

        status_val = status.value if hasattr(status, "value") else status
        esc_val = esc_level.value if hasattr(esc_level, "value") else esc_level

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    UPDATE sla_assignments
                    SET status=?, pct_elapsed=?, escalation_level=?, breached_at=?
                    WHERE finding_id=?
                    """,
                    (status_val, round(pct, 4), esc_val, breached_at_iso, finding_id),
                )
                conn.commit()
            finally:
                self._close(conn)

        logger.debug(
            "sla_management: status updated",
            finding=finding_id,
            status=status_val,
            pct=round(pct, 2),
            escalation=esc_val,
        )
        return self.get_assignment(finding_id)  # type: ignore[return-value]

    def detect_breaches(self, org_id: str) -> List[SLAAssignment]:
        """Scan all open assignments for an org and return those that are breached."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM sla_assignments
                    WHERE org_id=?
                      AND status NOT IN ('resolved','exempt')
                      AND resolved_at IS NULL
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                self._close(conn)

        breached: List[SLAAssignment] = []
        now = _now()
        for row in rows:
            a = self._assignment_from_row(row)
            deadline = a.deadline
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            if now >= deadline:
                updated = self.check_and_update_status(a.finding_id)
                breached.append(updated)
        return breached

    def mark_resolved(
        self, finding_id: str, resolved_at: Optional[datetime] = None
    ) -> SLAAssignment:
        """Mark a finding as resolved."""
        ts = resolved_at or _now()
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM sla_assignments WHERE finding_id=?",
                    (finding_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(
                        f"No SLA assignment for finding '{finding_id}'"
                    )
                a = self._assignment_from_row(row)
                deadline = a.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)

                disc = a.discovered_at
                if disc.tzinfo is None:
                    disc = disc.replace(tzinfo=timezone.utc)

                pct = _compute_pct_elapsed(disc, deadline, ts)
                final_status = (
                    SLAStatusV2.BREACHED.value if ts > deadline
                    else SLAStatusV2.RESOLVED.value
                )
                conn.execute(
                    """
                    UPDATE sla_assignments
                    SET resolved_at=?, status=?, pct_elapsed=?
                    WHERE finding_id=?
                    """,
                    (ts.isoformat(), final_status, round(pct, 4), finding_id),
                )
                conn.commit()
            finally:
                self._close(conn)

        logger.info("sla_management: resolved", finding=finding_id, at=ts.isoformat())
        return self.get_assignment(finding_id)  # type: ignore[return-value]

    def mark_exempt(self, finding_id: str, reason: str = "") -> SLAAssignment:
        """Exempt a finding from SLA enforcement."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE sla_assignments SET status='exempt' WHERE finding_id=?",
                    (finding_id,),
                )
                conn.commit()
            finally:
                self._close(conn)
        logger.info("sla_management: exempted", finding=finding_id, reason=reason)
        return self.get_assignment(finding_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Exception Management
    # ------------------------------------------------------------------

    def request_exception(
        self,
        finding_id: str,
        org_id: str,
        exception_type: ExceptionType,
        justification: str,
        requested_by: str,
        expiry_date: Optional[datetime] = None,
        evidence: Optional[Dict[str, Any]] = None,
        new_deadline: Optional[datetime] = None,
    ) -> SLAException:
        """Submit an SLA exception request."""
        exc = SLAException(
            finding_id=finding_id,
            org_id=org_id,
            exception_type=exception_type,
            justification=justification,
            requested_by=requested_by,
            expiry_date=expiry_date,
            evidence=evidence or {},
            new_deadline=new_deadline,
        )
        now_iso = _now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO sla_exceptions
                        (id, finding_id, org_id, exception_type, justification,
                         requested_by, approved_by, status, expiry_date,
                         evidence, new_deadline, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        exc.id,
                        exc.finding_id,
                        exc.org_id,
                        exc.exception_type if isinstance(exc.exception_type, str)
                        else exc.exception_type.value,
                        exc.justification,
                        exc.requested_by,
                        None,
                        ExceptionStatus.PENDING.value,
                        exc.expiry_date.isoformat() if exc.expiry_date else None,
                        json.dumps(exc.evidence),
                        exc.new_deadline.isoformat() if exc.new_deadline else None,
                        now_iso,
                        now_iso,
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)

        logger.info(
            "sla_management: exception requested",
            finding=finding_id,
            type=exc.exception_type,
            by=requested_by,
        )
        return exc

    def approve_exception(
        self,
        exception_id: str,
        approved_by: str,
    ) -> SLAException:
        """Approve an exception and apply its effect (exempt or extend deadline)."""
        exc = self._get_exception(exception_id)
        if exc is None:
            raise ValueError(f"Exception '{exception_id}' not found")

        now_iso = _now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    UPDATE sla_exceptions
                    SET status=?, approved_by=?, updated_at=?
                    WHERE id=?
                    """,
                    (ExceptionStatus.APPROVED.value, approved_by, now_iso, exception_id),
                )
                conn.commit()
            finally:
                self._close(conn)

        # Apply effect
        exc_type = exc.exception_type
        if isinstance(exc_type, str):
            exc_type = ExceptionType(exc_type)

        if exc_type == ExceptionType.FALSE_POSITIVE:
            self.mark_exempt(exc.finding_id, reason="false_positive approved")
        elif exc_type == ExceptionType.RISK_ACCEPTANCE:
            self.mark_exempt(exc.finding_id, reason=f"risk_acceptance: {exc.justification}")
        elif exc_type == ExceptionType.EXTENDED_DEADLINE and exc.new_deadline:
            self._extend_deadline(exc.finding_id, exc.new_deadline)

        logger.info(
            "sla_management: exception approved",
            id=exception_id,
            by=approved_by,
        )
        return self._get_exception(exception_id)  # type: ignore[return-value]

    def reject_exception(self, exception_id: str, rejected_by: str) -> SLAException:
        """Reject an exception request."""
        now_iso = _now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    UPDATE sla_exceptions
                    SET status=?, approved_by=?, updated_at=?
                    WHERE id=?
                    """,
                    (ExceptionStatus.REJECTED.value, rejected_by, now_iso, exception_id),
                )
                conn.commit()
            finally:
                self._close(conn)
        logger.info("sla_management: exception rejected", id=exception_id)
        return self._get_exception(exception_id)  # type: ignore[return-value]

    def list_exceptions(
        self,
        org_id: str,
        status: Optional[ExceptionStatus] = None,
    ) -> List[SLAException]:
        """List exceptions for an org, optionally filtered by status."""
        with self._lock:
            conn = self._get_conn()
            try:
                if status is not None:
                    status_val = status.value if hasattr(status, "value") else status
                    rows = conn.execute(
                        "SELECT * FROM sla_exceptions WHERE org_id=? AND status=?",
                        (org_id, status_val),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM sla_exceptions WHERE org_id=?",
                        (org_id,),
                    ).fetchall()
            finally:
                self._close(conn)
        return [self._exception_from_row(r) for r in rows]

    def _get_exception(self, exception_id: str) -> Optional[SLAException]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM sla_exceptions WHERE id=?", (exception_id,)
                ).fetchone()
            finally:
                self._close(conn)
        return self._exception_from_row(row) if row else None

    @staticmethod
    def _exception_from_row(row: sqlite3.Row) -> SLAException:
        d = dict(row)
        d["evidence"] = json.loads(d.get("evidence") or "{}")
        return SLAException(**d)

    def _extend_deadline(
        self, finding_id: str, new_deadline: datetime
    ) -> None:
        if new_deadline.tzinfo is None:
            new_deadline = new_deadline.replace(tzinfo=timezone.utc)
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE sla_assignments SET deadline=?, status='within_sla' WHERE finding_id=?",
                    (new_deadline.isoformat(), finding_id),
                )
                conn.commit()
            finally:
                self._close(conn)

    # ------------------------------------------------------------------
    # Team Performance
    # ------------------------------------------------------------------

    def compute_team_metrics(
        self,
        org_id: str,
        team_id: str,
        period_days: int = 30,
    ) -> TeamMetrics:
        """Compute and persist team SLA performance for a period."""
        now = _now()
        period_start = now - timedelta(days=period_days)

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM sla_assignments
                    WHERE org_id=? AND team_id=?
                      AND created_at >= ?
                    """,
                    (org_id, team_id, period_start.isoformat()),
                ).fetchall()
            finally:
                self._close(conn)

        assignments = [self._assignment_from_row(r) for r in rows]
        total = len(assignments)
        resolved_within = 0
        breached_count = 0
        resolution_hours: List[float] = []

        for a in assignments:
            status_val = a.status if isinstance(a.status, str) else a.status.value
            if status_val == SLAStatusV2.RESOLVED.value and a.resolved_at:
                disc = a.discovered_at
                res = a.resolved_at
                if disc.tzinfo is None:
                    disc = disc.replace(tzinfo=timezone.utc)
                if res.tzinfo is None:
                    res = res.replace(tzinfo=timezone.utc)
                deadline = a.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                hours = (res - disc).total_seconds() / 3600
                resolution_hours.append(hours)
                if res <= deadline:
                    resolved_within += 1
            elif status_val in (
                SLAStatusV2.BREACHED.value,
                SLAStatusV2.SEVERELY_BREACHED.value,
            ):
                breached_count += 1

        avg_hours = (
            round(sum(resolution_hours) / len(resolution_hours), 2)
            if resolution_hours
            else 0.0
        )
        compliance_rate = round(resolved_within / max(total, 1) * 100, 2)

        # Determine trend: compare compliance rate to previous period
        trend = self._compute_trend(org_id, team_id, period_days, compliance_rate)

        metrics = TeamMetrics(
            org_id=org_id,
            team_id=team_id,
            period_start=period_start,
            period_end=now,
            total_assigned=total,
            resolved_within=resolved_within,
            breached=breached_count,
            avg_resolution_hours=avg_hours,
            compliance_rate=compliance_rate,
            trend=trend,
        )

        # Persist
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO sla_team_metrics
                        (id, org_id, team_id, period_start, period_end,
                         total_assigned, resolved_within, breached,
                         avg_resolution_hours, compliance_rate, trend, computed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        metrics.id,
                        org_id,
                        team_id,
                        period_start.isoformat(),
                        now.isoformat(),
                        total,
                        resolved_within,
                        breached_count,
                        avg_hours,
                        compliance_rate,
                        metrics.trend if isinstance(metrics.trend, str)
                        else metrics.trend.value,
                        now.isoformat(),
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)

        return metrics

    def _compute_trend(
        self,
        org_id: str,
        team_id: str,
        period_days: int,
        current_rate: float,
    ) -> TrendDirection:
        """Compare current compliance rate to previous period to infer trend."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    """
                    SELECT compliance_rate FROM sla_team_metrics
                    WHERE org_id=? AND team_id=?
                    ORDER BY computed_at DESC LIMIT 1
                    """,
                    (org_id, team_id),
                ).fetchone()
            finally:
                self._close(conn)

        if row is None:
            return TrendDirection.STABLE
        prev_rate = float(dict(row).get("compliance_rate", current_rate))
        delta = current_rate - prev_rate
        if delta >= 5.0:
            return TrendDirection.IMPROVING
        if delta <= -5.0:
            return TrendDirection.DEGRADING
        return TrendDirection.STABLE

    def get_team_leaderboard(
        self, org_id: str, period_days: int = 30
    ) -> List[Dict[str, Any]]:
        """Return per-team SLA metrics sorted by compliance rate (descending)."""
        # Find all teams with assignments in the period
        now = _now()
        period_start = now - timedelta(days=period_days)
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT DISTINCT team_id FROM sla_assignments
                    WHERE org_id=? AND created_at >= ? AND team_id IS NOT NULL
                    """,
                    (org_id, period_start.isoformat()),
                ).fetchall()
            finally:
                self._close(conn)

        leaderboard = []
        for row in rows:
            team_id = dict(row)["team_id"]
            if not team_id:
                continue
            metrics = self.compute_team_metrics(org_id, team_id, period_days)
            leaderboard.append({
                "rank": 0,  # set below
                "team_id": team_id,
                "compliance_rate": metrics.compliance_rate,
                "total_assigned": metrics.total_assigned,
                "breached": metrics.breached,
                "avg_resolution_hours": metrics.avg_resolution_hours,
                "trend": metrics.trend if isinstance(metrics.trend, str)
                else metrics.trend.value,
            })

        leaderboard.sort(key=lambda x: x["compliance_rate"], reverse=True)
        for i, item in enumerate(leaderboard, start=1):
            item["rank"] = i
        return leaderboard

    # ------------------------------------------------------------------
    # Escalation Rules
    # ------------------------------------------------------------------

    def run_escalation_check(self, org_id: str) -> Dict[str, Any]:
        """Evaluate all open assignments and fire escalation notifications.

        Escalation levels:
          - approaching (≥80% elapsed) → team lead
          - breached                   → director
          - severely_breached (≥2x)    → CISO

        Returns summary of escalations fired.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM sla_assignments
                    WHERE org_id=?
                      AND status NOT IN ('resolved','exempt')
                      AND resolved_at IS NULL
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                self._close(conn)

        policies_cache: Dict[Tuple[Optional[str], Optional[str]], Optional[SLAPolicyV2]] = {}
        summary: Dict[str, int] = {
            "team_lead": 0,
            "director": 0,
            "ciso": 0,
            "no_action": 0,
        }

        for row in rows:
            a = self._assignment_from_row(row)
            updated = self.check_and_update_status(a.finding_id)

            updated.status if isinstance(updated.status, str) else updated.status.value
            esc_val = (
                updated.escalation_level if isinstance(updated.escalation_level, str)
                else updated.escalation_level.value
            )

            if esc_val == EscalationLevel.NONE.value:
                summary["no_action"] += 1
                continue

            # Fetch escalation rules from policy
            cache_key = (a.team_id, a.asset_tier)
            if cache_key not in policies_cache:
                policies_cache[cache_key] = self.get_policy(
                    org_id, team_id=a.team_id, asset_tier=a.asset_tier
                )
            policy = policies_cache[cache_key]
            escalation_rules = policy.escalation_rules if policy else []

            rule: Optional[EscalationRule] = None
            for r in escalation_rules:
                if r.severity.lower() == a.severity.lower():
                    rule = r
                    break

            if rule:
                self._fire_escalation(updated, rule, esc_val)

            if esc_val == EscalationLevel.TEAM_LEAD.value:
                summary["team_lead"] += 1
            elif esc_val == EscalationLevel.DIRECTOR.value:
                summary["director"] += 1
            elif esc_val == EscalationLevel.CISO.value:
                summary["ciso"] += 1

        logger.info("sla_management: escalation check complete", org=org_id, summary=summary)
        return summary

    def _fire_escalation(
        self,
        assignment: SLAAssignment,
        rule: EscalationRule,
        level: str,
    ) -> None:
        """Attempt to send an escalation notification (best-effort)."""
        recipient_map = {
            EscalationLevel.TEAM_LEAD.value: rule.team_lead_email,
            EscalationLevel.DIRECTOR.value: rule.director_email,
            EscalationLevel.CISO.value: rule.ciso_email,
        }
        recipient = recipient_map.get(level)
        if not recipient:
            return

        try:
            from core.notifications import Channel, Notification, NotificationEngine

            subject = (
                f"[SLA {level.upper().replace('_', ' ')}] "
                f"{assignment.severity.upper()} finding {assignment.finding_id}"
            )
            body = (
                f"Finding {assignment.finding_id} (severity: {assignment.severity}, "
                f"tier: {assignment.asset_tier}) has reached escalation level: {level}.\n"
                f"Deadline: {assignment.deadline.isoformat()}\n"
                f"Elapsed: {round(assignment.pct_elapsed * 100, 1)}%\n"
                f"Immediate action required."
            )
            engine = NotificationEngine()
            engine.send(
                Notification(
                    rule_name="sla_escalation",
                    channel=Channel.EMAIL,
                    recipient=recipient,
                    subject=subject,
                    body=body,
                )
            )
        except Exception as exc:
            logger.warning(
                "sla_management: escalation notify failed",
                finding=assignment.finding_id,
                level=level,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self, org_id: str, period_days: int = 30) -> SLAReport:
        """Generate a comprehensive SLA compliance report.

        Covers: per-severity, per-team, per-framework, per-asset-tier.
        """
        now = _now()
        cutoff = (now - timedelta(days=period_days)).isoformat()

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM sla_assignments WHERE org_id=? AND created_at >= ?",
                    (org_id, cutoff),
                ).fetchall()
                exc_rows = conn.execute(
                    "SELECT status, COUNT(*) as cnt FROM sla_exceptions "
                    "WHERE org_id=? AND created_at >= ? GROUP BY status",
                    (org_id, cutoff),
                ).fetchall()
            finally:
                self._close(conn)

        assignments = [self._assignment_from_row(r) for r in rows]
        total = len(assignments)

        # Per-severity
        by_severity: Dict[str, Dict[str, Any]] = {}
        # Per-team (aggregated)
        by_team_raw: Dict[str, Dict[str, int]] = {}
        # Per-framework
        by_framework: Dict[str, Dict[str, int]] = {}
        # Per-asset-tier
        by_asset_tier: Dict[str, Dict[str, int]] = {}
        # Escalation counts
        esc_summary: Dict[str, int] = {
            EscalationLevel.TEAM_LEAD.value: 0,
            EscalationLevel.DIRECTOR.value: 0,
            EscalationLevel.CISO.value: 0,
        }
        resolved_within_global = 0

        for a in assignments:
            sev = a.severity
            status_val = a.status if isinstance(a.status, str) else a.status.value
            tier = a.asset_tier
            team = a.team_id or "unassigned"
            esc_val = (
                a.escalation_level if isinstance(a.escalation_level, str)
                else a.escalation_level.value
            )

            is_resolved = status_val == SLAStatusV2.RESOLVED.value
            is_breached = status_val in (
                SLAStatusV2.BREACHED.value,
                SLAStatusV2.SEVERELY_BREACHED.value,
            )

            # Global compliance
            if is_resolved and a.resolved_at:
                deadline = a.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                res = a.resolved_at
                if res.tzinfo is None:
                    res = res.replace(tzinfo=timezone.utc)
                if res <= deadline:
                    resolved_within_global += 1

            # Per-severity
            if sev not in by_severity:
                by_severity[sev] = {
                    "total": 0,
                    "resolved_within": 0,
                    "breached": 0,
                    "compliance_rate": 0.0,
                }
            by_severity[sev]["total"] += 1
            if is_resolved and a.resolved_at:
                deadline = a.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                res = a.resolved_at
                if res.tzinfo is None:
                    res = res.replace(tzinfo=timezone.utc)
                if res <= deadline:
                    by_severity[sev]["resolved_within"] += 1
            if is_breached:
                by_severity[sev]["breached"] += 1

            # Per-team
            if team not in by_team_raw:
                by_team_raw[team] = {"total": 0, "resolved_within": 0, "breached": 0}
            by_team_raw[team]["total"] += 1
            if is_resolved and a.resolved_at:
                deadline = a.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                res = a.resolved_at
                if res.tzinfo is None:
                    res = res.replace(tzinfo=timezone.utc)
                if res <= deadline:
                    by_team_raw[team]["resolved_within"] += 1
            if is_breached:
                by_team_raw[team]["breached"] += 1

            # Per-framework
            for fw in a.frameworks:
                if fw not in by_framework:
                    by_framework[fw] = {"total": 0, "resolved_within": 0, "breached": 0}
                by_framework[fw]["total"] += 1
                if is_breached:
                    by_framework[fw]["breached"] += 1

            # Per-asset-tier
            if tier not in by_asset_tier:
                by_asset_tier[tier] = {"total": 0, "resolved_within": 0, "breached": 0}
            by_asset_tier[tier]["total"] += 1
            if is_resolved and a.resolved_at:
                deadline = a.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                res = a.resolved_at
                if res.tzinfo is None:
                    res = res.replace(tzinfo=timezone.utc)
                if res <= deadline:
                    by_asset_tier[tier]["resolved_within"] += 1
            if is_breached:
                by_asset_tier[tier]["breached"] += 1

            # Escalation
            if esc_val in esc_summary:
                esc_summary[esc_val] += 1

        # Compute compliance rates
        for sev_data in by_severity.values():
            t = sev_data["total"]
            sev_data["compliance_rate"] = round(
                sev_data["resolved_within"] / max(t, 1) * 100, 2
            )
        for tier_data in by_asset_tier.values():
            t = tier_data["total"]
            tier_data["compliance_rate"] = round(
                tier_data["resolved_within"] / max(t, 1) * 100, 2
            )
        for fw_data in by_framework.values():
            t = fw_data["total"]
            fw_data["compliance_rate"] = round(
                (t - fw_data["breached"]) / max(t, 1) * 100, 2
            )

        by_team_list = [
            {
                "team_id": team,
                "total": d["total"],
                "resolved_within": d["resolved_within"],
                "breached": d["breached"],
                "compliance_rate": round(d["resolved_within"] / max(d["total"], 1) * 100, 2),
            }
            for team, d in by_team_raw.items()
        ]
        by_team_list.sort(key=lambda x: x["compliance_rate"], reverse=True)

        # Leaderboard
        leaderboard = self.get_team_leaderboard(org_id, period_days=period_days)

        # Exception summary
        exc_summary: Dict[str, int] = {}
        for row in exc_rows:
            d = dict(row)
            exc_summary[d["status"]] = d["cnt"]

        overall_rate = round(resolved_within_global / max(total, 1) * 100, 2)

        return SLAReport(
            org_id=org_id,
            generated_at=now,
            period_days=period_days,
            overall_compliance_rate=overall_rate,
            by_severity=by_severity,
            by_team=by_team_list,
            by_framework=by_framework,
            by_asset_tier=by_asset_tier,
            escalation_summary=esc_summary,
            exception_summary=exc_summary,
            leaderboard=leaderboard,
        )


__all__ = [
    "SLAManagement",
    "SLAPolicyV2",
    "SLAAssignment",
    "SLAException",
    "TeamMetrics",
    "SLAReport",
    "SLAStatusV2",
    "ExceptionType",
    "ExceptionStatus",
    "EscalationLevel",
    "EscalationRule",
    "TrendDirection",
]
