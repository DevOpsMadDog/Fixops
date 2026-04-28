"""
SLA Engine — Security Finding SLA Tracking and Breach Prevention.

Provides deadline-based SLA tracking for security findings with:
- Per-severity default deadlines (critical 24h, high 72h, medium 7d, low 30d)
- Named SLA policies per org
- Status progression: ON_TRACK → AT_RISK (>75%) → BREACHED
- Breach alert generation (>90% of deadline)
- Compliance rate calculation
- SQLite persistence

Compliance: SOC2 CC7.2, ISO27001 A.12.6.1, PCI-DSS Req 6.3, NIST SP 800-137
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# DB path
# ---------------------------------------------------------------------------

_DB_PATH = str(
    Path(__file__).resolve().parents[2] / "data" / "sla_tracking.db"
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sla_policies (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    org_id          TEXT NOT NULL,
    deadlines_json  TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_engine_pol_name_org
    ON sla_policies(name, org_id);

CREATE TABLE IF NOT EXISTS sla_tracking (
    tracking_id     TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL UNIQUE,
    severity        TEXT NOT NULL,
    policy_id       TEXT,
    org_id          TEXT NOT NULL DEFAULT 'default',
    created_at      TEXT NOT NULL,
    deadline        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'ON_TRACK',
    resolution_time TEXT,
    alert_sent      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_engine_trk_org    ON sla_tracking(org_id);
CREATE INDEX IF NOT EXISTS idx_engine_trk_status ON sla_tracking(org_id, status);
CREATE INDEX IF NOT EXISTS idx_engine_trk_finding ON sla_tracking(finding_id);
"""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_DEADLINES: Dict[str, timedelta] = {
    "critical": timedelta(hours=24),
    "high": timedelta(hours=72),
    "medium": timedelta(days=7),
    "low": timedelta(days=30),
}

_AT_RISK_THRESHOLD = 0.75   # >75% of deadline elapsed → AT_RISK
_BREACH_ALERT_THRESHOLD = 0.90  # >90% of deadline elapsed → send alert


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SLAStatusEnum(str, Enum):
    ON_TRACK = "ON_TRACK"
    AT_RISK = "AT_RISK"
    BREACHED = "BREACHED"
    RESOLVED = "RESOLVED"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SLAPolicy(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    org_id: str
    deadlines: Dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 24,
            "high": 72,
            "medium": 168,
            "low": 720,
        },
        description="Deadline in hours per severity",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SLATracking(BaseModel):
    tracking_id: str
    finding_id: str
    severity: str
    policy_id: Optional[str]
    org_id: str
    created_at: datetime
    deadline: datetime
    status: SLAStatusEnum
    time_remaining: Optional[timedelta]
    resolution_time: Optional[datetime]


class SLAStatus(BaseModel):
    tracking_id: str
    finding_id: str
    severity: str
    org_id: str
    status: SLAStatusEnum
    created_at: datetime
    deadline: datetime
    time_remaining: Optional[timedelta]
    pct_elapsed: float
    resolution_time: Optional[datetime]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SLAEngine:
    """Security finding SLA tracking and breach prevention."""

    # Default SLA deadlines by severity
    SLA_DEADLINES = _DEFAULT_DEADLINES

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _deadline_for(self, severity: str, policy_id: Optional[str]) -> datetime:
        """Compute deadline from policy (if given) or defaults."""
        hours: Optional[int] = None
        if policy_id:
            row = self._conn.execute(
                "SELECT deadlines_json FROM sla_policies WHERE id = ?", (policy_id,)
            ).fetchone()
            if row:
                deadlines = json.loads(row["deadlines_json"])
                hours = deadlines.get(severity.lower())

        if hours is None:
            td = _DEFAULT_DEADLINES.get(severity.lower(), timedelta(days=30))
            hours = int(td.total_seconds() / 3600)

        return self._now() + timedelta(hours=hours)

    def _compute_status(
        self,
        created_at: datetime,
        deadline: datetime,
        resolved: bool,
        resolution_time: Optional[datetime],
    ) -> SLAStatusEnum:
        now = self._now()
        if resolved and resolution_time is not None:
            return SLAStatusEnum.RESOLVED
        if now >= deadline:
            return SLAStatusEnum.BREACHED
        total = (deadline - created_at).total_seconds()
        elapsed = (now - created_at).total_seconds()
        pct = elapsed / total if total > 0 else 0.0
        if pct >= _AT_RISK_THRESHOLD:
            return SLAStatusEnum.AT_RISK
        return SLAStatusEnum.ON_TRACK

    def _pct_elapsed(self, created_at: datetime, deadline: datetime) -> float:
        now = self._now()
        total = (deadline - created_at).total_seconds()
        elapsed = (now - created_at).total_seconds()
        if total <= 0:
            return 1.0
        return min(elapsed / total, 1.0)

    def _row_to_tracking(self, row: sqlite3.Row) -> SLATracking:
        created_at = datetime.fromisoformat(row["created_at"])
        deadline = datetime.fromisoformat(row["deadline"])
        resolution_time = (
            datetime.fromisoformat(row["resolution_time"])
            if row["resolution_time"]
            else None
        )
        status = self._compute_status(
            created_at,
            deadline,
            row["status"] == SLAStatusEnum.RESOLVED,
            resolution_time,
        )
        now = self._now()
        time_remaining = deadline - now if now < deadline else timedelta(0)
        return SLATracking(
            tracking_id=row["tracking_id"],
            finding_id=row["finding_id"],
            severity=row["severity"],
            policy_id=row["policy_id"],
            org_id=row["org_id"],
            created_at=created_at,
            deadline=deadline,
            status=status,
            time_remaining=time_remaining,
            resolution_time=resolution_time,
        )

    def _row_to_status(self, row: sqlite3.Row) -> SLAStatus:
        tr = self._row_to_tracking(row)
        return SLAStatus(
            tracking_id=tr.tracking_id,
            finding_id=tr.finding_id,
            severity=tr.severity,
            org_id=tr.org_id,
            status=tr.status,
            created_at=tr.created_at,
            deadline=tr.deadline,
            time_remaining=tr.time_remaining,
            pct_elapsed=self._pct_elapsed(tr.created_at, tr.deadline),
            resolution_time=tr.resolution_time,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_sla_policy(
        self, name: str, deadlines: Dict[str, int], org_id: str
    ) -> SLAPolicy:
        """Create a named SLA policy. Updates existing policy with same name+org."""
        policy = SLAPolicy(name=name, org_id=org_id, deadlines=deadlines)
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM sla_policies WHERE name = ? AND org_id = ?",
                (name, org_id),
            ).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE sla_policies SET deadlines_json = ? WHERE id = ?",
                    (json.dumps(deadlines), existing["id"]),
                )
                policy = SLAPolicy(
                    id=existing["id"],
                    name=name,
                    org_id=org_id,
                    deadlines=deadlines,
                )
            else:
                self._conn.execute(
                    "INSERT INTO sla_policies(id, name, org_id, deadlines_json, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        policy.id,
                        policy.name,
                        policy.org_id,
                        json.dumps(deadlines),
                        policy.created_at.isoformat(),
                    ),
                )
            self._conn.commit()
        logger.info("sla_policy_created", policy_id=policy.id, name=name, org_id=org_id)
        return policy

    def track_finding(
        self,
        finding_id: str,
        severity: str,
        policy_id: Optional[str] = None,
        org_id: str = "default",
        discovered_at: Optional[datetime] = None,
    ) -> SLATracking:
        """Start tracking a finding against SLA. Returns tracking record."""
        now = discovered_at or self._now()
        tracking_id = str(uuid.uuid4())
        deadline = self._deadline_for(severity, policy_id)

        with self._lock:
            # Upsert: if finding already tracked, return existing
            existing = self._conn.execute(
                "SELECT * FROM sla_tracking WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            if existing:
                return self._row_to_tracking(existing)

            self._conn.execute(
                "INSERT INTO sla_tracking"
                "(tracking_id, finding_id, severity, policy_id, org_id, created_at, deadline, status)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tracking_id,
                    finding_id,
                    severity.lower(),
                    policy_id,
                    org_id,
                    now.isoformat(),
                    deadline.isoformat(),
                    SLAStatusEnum.ON_TRACK,
                ),
            )
            self._conn.commit()

        logger.info(
            "sla_tracking_started",
            finding_id=finding_id,
            severity=severity,
            deadline=deadline.isoformat(),
        )
        row = self._conn.execute(
            "SELECT * FROM sla_tracking WHERE tracking_id = ?", (tracking_id,)
        ).fetchone()
        return self._row_to_tracking(row)

    def check_status(self, finding_id: str) -> SLAStatus:
        """Check SLA status for a finding. Returns ON_TRACK, AT_RISK, BREACHED, or RESOLVED."""
        row = self._conn.execute(
            "SELECT * FROM sla_tracking WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Finding '{finding_id}' is not being tracked.")
        return self._row_to_status(row)

    def get_at_risk_findings(self, org_id: str = "default") -> List[SLAStatus]:
        """Get all findings at risk of SLA breach (AT_RISK or BREACHED, not RESOLVED)."""
        rows = self._conn.execute(
            "SELECT * FROM sla_tracking WHERE org_id = ? AND status != ?",
            (org_id, SLAStatusEnum.RESOLVED),
        ).fetchall()
        results: List[SLAStatus] = []
        for row in rows:
            s = self._row_to_status(row)
            if s.status in (SLAStatusEnum.AT_RISK, SLAStatusEnum.BREACHED):
                results.append(s)
        return results

    def record_resolution(self, finding_id: str) -> SLAStatus:
        """Record that a finding has been resolved. Marks SLA as RESOLVED."""
        row = self._conn.execute(
            "SELECT * FROM sla_tracking WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Finding '{finding_id}' is not being tracked.")
        now = self._now()
        with self._lock:
            self._conn.execute(
                "UPDATE sla_tracking SET status = ?, resolution_time = ? WHERE finding_id = ?",
                (SLAStatusEnum.RESOLVED, now.isoformat(), finding_id),
            )
            self._conn.commit()
        logger.info("sla_resolved", finding_id=finding_id, resolved_at=now.isoformat())
        row = self._conn.execute(
            "SELECT * FROM sla_tracking WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return self._row_to_status(row)

    def calculate_compliance_rate(
        self, org_id: str = "default", days: int = 30
    ) -> float:
        """Calculate SLA compliance rate for past N days (findings resolved within deadline)."""
        since = (self._now() - timedelta(days=days)).isoformat()
        rows = self._conn.execute(
            "SELECT * FROM sla_tracking WHERE org_id = ? AND status = ? AND created_at >= ?",
            (org_id, SLAStatusEnum.RESOLVED, since),
        ).fetchall()
        if not rows:
            return 100.0
        compliant = 0
        for row in rows:
            deadline = datetime.fromisoformat(row["deadline"])
            resolution = (
                datetime.fromisoformat(row["resolution_time"])
                if row["resolution_time"]
                else None
            )
            if resolution and resolution <= deadline:
                compliant += 1
        return round((compliant / len(rows)) * 100, 2)

    def send_breach_alerts(self) -> List[str]:
        """Send alerts for findings about to breach (>90% of deadline). Returns alert IDs."""
        rows = self._conn.execute(
            "SELECT * FROM sla_tracking WHERE status != ? AND alert_sent = 0",
            (SLAStatusEnum.RESOLVED,),
        ).fetchall()
        alert_ids: List[str] = []
        now = self._now()
        for row in rows:
            created_at = datetime.fromisoformat(row["created_at"])
            deadline = datetime.fromisoformat(row["deadline"])
            total = (deadline - created_at).total_seconds()
            elapsed = (now - created_at).total_seconds()
            pct = elapsed / total if total > 0 else 0.0
            # Alert if >90% elapsed or already breached
            if pct >= _BREACH_ALERT_THRESHOLD or now >= deadline:
                alert_id = str(uuid.uuid4())
                logger.warning(
                    "sla_breach_alert",
                    alert_id=alert_id,
                    finding_id=row["finding_id"],
                    severity=row["severity"],
                    pct_elapsed=round(pct * 100, 1),
                    deadline=deadline.isoformat(),
                )
                with self._lock:
                    self._conn.execute(
                        "UPDATE sla_tracking SET alert_sent = 1 WHERE finding_id = ?",
                        (row["finding_id"],),
                    )
                    self._conn.commit()
                alert_ids.append(alert_id)
        return alert_ids

    def get_dashboard(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregated SLA dashboard metrics."""
        rows = self._conn.execute(
            "SELECT * FROM sla_tracking WHERE org_id = ?", (org_id,)
        ).fetchall()
        counts: Dict[str, int] = {
            "ON_TRACK": 0,
            "AT_RISK": 0,
            "BREACHED": 0,
            "RESOLVED": 0,
        }
        for row in rows:
            s = self._row_to_status(row)
            counts[s.status] += 1

        total = len(rows)
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "sla_engine", "org_id": "unknown", "source_engine": "sla_engine"})
            except Exception:
                pass
        return {
            "org_id": org_id,
            "total_tracked": total,
            "on_track": counts["ON_TRACK"],
            "at_risk": counts["AT_RISK"],
            "breached": counts["BREACHED"],
            "resolved": counts["RESOLVED"],
            "compliance_rate_30d": self.calculate_compliance_rate(org_id, days=30),
        }
