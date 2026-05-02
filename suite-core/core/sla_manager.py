"""
SLA Management Engine for ALDECI.

Provides per-severity remediation deadlines, compliance tracking, and
auto-escalation with SQLite persistence.

Compliance: SOC2 CC7.2, ISO27001 A.12.6, NIST SP 800-137
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default DB path
# ---------------------------------------------------------------------------

_DB_PATH = str(
    Path(__file__).resolve().parents[2] / "data" / "sla.db"
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sla_policies (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    severity_deadlines TEXT NOT NULL DEFAULT '{}',
    escalation_chain   TEXT NOT NULL DEFAULT '[]',
    grace_period_hours INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_pol_org ON sla_policies(org_id);

CREATE TABLE IF NOT EXISTS sla_records (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL UNIQUE,
    org_id          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    discovered_at   TEXT NOT NULL,
    deadline        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'within_sla',
    breached_at     TEXT,
    resolved_at     TEXT,
    escalated       INTEGER NOT NULL DEFAULT 0,
    exempt_reason   TEXT
);
CREATE INDEX IF NOT EXISTS idx_rec_org    ON sla_records(org_id);
CREATE INDEX IF NOT EXISTS idx_rec_finding ON sla_records(finding_id);
CREATE INDEX IF NOT EXISTS idx_rec_status  ON sla_records(org_id, status);
"""

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

# Default severity deadlines (hours)
_DEFAULT_DEADLINES: Dict[str, int] = {
    "critical": 24,
    "high": 72,
    "medium": 336,
    "low": 720,
}


class SLAStatus(str, Enum):
    """Lifecycle states for an SLA record."""

    WITHIN_SLA = "within_sla"
    AT_RISK = "at_risk"
    BREACHED = "breached"
    EXEMPT = "exempt"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SLAPolicy(BaseModel):
    """Per-org SLA policy with severity-specific deadlines."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    name: str
    severity_deadlines: Dict[str, int] = Field(
        default_factory=lambda: dict(_DEFAULT_DEADLINES)
    )
    escalation_chain: List[str] = Field(default_factory=list)
    grace_period_hours: int = 0
    enabled: bool = True

    model_config = {"use_enum_values": True}


class SLARecord(BaseModel):
    """Tracks SLA compliance for a single finding."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    org_id: str
    severity: str
    discovered_at: datetime
    deadline: datetime
    status: SLAStatus = SLAStatus.WITHIN_SLA
    breached_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    escalated: bool = False
    exempt_reason: Optional[str] = None

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO datetime string, returning None if value is None."""
    if value is None:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


# ---------------------------------------------------------------------------
# SLAManager
# ---------------------------------------------------------------------------


class SLAManager:
    """SQLite-backed SLA management engine.

    Args:
        db_path: Path to the SQLite database file, or ``:memory:`` for tests.
    """

    def __init__(self, db_path: Union[str, Path] = ":memory:") -> None:
        self._db_path = str(db_path)
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # Internal DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._db_path == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
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

    @staticmethod
    def _policy_from_row(row: sqlite3.Row) -> SLAPolicy:
        d = dict(row)
        d["severity_deadlines"] = json.loads(d.get("severity_deadlines") or "{}")
        d["escalation_chain"] = json.loads(d.get("escalation_chain") or "[]")
        d["enabled"] = bool(d.get("enabled", 1))
        return SLAPolicy(**d)

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> SLARecord:
        d = dict(row)
        d["escalated"] = bool(d.get("escalated", 0))
        return SLARecord(**d)

    def _get_conn(self) -> sqlite3.Connection:
        """Return an open connection (shared for :memory:, new for file)."""
        return self._connect()

    def _close(self, conn: sqlite3.Connection) -> None:
        if self._db_path != ":memory:":
            conn.close()

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def create_policy(self, policy: SLAPolicy) -> SLAPolicy:
        """Persist a new SLA policy. Upserts by org_id."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO sla_policies
                        (id, org_id, name, severity_deadlines, escalation_chain,
                         grace_period_hours, enabled)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        policy.id,
                        policy.org_id,
                        policy.name,
                        json.dumps(policy.severity_deadlines),
                        json.dumps(policy.escalation_chain),
                        policy.grace_period_hours,
                        1 if policy.enabled else 0,
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)
        _logger.info("sla: created/updated policy for org=%s", policy.org_id)
        return policy

    def get_policy(self, org_id: str) -> Optional[SLAPolicy]:
        """Return the SLA policy for an org, or None if not set."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM sla_policies WHERE org_id = ?", (org_id,)
                ).fetchone()
            finally:
                self._close(conn)
        if row is None:
            return None
        return self._policy_from_row(row)

    def update_policy(self, org_id: str, updates: Dict[str, Any]) -> SLAPolicy:
        """Apply partial updates to an existing policy.

        Raises:
            ValueError: if no policy exists for org_id.
        """
        existing = self.get_policy(org_id)
        if existing is None:
            raise ValueError(f"No SLA policy found for org '{org_id}'")
        updated = existing.model_copy(update=updates)
        return self.create_policy(updated)

    def _get_effective_deadlines(self, org_id: str) -> Dict[str, int]:
        """Return severity deadlines for org (or defaults)."""
        policy = self.get_policy(org_id)
        if policy and policy.enabled:
            deadlines = dict(_DEFAULT_DEADLINES)
            deadlines.update(policy.severity_deadlines)
            return deadlines
        return dict(_DEFAULT_DEADLINES)

    def _get_grace_period(self, org_id: str) -> int:
        policy = self.get_policy(org_id)
        return policy.grace_period_hours if policy else 0

    # ------------------------------------------------------------------
    # Finding tracking
    # ------------------------------------------------------------------

    def track_finding(
        self,
        finding_id: str,
        severity: str,
        discovered_at: datetime,
        org_id: str,
    ) -> SLARecord:
        """Create an SLA tracking record for a finding.

        Computes the remediation deadline from the org's SLA policy and the
        finding severity.  Idempotent — returns existing record if already
        tracked.
        """
        severity_lower = severity.lower()
        deadlines = self._get_effective_deadlines(org_id)
        grace = self._get_grace_period(org_id)
        sla_hours = deadlines.get(severity_lower, _DEFAULT_DEADLINES.get(severity_lower, 720))
        total_hours = sla_hours + grace

        if discovered_at.tzinfo is None:
            discovered_at = discovered_at.replace(tzinfo=timezone.utc)
        deadline = discovered_at + timedelta(hours=total_hours)

        record = SLARecord(
            finding_id=finding_id,
            org_id=org_id,
            severity=severity_lower,
            discovered_at=discovered_at,
            deadline=deadline,
            status=SLAStatus.WITHIN_SLA,
        )

        with self._lock:
            conn = self._get_conn()
            try:
                existing = conn.execute(
                    "SELECT * FROM sla_records WHERE finding_id = ?", (finding_id,)
                ).fetchone()
                if existing:
                    self._close(conn)
                    return self._record_from_row(existing)
                conn.execute(
                    """
                    INSERT INTO sla_records
                        (id, finding_id, org_id, severity, discovered_at, deadline,
                         status, breached_at, resolved_at, escalated, exempt_reason)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record.id,
                        record.finding_id,
                        record.org_id,
                        record.severity,
                        record.discovered_at.isoformat(),
                        record.deadline.isoformat(),
                        record.status if isinstance(record.status, str) else record.status.value,
                        None,
                        None,
                        0,
                        None,
                    ),
                )
                conn.commit()
            finally:
                self._close(conn)

        _logger.info(
            "sla: tracking finding=%s org=%s severity=%s deadline=%s",
            finding_id, org_id, severity_lower, deadline.isoformat(),
        )
        _emit_event("sla_manager.finding_tracked", {
            "finding_id": finding_id,
            "org_id": org_id,
            "severity": severity_lower,
            "deadline": deadline.isoformat(),
            "sla_hours": sla_hours,
        })
        return record

    def check_sla_status(self, finding_id: str) -> SLAStatus:
        """Compute and persist the current SLA status for a finding.

        Returns:
            SLAStatus enum value.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM sla_records WHERE finding_id = ?", (finding_id,)
                ).fetchone()
                if row is None:
                    return SLAStatus.WITHIN_SLA

                record = self._record_from_row(row)

                # Resolved / exempt — status is terminal
                if record.status in (SLAStatus.EXEMPT, "exempt"):
                    return SLAStatus.EXEMPT
                if record.resolved_at is not None:
                    # Status is already stored (within_sla or breached)
                    stored = record.status if isinstance(record.status, str) else record.status.value
                    return SLAStatus(stored)

                now = _now()
                deadline = record.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)

                discovered = record.discovered_at
                if discovered.tzinfo is None:
                    discovered = discovered.replace(tzinfo=timezone.utc)
                total_window_seconds = (deadline - discovered).total_seconds()
                remaining_seconds = (deadline - now).total_seconds()

                if now >= deadline:
                    new_status = SLAStatus.BREACHED
                    breached_at = record.breached_at or now
                    conn.execute(
                        "UPDATE sla_records SET status=?, breached_at=? WHERE finding_id=?",
                        (SLAStatus.BREACHED.value, breached_at.isoformat(), finding_id),
                    )
                elif total_window_seconds > 0 and remaining_seconds / total_window_seconds <= 0.2:
                    # Within last 20% of the SLA window → at risk
                    new_status = SLAStatus.AT_RISK
                    conn.execute(
                        "UPDATE sla_records SET status=? WHERE finding_id=?",
                        (new_status.value, finding_id),
                    )
                else:
                    new_status = SLAStatus.WITHIN_SLA
                    conn.execute(
                        "UPDATE sla_records SET status=? WHERE finding_id=?",
                        (new_status.value, finding_id),
                    )
                conn.commit()
                return new_status
            finally:
                self._close(conn)

    def mark_resolved(self, finding_id: str, resolved_at: Optional[datetime] = None) -> None:
        """Mark a finding as resolved, capturing resolution time."""
        ts = resolved_at or _now()
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM sla_records WHERE finding_id = ?", (finding_id,)
                ).fetchone()
                if row is None:
                    return

                record = self._record_from_row(row)
                deadline = record.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)

                # Determine final status
                if record.status in (SLAStatus.EXEMPT, "exempt"):
                    final_status = SLAStatus.EXEMPT
                elif ts > deadline:
                    final_status = SLAStatus.BREACHED
                else:
                    final_status = SLAStatus.WITHIN_SLA

                conn.execute(
                    "UPDATE sla_records SET resolved_at=?, status=? WHERE finding_id=?",
                    (ts.isoformat(), final_status.value, finding_id),
                )
                conn.commit()
            finally:
                self._close(conn)

        _logger.info("sla: resolved finding=%s at=%s", finding_id, ts.isoformat())

    def mark_exempt(self, finding_id: str, reason: str) -> None:
        """Exempt a finding from SLA tracking (e.g., risk-accepted)."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE sla_records SET status=?, exempt_reason=? WHERE finding_id=?",
                    (SLAStatus.EXEMPT.value, reason, finding_id),
                )
                conn.commit()
            finally:
                self._close(conn)
        _logger.info("sla: exempted finding=%s reason=%s", finding_id, reason)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_record(self, finding_id: str) -> Optional[SLARecord]:
        """Return the SLA record for a finding."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM sla_records WHERE finding_id = ?", (finding_id,)
                ).fetchone()
            finally:
                self._close(conn)
        return self._record_from_row(row) if row else None

    def get_breached(self, org_id: str) -> List[SLARecord]:
        """Return all breached SLA records for an org."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM sla_records WHERE org_id=? AND status=?",
                    (org_id, SLAStatus.BREACHED.value),
                ).fetchall()
            finally:
                self._close(conn)
        return [self._record_from_row(r) for r in rows]

    def get_at_risk(self, org_id: str, hours_threshold: float = 24.0) -> List[SLARecord]:
        """Return records approaching their deadline within *hours_threshold* hours."""
        now = _now()
        threshold_dt = now + timedelta(hours=hours_threshold)
        threshold_iso = threshold_dt.isoformat()
        now_iso = now.isoformat()

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM sla_records
                    WHERE org_id=?
                      AND status NOT IN (?, ?)
                      AND resolved_at IS NULL
                      AND deadline <= ?
                      AND deadline > ?
                    """,
                    (org_id, SLAStatus.EXEMPT.value, SLAStatus.BREACHED.value,
                     threshold_iso, now_iso),
                ).fetchall()
            finally:
                self._close(conn)
        return [self._record_from_row(r) for r in rows]

    def get_sla_compliance_rate(self, org_id: str, period_days: int = 30) -> float:
        """Return the percentage of findings resolved within SLA in the given period.

        Only considers resolved findings with a resolution within *period_days*.
        """
        cutoff = (_now() - timedelta(days=period_days)).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT status FROM sla_records
                    WHERE org_id=?
                      AND resolved_at IS NOT NULL
                      AND resolved_at >= ?
                    """,
                    (org_id, cutoff),
                ).fetchall()
            finally:
                self._close(conn)

        if not rows:
            return 100.0

        total = len(rows)
        within = sum(
            1 for r in rows
            if dict(r).get("status") in (SLAStatus.WITHIN_SLA.value, "within_sla")
        )
        return round(within / total * 100, 2)

    def get_mttr_by_severity(self, org_id: str) -> Dict[str, float]:
        """Return average resolution time (hours) per severity for an org.

        Only includes resolved findings.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT severity, discovered_at, resolved_at
                    FROM sla_records
                    WHERE org_id=? AND resolved_at IS NOT NULL
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                self._close(conn)

        by_severity: Dict[str, List[float]] = {}
        for row in rows:
            d = dict(row)
            disc = _parse_dt(d.get("discovered_at"))
            res = _parse_dt(d.get("resolved_at"))
            if disc is None or res is None:
                continue
            hours = (res - disc).total_seconds() / 3600
            sev = d.get("severity", "unknown")
            by_severity.setdefault(sev, []).append(hours)

        return {
            sev: round(sum(times) / len(times), 2)
            for sev, times in by_severity.items()
        }

    def run_escalation_check(self, org_id: str) -> int:
        """Check all records for breaches and send escalation alerts.

        Returns:
            Number of records escalated in this run.
        """
        policy = self.get_policy(org_id)
        escalation_chain = policy.escalation_chain if policy else []

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM sla_records
                    WHERE org_id=? AND status=? AND escalated=0 AND resolved_at IS NULL
                    """,
                    (org_id, SLAStatus.BREACHED.value),
                ).fetchall()
            finally:
                self._close(conn)

        escalated = 0
        for row in rows:
            record = self._record_from_row(row)
            # Attempt notification
            try:
                from core.notifications import Channel, Notification, NotificationEngine
                engine = NotificationEngine()
                for recipient in escalation_chain:
                    notif = Notification(
                        rule_name="sla_breach_escalation",
                        channel=Channel.EMAIL,
                        recipient=recipient,
                        subject=f"SLA BREACH: {record.severity.upper()} finding {record.finding_id}",
                        body=(
                            f"Finding {record.finding_id} (severity: {record.severity}) "
                            f"breached SLA deadline {record.deadline.isoformat()}. "
                            f"Immediate action required."
                        ),
                    )
                    engine.send(notif)
            except Exception as exc:  # noqa: BLE001
                _logger.warning("sla: escalation notify failed for %s: %s", record.finding_id, exc)

            # Mark escalated
            with self._lock:
                conn = self._get_conn()
                try:
                    conn.execute(
                        "UPDATE sla_records SET escalated=1 WHERE finding_id=?",
                        (record.finding_id,),
                    )
                    conn.commit()
                finally:
                    self._close(conn)
            escalated += 1
            _logger.info("sla: escalated finding=%s", record.finding_id)

        return escalated

    def get_sla_dashboard(self, org_id: str) -> Dict[str, Any]:
        """Return all SLA metrics for dashboard display."""
        with self._lock:
            conn = self._get_conn()
            try:
                all_rows = conn.execute(
                    "SELECT * FROM sla_records WHERE org_id=?", (org_id,)
                ).fetchall()
            finally:
                self._close(conn)

        records = [self._record_from_row(r) for r in all_rows]
        now = _now()

        total = len(records)
        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        breached_list = []
        at_risk_list = []

        for rec in records:
            st = rec.status if isinstance(rec.status, str) else rec.status.value
            by_status[st] = by_status.get(st, 0) + 1
            by_severity[rec.severity] = by_severity.get(rec.severity, 0) + 1
            if st == SLAStatus.BREACHED.value:
                deadline = rec.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                overdue_hours = round((now - deadline).total_seconds() / 3600, 1)
                breached_list.append({
                    "finding_id": rec.finding_id,
                    "severity": rec.severity,
                    "overdue_hours": max(overdue_hours, 0),
                    "escalated": rec.escalated,
                })
            elif st == SLAStatus.AT_RISK.value:
                deadline = rec.deadline
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                remaining_hours = round((deadline - now).total_seconds() / 3600, 1)
                at_risk_list.append({
                    "finding_id": rec.finding_id,
                    "severity": rec.severity,
                    "remaining_hours": max(remaining_hours, 0),
                })

        compliance_rate = self.get_sla_compliance_rate(org_id)
        mttr = self.get_mttr_by_severity(org_id)

        policy = self.get_policy(org_id)
        deadlines = policy.severity_deadlines if policy else _DEFAULT_DEADLINES

        return {
            "org_id": org_id,
            "total_findings": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "compliance_rate": compliance_rate,
            "mttr_by_severity": mttr,
            "breached": breached_list,
            "at_risk": at_risk_list,
            "sla_targets": deadlines,
            "policy_enabled": policy.enabled if policy else True,
        }

    def bulk_track(
        self,
        findings: List[Dict[str, Any]],
        org_id: str,
    ) -> int:
        """Track multiple findings at once.

        Each item in *findings* must have: ``finding_id``, ``severity``,
        ``discovered_at`` (datetime or ISO string).

        Returns:
            Number of findings newly tracked (skips already-tracked).
        """
        tracked = 0
        for item in findings:
            fid = item.get("finding_id") or item.get("id", "")
            severity = item.get("severity", "medium")
            disc = item.get("discovered_at", _now())
            if isinstance(disc, str):
                disc = _parse_dt(disc) or _now()
            if not fid:
                continue
            rec = self.track_finding(fid, severity, disc, org_id)
            # track_finding returns existing if already present; check id matches new
            if rec.finding_id == fid:
                tracked += 1
        return tracked


__all__ = ["SLAManager", "SLAPolicy", "SLARecord", "SLAStatus"]
