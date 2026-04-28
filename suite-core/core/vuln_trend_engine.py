"""Vulnerability Trend Analyzer — ALDECI.

Tracks daily vulnerability snapshots, computes severity trends,
manages SLA tracking per finding, and groups vulns into cohorts.

Thread-safe via RLock. Multi-tenant via org_id.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "vuln_trend.db"
)

# SLA days per severity
_SLA_DAYS: Dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 365,
}

# Threshold (% change) to classify trend as increasing / decreasing
_TREND_THRESHOLD = 10.0


class VulnTrendEngine:
    """SQLite WAL-backed vulnerability trend engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vuln_snapshots (
                    snapshot_id        TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    taken_at           DATETIME NOT NULL,
                    total_vulns        INTEGER NOT NULL DEFAULT 0,
                    critical           INTEGER NOT NULL DEFAULT 0,
                    high               INTEGER NOT NULL DEFAULT 0,
                    medium             INTEGER NOT NULL DEFAULT 0,
                    low                INTEGER NOT NULL DEFAULT 0,
                    info               INTEGER NOT NULL DEFAULT 0,
                    mttr_days          REAL NOT NULL DEFAULT 0.0,
                    new_this_week      INTEGER NOT NULL DEFAULT 0,
                    resolved_this_week INTEGER NOT NULL DEFAULT 0,
                    sla_breached       INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_snap_org
                    ON vuln_snapshots (org_id, taken_at DESC);

                CREATE TABLE IF NOT EXISTS vuln_trends (
                    trend_id          TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    trend_type        TEXT NOT NULL,
                    affected_severity TEXT NOT NULL DEFAULT '',
                    pct_change        REAL NOT NULL DEFAULT 0.0,
                    period_days       INTEGER NOT NULL DEFAULT 7,
                    detected_at       DATETIME NOT NULL,
                    details           TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_trend_org
                    ON vuln_trends (org_id, detected_at DESC);

                CREATE TABLE IF NOT EXISTS sla_tracking (
                    sla_id        TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    vuln_id       TEXT NOT NULL,
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    discovered_at DATETIME NOT NULL,
                    sla_days      INTEGER NOT NULL DEFAULT 90,
                    resolved_at   DATETIME,
                    breached      INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_sla_org
                    ON sla_tracking (org_id, discovered_at DESC);

                CREATE TABLE IF NOT EXISTS vuln_cohorts (
                    cohort_id    TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    cohort_name  TEXT NOT NULL,
                    vuln_ids     TEXT NOT NULL DEFAULT '[]',
                    avg_age_days REAL NOT NULL DEFAULT 0.0,
                    avg_cvss     REAL NOT NULL DEFAULT 0.0,
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cohort_org
                    ON vuln_cohorts (org_id, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def record_snapshot(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and save a daily vulnerability snapshot."""
        snap_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        critical = int(data.get("critical", 0))
        high = int(data.get("high", 0))
        medium = int(data.get("medium", 0))
        low = int(data.get("low", 0))
        info = int(data.get("info", 0))
        total = int(data.get("total_vulns", critical + high + medium + low + info))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vuln_snapshots
                        (snapshot_id, org_id, taken_at, total_vulns, critical, high,
                         medium, low, info, mttr_days, new_this_week,
                         resolved_this_week, sla_breached)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        snap_id,
                        org_id,
                        data.get("taken_at", now),
                        total,
                        critical,
                        high,
                        medium,
                        low,
                        info,
                        float(data.get("mttr_days", 0.0)),
                        int(data.get("new_this_week", 0)),
                        int(data.get("resolved_this_week", 0)),
                        int(data.get("sla_breached", 0)),
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "vuln_trend", "org_id": org_id, "source_engine": "vuln_trend"})
            except Exception:
                pass

        return {"snapshot_id": snap_id, "org_id": org_id, **data, "taken_at": data.get("taken_at", now)}

    def list_snapshots(self, org_id: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Return the most recent N snapshots for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM vuln_snapshots WHERE org_id=? ORDER BY taken_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Trend analysis
    # ------------------------------------------------------------------

    def get_trend_analysis(self, org_id: str) -> Dict[str, Any]:
        """Compare last 2 snapshots, compute pct_change per severity, save trend."""
        snapshots = self.list_snapshots(org_id, limit=2)
        if len(snapshots) < 2:
            return {
                "org_id": org_id,
                "overall_trend": "stable",
                "severities": {},
                "message": "Need at least 2 snapshots for trend analysis",
            }

        current = snapshots[0]
        previous = snapshots[1]

        severity_keys = ["critical", "high", "medium", "low", "info"]
        severity_changes: Dict[str, float] = {}
        for sev in severity_keys:
            prev_val = previous.get(sev, 0) or 0
            curr_val = current.get(sev, 0) or 0
            if prev_val == 0:
                pct = 100.0 if curr_val > 0 else 0.0
            else:
                pct = round(((curr_val - prev_val) / prev_val) * 100.0, 2)
            severity_changes[sev] = pct

        # Overall trend: driven by critical + high
        critical_change = severity_changes.get("critical", 0.0)
        high_change = severity_changes.get("high", 0.0)
        combined = (critical_change + high_change) / 2.0

        if combined > _TREND_THRESHOLD:
            overall_trend = "increasing"
        elif combined < -_TREND_THRESHOLD:
            overall_trend = "decreasing"
        else:
            overall_trend = "stable"

        # Persist trend record
        trend_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        details = json.dumps({"severity_changes": severity_changes, "combined_change": combined})

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vuln_trends
                        (trend_id, org_id, trend_type, affected_severity,
                         pct_change, period_days, detected_at, details)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        trend_id,
                        org_id,
                        overall_trend,
                        "critical,high",
                        round(combined, 2),
                        7,
                        now,
                        details,
                    ),
                )

        return {
            "trend_id": trend_id,
            "org_id": org_id,
            "overall_trend": overall_trend,
            "pct_change": round(combined, 2),
            "severities": severity_changes,
            "detected_at": now,
            "current_snapshot": current.get("snapshot_id"),
            "previous_snapshot": previous.get("snapshot_id"),
        }

    # ------------------------------------------------------------------
    # SLA tracking
    # ------------------------------------------------------------------

    def track_sla(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a vulnerability to SLA tracking."""
        sla_id = str(uuid.uuid4())
        severity = str(data.get("severity", "medium")).lower()
        sla_days = _SLA_DAYS.get(severity, 90)
        now = datetime.now(timezone.utc).isoformat()
        discovered_at = data.get("discovered_at", now)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO sla_tracking
                        (sla_id, org_id, vuln_id, severity, discovered_at, sla_days, resolved_at, breached)
                    VALUES (?,?,?,?,?,?,NULL,0)
                    """,
                    (
                        sla_id,
                        org_id,
                        str(data.get("vuln_id", str(uuid.uuid4()))),
                        severity,
                        discovered_at,
                        sla_days,
                    ),
                )
        return {
            "sla_id": sla_id,
            "org_id": org_id,
            "vuln_id": data.get("vuln_id"),
            "severity": severity,
            "sla_days": sla_days,
            "discovered_at": discovered_at,
            "due_date": (
                datetime.fromisoformat(discovered_at.replace("Z", "+00:00"))
                + timedelta(days=sla_days)
            ).isoformat(),
        }

    def check_sla_breaches(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all SLAs where due date has passed and vuln is unresolved."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM sla_tracking
                WHERE org_id=?
                  AND resolved_at IS NULL
                  AND datetime(discovered_at, '+' || sla_days || ' days') < datetime(?)
                ORDER BY discovered_at ASC
                """,
                (org_id, now),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def resolve_sla(self, org_id: str, sla_id: str) -> bool:
        """Mark an SLA entry as resolved; flag breached if past due."""
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sla_tracking WHERE sla_id=? AND org_id=?",
                (sla_id, org_id),
            ).fetchone()

        if not row:
            return False

        discovered_at = row["discovered_at"]
        sla_days = row["sla_days"]
        try:
            due = datetime.fromisoformat(discovered_at.replace("Z", "+00:00")) + timedelta(days=sla_days)
            breached = 1 if now > due else 0
        except Exception:
            breached = 0

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE sla_tracking SET resolved_at=?, breached=? WHERE sla_id=? AND org_id=?",
                    (now_iso, breached, sla_id, org_id),
                )
        return True

    # ------------------------------------------------------------------
    # Cohorts
    # ------------------------------------------------------------------

    def create_cohort(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a vulnerability cohort grouping."""
        cohort_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        vuln_ids = data.get("vuln_ids", [])

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vuln_cohorts
                        (cohort_id, org_id, cohort_name, vuln_ids, avg_age_days, avg_cvss, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        cohort_id,
                        org_id,
                        str(data.get("cohort_name", "Unnamed Cohort")),
                        json.dumps(vuln_ids),
                        float(data.get("avg_age_days", 0.0)),
                        float(data.get("avg_cvss", 0.0)),
                        now,
                    ),
                )
        return {
            "cohort_id": cohort_id,
            "org_id": org_id,
            "cohort_name": data.get("cohort_name", "Unnamed Cohort"),
            "vuln_ids": vuln_ids,
            "avg_age_days": float(data.get("avg_age_days", 0.0)),
            "avg_cvss": float(data.get("avg_cvss", 0.0)),
            "created_at": now,
        }

    def list_cohorts(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all cohorts for an org with deserialized vuln_ids."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM vuln_cohorts WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        result = []
        for r in rows:
            d = self._row_to_dict(r)
            try:
                d["vuln_ids"] = json.loads(d.get("vuln_ids") or "[]")
            except (json.JSONDecodeError, TypeError):
                d["vuln_ids"] = []
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # GAP-063 Lifecycle-aware trend
    # ------------------------------------------------------------------

    def trend_by_lifecycle(self, org_id: str, days: int = 7) -> Dict[str, Any]:
        """Return rolling `{new, unchanged, resolved}` counts sourced from the
        SecurityFindingsEngine lifecycle columns (GAP-063).

        Falls back to zeros if the findings engine cannot be imported (keeps
        the trend engine standalone-usable).
        """
        try:
            from core.security_findings_engine import SecurityFindingsEngine
        except ImportError:
            return {
                "org_id": org_id,
                "window_days": days,
                "new": 0,
                "unchanged": 0,
                "resolved": 0,
                "source": "unavailable",
            }
        try:
            sfe = SecurityFindingsEngine()
            summary = sfe.lifecycle_summary(org_id=org_id, days=days)
            return {
                "org_id": org_id,
                "window_days": days,
                "new": summary.get("new_last_Nd", 0),
                "unchanged": summary.get("unchanged_last_Nd", 0),
                "resolved": summary.get("resolved_last_Nd", 0),
                "source": "security_findings_engine",
            }
        except Exception as exc:  # pragma: no cover — defensive
            _logger.warning("trend_by_lifecycle fallback due to %s", exc)
            return {
                "org_id": org_id,
                "window_days": days,
                "new": 0,
                "unchanged": 0,
                "resolved": 0,
                "source": "error",
            }

    def get_trend_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate stats for an org."""
        with self._conn() as conn:
            snap_row = conn.execute(
                "SELECT COUNT(*) as cnt, AVG(critical) as avg_crit, AVG(high) as avg_high FROM vuln_snapshots WHERE org_id=?",
                (org_id,),
            ).fetchone()

            sla_row = conn.execute(
                "SELECT COUNT(*) as total, SUM(breached) as total_breached FROM sla_tracking WHERE org_id=?",
                (org_id,),
            ).fetchone()

            active_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM sla_tracking WHERE org_id=? AND resolved_at IS NULL",
                (org_id,),
            ).fetchone()

            cohort_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM vuln_cohorts WHERE org_id=?",
                (org_id,),
            ).fetchone()

            trend_row = conn.execute(
                "SELECT trend_type FROM vuln_trends WHERE org_id=? ORDER BY detected_at DESC LIMIT 1",
                (org_id,),
            ).fetchone()

        total_slas = sla_row["total"] or 0
        total_breached = sla_row["total_breached"] or 0
        breach_rate = round(total_breached / total_slas, 4) if total_slas > 0 else 0.0

        return {
            "org_id": org_id,
            "snapshots_count": snap_row["cnt"] or 0,
            "avg_critical": round(snap_row["avg_crit"] or 0.0, 2),
            "avg_high": round(snap_row["avg_high"] or 0.0, 2),
            "sla_breach_rate": breach_rate,
            "active_slas": active_row["cnt"] or 0,
            "cohorts_count": cohort_row["cnt"] or 0,
            "overall_trend": trend_row["trend_type"] if trend_row else "stable",
        }
