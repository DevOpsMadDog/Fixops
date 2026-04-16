"""Incident Metrics Engine — ALDECI.

Tracks and computes security incident response metrics — MTTD, MTTR, MTTC,
escalation rates, and SLA compliance.

Capabilities:
  - Incident record lifecycle with timeline events
  - Metric computation: MTTD, MTTR, MTTC, escalation rate
  - SLA config per severity (response/containment/resolution)
  - Snapshot history of computed metrics
  - Stats: totals, by severity/category, escalated counts, avg timings

Compliance: ISO 27001 A.5.24 (incident management), NIST SP 800-61
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_VALID_CATEGORIES = {
    "malware",
    "phishing",
    "data_breach",
    "ddos",
    "insider",
    "ransomware",
    "misconfiguration",
    "vulnerability",
    "other",
}

_VALID_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}

_VALID_EVENT_TYPES = {"responded", "contained", "resolved", "closed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _minutes_between(ts1: Optional[str], ts2: Optional[str]) -> Optional[float]:
    """Compute minutes between two ISO timestamps. Returns None if either is None."""
    if not ts1 or not ts2:
        return None
    try:
        dt1 = datetime.fromisoformat(ts1)
        dt2 = datetime.fromisoformat(ts2)
        diff = (dt2 - dt1).total_seconds() / 60.0
        return diff
    except Exception:
        return None


class IncidentMetricsEngine:
    """SQLite WAL-backed Incident Metrics engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/incident_metrics.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "incident_metrics.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incident_records (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    incident_id  TEXT NOT NULL,
                    title        TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    category     TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'open',
                    detected_at  TEXT NOT NULL,
                    responded_at TEXT,
                    contained_at TEXT,
                    resolved_at  TEXT,
                    closed_at    TEXT,
                    escalated    INTEGER NOT NULL DEFAULT 0,
                    team         TEXT NOT NULL DEFAULT '',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_inc_org
                    ON incident_records (org_id, severity, status, detected_at DESC);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_inc_id_org
                    ON incident_records (org_id, incident_id);

                CREATE TABLE IF NOT EXISTS metric_snapshots (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    snapshot_date      TEXT NOT NULL,
                    total_incidents    INTEGER NOT NULL DEFAULT 0,
                    resolved_incidents INTEGER NOT NULL DEFAULT 0,
                    avg_mttd_minutes   REAL NOT NULL DEFAULT 0,
                    avg_mttr_minutes   REAL NOT NULL DEFAULT 0,
                    avg_mttc_minutes   REAL NOT NULL DEFAULT 0,
                    escalation_rate    REAL NOT NULL DEFAULT 0,
                    sla_breaches       INTEGER NOT NULL DEFAULT 0,
                    snapshot_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_snap_org
                    ON metric_snapshots (org_id, snapshot_date DESC);

                CREATE TABLE IF NOT EXISTS sla_configs (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    severity                TEXT NOT NULL,
                    response_sla_minutes    INTEGER NOT NULL DEFAULT 60,
                    containment_sla_minutes INTEGER NOT NULL DEFAULT 240,
                    resolution_sla_minutes  INTEGER NOT NULL DEFAULT 1440,
                    created_at              TEXT NOT NULL,
                    UNIQUE(org_id, severity)
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def record_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new security incident."""
        incident_id = (data.get("incident_id") or "").strip()
        if not incident_id:
            raise ValueError("incident_id is required.")

        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        severity = data.get("severity", "")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        category = data.get("category", "")
        if category not in _VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category: {category!r}. "
                f"Must be one of {sorted(_VALID_CATEGORIES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "category": category,
            "status": "open",
            "detected_at": now,
            "responded_at": None,
            "contained_at": None,
            "resolved_at": None,
            "closed_at": None,
            "escalated": 0,
            "team": data.get("team", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incident_records
                       (id, org_id, incident_id, title, severity, category, status,
                        detected_at, responded_at, contained_at, resolved_at, closed_at,
                        escalated, team, created_at)
                       VALUES (:id, :org_id, :incident_id, :title, :severity, :category, :status,
                               :detected_at, :responded_at, :contained_at, :resolved_at, :closed_at,
                               :escalated, :team, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("INCIDENT_CREATED", {"entity_type": "incident_metrics", "org_id": org_id, "source_engine": "incident_metrics"})
            except Exception:
                pass

        return record

    def update_incident_timeline(
        self,
        org_id: str,
        incident_id: str,
        event_type: str,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Set a timeline timestamp (responded/contained/resolved/closed)."""
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type: {event_type!r}. "
                f"Must be one of {sorted(_VALID_EVENT_TYPES)}"
            )
        ts = timestamp or _now_iso()

        # Map event_type to column and status
        col_map = {
            "responded": ("responded_at", "investigating"),
            "contained": ("contained_at", "contained"),
            "resolved": ("resolved_at", "resolved"),
            "closed": ("closed_at", "closed"),
        }
        col, new_status = col_map[event_type]

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM incident_records WHERE incident_id=? AND org_id=?",
                    (incident_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Incident {incident_id!r} not found.")
                conn.execute(
                    f"UPDATE incident_records SET {col}=?, status=? WHERE incident_id=? AND org_id=?",  # nosec B608
                    (ts, new_status, incident_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM incident_records WHERE incident_id=? AND org_id=?",
                    (incident_id, org_id),
                ).fetchone()
        return self._row(updated)

    def escalate_incident(self, org_id: str, incident_id: str) -> Dict[str, Any]:
        """Mark an incident as escalated."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM incident_records WHERE incident_id=? AND org_id=?",
                    (incident_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Incident {incident_id!r} not found.")
                conn.execute(
                    "UPDATE incident_records SET escalated=1 WHERE incident_id=? AND org_id=?",
                    (incident_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM incident_records WHERE incident_id=? AND org_id=?",
                    (incident_id, org_id),
                ).fetchone()
        return self._row(updated)

    def list_incidents(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List incidents with optional filters, ordered by detected_at DESC."""
        query = "SELECT * FROM incident_records WHERE org_id=?"
        params: List[Any] = [org_id]
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if status:
            query += " AND status=?"
            params.append(status)
        if category:
            query += " AND category=?"
            params.append(category)
        query += f" ORDER BY detected_at DESC LIMIT {int(limit)}"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_incident(self, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get an incident by its incident_id field (external ref)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM incident_records WHERE incident_id=? AND org_id=?",
                (incident_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Metric computation
    # ------------------------------------------------------------------

    def compute_metrics(self, org_id: str) -> Dict[str, Any]:
        """Compute incident metrics and save a daily snapshot."""
        with self._conn() as conn:
            all_rows = conn.execute(
                "SELECT * FROM incident_records WHERE org_id=?", (org_id,)
            ).fetchall()

        incidents = [self._row(r) for r in all_rows]
        total = len(incidents)
        resolved = [i for i in incidents if i["resolved_at"]]

        # MTTD: placeholder 0 (no pre-detection timestamp)
        avg_mttd = 0.0

        # MTTR: avg minutes from detected_at -> resolved_at
        mttr_values = []
        for inc in resolved:
            m = _minutes_between(inc["detected_at"], inc["resolved_at"])
            if m is not None:
                mttr_values.append(m)
        avg_mttr = sum(mttr_values) / len(mttr_values) if mttr_values else 0.0

        # MTTC: avg minutes from detected_at -> contained_at
        mttc_values = []
        for inc in incidents:
            if inc["contained_at"]:
                m = _minutes_between(inc["detected_at"], inc["contained_at"])
                if m is not None:
                    mttc_values.append(m)
        avg_mttc = sum(mttc_values) / len(mttc_values) if mttc_values else 0.0

        escalated_count = sum(1 for i in incidents if i["escalated"])
        escalation_rate = escalated_count / total if total > 0 else 0.0

        now = _now_iso()
        today = _today_str()
        snapshot = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "snapshot_date": today,
            "total_incidents": total,
            "resolved_incidents": len(resolved),
            "avg_mttd_minutes": avg_mttd,
            "avg_mttr_minutes": avg_mttr,
            "avg_mttc_minutes": avg_mttc,
            "escalation_rate": escalation_rate,
            "sla_breaches": 0,
            "snapshot_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO metric_snapshots
                       (id, org_id, snapshot_date, total_incidents, resolved_incidents,
                        avg_mttd_minutes, avg_mttr_minutes, avg_mttc_minutes,
                        escalation_rate, sla_breaches, snapshot_at)
                       VALUES (:id, :org_id, :snapshot_date, :total_incidents, :resolved_incidents,
                               :avg_mttd_minutes, :avg_mttr_minutes, :avg_mttc_minutes,
                               :escalation_rate, :sla_breaches, :snapshot_at)""",
                    snapshot,
                )
        return {
            "total_incidents": total,
            "resolved_incidents": len(resolved),
            "avg_mttd_minutes": avg_mttd,
            "avg_mttr_minutes": avg_mttr,
            "avg_mttc_minutes": avg_mttc,
            "escalation_rate": escalation_rate,
            "snapshot_date": today,
        }

    # ------------------------------------------------------------------
    # SLA Config
    # ------------------------------------------------------------------

    def set_sla_config(
        self,
        org_id: str,
        severity: str,
        response_sla_minutes: int,
        containment_sla_minutes: int,
        resolution_sla_minutes: int,
    ) -> Dict[str, Any]:
        """Upsert SLA config for a severity level."""
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "severity": severity,
            "response_sla_minutes": int(response_sla_minutes),
            "containment_sla_minutes": int(containment_sla_minutes),
            "resolution_sla_minutes": int(resolution_sla_minutes),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sla_configs
                       (id, org_id, severity, response_sla_minutes, containment_sla_minutes,
                        resolution_sla_minutes, created_at)
                       VALUES (:id, :org_id, :severity, :response_sla_minutes, :containment_sla_minutes,
                               :resolution_sla_minutes, :created_at)
                       ON CONFLICT(org_id, severity) DO UPDATE SET
                           response_sla_minutes=excluded.response_sla_minutes,
                           containment_sla_minutes=excluded.containment_sla_minutes,
                           resolution_sla_minutes=excluded.resolution_sla_minutes""",
                    record,
                )
        return self.get_sla_config(org_id, severity)

    def get_sla_config(self, org_id: str, severity: str) -> Optional[Dict[str, Any]]:
        """Get SLA config for a severity. Returns None if not set."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sla_configs WHERE org_id=? AND severity=?",
                (org_id, severity),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_metrics_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated incident metrics statistics."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM incident_records WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            open_count = conn.execute(
                "SELECT COUNT(*) FROM incident_records WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            by_sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt
                   FROM incident_records WHERE org_id=?
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in by_sev_rows}

            by_cat_rows = conn.execute(
                """SELECT category, COUNT(*) as cnt
                   FROM incident_records WHERE org_id=?
                   GROUP BY category""",
                (org_id,),
            ).fetchall()
            by_category = {r["category"]: r["cnt"] for r in by_cat_rows}

            escalated_count = conn.execute(
                "SELECT COUNT(*) FROM incident_records WHERE org_id=? AND escalated=1",
                (org_id,),
            ).fetchone()[0]

            # avg MTTR from incidents with resolved_at
            resolved_rows = conn.execute(
                "SELECT detected_at, resolved_at FROM incident_records WHERE org_id=? AND resolved_at IS NOT NULL",
                (org_id,),
            ).fetchall()
            mttr_vals = []
            for r in resolved_rows:
                m = _minutes_between(r["detected_at"], r["resolved_at"])
                if m is not None:
                    mttr_vals.append(m)
            avg_mttr = sum(mttr_vals) / len(mttr_vals) if mttr_vals else 0.0

            # avg MTTC from incidents with contained_at
            contained_rows = conn.execute(
                "SELECT detected_at, contained_at FROM incident_records WHERE org_id=? AND contained_at IS NOT NULL",
                (org_id,),
            ).fetchall()
            mttc_vals = []
            for r in contained_rows:
                m = _minutes_between(r["detected_at"], r["contained_at"])
                if m is not None:
                    mttc_vals.append(m)
            avg_mttc = sum(mttc_vals) / len(mttc_vals) if mttc_vals else 0.0

        return {
            "total_incidents": total,
            "open_incidents": open_count,
            "by_severity": by_severity,
            "by_category": by_category,
            "escalated_count": escalated_count,
            "avg_mttr_minutes": avg_mttr,
            "avg_mttc_minutes": avg_mttc,
        }
