"""Security Service Catalog Engine — ALDECI.

Security service catalog: services offered, SLAs, requests, utilization,
and outage availability tracking.

Supports multi-tenant org isolation, WAL SQLite, threading.RLock.
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_service_catalog.db"
)

_VALID_SERVICE_CATEGORIES = frozenset({
    "vulnerability_management", "incident_response", "access_management",
    "compliance", "threat_intel", "security_training", "pen_testing",
    "forensics", "monitoring", "consulting",
})
_VALID_PRIORITIES = frozenset({"critical", "high", "medium", "low"})
_VALID_OUTAGE_TYPES = frozenset({"planned", "unplanned", "degraded"})
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
_VALID_STATUSES = frozenset({"active", "deprecated", "inactive"})

_MONTH_MINS = 30 * 24 * 60  # 43200 minutes per month baseline


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)


class SecurityServiceCatalogEngine:
    """SQLite WAL-backed Security Service Catalog engine.

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
                CREATE TABLE IF NOT EXISTS catalog_services (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    service_name        TEXT NOT NULL,
                    service_category    TEXT NOT NULL DEFAULT 'monitoring',
                    description         TEXT NOT NULL DEFAULT '',
                    owner_team          TEXT NOT NULL DEFAULT '',
                    sla_response_hours  INTEGER NOT NULL DEFAULT 24,
                    sla_resolution_hours INTEGER NOT NULL DEFAULT 72,
                    cost_center         TEXT NOT NULL DEFAULT '',
                    availability_pct    REAL NOT NULL DEFAULT 99.0,
                    request_count       INTEGER NOT NULL DEFAULT 0,
                    status              TEXT NOT NULL DEFAULT 'active',
                    created_at          TEXT NOT NULL,
                    UNIQUE (org_id, service_name)
                );

                CREATE INDEX IF NOT EXISTS idx_cs_org
                    ON catalog_services (org_id, status);

                CREATE TABLE IF NOT EXISTS service_requests (
                    id              TEXT PRIMARY KEY,
                    service_id      TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    requester       TEXT NOT NULL DEFAULT '',
                    requester_dept  TEXT NOT NULL DEFAULT '',
                    priority        TEXT NOT NULL DEFAULT 'medium',
                    request_details TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'submitted',
                    submitted_at    TEXT NOT NULL DEFAULT '',
                    acknowledged_at TEXT NOT NULL DEFAULT '',
                    resolved_at     TEXT NOT NULL DEFAULT '',
                    response_hrs    REAL NOT NULL DEFAULT 0.0,
                    resolution_hrs  REAL NOT NULL DEFAULT 0.0,
                    sla_met         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sr_org
                    ON service_requests (org_id, service_id, status);

                CREATE TABLE IF NOT EXISTS service_outages (
                    id              TEXT PRIMARY KEY,
                    service_id      TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    outage_type     TEXT NOT NULL DEFAULT 'unplanned',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    started_at      TEXT NOT NULL DEFAULT '',
                    resolved_at     TEXT NOT NULL DEFAULT '',
                    duration_mins   REAL NOT NULL DEFAULT 0.0,
                    affected_users  INTEGER NOT NULL DEFAULT 0,
                    root_cause      TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_so_org
                    ON service_outages (org_id, service_id, started_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for bool_field in ("sla_met",):
            if bool_field in d:
                d[bool_field] = bool(d[bool_field])
        return d

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def register_service(
        self,
        org_id: str,
        service_name: str,
        service_category: str,
        description: str,
        owner_team: str,
        sla_response_hours: int = 24,
        sla_resolution_hours: int = 72,
        cost_center: str = "",
        availability_pct: float = 99.0,
    ) -> Dict[str, Any]:
        """Register a new service. INSERT OR IGNORE on (org_id, service_name)."""
        service_id = str(uuid.uuid4())
        now = _now()

        if service_category not in _VALID_SERVICE_CATEGORIES:
            service_category = "monitoring"

        with self._lock:
            with self._conn() as conn:
                # Check if already exists
                existing = conn.execute(
                    "SELECT id FROM catalog_services WHERE org_id=? AND service_name=?",
                    (org_id, service_name),
                ).fetchone()
                if existing:
                    service_id = existing["id"]
                else:
                    conn.execute(
                        """INSERT OR IGNORE INTO catalog_services
                           (id, org_id, service_name, service_category, description,
                            owner_team, sla_response_hours, sla_resolution_hours,
                            cost_center, availability_pct, request_count, status, created_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            service_id, org_id, service_name, service_category,
                            description, owner_team, sla_response_hours,
                            sla_resolution_hours, cost_center, availability_pct,
                            0, "active", now,
                        ),
                    )
        return self._get_service_row(service_id, org_id)

    def _get_service_row(self, service_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM catalog_services WHERE id=? AND org_id=?",
                    (service_id, org_id),
                ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_service_catalog_engine", "org_id": org_id, "source_engine": "security_service_catalog_engine"})
            except Exception:
                pass
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def submit_request(
        self,
        service_id: str,
        org_id: str,
        requester: str,
        requester_dept: str,
        priority: str,
        request_details: str,
    ) -> Dict[str, Any]:
        """Submit a service request and increment service request_count."""
        if priority not in _VALID_PRIORITIES:
            priority = "medium"
        request_id = str(uuid.uuid4())
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO service_requests
                       (id, service_id, org_id, requester, requester_dept,
                        priority, request_details, status, submitted_at,
                        acknowledged_at, resolved_at, response_hrs, resolution_hrs,
                        sla_met, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        request_id, service_id, org_id, requester, requester_dept,
                        priority, request_details, "submitted", now,
                        "", "", 0.0, 0.0, 1, now,
                    ),
                )
                conn.execute(
                    "UPDATE catalog_services SET request_count = request_count + 1 WHERE id=? AND org_id=?",
                    (service_id, org_id),
                )
        return self._get_request_row(request_id, org_id)

    def _get_request_row(self, request_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM service_requests WHERE id=? AND org_id=?",
                    (request_id, org_id),
                ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_service_catalog_engine", "org_id": org_id, "source_engine": "security_service_catalog_engine"})
            except Exception:
                pass
        return self._row_to_dict(row) if row else None

    def acknowledge_request(self, request_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Acknowledge a request; compute response_hrs from submitted_at."""
        req = self._get_request_row(request_id, org_id)
        if req is None:
            return None
        now = _now()
        submitted_dt = _parse_dt(req["submitted_at"])
        acknowledged_dt = _parse_dt(now)
        response_hrs = (acknowledged_dt - submitted_dt).total_seconds() / 3600.0

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE service_requests
                       SET acknowledged_at=?, response_hrs=?, status='in_progress'
                       WHERE id=? AND org_id=?""",
                    (now, response_hrs, request_id, org_id),
                )
        return self._get_request_row(request_id, org_id)

    def resolve_request(self, request_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Resolve a request; compute resolution_hrs and sla_met flag."""
        req = self._get_request_row(request_id, org_id)
        if req is None:
            return None

        now = _now()
        submitted_dt = _parse_dt(req["submitted_at"])
        resolved_dt = _parse_dt(now)
        resolution_hrs = (resolved_dt - submitted_dt).total_seconds() / 3600.0

        # Look up service SLA
        sla_met = 1
        with self._lock:
            with self._conn() as conn:
                svc_row = conn.execute(
                    "SELECT sla_resolution_hours FROM catalog_services WHERE id=? AND org_id=?",
                    (req["service_id"], org_id),
                ).fetchone()
                if svc_row:
                    sla_met = 1 if resolution_hrs <= svc_row["sla_resolution_hours"] else 0

                conn.execute(
                    """UPDATE service_requests
                       SET resolved_at=?, resolution_hrs=?, status='resolved', sla_met=?
                       WHERE id=? AND org_id=?""",
                    (now, resolution_hrs, sla_met, request_id, org_id),
                )
        return self._get_request_row(request_id, org_id)

    # ------------------------------------------------------------------
    # Outages
    # ------------------------------------------------------------------

    def record_outage(
        self,
        service_id: str,
        org_id: str,
        outage_type: str,
        severity: str,
        started_at: str,
        affected_users: int,
        root_cause: str = "",
    ) -> Dict[str, Any]:
        """Record a new outage. resolved_at is empty initially."""
        if outage_type not in _VALID_OUTAGE_TYPES:
            outage_type = "unplanned"
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        outage_id = str(uuid.uuid4())
        now = _now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO service_outages
                       (id, service_id, org_id, outage_type, severity,
                        started_at, resolved_at, duration_mins, affected_users,
                        root_cause, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        outage_id, service_id, org_id, outage_type, severity,
                        started_at, "", 0.0, affected_users, root_cause, now,
                    ),
                )
        return self._get_outage_row(outage_id, org_id)

    def _get_outage_row(self, outage_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM service_outages WHERE id=? AND org_id=?",
                    (outage_id, org_id),
                ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_service_catalog_engine", "org_id": org_id, "source_engine": "security_service_catalog_engine"})
            except Exception:
                pass
        return self._row_to_dict(row) if row else None

    def resolve_outage(self, outage_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Resolve outage; compute duration and recompute service availability_pct."""
        outage = self._get_outage_row(outage_id, org_id)
        if outage is None:
            return None

        now = _now()
        started_dt = _parse_dt(outage["started_at"])
        resolved_dt = _parse_dt(now)
        duration_mins = (resolved_dt - started_dt).total_seconds() / 60.0

        service_id = outage["service_id"]

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE service_outages SET resolved_at=?, duration_mins=? WHERE id=? AND org_id=?",
                    (now, duration_mins, outage_id, org_id),
                )

                # Recompute availability: current month outage total
                # Use current year-month prefix for "this month"
                current_month_prefix = now[:7]  # e.g. "2026-04"
                total_outage_mins = conn.execute(
                    """SELECT COALESCE(SUM(duration_mins), 0) FROM service_outages
                       WHERE service_id=? AND org_id=?
                         AND resolved_at != ''
                         AND substr(started_at, 1, 7) = ?""",
                    (service_id, org_id, current_month_prefix),
                ).fetchone()[0]

                available_mins = _MONTH_MINS - total_outage_mins
                availability_pct = max(0.0, min(100.0, (available_mins / _MONTH_MINS) * 100.0))

                conn.execute(
                    "UPDATE catalog_services SET availability_pct=? WHERE id=? AND org_id=?",
                    (availability_pct, service_id, org_id),
                )
        return self._get_outage_row(outage_id, org_id)

    # ------------------------------------------------------------------
    # Summaries & Reporting
    # ------------------------------------------------------------------

    def get_service_summary(self, org_id: str) -> Dict[str, Any]:
        """Return catalog-wide statistics."""
        with self._lock:
            with self._conn() as conn:
                total_services = conn.execute(
                    "SELECT COUNT(*) FROM catalog_services WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                active_count = conn.execute(
                    "SELECT COUNT(*) FROM catalog_services WHERE org_id=? AND status='active'",
                    (org_id,),
                ).fetchone()[0]

                open_requests = conn.execute(
                    """SELECT COUNT(*) FROM service_requests
                       WHERE org_id=? AND status NOT IN ('resolved', 'closed')""",
                    (org_id,),
                ).fetchone()[0]

                cat_rows = conn.execute(
                    """SELECT service_category, COUNT(*) as cnt
                       FROM catalog_services WHERE org_id=? GROUP BY service_category""",
                    (org_id,),
                ).fetchall()
                by_category = {r["service_category"]: r["cnt"] for r in cat_rows}

                avg_avail = conn.execute(
                    "SELECT COALESCE(AVG(availability_pct), 100.0) FROM catalog_services WHERE org_id=?",
                    (org_id,),
                ).fetchone()[0]

                resolved = conn.execute(
                    "SELECT COUNT(*), COALESCE(SUM(sla_met), 0) FROM service_requests WHERE org_id=? AND status='resolved'",
                    (org_id,),
                ).fetchone()
                resolved_total = resolved[0]
                sla_met_total = resolved[1]
                sla_compliance_rate = (
                    (sla_met_total / resolved_total * 100.0) if resolved_total > 0 else 100.0
                )

        return {
            "total_services": total_services,
            "active_count": active_count,
            "open_requests": open_requests,
            "by_category": by_category,
            "avg_availability": round(avg_avail, 4),
            "sla_compliance_rate": round(sla_compliance_rate, 2),
        }

    def get_service_detail(self, service_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return service + last 10 requests + last 5 outages."""
        svc = self._get_service_row(service_id, org_id)
        if svc is None:
            return None
        with self._lock:
            with self._conn() as conn:
                req_rows = conn.execute(
                    """SELECT * FROM service_requests WHERE service_id=? AND org_id=?
                       ORDER BY created_at DESC LIMIT 10""",
                    (service_id, org_id),
                ).fetchall()
                out_rows = conn.execute(
                    """SELECT * FROM service_outages WHERE service_id=? AND org_id=?
                       ORDER BY created_at DESC LIMIT 5""",
                    (service_id, org_id),
                ).fetchall()
        svc["recent_requests"] = [self._row_to_dict(r) for r in req_rows]
        svc["recent_outages"] = [self._row_to_dict(r) for r in out_rows]
        return svc

    def get_sla_performance(self, org_id: str) -> List[Dict[str, Any]]:
        """Return per-service SLA performance metrics."""
        with self._lock:
            with self._conn() as conn:
                services = conn.execute(
                    "SELECT id, service_name FROM catalog_services WHERE org_id=?",
                    (org_id,),
                ).fetchall()

                result = []
                for svc in services:
                    sid = svc["id"]
                    row = conn.execute(
                        """SELECT
                             COUNT(*) as request_count,
                             COALESCE(SUM(sla_met), 0) as sla_met_count
                           FROM service_requests
                           WHERE service_id=? AND org_id=? AND status='resolved'""",
                        (sid, org_id),
                    ).fetchone()
                    req_count = row["request_count"]
                    met_count = row["sla_met_count"]
                    breach_count = req_count - met_count
                    compliance_rate = (met_count / req_count * 100.0) if req_count > 0 else 100.0

                    result.append({
                        "service_id": sid,
                        "service_name": svc["service_name"],
                        "request_count": req_count,
                        "sla_met_count": met_count,
                        "sla_breach_count": breach_count,
                        "compliance_rate": round(compliance_rate, 2),
                    })
        return result
