"""Security Tool Inventory Engine — ALDECI.

Tracks the full inventory of security tools across an organisation:
registration, integration wiring, assessment scoring, and stats.

Compliance: NIST CSF ID.AM, CIS Control 2 (Inventory of Software Assets)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2]
    / ".fixops_data"
    / "security_tool_inventory.db"
)

_VALID_TOOL_CATEGORIES = {
    "siem", "edr", "dlp", "firewall", "waf", "sca", "dast", "sast",
    "iam", "pam", "soar", "threat_intel", "vulnerability_scanner",
    "network_monitor", "other",
}
_VALID_LICENSE_TYPES = {"perpetual", "subscription", "open_source", "trial"}
_VALID_DEPLOYMENT_TYPES = {"cloud", "on_prem", "hybrid", "saas"}
_VALID_TOOL_STATUSES = {"active", "inactive", "deprecated", "evaluating"}
_VALID_INTEGRATION_TYPES = {"api", "syslog", "webhook", "agent", "manual"}
_VALID_INTEGRATION_STATUSES = {"active", "inactive", "broken", "pending"}


class SecurityToolInventoryEngine:
    """SQLite WAL-backed Security Tool Inventory engine.

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
                CREATE TABLE IF NOT EXISTS sti_tools (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    vendor           TEXT NOT NULL DEFAULT '',
                    version          TEXT NOT NULL DEFAULT '',
                    tool_category    TEXT NOT NULL DEFAULT 'other',
                    license_type     TEXT NOT NULL DEFAULT 'subscription',
                    license_expiry   TEXT,
                    status           TEXT NOT NULL DEFAULT 'active',
                    deployment_type  TEXT NOT NULL DEFAULT 'cloud',
                    owner_team       TEXT NOT NULL DEFAULT '',
                    cost_annual      REAL NOT NULL DEFAULT 0,
                    last_assessed    TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sti_integrations (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    tool_id          TEXT NOT NULL,
                    integrated_with  TEXT NOT NULL DEFAULT '',
                    integration_type TEXT NOT NULL DEFAULT 'api',
                    status           TEXT NOT NULL DEFAULT 'pending',
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sti_assessments (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    tool_id             TEXT NOT NULL,
                    assessed_by         TEXT NOT NULL DEFAULT '',
                    coverage_score      REAL NOT NULL DEFAULT 0,
                    effectiveness_score REAL NOT NULL DEFAULT 0,
                    utilization_pct     REAL NOT NULL DEFAULT 0,
                    findings            TEXT NOT NULL DEFAULT '',
                    assessed_at         TEXT NOT NULL,
                    created_at          TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def register_tool(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new security tool."""
        tool_category = data.get("tool_category", "other")
        if tool_category not in _VALID_TOOL_CATEGORIES:
            raise ValueError(
                f"Invalid tool_category '{tool_category}'. "
                f"Valid: {sorted(_VALID_TOOL_CATEGORIES)}"
            )

        license_type = data.get("license_type", "subscription")
        if license_type not in _VALID_LICENSE_TYPES:
            raise ValueError(
                f"Invalid license_type '{license_type}'. "
                f"Valid: {sorted(_VALID_LICENSE_TYPES)}"
            )

        deployment_type = data.get("deployment_type", "cloud")
        if deployment_type not in _VALID_DEPLOYMENT_TYPES:
            raise ValueError(
                f"Invalid deployment_type '{deployment_type}'. "
                f"Valid: {sorted(_VALID_DEPLOYMENT_TYPES)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        tool_id = str(uuid.uuid4())
        row = {
            "id": tool_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "vendor": data.get("vendor", ""),
            "version": data.get("version", ""),
            "tool_category": tool_category,
            "license_type": license_type,
            "license_expiry": data.get("license_expiry"),
            "status": data.get("status", "active"),
            "deployment_type": deployment_type,
            "owner_team": data.get("owner_team", ""),
            "cost_annual": float(data.get("cost_annual", 0)),
            "last_assessed": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO sti_tools
                        (id, org_id, name, vendor, version, tool_category,
                         license_type, license_expiry, status, deployment_type,
                         owner_team, cost_annual, last_assessed, created_at)
                    VALUES
                        (:id, :org_id, :name, :vendor, :version, :tool_category,
                         :license_type, :license_expiry, :status, :deployment_type,
                         :owner_team, :cost_annual, :last_assessed, :created_at)
                    """,
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "security_tool_inventory", "org_id": org_id, "source_engine": "security_tool_inventory"})
            except Exception:
                pass

        return row

    def list_tools(
        self,
        org_id: str,
        tool_category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tools with optional filters."""
        query = "SELECT * FROM sti_tools WHERE org_id = ?"
        params: list = [org_id]
        if tool_category:
            query += " AND tool_category = ?"
            params.append(tool_category)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_tool(self, org_id: str, tool_id: str) -> Optional[Dict[str, Any]]:
        """Get a single tool by ID with org isolation."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM sti_tools WHERE id = ? AND org_id = ?",
                    (tool_id, org_id),
                ).fetchone()
        return dict(row) if row else None

    def update_tool_status(
        self, org_id: str, tool_id: str, status: str
    ) -> Dict[str, Any]:
        """Update a tool's status."""
        if status not in _VALID_TOOL_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Valid: {sorted(_VALID_TOOL_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE sti_tools SET status = ? WHERE id = ? AND org_id = ?",
                    (status, tool_id, org_id),
                )
        return self.get_tool(org_id, tool_id) or {}

    # ------------------------------------------------------------------
    # Integrations
    # ------------------------------------------------------------------

    def add_integration(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an integration between tools."""
        integration_type = data.get("integration_type", "api")
        if integration_type not in _VALID_INTEGRATION_TYPES:
            raise ValueError(
                f"Invalid integration_type '{integration_type}'. "
                f"Valid: {sorted(_VALID_INTEGRATION_TYPES)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        int_id = str(uuid.uuid4())
        row = {
            "id": int_id,
            "org_id": org_id,
            "tool_id": data.get("tool_id", ""),
            "integrated_with": data.get("integrated_with", ""),
            "integration_type": integration_type,
            "status": data.get("status", "pending"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO sti_integrations
                        (id, org_id, tool_id, integrated_with, integration_type,
                         status, created_at)
                    VALUES
                        (:id, :org_id, :tool_id, :integrated_with, :integration_type,
                         :status, :created_at)
                    """,
                    row,
                )
        return row

    def list_integrations(
        self,
        org_id: str,
        tool_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List integrations with optional filters."""
        query = "SELECT * FROM sti_integrations WHERE org_id = ?"
        params: list = [org_id]
        if tool_id:
            query += " AND tool_id = ?"
            params.append(tool_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def record_assessment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a tool assessment with clamped scores."""
        def _clamp(v: Any) -> float:
            return max(0.0, min(100.0, float(v or 0)))

        now = datetime.now(timezone.utc).isoformat()
        assess_id = str(uuid.uuid4())
        tool_id = data.get("tool_id", "")
        row = {
            "id": assess_id,
            "org_id": org_id,
            "tool_id": tool_id,
            "assessed_by": data.get("assessed_by", ""),
            "coverage_score": _clamp(data.get("coverage_score", 0)),
            "effectiveness_score": _clamp(data.get("effectiveness_score", 0)),
            "utilization_pct": _clamp(data.get("utilization_pct", 0)),
            "findings": data.get("findings", ""),
            "assessed_at": data.get("assessed_at", now),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO sti_assessments
                        (id, org_id, tool_id, assessed_by, coverage_score,
                         effectiveness_score, utilization_pct, findings,
                         assessed_at, created_at)
                    VALUES
                        (:id, :org_id, :tool_id, :assessed_by, :coverage_score,
                         :effectiveness_score, :utilization_pct, :findings,
                         :assessed_at, :created_at)
                    """,
                    row,
                )
                # Update tool.last_assessed
                if tool_id:
                    conn.execute(
                        "UPDATE sti_tools SET last_assessed = ? WHERE id = ? AND org_id = ?",
                        (now, tool_id, org_id),
                    )
        return row

    def list_assessments(
        self, org_id: str, tool_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List assessments with optional tool_id filter."""
        query = "SELECT * FROM sti_assessments WHERE org_id = ?"
        params: list = [org_id]
        if tool_id:
            query += " AND tool_id = ?"
            params.append(tool_id)
        query += " ORDER BY assessed_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_inventory_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated inventory statistics for an org."""
        now = datetime.now(timezone.utc)
        threshold_30 = (now + timedelta(days=30)).isoformat()
        now_iso = now.isoformat()

        with self._lock:
            with self._conn() as conn:
                total_tools = conn.execute(
                    "SELECT COUNT(*) FROM sti_tools WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                active_tools = conn.execute(
                    "SELECT COUNT(*) FROM sti_tools WHERE org_id = ? AND status = 'active'",
                    (org_id,),
                ).fetchone()[0]
                total_cost = conn.execute(
                    "SELECT COALESCE(SUM(cost_annual), 0) FROM sti_tools WHERE org_id = ?",
                    (org_id,),
                ).fetchone()[0]
                expiring_30d = conn.execute(
                    """
                    SELECT COUNT(*) FROM sti_tools
                    WHERE org_id = ? AND license_expiry IS NOT NULL
                      AND license_expiry <= ? AND license_expiry > ?
                    """,
                    (org_id, threshold_30, now_iso),
                ).fetchone()[0]
                by_category_rows = conn.execute(
                    """
                    SELECT tool_category, COUNT(*) as cnt
                    FROM sti_tools WHERE org_id = ?
                    GROUP BY tool_category
                    """,
                    (org_id,),
                ).fetchall()
                by_deployment_rows = conn.execute(
                    """
                    SELECT deployment_type, COUNT(*) as cnt
                    FROM sti_tools WHERE org_id = ?
                    GROUP BY deployment_type
                    """,
                    (org_id,),
                ).fetchall()
                avg_row = conn.execute(
                    """
                    SELECT AVG(coverage_score), AVG(effectiveness_score)
                    FROM sti_assessments WHERE org_id = ?
                    """,
                    (org_id,),
                ).fetchone()

        coverage_avg = round(avg_row[0] or 0, 2)
        effectiveness_avg = round(avg_row[1] or 0, 2)

        return {
            "total_tools": total_tools,
            "active_tools": active_tools,
            "total_cost_annual": round(total_cost, 2),
            "tools_expiring_30d": expiring_30d,
            "by_category": {r["tool_category"]: r["cnt"] for r in by_category_rows},
            "by_deployment": {r["deployment_type"]: r["cnt"] for r in by_deployment_rows},
            "coverage_avg": coverage_avg,
            "effectiveness_avg": effectiveness_avg,
        }
