"""Security Roadmap / Strategic Planning Engine — ALDECI.

Tracks multi-year security initiatives, milestones, capability gaps, and
success metrics.  Multi-tenant via org_id.  Thread-safe via RLock.
SQLite WAL journal for concurrent access.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_roadmap.db"
)

_VALID_CATEGORIES = {"people", "process", "technology", "compliance"}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"planned", "in_progress", "completed", "deferred", "cancelled"}
_VALID_MILESTONE_STATUSES = {"pending", "in_progress", "completed", "overdue"}
_VALID_GAP_TYPES = {"capability", "compliance", "technology", "people"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


class SecurityRoadmapEngine:
    """SQLite WAL-backed security roadmap / strategic planning engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS roadmap_initiatives (
                    initiative_id    TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    title            TEXT NOT NULL,
                    description      TEXT NOT NULL DEFAULT '',
                    category         TEXT NOT NULL DEFAULT 'technology',
                    priority         TEXT NOT NULL DEFAULT 'medium',
                    status           TEXT NOT NULL DEFAULT 'planned',
                    owner            TEXT NOT NULL DEFAULT '',
                    budget_usd       REAL NOT NULL DEFAULT 0.0,
                    start_date       TEXT NOT NULL DEFAULT '',
                    target_date      TEXT NOT NULL DEFAULT '',
                    completion_date  TEXT NOT NULL DEFAULT '',
                    risk_reduction_score REAL NOT NULL DEFAULT 0.0,
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ri_org
                    ON roadmap_initiatives (org_id, status, category);

                CREATE TABLE IF NOT EXISTS initiative_milestones (
                    milestone_id     TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    initiative_id    TEXT NOT NULL
                        REFERENCES roadmap_initiatives(initiative_id) ON DELETE CASCADE,
                    title            TEXT NOT NULL,
                    description      TEXT NOT NULL DEFAULT '',
                    due_date         TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'pending',
                    completion_date  TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ms_org
                    ON initiative_milestones (org_id, initiative_id);

                CREATE TABLE IF NOT EXISTS roadmap_gaps (
                    gap_id           TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    title            TEXT NOT NULL,
                    description      TEXT NOT NULL DEFAULT '',
                    gap_type         TEXT NOT NULL DEFAULT 'capability',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    linked_initiative_id TEXT NOT NULL DEFAULT '',
                    identified_at    DATETIME NOT NULL,
                    resolved_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_gap_org
                    ON roadmap_gaps (org_id, severity);

                CREATE TABLE IF NOT EXISTS roadmap_metrics (
                    metric_id        TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    initiative_id    TEXT NOT NULL,
                    metric_name      TEXT NOT NULL,
                    target_value     REAL NOT NULL DEFAULT 0.0,
                    current_value    REAL NOT NULL DEFAULT 0.0,
                    unit             TEXT NOT NULL DEFAULT '',
                    measured_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_metric_org
                    ON roadmap_metrics (org_id, initiative_id);
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
    # Initiatives
    # ------------------------------------------------------------------

    def create_initiative(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security initiative. Returns the full record."""
        initiative_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        category = data.get("category", "technology")
        if category not in _VALID_CATEGORIES:
            category = "technology"
        priority = data.get("priority", "medium")
        if priority not in _VALID_PRIORITIES:
            priority = "medium"
        status = data.get("status", "planned")
        if status not in _VALID_STATUSES:
            status = "planned"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO roadmap_initiatives
                        (initiative_id, org_id, title, description, category,
                         priority, status, owner, budget_usd, start_date,
                         target_date, completion_date, risk_reduction_score, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        initiative_id,
                        org_id,
                        data.get("title", "Untitled Initiative"),
                        data.get("description", ""),
                        category,
                        priority,
                        status,
                        data.get("owner", ""),
                        float(data.get("budget_usd", 0.0)),
                        data.get("start_date", ""),
                        data.get("target_date", ""),
                        data.get("completion_date", ""),
                        float(data.get("risk_reduction_score", 0.0)),
                        now,
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_roadmap", "org_id": org_id, "source_engine": "security_roadmap"})
            except Exception:
                pass

        return self.get_initiative(org_id, initiative_id) or {}

    def list_initiatives(
        self,
        org_id: str,
        status: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List initiatives for an org, with optional status/category filter."""
        query = "SELECT * FROM roadmap_initiatives WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if category:
            query += " AND category=?"
            params.append(category)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_initiative(
        self, org_id: str, initiative_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return a single initiative or None if not found / wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM roadmap_initiatives WHERE initiative_id=? AND org_id=?",
                (initiative_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_initiative(
        self, org_id: str, initiative_id: str, data: Dict[str, Any]
    ) -> bool:
        """Update allowed fields: status, owner, budget_usd, target_date.
        Returns True if a row was updated."""
        allowed = {"status", "owner", "budget_usd", "target_date"}
        updates = {k: v for k, v in data.items() if k in allowed}
        if not updates:
            return False

        # Validate status if provided
        if "status" in updates and updates["status"] not in _VALID_STATUSES:
            return False

        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [initiative_id, org_id]

        with self._lock:
            with self._conn() as conn:
                cursor = conn.execute(
                    f"UPDATE roadmap_initiatives SET {set_clause} "  # nosec B608
                    f"WHERE initiative_id=? AND org_id=?",
                    values,
                )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Milestones
    # ------------------------------------------------------------------

    def add_milestone(
        self, org_id: str, initiative_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a milestone to an initiative. Returns the full record."""
        milestone_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        status = data.get("status", "pending")
        if status not in _VALID_MILESTONE_STATUSES:
            status = "pending"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO initiative_milestones
                        (milestone_id, org_id, initiative_id, title, description,
                         due_date, status, completion_date, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        milestone_id,
                        org_id,
                        initiative_id,
                        data.get("title", "Untitled Milestone"),
                        data.get("description", ""),
                        data.get("due_date", ""),
                        status,
                        data.get("completion_date", ""),
                        now,
                    ),
                )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM initiative_milestones WHERE milestone_id=? AND org_id=?",
                (milestone_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else {}

    def list_milestones(
        self, org_id: str, initiative_id: str
    ) -> List[Dict[str, Any]]:
        """List all milestones for an initiative."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM initiative_milestones
                WHERE org_id=? AND initiative_id=?
                ORDER BY due_date ASC, created_at ASC
                """,
                (org_id, initiative_id),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def complete_milestone(self, org_id: str, milestone_id: str) -> bool:
        """Mark a milestone as completed. Returns True on success."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE initiative_milestones
                    SET status='completed', completion_date=?
                    WHERE milestone_id=? AND org_id=?
                    """,
                    (now, milestone_id, org_id),
                )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Gaps
    # ------------------------------------------------------------------

    def add_gap(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a capability / compliance / technology / people gap."""
        gap_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        gap_type = data.get("gap_type", "capability")
        if gap_type not in _VALID_GAP_TYPES:
            gap_type = "capability"
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO roadmap_gaps
                        (gap_id, org_id, title, description, gap_type, severity,
                         linked_initiative_id, identified_at, resolved_at)
                    VALUES (?,?,?,?,?,?,?,?,NULL)
                    """,
                    (
                        gap_id,
                        org_id,
                        data.get("title", "Untitled Gap"),
                        data.get("description", ""),
                        gap_type,
                        severity,
                        data.get("linked_initiative_id", ""),
                        now,
                    ),
                )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM roadmap_gaps WHERE gap_id=? AND org_id=?",
                (gap_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else {}

    def list_gaps(
        self,
        org_id: str,
        severity: Optional[str] = None,
        resolved: bool = False,
    ) -> List[Dict[str, Any]]:
        """List gaps. resolved=True returns only resolved gaps; False (default) returns unresolved."""
        query = "SELECT * FROM roadmap_gaps WHERE org_id=?"
        params: List[Any] = [org_id]
        if resolved:
            query += " AND resolved_at IS NOT NULL"
        else:
            query += " AND resolved_at IS NULL"
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY identified_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def link_gap_to_initiative(
        self, org_id: str, gap_id: str, initiative_id: str
    ) -> bool:
        """Link a gap to an initiative. Returns True on success."""
        with self._lock:
            with self._conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE roadmap_gaps
                    SET linked_initiative_id=?
                    WHERE gap_id=? AND org_id=?
                    """,
                    (initiative_id, gap_id, org_id),
                )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def add_metric(
        self, org_id: str, initiative_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a success metric to an initiative."""
        metric_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO roadmap_metrics
                        (metric_id, org_id, initiative_id, metric_name,
                         target_value, current_value, unit, measured_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        metric_id,
                        org_id,
                        initiative_id,
                        data.get("metric_name", ""),
                        float(data.get("target_value", 0.0)),
                        float(data.get("current_value", 0.0)),
                        data.get("unit", ""),
                        now,
                    ),
                )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM roadmap_metrics WHERE metric_id=? AND org_id=?",
                (metric_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else {}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_roadmap_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate stats for the org's security roadmap."""
        today = date.today().isoformat()

        with self._conn() as conn:
            # Total initiatives
            total_initiatives = conn.execute(
                "SELECT COUNT(*) FROM roadmap_initiatives WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            # By status
            status_rows = conn.execute(
                """
                SELECT status, COUNT(*) as cnt
                FROM roadmap_initiatives WHERE org_id=?
                GROUP BY status
                """,
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            # By category
            cat_rows = conn.execute(
                """
                SELECT category, COUNT(*) as cnt
                FROM roadmap_initiatives WHERE org_id=?
                GROUP BY category
                """,
                (org_id,),
            ).fetchall()
            by_category = {r["category"]: r["cnt"] for r in cat_rows}

            # Gaps
            total_gaps = conn.execute(
                "SELECT COUNT(*) FROM roadmap_gaps WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            unresolved_gaps = conn.execute(
                "SELECT COUNT(*) FROM roadmap_gaps WHERE org_id=? AND resolved_at IS NULL",
                (org_id,),
            ).fetchone()[0]

            # Total budget
            budget_row = conn.execute(
                "SELECT COALESCE(SUM(budget_usd), 0.0) FROM roadmap_initiatives WHERE org_id=?",
                (org_id,),
            ).fetchone()
            total_budget = float(budget_row[0])

            # On-track: in_progress AND target_date >= today
            on_track = conn.execute(
                """
                SELECT COUNT(*) FROM roadmap_initiatives
                WHERE org_id=? AND status='in_progress'
                  AND target_date != '' AND target_date >= ?
                """,
                (org_id, today),
            ).fetchone()[0]

            # Overdue milestones: not completed, due_date < today
            overdue_ms = conn.execute(
                """
                SELECT COUNT(*) FROM initiative_milestones
                WHERE org_id=? AND status != 'completed'
                  AND due_date != '' AND due_date < ?
                """,
                (org_id, today),
            ).fetchone()[0]

        return {
            "total_initiatives": total_initiatives,
            "by_status": by_status,
            "by_category": by_category,
            "total_gaps": total_gaps,
            "unresolved_gaps": unresolved_gaps,
            "total_budget": total_budget,
            "initiatives_on_track": on_track,
            "overdue_milestones": overdue_ms,
        }
