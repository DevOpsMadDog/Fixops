"""Security Health Check Engine — ALDECI.

Tracks health checks across security categories, records snapshots of overall
posture, and manages incident lifecycle.

Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
"""

from __future__ import annotations

import json
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_health.db"
)

_VALID_CATEGORIES = {
    "network", "endpoint", "identity", "cloud", "data", "application", "compliance",
}
_VALID_STATUSES = {"healthy", "degraded", "critical", "unknown"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


class SecurityHealthEngine:
    """SQLite WAL-backed security health check engine.

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
                CREATE TABLE IF NOT EXISTS health_checks (
                    check_id              TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    check_name           TEXT NOT NULL,
                    category             TEXT NOT NULL DEFAULT 'network',
                    status               TEXT NOT NULL DEFAULT 'unknown',
                    score                INTEGER NOT NULL DEFAULT 0,
                    details              TEXT NOT NULL DEFAULT '',
                    last_checked         DATETIME,
                    check_interval_hours INTEGER NOT NULL DEFAULT 24
                );

                CREATE INDEX IF NOT EXISTS idx_hc_org
                    ON health_checks (org_id);

                CREATE TABLE IF NOT EXISTS health_incidents (
                    incident_id  TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    check_id     TEXT NOT NULL,
                    title        TEXT NOT NULL,
                    description  TEXT NOT NULL DEFAULT '',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    detected_at  DATETIME NOT NULL,
                    resolved_at  DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_hi_org
                    ON health_incidents (org_id, detected_at DESC);

                CREATE TABLE IF NOT EXISTS health_snapshots (
                    snapshot_id     TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    taken_at        DATETIME NOT NULL,
                    overall_score   INTEGER NOT NULL DEFAULT 0,
                    by_category     TEXT NOT NULL DEFAULT '{}',
                    healthy_count   INTEGER NOT NULL DEFAULT 0,
                    degraded_count  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_hs_org
                    ON health_snapshots (org_id, taken_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    def register_check(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new health check. Returns the created record."""
        check_name = data.get("check_name", "")
        if not check_name:
            raise ValueError("check_name is required.")

        category = data.get("category", "network")
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid category: {category}. Must be one of {_VALID_CATEGORIES}")

        status = data.get("status", "unknown")
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        check_id = str(uuid.uuid4())
        score = max(0, min(100, int(data.get("score", 0))))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO health_checks
                        (check_id, org_id, check_name, category, status, score,
                         details, last_checked, check_interval_hours)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        check_id, org_id, check_name, category, status, score,
                        data.get("details", ""),
                        data.get("last_checked"),
                        int(data.get("check_interval_hours", 24)),
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_health", "org_id": org_id, "source_engine": "security_health"})
            except Exception:
                pass

        return {
            "check_id": check_id,
            "org_id": org_id,
            "check_name": check_name,
            "category": category,
            "status": status,
            "score": score,
            "details": data.get("details", ""),
            "last_checked": data.get("last_checked"),
            "check_interval_hours": int(data.get("check_interval_hours", 24)),
        }

    def update_check_status(
        self,
        org_id: str,
        check_id: str,
        status: str,
        score: int,
        details: str = "",
    ) -> bool:
        """Update the status, score, and details of an existing check.

        Also updates last_checked to now. Returns True on success.
        """
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        score = max(0, min(100, int(score)))
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE health_checks
                    SET status=?, score=?, details=?, last_checked=?
                    WHERE org_id=? AND check_id=?
                    """,
                    (status, score, details, now, org_id, check_id),
                )
        return cur.rowcount > 0

    def list_checks(
        self,
        org_id: str,
        category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List health checks with optional category/status filters."""
        query = "SELECT * FROM health_checks WHERE org_id=?"
        params: list = [org_id]
        if category:
            query += " AND category=?"
            params.append(category)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY check_name"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def run_health_snapshot(self, org_id: str) -> Dict[str, Any]:
        """Calculate current health scores, save a snapshot, and return it."""
        checks = self.list_checks(org_id)

        overall_scores: List[int] = []
        by_category: Dict[str, List[int]] = {}
        healthy_count = degraded_count = critical_count = 0

        for check in checks:
            score = int(check.get("score", 0))
            status = check.get("status", "unknown")
            cat = check.get("category", "network")

            overall_scores.append(score)
            by_category.setdefault(cat, []).append(score)

            if status == "healthy":
                healthy_count += 1
            elif status == "degraded":
                degraded_count += 1
            elif status == "critical":
                critical_count += 1

        overall_score = (
            int(sum(overall_scores) / len(overall_scores)) if overall_scores else 0
        )
        by_category_avg: Dict[str, int] = {
            cat: int(sum(scores) / len(scores))
            for cat, scores in by_category.items()
        }

        snapshot_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO health_snapshots
                        (snapshot_id, org_id, taken_at, overall_score, by_category,
                         healthy_count, degraded_count, critical_count)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        snapshot_id, org_id, now, overall_score,
                        json.dumps(by_category_avg),
                        healthy_count, degraded_count, critical_count,
                    ),
                )
        return {
            "snapshot_id": snapshot_id,
            "org_id": org_id,
            "taken_at": now,
            "overall_score": overall_score,
            "by_category": by_category_avg,
            "healthy_count": healthy_count,
            "degraded_count": degraded_count,
            "critical_count": critical_count,
        }

    def get_latest_snapshot(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Return the most recent health snapshot for an org."""
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM health_snapshots
                WHERE org_id=? ORDER BY taken_at DESC LIMIT 1
                """,
                (org_id,),
            ).fetchone()
        if not row:
            return None
        d = self._row(row)
        d["by_category"] = json.loads(d.get("by_category") or "{}")
        return d

    def list_snapshots(self, org_id: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Return the last N health snapshots for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM health_snapshots
                WHERE org_id=? ORDER BY taken_at DESC LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        result = []
        for r in rows:
            d = self._row(r)
            d["by_category"] = json.loads(d.get("by_category") or "{}")
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def log_incident(
        self, org_id: str, check_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Log a health incident linked to a check."""
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO health_incidents
                        (incident_id, org_id, check_id, title, description,
                         severity, detected_at, resolved_at)
                    VALUES (?,?,?,?,?,?,?,NULL)
                    """,
                    (
                        incident_id, org_id, check_id,
                        data.get("title", ""),
                        data.get("description", ""),
                        severity, now,
                    ),
                )
        return {
            "incident_id": incident_id,
            "org_id": org_id,
            "check_id": check_id,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "severity": severity,
            "detected_at": now,
            "resolved_at": None,
        }

    def resolve_incident(self, org_id: str, incident_id: str) -> bool:
        """Mark an incident as resolved. Returns True if found and updated."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE health_incidents
                    SET resolved_at=?
                    WHERE org_id=? AND incident_id=? AND resolved_at IS NULL
                    """,
                    (now, org_id, incident_id),
                )
        return cur.rowcount > 0

    def list_incidents(
        self, org_id: str, resolved: bool = False
    ) -> List[Dict[str, Any]]:
        """List incidents for an org. By default returns only open (unresolved)."""
        if resolved:
            query = """
                SELECT * FROM health_incidents
                WHERE org_id=? AND resolved_at IS NOT NULL
                ORDER BY detected_at DESC
            """
        else:
            query = """
                SELECT * FROM health_incidents
                WHERE org_id=? AND resolved_at IS NULL
                ORDER BY detected_at DESC
            """
        with self._conn() as conn:
            rows = conn.execute(query, (org_id,)).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_health_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate health statistics for an org."""
        checks = self.list_checks(org_id)
        total_checks = len(checks)

        by_status: Dict[str, int] = {
            "healthy": 0, "degraded": 0, "critical": 0, "unknown": 0,
        }
        by_category_scores: Dict[str, List[int]] = {}

        for check in checks:
            status = check.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            cat = check.get("category", "network")
            by_category_scores.setdefault(cat, []).append(int(check.get("score", 0)))

        by_category: Dict[str, int] = {
            cat: int(sum(scores) / len(scores))
            for cat, scores in by_category_scores.items()
        }

        all_scores = [int(c.get("score", 0)) for c in checks]
        overall_score = (
            int(sum(all_scores) / len(all_scores)) if all_scores else 0
        )

        # Incident counts
        open_incidents = self.list_incidents(org_id, resolved=False)
        critical_incidents = [
            i for i in open_incidents if i.get("severity") == "critical"
        ]

        return {
            "total_checks": total_checks,
            "by_status": by_status,
            "by_category": by_category,
            "overall_score": overall_score,
            "open_incidents": len(open_incidents),
            "critical_incidents": len(critical_incidents),
        }
