"""Deduplication Service — ALDECI.

Clusters duplicate findings and exposes lifecycle operations:
  - suppress_cluster(cluster_id, reason)
  - accept_risk(cluster_id, justification, approved_by)
  - dismiss_cluster(cluster_id, reason)
  - update_cluster_status(cluster_id, status)

Backed by a SQLite store at data/deduplication.db.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = Path("data/deduplication.db")

_VALID_STATUSES = {"open", "suppressed", "accepted", "dismissed", "resolved"}


class DeduplicationService:
    """SQLite-backed finding cluster deduplication service."""

    def __init__(self, db_path: Path = _DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS clusters (
                    id          TEXT PRIMARY KEY,
                    status      TEXT NOT NULL DEFAULT 'open',
                    reason      TEXT,
                    approved_by TEXT,
                    updated_at  TEXT NOT NULL
                );
            """)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _upsert(self, cluster_id: str, status: str, reason: Optional[str] = None,
                approved_by: Optional[str] = None) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO clusters (id, status, reason, approved_by, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    reason=excluded.reason,
                    approved_by=excluded.approved_by,
                    updated_at=excluded.updated_at
                """,
                (cluster_id, status, reason, approved_by, self._now()),
            )
        _logger.debug("cluster %s -> %s", cluster_id, status)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def suppress_cluster(self, cluster_id: str, reason: str = "") -> Dict[str, Any]:
        """Mark a finding cluster as suppressed (noise/false-positive)."""
        self._upsert(cluster_id, "suppressed", reason=reason)
        return {"cluster_id": cluster_id, "status": "suppressed", "reason": reason}

    def accept_risk(self, cluster_id: str, justification: str = "",
                    approved_by: str = "system") -> Dict[str, Any]:
        """Accept residual risk for a finding cluster."""
        self._upsert(cluster_id, "accepted", reason=justification, approved_by=approved_by)
        return {"cluster_id": cluster_id, "status": "accepted",
                "justification": justification, "approved_by": approved_by}

    def dismiss_cluster(self, cluster_id: str, reason: str = "") -> Dict[str, Any]:
        """Dismiss a cluster as not applicable."""
        self._upsert(cluster_id, "dismissed", reason=reason)
        return {"cluster_id": cluster_id, "status": "dismissed", "reason": reason}

    def update_cluster_status(self, cluster_id: str, status: str) -> Dict[str, Any]:
        """Generic status update for a cluster."""
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Valid: {sorted(_VALID_STATUSES)}")
        self._upsert(cluster_id, status)
        return {"cluster_id": cluster_id, "status": status}

    def get_cluster(self, cluster_id: str) -> Optional[Dict[str, Any]]:
        """Return cluster record or None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM clusters WHERE id = ?", (cluster_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_clusters(self, status: Optional[str] = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        """List clusters, optionally filtered by status."""
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM clusters WHERE status = ? ORDER BY updated_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM clusters ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> Dict[str, Any]:
        """Return aggregate counts by status."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM clusters GROUP BY status"
            ).fetchall()
        by_status = {r["status"]: r["cnt"] for r in rows}
        return {"total": sum(by_status.values()), "by_status": by_status}


_service: Optional[DeduplicationService] = None


def get_dedup_service() -> DeduplicationService:
    """Return the process-level singleton DeduplicationService."""
    global _service
    if _service is None:
        _service = DeduplicationService()
    return _service
