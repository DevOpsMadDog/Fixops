"""
API Analytics — SQLite-backed call tracking and statistics.

Records every API call with endpoint, method, status code, response time,
api_key_id, org_id, and timestamp. Provides aggregated stats endpoints for
monitoring, capacity planning, and SLA reporting.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class APICall(BaseModel):
    """Record of a single API call."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint: str
    method: str
    status_code: int
    response_ms: float
    api_key_id: Optional[str] = None
    org_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Analytics class
# ---------------------------------------------------------------------------


class APIAnalytics:
    """SQLite-backed API call analytics."""

    def __init__(self, db_path: str = "data/api_analytics.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_calls (
                    id          TEXT PRIMARY KEY,
                    endpoint    TEXT NOT NULL,
                    method      TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_ms REAL NOT NULL,
                    api_key_id  TEXT,
                    org_id      TEXT,
                    timestamp   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ac_endpoint   ON api_calls(endpoint);
                CREATE INDEX IF NOT EXISTS idx_ac_timestamp  ON api_calls(timestamp);
                CREATE INDEX IF NOT EXISTS idx_ac_status     ON api_calls(status_code);
                CREATE INDEX IF NOT EXISTS idx_ac_org        ON api_calls(org_id);
                CREATE INDEX IF NOT EXISTS idx_ac_apikey     ON api_calls(api_key_id);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record_call(self, call: APICall) -> APICall:
        """Persist an API call record."""
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO api_calls VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    call.id,
                    call.endpoint,
                    call.method,
                    call.status_code,
                    call.response_ms,
                    call.api_key_id,
                    call.org_id,
                    call.timestamp.isoformat(),
                ),
            )
            conn.commit()
            return call
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Read — aggregated stats
    # ------------------------------------------------------------------

    def get_endpoint_stats(
        self,
        endpoint: str,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return call count, avg/p95 response time, error rate for one endpoint."""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM api_calls WHERE endpoint = ?"
            params: List[Any] = [endpoint]
            if org_id:
                query += " AND org_id = ?"
                params.append(org_id)

            rows = conn.execute(query, params).fetchall()
            if not rows:
                return {
                    "endpoint": endpoint,
                    "total_calls": 0,
                    "avg_response_ms": 0.0,
                    "p95_response_ms": 0.0,
                    "error_rate": 0.0,
                }

            times = sorted(r["response_ms"] for r in rows)
            errors = sum(1 for r in rows if r["status_code"] >= 400)
            p95_idx = max(0, int(len(times) * 0.95) - 1)

            return {
                "endpoint": endpoint,
                "total_calls": len(rows),
                "avg_response_ms": round(sum(times) / len(times), 2),
                "p95_response_ms": round(times[p95_idx], 2),
                "error_rate": round(errors / len(rows), 4),
            }
        finally:
            conn.close()

    def get_top_endpoints(
        self,
        limit: int = 10,
        org_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return endpoints ranked by total call count."""
        conn = self._get_connection()
        try:
            query = "SELECT endpoint, COUNT(*) AS total FROM api_calls"
            params: List[Any] = []
            if org_id:
                query += " WHERE org_id = ?"
                params.append(org_id)
            query += " GROUP BY endpoint ORDER BY total DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [{"endpoint": r["endpoint"], "total_calls": r["total"]} for r in rows]
        finally:
            conn.close()

    def get_slowest_endpoints(
        self,
        limit: int = 10,
        org_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return endpoints ranked by average response time (slowest first)."""
        conn = self._get_connection()
        try:
            query = (
                "SELECT endpoint, AVG(response_ms) AS avg_ms, COUNT(*) AS total "
                "FROM api_calls"
            )
            params: List[Any] = []
            if org_id:
                query += " WHERE org_id = ?"
                params.append(org_id)
            query += " GROUP BY endpoint ORDER BY avg_ms DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [
                {
                    "endpoint": r["endpoint"],
                    "avg_response_ms": round(r["avg_ms"], 2),
                    "total_calls": r["total"],
                }
                for r in rows
            ]
        finally:
            conn.close()

    def get_error_endpoints(
        self,
        limit: int = 10,
        org_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return endpoints with highest error rates (status >= 400)."""
        conn = self._get_connection()
        try:
            query = (
                "SELECT endpoint, "
                "  COUNT(*) AS total, "
                "  SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors "
                "FROM api_calls"
            )
            params: List[Any] = []
            if org_id:
                query += " WHERE org_id = ?"
                params.append(org_id)
            query += (
                " GROUP BY endpoint"
                " HAVING errors > 0"
                " ORDER BY CAST(errors AS REAL) / total DESC"
                " LIMIT ?"
            )
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [
                {
                    "endpoint": r["endpoint"],
                    "total_calls": r["total"],
                    "error_calls": r["errors"],
                    "error_rate": round(r["errors"] / r["total"], 4),
                }
                for r in rows
            ]
        finally:
            conn.close()

    def get_usage_over_time(
        self,
        bucket: str = "hour",
        days: int = 7,
        org_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return call counts bucketed by hour or day over the last N days."""
        conn = self._get_connection()
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

            if bucket == "day":
                trunc = "substr(timestamp, 1, 10)"
            else:
                trunc = "substr(timestamp, 1, 13)"  # YYYY-MM-DDTHH

            query = (
                f"SELECT {trunc} AS bucket, COUNT(*) AS total "  # nosec B608
                "FROM api_calls WHERE timestamp >= ?"
            )
            params: List[Any] = [since]
            if org_id:
                query += " AND org_id = ?"
                params.append(org_id)
            query += f" GROUP BY {trunc} ORDER BY bucket ASC"

            rows = conn.execute(query, params).fetchall()
            return [{"bucket": r["bucket"], "total_calls": r["total"]} for r in rows]
        finally:
            conn.close()

    def get_api_key_usage(
        self,
        api_key_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Return per-key call counts and avg response time."""
        conn = self._get_connection()
        try:
            query = (
                "SELECT api_key_id, COUNT(*) AS total, AVG(response_ms) AS avg_ms "
                "FROM api_calls WHERE api_key_id IS NOT NULL"
            )
            params: List[Any] = []
            if api_key_id:
                query += " AND api_key_id = ?"
                params.append(api_key_id)
            query += " GROUP BY api_key_id ORDER BY total DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [
                {
                    "api_key_id": r["api_key_id"],
                    "total_calls": r["total"],
                    "avg_response_ms": round(r["avg_ms"], 2),
                }
                for r in rows
            ]
        finally:
            conn.close()

    def get_status_code_distribution(
        self,
        org_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return call counts grouped by HTTP status code."""
        conn = self._get_connection()
        try:
            query = (
                "SELECT status_code, COUNT(*) AS total FROM api_calls"
            )
            params: List[Any] = []
            if org_id:
                query += " WHERE org_id = ?"
                params.append(org_id)
            query += " GROUP BY status_code ORDER BY status_code ASC"

            rows = conn.execute(query, params).fetchall()
            return [{"status_code": r["status_code"], "total_calls": r["total"]} for r in rows]
        finally:
            conn.close()

    def cleanup_old(self, days: int = 90) -> int:
        """Delete records older than N days. Returns number of rows deleted."""
        conn = self._get_connection()
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            cursor = conn.execute(
                "DELETE FROM api_calls WHERE timestamp < ?", (cutoff,)
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()
