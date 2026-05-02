"""Integration health monitoring module for ALDECI.

Tracks health status, uptime, and failure alerts for all registered
integrations. SQLite-backed with automatic disable after consecutive failures.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums and Pydantic models
# ---------------------------------------------------------------------------


class ServiceStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"
    DISABLED = "disabled"


class IntegrationInfo(BaseModel):
    id: str
    name: str
    type: str
    endpoint_url: str
    status: ServiceStatus = ServiceStatus.UNKNOWN
    last_check: Optional[str] = None
    last_success: Optional[str] = None
    response_ms: Optional[float] = None
    error_message: Optional[str] = None
    uptime_pct: float = 100.0
    consecutive_failures: int = 0
    auto_disabled: bool = False
    org_id: str


class HealthCheckResult(BaseModel):
    integration_id: str
    status: ServiceStatus
    response_ms: float
    error: Optional[str] = None
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Auto-disable threshold
# ---------------------------------------------------------------------------

_MAX_CONSECUTIVE_FAILURES = 5


# ---------------------------------------------------------------------------
# Monitor class
# ---------------------------------------------------------------------------


class IntegrationHealthMonitor:
    """SQLite-backed integration health monitor."""

    def __init__(self, db_path: str = "data/integration_health.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS integrations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    endpoint_url TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'unknown',
                    last_check TEXT,
                    last_success TEXT,
                    response_ms REAL,
                    error_message TEXT,
                    uptime_pct REAL NOT NULL DEFAULT 100.0,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    auto_disabled INTEGER NOT NULL DEFAULT 0,
                    org_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS health_checks (
                    id TEXT PRIMARY KEY,
                    integration_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    response_ms REAL NOT NULL,
                    error TEXT,
                    checked_at TEXT NOT NULL,
                    FOREIGN KEY (integration_id) REFERENCES integrations(id)
                );

                CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations(org_id);
                CREATE INDEX IF NOT EXISTS idx_integrations_status ON integrations(status);
                CREATE INDEX IF NOT EXISTS idx_checks_integration ON health_checks(integration_id);
                CREATE INDEX IF NOT EXISTS idx_checks_checked_at ON health_checks(checked_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _row_to_info(self, row: sqlite3.Row) -> IntegrationInfo:
        return IntegrationInfo(
            id=row["id"],
            name=row["name"],
            type=row["type"],
            endpoint_url=row["endpoint_url"],
            status=ServiceStatus(row["status"]),
            last_check=row["last_check"],
            last_success=row["last_success"],
            response_ms=row["response_ms"],
            error_message=row["error_message"],
            uptime_pct=row["uptime_pct"],
            consecutive_failures=row["consecutive_failures"],
            auto_disabled=bool(row["auto_disabled"]),
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register_integration(
        self,
        name: str,
        type: str,
        endpoint_url: str,
        org_id: str,
    ) -> IntegrationInfo:
        """Register a new integration and return its info."""
        integration_id = str(uuid.uuid4())
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO integrations
                    (id, name, type, endpoint_url, org_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (integration_id, name, type, endpoint_url, org_id),
            )
            conn.commit()
        finally:
            conn.close()
        return self.get_integration(integration_id)

    def list_integrations(
        self,
        org_id: str,
        status_filter: Optional[str] = None,
    ) -> List[IntegrationInfo]:
        """List integrations for an org, optionally filtered by status."""
        conn = self._conn()
        try:
            if status_filter:
                rows = conn.execute(
                    "SELECT * FROM integrations WHERE org_id = ? AND status = ? ORDER BY name",
                    (org_id, status_filter),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM integrations WHERE org_id = ? ORDER BY name",
                    (org_id,),
                ).fetchall()
            return [self._row_to_info(r) for r in rows]
        finally:
            conn.close()

    def get_integration(self, integration_id: str) -> IntegrationInfo:
        """Return a single integration by ID or raise ValueError."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM integrations WHERE id = ?",
                (integration_id,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise ValueError(f"Integration not found: {integration_id}")
        return self._row_to_info(row)

    def delete_integration(self, integration_id: str) -> None:
        """Delete integration and its check history."""
        conn = self._conn()
        try:
            conn.execute(
                "DELETE FROM health_checks WHERE integration_id = ?",
                (integration_id,),
            )
            conn.execute(
                "DELETE FROM integrations WHERE id = ?",
                (integration_id,),
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    def check_health(self, integration_id: str) -> HealthCheckResult:
        """Simulate a health check for the integration and record the result."""
        info = self.get_integration(integration_id)

        if info.auto_disabled or info.status == ServiceStatus.DISABLED:
            result = HealthCheckResult(
                integration_id=integration_id,
                status=ServiceStatus.DISABLED,
                response_ms=0.0,
                error="Integration is disabled",
            )
            return result

        # Simulate latency and outcome based on endpoint reachability heuristic.
        time.monotonic()
        response_ms, status, error = _simulate_check(info.endpoint_url)

        result = HealthCheckResult(
            integration_id=integration_id,
            status=status,
            response_ms=response_ms,
            error=error,
        )
        self.record_check(integration_id, status, response_ms, error)
        return result

    def check_all(self, org_id: str) -> List[HealthCheckResult]:
        """Run health checks for all non-disabled integrations in the org."""
        integrations = self.list_integrations(org_id)
        results: List[HealthCheckResult] = []
        for info in integrations:
            if info.auto_disabled:
                results.append(
                    HealthCheckResult(
                        integration_id=info.id,
                        status=ServiceStatus.DISABLED,
                        response_ms=0.0,
                        error="Integration is auto-disabled",
                    )
                )
            else:
                results.append(self.check_health(info.id))
        return results

    def record_check(
        self,
        integration_id: str,
        status: ServiceStatus,
        response_ms: float,
        error: Optional[str],
    ) -> None:
        """Persist a health check result and update integration state."""
        check_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO health_checks (id, integration_id, status, response_ms, error, checked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (check_id, integration_id, status.value, response_ms, error, now),
            )

            # Fetch current consecutive_failures
            row = conn.execute(
                "SELECT consecutive_failures FROM integrations WHERE id = ?",
                (integration_id,),
            ).fetchone()
            if row is None:
                conn.commit()
                return

            consecutive = row["consecutive_failures"]
            is_failure = status in (ServiceStatus.DOWN, ServiceStatus.DEGRADED)

            if is_failure:
                consecutive += 1
            else:
                consecutive = 0

            auto_disabled = consecutive >= _MAX_CONSECUTIVE_FAILURES
            final_status = ServiceStatus.DISABLED if auto_disabled else status

            update_params: tuple
            if is_failure:
                update_params = (
                    final_status.value,
                    now,
                    response_ms,
                    error,
                    consecutive,
                    int(auto_disabled),
                    integration_id,
                )
                conn.execute(
                    """
                    UPDATE integrations
                    SET status = ?, last_check = ?, response_ms = ?,
                        error_message = ?, consecutive_failures = ?,
                        auto_disabled = ?
                    WHERE id = ?
                    """,
                    update_params,
                )
            else:
                update_params = (
                    final_status.value,
                    now,
                    now,
                    response_ms,
                    None,
                    0,
                    0,
                    integration_id,
                )
                conn.execute(
                    """
                    UPDATE integrations
                    SET status = ?, last_check = ?, last_success = ?,
                        response_ms = ?, error_message = ?,
                        consecutive_failures = ?, auto_disabled = ?
                    WHERE id = ?
                    """,
                    update_params,
                )

            # Recalculate uptime percentage
            uptime = self._calc_uptime(integration_id, days=30, conn=conn)
            conn.execute(
                "UPDATE integrations SET uptime_pct = ? WHERE id = ?",
                (uptime, integration_id),
            )
            conn.commit()
        finally:
            conn.close()

        # If consecutive failures hit threshold, auto-disable
        if auto_disabled:
            self.auto_disable(integration_id)

    def get_check_history(
        self, integration_id: str, limit: int = 50
    ) -> List[HealthCheckResult]:
        """Return recent health check results for an integration."""
        conn = self._conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM health_checks
                WHERE integration_id = ?
                ORDER BY checked_at DESC
                LIMIT ?
                """,
                (integration_id, limit),
            ).fetchall()
        finally:
            conn.close()
        return [
            HealthCheckResult(
                integration_id=r["integration_id"],
                status=ServiceStatus(r["status"]),
                response_ms=r["response_ms"],
                error=r["error"],
                checked_at=r["checked_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Enable / disable
    # ------------------------------------------------------------------

    def auto_disable(self, integration_id: str) -> None:
        """Mark integration as auto-disabled after too many consecutive failures."""
        conn = self._conn()
        try:
            conn.execute(
                """
                UPDATE integrations
                SET status = 'disabled', auto_disabled = 1
                WHERE id = ?
                """,
                (integration_id,),
            )
            conn.commit()
        finally:
            conn.close()

    def enable_integration(self, integration_id: str) -> None:
        """Re-enable a disabled integration and reset failure counters."""
        conn = self._conn()
        try:
            conn.execute(
                """
                UPDATE integrations
                SET status = 'unknown', auto_disabled = 0,
                    consecutive_failures = 0, error_message = NULL
                WHERE id = ?
                """,
                (integration_id,),
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Uptime and dashboard
    # ------------------------------------------------------------------

    def get_uptime(self, integration_id: str, days: int = 30) -> float:
        """Return uptime percentage over the last N days."""
        conn = self._conn()
        try:
            return self._calc_uptime(integration_id, days=days, conn=conn)
        finally:
            conn.close()

    def _calc_uptime(
        self, integration_id: str, days: int, conn: sqlite3.Connection
    ) -> float:
        """Compute uptime percentage from check history within connection."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = conn.execute(
            """
            SELECT status FROM health_checks
            WHERE integration_id = ? AND checked_at >= ?
            """,
            (integration_id, since),
        ).fetchall()
        if not rows:
            return 100.0
        total = len(rows)
        healthy = sum(
            1 for r in rows if r["status"] in (ServiceStatus.HEALTHY.value, ServiceStatus.DEGRADED.value)
        )
        return round(healthy / total * 100, 2)

    def get_dashboard(self, org_id: str) -> Dict[str, Any]:
        """Return full dashboard: all integrations plus status summary."""
        integrations = self.list_integrations(org_id)
        counts: Dict[str, int] = {s.value: 0 for s in ServiceStatus}
        for info in integrations:
            counts[info.status.value] += 1

        return {
            "org_id": org_id,
            "total": len(integrations),
            "summary": counts,
            "integrations": [i.model_dump() for i in integrations],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_alerts(self, org_id: str) -> List[Dict[str, Any]]:
        """Return integrations that need attention (down, degraded, or disabled)."""
        integrations = self.list_integrations(org_id)
        alert_statuses = {ServiceStatus.DOWN, ServiceStatus.DEGRADED, ServiceStatus.DISABLED}
        alerts: List[Dict[str, Any]] = []
        for info in integrations:
            if info.status in alert_statuses:
                alerts.append(
                    {
                        "integration_id": info.id,
                        "name": info.name,
                        "status": info.status.value,
                        "consecutive_failures": info.consecutive_failures,
                        "auto_disabled": info.auto_disabled,
                        "error_message": info.error_message,
                        "last_check": info.last_check,
                        "uptime_pct": info.uptime_pct,
                    }
                )
        return alerts

    def get_health_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate health statistics for the org."""
        integrations = self.list_integrations(org_id)
        if not integrations:
            return {
                "org_id": org_id,
                "total": 0,
                "healthy": 0,
                "degraded": 0,
                "down": 0,
                "disabled": 0,
                "unknown": 0,
                "avg_uptime_pct": 0.0,
                "avg_response_ms": None,
            }

        counts: Dict[str, int] = {s.value: 0 for s in ServiceStatus}
        for info in integrations:
            counts[info.status.value] += 1

        response_times = [i.response_ms for i in integrations if i.response_ms is not None]
        avg_response = round(sum(response_times) / len(response_times), 2) if response_times else None
        avg_uptime = round(sum(i.uptime_pct for i in integrations) / len(integrations), 2)

        return {
            "org_id": org_id,
            "total": len(integrations),
            **counts,
            "avg_uptime_pct": avg_uptime,
            "avg_response_ms": avg_response,
        }


# ---------------------------------------------------------------------------
# Simulation helper
# ---------------------------------------------------------------------------


def _simulate_check(endpoint_url: str) -> tuple[float, ServiceStatus, Optional[str]]:
    """Simulate a connectivity check to the endpoint.

    Uses deterministic seed derived from URL so behaviour is reproducible
    in tests while remaining varied across different endpoints.
    """
    seed = sum(ord(c) for c in endpoint_url) % 100

    # 70% healthy, 15% degraded, 15% down — biased by URL hash
    if seed < 70:
        response_ms = round(50.0 + seed * 2.5, 2)
        return response_ms, ServiceStatus.HEALTHY, None
    elif seed < 85:
        response_ms = round(500.0 + seed * 10.0, 2)
        return response_ms, ServiceStatus.DEGRADED, "High response latency detected"
    else:
        return 0.0, ServiceStatus.DOWN, "Connection refused or timeout"
