"""System health monitoring module for ALDECI.

Aggregates health from all subsystems (pipeline, connectors, feeds, queues,
databases) into a comprehensive health report. SQLite-backed with history.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums and Pydantic models
# ---------------------------------------------------------------------------


class SubsystemStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class SubsystemHealth(BaseModel):
    name: str
    status: SubsystemStatus
    response_ms: float
    details: Dict[str, Any] = Field(default_factory=dict)
    last_check: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error: Optional[str] = None


class ResourceUsage(BaseModel):
    disk_total_gb: float
    disk_used_gb: float
    disk_pct: float
    memory_total_mb: float
    memory_used_mb: float
    memory_pct: float
    cpu_pct: float
    db_size_mb: float


class SystemHealthReport(BaseModel):
    overall_status: SubsystemStatus
    subsystems: List[SubsystemHealth]
    resources: ResourceUsage
    uptime_seconds: float
    checked_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    warnings: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Monitor class
# ---------------------------------------------------------------------------


class SystemHealthMonitor:
    """SQLite-backed system health monitor."""

    def __init__(self, db_path: str = "data/system_health.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._start_time: float = time.time()
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
                CREATE TABLE IF NOT EXISTS health_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    overall_status TEXT NOT NULL,
                    subsystems_json TEXT NOT NULL,
                    resources_json TEXT NOT NULL,
                    uptime_seconds REAL NOT NULL,
                    warnings_json TEXT NOT NULL,
                    checked_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_reports_checked_at
                    ON health_reports(checked_at);

                CREATE TABLE IF NOT EXISTS subsystem_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subsystem_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    response_ms REAL NOT NULL,
                    error TEXT,
                    checked_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_subsystem_history_name
                    ON subsystem_history(subsystem_name, checked_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_all(self) -> SystemHealthReport:
        """Run all subsystem checks and return a full health report."""
        checks = [
            self._check_pipeline,
            self._check_database,
            self._check_connectors,
            self._check_feeds,
            self._check_queue,
            self._check_cache,
        ]
        subsystems: List[SubsystemHealth] = []
        for check_fn in checks:
            try:
                subsystems.append(check_fn())
            except Exception as exc:  # noqa: BLE001
                name = check_fn.__name__.replace("_check_", "")
                subsystems.append(
                    SubsystemHealth(
                        name=name,
                        status=SubsystemStatus.UNKNOWN,
                        response_ms=0.0,
                        error=str(exc),
                    )
                )

        resources = self.get_resource_usage()
        overall = self._determine_overall(subsystems)
        warnings = self.get_warnings(subsystems=subsystems, resources=resources)
        uptime = self.get_uptime()

        report = SystemHealthReport(
            overall_status=overall,
            subsystems=subsystems,
            resources=resources,
            uptime_seconds=uptime,
            warnings=warnings,
        )
        self.record_health(report)
        return report

    def check_subsystem(self, name: str) -> SubsystemHealth:
        """Check a specific subsystem by name."""
        dispatch: Dict[str, Any] = {
            "pipeline": self._check_pipeline,
            "database": self._check_database,
            "connectors": self._check_connectors,
            "feeds": self._check_feeds,
            "queue": self._check_queue,
            "cache": self._check_cache,
        }
        fn = dispatch.get(name.lower())
        if fn is None:
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.UNKNOWN,
                response_ms=0.0,
                error=f"Unknown subsystem: {name}",
            )
        return fn()

    def get_resource_usage(self) -> ResourceUsage:
        """Return current disk, memory, CPU, and DB usage."""
        # --- Disk ---
        try:
            disk = shutil.disk_usage(os.getcwd())
            disk_total_gb = disk.total / (1024 ** 3)
            disk_used_gb = disk.used / (1024 ** 3)
            disk_pct = (disk.used / disk.total * 100) if disk.total > 0 else 0.0
        except OSError:
            disk_total_gb = disk_used_gb = disk_pct = 0.0

        # --- Memory ---
        memory_total_mb = memory_used_mb = memory_pct = 0.0
        try:
            import psutil  # type: ignore[import]
            vm = psutil.virtual_memory()
            memory_total_mb = vm.total / (1024 * 1024)
            memory_used_mb = vm.used / (1024 * 1024)
            memory_pct = vm.percent
        except ImportError:
            # Fallback: /proc/meminfo (Linux)
            proc_meminfo = Path("/proc/meminfo")
            if proc_meminfo.exists():
                try:
                    info: Dict[str, float] = {}
                    for line in proc_meminfo.read_text().splitlines():
                        parts = line.split()
                        if len(parts) >= 2:
                            info[parts[0].rstrip(":")] = float(parts[1])
                    mem_total_kb = info.get("MemTotal", 0.0)
                    mem_available_kb = info.get("MemAvailable", 0.0)
                    memory_total_mb = mem_total_kb / 1024
                    memory_used_mb = (mem_total_kb - mem_available_kb) / 1024
                    memory_pct = (
                        (memory_used_mb / memory_total_mb * 100)
                        if memory_total_mb > 0
                        else 0.0
                    )
                except (OSError, ValueError):
                    pass
        except (OSError, ValueError):
            pass

        # --- CPU ---
        cpu_pct = 0.0
        try:
            import psutil  # type: ignore[import]
            cpu_pct = psutil.cpu_percent(interval=0.1)
        except (ImportError, OSError):
            pass

        # --- DB size (sum of all .db files in data/) ---
        db_size_mb = 0.0
        try:
            data_dir = Path("data")
            if data_dir.exists():
                db_size_mb = sum(
                    p.stat().st_size for p in data_dir.rglob("*.db") if p.is_file()
                ) / (1024 * 1024)
        except OSError:
            pass

        return ResourceUsage(
            disk_total_gb=round(disk_total_gb, 2),
            disk_used_gb=round(disk_used_gb, 2),
            disk_pct=round(disk_pct, 1),
            memory_total_mb=round(memory_total_mb, 1),
            memory_used_mb=round(memory_used_mb, 1),
            memory_pct=round(memory_pct, 1),
            cpu_pct=round(cpu_pct, 1),
            db_size_mb=round(db_size_mb, 2),
        )

    def get_uptime(self) -> float:
        """Return seconds since first health check (monitor init)."""
        return time.time() - self._start_time

    def record_health(self, report: SystemHealthReport) -> None:
        """Store a health report for history."""
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO health_reports
                    (overall_status, subsystems_json, resources_json,
                     uptime_seconds, warnings_json, checked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    report.overall_status.value,
                    json.dumps([s.model_dump() for s in report.subsystems]),
                    json.dumps(report.resources.model_dump()),
                    report.uptime_seconds,
                    json.dumps(report.warnings),
                    report.checked_at,
                ),
            )
            # Store per-subsystem history rows
            for sub in report.subsystems:
                conn.execute(
                    """
                    INSERT INTO subsystem_history
                        (subsystem_name, status, response_ms, error, checked_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        sub.name,
                        sub.status.value,
                        sub.response_ms,
                        sub.error,
                        sub.last_check,
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def get_health_history(self, hours: int = 24) -> List[SystemHealthReport]:
        """Return health reports from the last N hours."""
        since = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).isoformat()
        conn = self._conn()
        try:
            rows = conn.execute(
                """
                SELECT overall_status, subsystems_json, resources_json,
                       uptime_seconds, warnings_json, checked_at
                FROM health_reports
                WHERE checked_at >= ?
                ORDER BY checked_at DESC
                """,
                (since,),
            ).fetchall()
        finally:
            conn.close()

        reports: List[SystemHealthReport] = []
        for row in rows:
            try:
                subsystems = [
                    SubsystemHealth(**s) for s in json.loads(row["subsystems_json"])
                ]
                resources = ResourceUsage(**json.loads(row["resources_json"]))
                reports.append(
                    SystemHealthReport(
                        overall_status=SubsystemStatus(row["overall_status"]),
                        subsystems=subsystems,
                        resources=resources,
                        uptime_seconds=row["uptime_seconds"],
                        warnings=json.loads(row["warnings_json"]),
                        checked_at=row["checked_at"],
                    )
                )
            except (KeyError, ValueError):
                continue
        return reports

    def get_degraded_subsystems(self) -> List[SubsystemHealth]:
        """Return subsystems that are not HEALTHY from the latest check."""
        report = self.check_all()
        return [
            s
            for s in report.subsystems
            if s.status != SubsystemStatus.HEALTHY
        ]

    def get_health_trend(
        self, subsystem: str, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Return status history for a specific subsystem over time."""
        since = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).isoformat()
        conn = self._conn()
        try:
            rows = conn.execute(
                """
                SELECT status, response_ms, error, checked_at
                FROM subsystem_history
                WHERE subsystem_name = ? AND checked_at >= ?
                ORDER BY checked_at DESC
                """,
                (subsystem, since),
            ).fetchall()
        finally:
            conn.close()

        return [
            {
                "status": row["status"],
                "response_ms": row["response_ms"],
                "error": row["error"],
                "checked_at": row["checked_at"],
            }
            for row in rows
        ]

    def get_warnings(
        self,
        subsystems: Optional[List[SubsystemHealth]] = None,
        resources: Optional[ResourceUsage] = None,
    ) -> List[str]:
        """Generate active warnings based on current state."""
        warnings: List[str] = []

        if resources is None:
            resources = self.get_resource_usage()

        if subsystems is None:
            # Lightweight check — avoid full check_all() recursion
            subsystems = []

        # Resource warnings
        if resources.disk_pct > 80:
            warnings.append(
                f"Disk usage critical: {resources.disk_pct:.1f}% used "
                f"({resources.disk_used_gb:.1f} GB / {resources.disk_total_gb:.1f} GB)"
            )
        if resources.memory_pct > 80:
            warnings.append(
                f"Memory usage high: {resources.memory_pct:.1f}% used "
                f"({resources.memory_used_mb:.0f} MB / {resources.memory_total_mb:.0f} MB)"
            )

        # Subsystem warnings
        for sub in subsystems:
            if sub.status == SubsystemStatus.CRITICAL:
                warnings.append(f"Subsystem DOWN: {sub.name} — {sub.error or 'no details'}")
            elif sub.status == SubsystemStatus.DEGRADED:
                warnings.append(f"Subsystem degraded: {sub.name} — {sub.error or 'check details'}")

        return warnings

    # ------------------------------------------------------------------
    # Subsystem checkers
    # ------------------------------------------------------------------

    def _check_pipeline(self) -> SubsystemHealth:
        start = time.monotonic()
        name = "pipeline"
        try:
            spec = importlib.util.find_spec("core.brain_pipeline")
            elapsed = (time.monotonic() - start) * 1000
            if spec is not None:
                return SubsystemHealth(
                    name=name,
                    status=SubsystemStatus.HEALTHY,
                    response_ms=round(elapsed, 2),
                    details={"module": "core.brain_pipeline", "importable": True},
                )
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.DEGRADED,
                response_ms=round(elapsed, 2),
                details={"importable": False},
                error="core.brain_pipeline not found on sys.path",
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.monotonic() - start) * 1000
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.CRITICAL,
                response_ms=round(elapsed, 2),
                error=str(exc),
            )

    def _check_database(self) -> SubsystemHealth:
        start = time.monotonic()
        name = "database"
        db_path = os.path.join(
            os.getenv("FIXOPS_DATA_DIR", ".fixops_data"), "audit.db"
        )
        try:
            import tempfile

            try:
                conn = sqlite3.connect(db_path, timeout=3)
                conn.execute("SELECT 1")
                conn.close()
                note = None
            except (sqlite3.OperationalError, OSError):
                # Primary DB not yet created — verify SQLite itself works
                with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tmp:
                    tmp_conn = sqlite3.connect(tmp.name, timeout=3)
                    tmp_conn.execute("SELECT 1")
                    tmp_conn.close()
                note = "primary db not yet created — sqlite operational"

            elapsed = (time.monotonic() - start) * 1000
            details: Dict[str, Any] = {"backend": "sqlite", "path": db_path}
            if note:
                details["note"] = note
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.HEALTHY,
                response_ms=round(elapsed, 2),
                details=details,
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.monotonic() - start) * 1000
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.CRITICAL,
                response_ms=round(elapsed, 2),
                error=str(exc),
            )

    def _check_connectors(self) -> SubsystemHealth:
        start = time.monotonic()
        name = "connectors"
        try:
            results: Dict[str, str] = {}
            connector_modules = [
                ("security_connectors", "core.security_connectors"),
                ("connectors", "core.connectors"),
            ]
            for label, mod_path in connector_modules:
                spec = importlib.util.find_spec(mod_path)
                results[label] = "available" if spec is not None else "not_found"

            available = sum(1 for v in results.values() if v == "available")
            elapsed = (time.monotonic() - start) * 1000
            status = (
                SubsystemStatus.HEALTHY
                if available == len(connector_modules)
                else SubsystemStatus.DEGRADED
            )
            return SubsystemHealth(
                name=name,
                status=status,
                response_ms=round(elapsed, 2),
                details={"modules": results, "available": available, "total": len(connector_modules)},
                error=None if status == SubsystemStatus.HEALTHY else "Some connector modules unavailable",
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.monotonic() - start) * 1000
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.CRITICAL,
                response_ms=round(elapsed, 2),
                error=str(exc),
            )

    def _check_feeds(self) -> SubsystemHealth:
        start = time.monotonic()
        name = "feeds"
        try:
            feeds_dir = Path("suite-feeds")
            if not feeds_dir.exists():
                # Try relative to cwd
                feeds_dir = Path(os.getcwd()) / "suite-feeds"
            feed_count = (
                len(list(feeds_dir.glob("*.py"))) if feeds_dir.exists() else 0
            )
            elapsed = (time.monotonic() - start) * 1000
            status = SubsystemStatus.HEALTHY if feed_count > 0 else SubsystemStatus.DEGRADED
            return SubsystemHealth(
                name=name,
                status=status,
                response_ms=round(elapsed, 2),
                details={"feed_files": feed_count, "feeds_dir": str(feeds_dir)},
                error=None if status == SubsystemStatus.HEALTHY else "No feed files found",
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.monotonic() - start) * 1000
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.CRITICAL,
                response_ms=round(elapsed, 2),
                error=str(exc),
            )

    def _check_queue(self) -> SubsystemHealth:
        start = time.monotonic()
        name = "queue"
        try:
            # Check Redis availability (optional — degrade gracefully if absent)
            redis_host = os.getenv("REDIS_HOST", "localhost")
            redis_port = int(os.getenv("REDIS_PORT", "6379"))
            details: Dict[str, Any] = {"host": redis_host, "port": redis_port}

            try:
                import socket
                sock = socket.create_connection((redis_host, redis_port), timeout=1)
                sock.close()
                details["connected"] = True
                status = SubsystemStatus.HEALTHY
            except (OSError, ConnectionRefusedError):
                details["connected"] = False
                status = SubsystemStatus.DEGRADED

            elapsed = (time.monotonic() - start) * 1000
            return SubsystemHealth(
                name=name,
                status=status,
                response_ms=round(elapsed, 2),
                details=details,
                error=None if status == SubsystemStatus.HEALTHY else "Redis not reachable — queue running in degraded mode",
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.monotonic() - start) * 1000
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.CRITICAL,
                response_ms=round(elapsed, 2),
                error=str(exc),
            )

    def _check_cache(self) -> SubsystemHealth:
        start = time.monotonic()
        name = "cache"
        try:
            # Check in-process cache availability — verify data dir is writable
            data_dir = Path(os.getenv("FIXOPS_DATA_DIR", ".fixops_data"))
            data_dir.mkdir(parents=True, exist_ok=True)
            test_file = data_dir / ".cache_probe"
            test_file.write_text("ok")
            test_file.unlink()

            elapsed = (time.monotonic() - start) * 1000
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.HEALTHY,
                response_ms=round(elapsed, 2),
                details={"data_dir": str(data_dir), "writable": True},
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.monotonic() - start) * 1000
            return SubsystemHealth(
                name=name,
                status=SubsystemStatus.CRITICAL,
                response_ms=round(elapsed, 2),
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def _determine_overall(self, subsystems: List[SubsystemHealth]) -> SubsystemStatus:
        """Return worst-of status across all subsystems."""
        if not subsystems:
            return SubsystemStatus.UNKNOWN
        priority = {
            SubsystemStatus.CRITICAL: 3,
            SubsystemStatus.DEGRADED: 2,
            SubsystemStatus.UNKNOWN: 1,
            SubsystemStatus.HEALTHY: 0,
        }
        worst = max(subsystems, key=lambda s: priority.get(s.status, 0))
        return worst.status
