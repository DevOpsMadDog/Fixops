"""Patch Manager — Automated Security Patch Tracking and Management.

Tracks CVE-linked patches across packages and assets, supports scheduling,
deployment, rollback, SLA compliance measurement, and velocity trending.

Usage:
    from core.patch_manager import PatchManager, get_patch_manager
    pm = get_patch_manager()
    patches = pm.discover_patches("org-1")
    pm.schedule_patch(patch_id, date)
    pm.deploy_patch(patch_id)
    compliance = pm.get_patch_compliance("org-1")
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_PATCH_MANAGER_DB", ".fixops_data/patch_manager.db")

# SLA windows (days) per priority within which a patch must be deployed
_SLA_DAYS: Dict[str, int] = {
    "emergency": 1,
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PatchPriority(str, Enum):
    EMERGENCY = "emergency"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PatchStatus(str, Enum):
    AVAILABLE = "available"
    SCHEDULED = "scheduled"
    TESTING = "testing"
    DEPLOYED = "deployed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class Patch(BaseModel):
    id: str = Field(default_factory=lambda: f"patch-{uuid.uuid4().hex[:12]}")
    cve_id: Optional[str] = Field(None, description="Associated CVE identifier, e.g. CVE-2024-1234")
    package_name: str = Field(..., description="Package or component name")
    current_version: str = Field(..., description="Currently installed version")
    fixed_version: str = Field(..., description="Version that resolves the vulnerability")
    priority: PatchPriority = Field(PatchPriority.MEDIUM, description="Patch urgency")
    status: PatchStatus = Field(PatchStatus.AVAILABLE, description="Current lifecycle state")
    affected_assets: List[str] = Field(default_factory=list, description="Asset IDs impacted by this patch")
    scheduled_date: Optional[str] = Field(None, description="ISO-8601 date/time scheduled for deployment")
    deployed_date: Optional[str] = Field(None, description="ISO-8601 date/time actually deployed")
    discovered_date: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="When the patch was first discovered",
    )
    org_id: str = Field("default", description="Organisation the patch belongs to")
    notes: Optional[str] = Field(None, description="Free-form notes or change-ticket reference")


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------


class _PatchDB:
    """SQLite persistence for patch records."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        dir_part = os.path.dirname(db_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS patches (
                    id TEXT PRIMARY KEY,
                    cve_id TEXT,
                    package_name TEXT NOT NULL,
                    current_version TEXT NOT NULL,
                    fixed_version TEXT NOT NULL,
                    priority TEXT NOT NULL DEFAULT 'medium',
                    status TEXT NOT NULL DEFAULT 'available',
                    affected_assets TEXT NOT NULL DEFAULT '[]',
                    scheduled_date TEXT,
                    deployed_date TEXT,
                    discovered_date TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    notes TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_patch_org ON patches(org_id);
                CREATE INDEX IF NOT EXISTS idx_patch_priority ON patches(priority);
                CREATE INDEX IF NOT EXISTS idx_patch_status ON patches(status);
                CREATE INDEX IF NOT EXISTS idx_patch_package ON patches(package_name);
                CREATE INDEX IF NOT EXISTS idx_patch_cve ON patches(cve_id);
            """)
            self._conn.commit()

    def upsert(self, patch: Patch) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO patches
                   (id, cve_id, package_name, current_version, fixed_version,
                    priority, status, affected_assets, scheduled_date, deployed_date,
                    discovered_date, org_id, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    patch.id, patch.cve_id, patch.package_name,
                    patch.current_version, patch.fixed_version,
                    patch.priority.value, patch.status.value,
                    json.dumps(patch.affected_assets),
                    patch.scheduled_date, patch.deployed_date,
                    patch.discovered_date, patch.org_id, patch.notes,
                ),
            )
            self._conn.commit()

    def get(self, patch_id: str) -> Optional[Patch]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM patches WHERE id = ?", (patch_id,)
            ).fetchone()
        return self._row_to_patch(row) if row else None

    def list_by_org(
        self,
        org_id: str,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        package_name: Optional[str] = None,
    ) -> List[Patch]:
        query = "SELECT * FROM patches WHERE org_id = ?"
        params: List[Any] = [org_id]
        if priority:
            query += " AND priority = ?"
            params.append(priority)
        if status:
            query += " AND status = ?"
            params.append(status)
        if package_name:
            query += " AND package_name = ?"
            params.append(package_name)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_patch(r) for r in rows]

    def list_by_status(self, org_id: str, statuses: List[str]) -> List[Patch]:
        placeholders = ",".join("?" * len(statuses))
        query = f"SELECT * FROM patches WHERE org_id = ? AND status IN ({placeholders})"  # nosec B608
        with self._lock:
            rows = self._conn.execute(query, [org_id] + statuses).fetchall()
        return [self._row_to_patch(r) for r in rows]

    def list_deployed_since(self, org_id: str, since: str) -> List[Patch]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM patches WHERE org_id = ? AND status = 'deployed' AND deployed_date >= ?",
                (org_id, since),
            ).fetchall()
        return [self._row_to_patch(r) for r in rows]

    def _row_to_patch(self, row: tuple) -> Patch:
        (
            id_, cve_id, package_name, current_version, fixed_version,
            priority, status, affected_assets, scheduled_date, deployed_date,
            discovered_date, org_id, notes,
        ) = row
        return Patch(
            id=id_,
            cve_id=cve_id,
            package_name=package_name,
            current_version=current_version,
            fixed_version=fixed_version,
            priority=PatchPriority(priority),
            status=PatchStatus(status),
            affected_assets=json.loads(affected_assets),
            scheduled_date=scheduled_date,
            deployed_date=deployed_date,
            discovered_date=discovered_date,
            org_id=org_id,
            notes=notes,
        )


# ---------------------------------------------------------------------------
# PatchManager
# ---------------------------------------------------------------------------


class PatchManager:
    """SQLite-backed automated patch management engine."""

    # Simulated package vulnerability data for discover_patches()
    _KNOWN_VULNS: List[Dict[str, Any]] = [
        {"cve_id": "CVE-2024-1234", "package": "openssl", "current": "1.1.1t", "fixed": "3.0.12", "priority": PatchPriority.CRITICAL},
        {"cve_id": "CVE-2024-2345", "package": "libssl", "current": "1.1.1s", "fixed": "1.1.1w", "priority": PatchPriority.HIGH},
        {"cve_id": "CVE-2024-3456", "package": "curl", "current": "7.88.0", "fixed": "8.5.0", "priority": PatchPriority.HIGH},
        {"cve_id": "CVE-2024-4567", "package": "python3", "current": "3.11.0", "fixed": "3.11.8", "priority": PatchPriority.MEDIUM},
        {"cve_id": "CVE-2024-5678", "package": "nginx", "current": "1.24.0", "fixed": "1.25.4", "priority": PatchPriority.HIGH},
        {"cve_id": "CVE-2024-6789", "package": "openssh", "current": "9.3p1", "fixed": "9.6p1", "priority": PatchPriority.CRITICAL},
        {"cve_id": "CVE-2024-7890", "package": "glibc", "current": "2.35", "fixed": "2.39", "priority": PatchPriority.EMERGENCY},
        {"cve_id": "CVE-2024-8901", "package": "zlib", "current": "1.2.11", "fixed": "1.3.1", "priority": PatchPriority.MEDIUM},
        {"cve_id": "CVE-2024-9012", "package": "expat", "current": "2.5.0", "fixed": "2.6.0", "priority": PatchPriority.LOW},
        {"cve_id": "CVE-2024-0123", "package": "sqlite3", "current": "3.41.0", "fixed": "3.44.2", "priority": PatchPriority.LOW},
    ]

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _PatchDB(db_path)
        logger.info("PatchManager initialised", db_path=db_path)

    # ---- Core operations ----

    def discover_patches(self, org_id: str) -> List[Patch]:
        """Scan for available patches and persist any that are not yet tracked.

        In production this would call package managers (apt, pip, npm, etc.)
        and cross-reference against NVD / OSV feeds.  Here we use a curated
        list of known vulnerabilities to simulate that process.
        """
        discovered: List[Patch] = []
        existing_cves = {
            p.cve_id
            for p in self._db.list_by_org(org_id)
            if p.cve_id
        }
        for vuln in self._KNOWN_VULNS:
            if vuln["cve_id"] in existing_cves:
                continue
            patch = Patch(
                cve_id=vuln["cve_id"],
                package_name=vuln["package"],
                current_version=vuln["current"],
                fixed_version=vuln["fixed"],
                priority=vuln["priority"],
                status=PatchStatus.AVAILABLE,
                org_id=org_id,
            )
            self._db.upsert(patch)
            discovered.append(patch)
            logger.info(
                "Discovered patch",
                cve_id=patch.cve_id,
                package=patch.package_name,
                priority=patch.priority.value,
                org_id=org_id,
            )
        return discovered

    def add_patch(self, patch: Patch) -> Patch:
        """Persist a caller-constructed Patch record."""
        self._db.upsert(patch)
        return patch

    def get_patch(self, patch_id: str) -> Optional[Patch]:
        """Return a single patch by ID, or None if not found."""
        return self._db.get(patch_id)

    def list_patches(
        self,
        org_id: str,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        package_name: Optional[str] = None,
    ) -> List[Patch]:
        """Return patches for an org with optional filters."""
        return self._db.list_by_org(
            org_id,
            priority=priority,
            status=status,
            package_name=package_name,
        )

    def schedule_patch(self, patch_id: str, scheduled_date: str) -> Patch:
        """Schedule a patch for deployment on *scheduled_date* (ISO-8601).

        Raises:
            ValueError: if the patch is not found or already deployed.
        """
        patch = self._db.get(patch_id)
        if not patch:
            raise ValueError(f"Patch '{patch_id}' not found")
        if patch.status == PatchStatus.DEPLOYED:
            raise ValueError(f"Patch '{patch_id}' is already deployed")
        patch.status = PatchStatus.SCHEDULED
        patch.scheduled_date = scheduled_date
        self._db.upsert(patch)
        logger.info("Patch scheduled", patch_id=patch_id, date=scheduled_date)
        return patch

    def deploy_patch(self, patch_id: str) -> Patch:
        """Mark a patch as deployed (sets deployed_date to now).

        Raises:
            ValueError: if the patch is not found or already deployed/rolled-back.
        """
        patch = self._db.get(patch_id)
        if not patch:
            raise ValueError(f"Patch '{patch_id}' not found")
        if patch.status in (PatchStatus.DEPLOYED,):
            raise ValueError(f"Patch '{patch_id}' is already deployed")
        if patch.status == PatchStatus.ROLLED_BACK:
            raise ValueError(f"Patch '{patch_id}' has been rolled back and cannot be re-deployed directly; create a new patch record")
        patch.status = PatchStatus.DEPLOYED
        patch.deployed_date = datetime.now(timezone.utc).isoformat()
        self._db.upsert(patch)
        logger.info("Patch deployed", patch_id=patch_id, package=patch.package_name)
        _emit_event("patch_manager.patch_deployed", {
            "patch_id": patch_id,
            "org_id": patch.org_id,
            "package_name": patch.package_name,
            "cve_ids": patch.cve_ids,
            "priority": patch.priority.value if hasattr(patch.priority, "value") else str(patch.priority),
        })
        return patch

    def rollback_patch(self, patch_id: str) -> Patch:
        """Mark a deployed patch as rolled back.

        Raises:
            ValueError: if the patch is not found or not in a deployed state.
        """
        patch = self._db.get(patch_id)
        if not patch:
            raise ValueError(f"Patch '{patch_id}' not found")
        if patch.status != PatchStatus.DEPLOYED:
            raise ValueError(
                f"Only DEPLOYED patches can be rolled back; current status is '{patch.status.value}'"
            )
        patch.status = PatchStatus.ROLLED_BACK
        self._db.upsert(patch)
        logger.info("Patch rolled back", patch_id=patch_id)
        return patch

    def mark_failed(self, patch_id: str) -> Patch:
        """Mark a patch as failed (e.g. deployment error)."""
        patch = self._db.get(patch_id)
        if not patch:
            raise ValueError(f"Patch '{patch_id}' not found")
        patch.status = PatchStatus.FAILED
        self._db.upsert(patch)
        logger.info("Patch marked failed", patch_id=patch_id)
        return patch

    # ---- Analytics ----

    def get_patch_compliance(self, org_id: str) -> Dict[str, Any]:
        """Return % of patches deployed within their SLA window.

        SLA windows (from *discovered_date*):
          EMERGENCY=1d, CRITICAL=7d, HIGH=30d, MEDIUM=90d, LOW=180d

        A patch counts as within-SLA if:
          - status == DEPLOYED and deployed_date <= discovered_date + SLA_days
          OR
          - status not DEPLOYED and discovered_date + SLA_days >= now (still on time)
        """
        all_patches = self._db.list_by_org(org_id)
        if not all_patches:
            return {
                "org_id": org_id,
                "total_patches": 0,
                "compliant_patches": 0,
                "compliance_pct": 100.0,
                "by_priority": {},
            }

        now = datetime.now(timezone.utc)
        compliant = 0
        by_priority: Dict[str, Dict[str, int]] = {}

        for p in all_patches:
            pri = p.priority.value
            sla_days = _SLA_DAYS[pri]
            discovered = datetime.fromisoformat(p.discovered_date)
            deadline = discovered + timedelta(days=sla_days)

            if pri not in by_priority:
                by_priority[pri] = {"total": 0, "compliant": 0}
            by_priority[pri]["total"] += 1

            if p.status == PatchStatus.DEPLOYED and p.deployed_date:
                deployed = datetime.fromisoformat(p.deployed_date)
                is_compliant = deployed <= deadline
            else:
                # Not yet deployed — compliant only if still within window
                is_compliant = now <= deadline

            if is_compliant:
                compliant += 1
                by_priority[pri]["compliant"] += 1

        total = len(all_patches)
        compliance_pct = round((compliant / total) * 100, 2) if total else 100.0
        return {
            "org_id": org_id,
            "total_patches": total,
            "compliant_patches": compliant,
            "compliance_pct": compliance_pct,
            "by_priority": by_priority,
        }

    def get_overdue_patches(self, org_id: str) -> List[Patch]:
        """Return patches that have exceeded their SLA window without being deployed."""
        now = datetime.now(timezone.utc)
        non_deployed = self._db.list_by_org(org_id)
        overdue: List[Patch] = []
        for p in non_deployed:
            if p.status == PatchStatus.DEPLOYED:
                continue
            sla_days = _SLA_DAYS[p.priority.value]
            discovered = datetime.fromisoformat(p.discovered_date)
            deadline = discovered + timedelta(days=sla_days)
            if now > deadline:
                overdue.append(p)
        return overdue

    def get_patch_velocity(self, org_id: str, weeks: int = 8) -> Dict[str, Any]:
        """Return patches-deployed-per-week trend over the last *weeks* weeks."""
        now = datetime.now(timezone.utc)
        since = (now - timedelta(weeks=weeks)).isoformat()
        deployed = self._db.list_deployed_since(org_id, since)

        # Bucket by ISO week
        weekly: Dict[str, int] = {}
        for p in deployed:
            if not p.deployed_date:
                continue
            dt = datetime.fromisoformat(p.deployed_date)
            week_key = dt.strftime("%Y-W%W")
            weekly[week_key] = weekly.get(week_key, 0) + 1

        # Ensure all weeks in range have an entry
        buckets = []
        for w in range(weeks):
            wdt = now - timedelta(weeks=(weeks - 1 - w))
            key = wdt.strftime("%Y-W%W")
            buckets.append({"week": key, "count": weekly.get(key, 0)})

        counts = [b["count"] for b in buckets]
        avg = round(sum(counts) / len(counts), 2) if counts else 0.0
        return {
            "org_id": org_id,
            "weeks": weeks,
            "weekly_counts": buckets,
            "average_per_week": avg,
            "total_deployed": sum(counts),
        }

    def get_patch_stats(self, org_id: str) -> Dict[str, Any]:
        """Return patch counts grouped by priority and status, plus package summary."""
        all_patches = self._db.list_by_org(org_id)

        by_priority: Dict[str, int] = {p.value: 0 for p in PatchPriority}
        by_status: Dict[str, int] = {s.value: 0 for s in PatchStatus}
        by_package: Dict[str, int] = {}

        for p in all_patches:
            by_priority[p.priority.value] += 1
            by_status[p.status.value] += 1
            by_package[p.package_name] = by_package.get(p.package_name, 0) + 1

        return {
            "org_id": org_id,
            "total": len(all_patches),
            "by_priority": by_priority,
            "by_status": by_status,
            "by_package": by_package,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_instance: Optional[PatchManager] = None
_instance_lock = threading.Lock()


def get_patch_manager(db_path: str = _DEFAULT_DB) -> PatchManager:
    """Return the module-level PatchManager singleton."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = PatchManager(db_path=db_path)
    return _instance
