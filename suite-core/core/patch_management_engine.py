"""Patch Management Engine — ALDECI.

Tracks patches across their full lifecycle from availability through deployment,
including per-asset deployment records, approval workflow, and statistics.

Capabilities:
  - Patch registry: security, feature, hotfix, rollup, service_pack, firmware
  - Status lifecycle: available → testing → approved → deploying → deployed / failed / rollback
  - Per-asset deployment records with success/failure counters
  - Stats: critical undeployed, deployment success rate, patches needing attention

Compliance: NIST SP 800-40 (Guide to Enterprise Patch Management), CIS Control 7
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "patch_management.db"
)

_VALID_PATCH_TYPES = {
    "security",
    "feature",
    "hotfix",
    "rollup",
    "service_pack",
    "firmware",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_VALID_PATCH_STATUSES = {
    "available",
    "testing",
    "approved",
    "deploying",
    "deployed",
    "failed",
    "rollback",
}

_VALID_OS_TYPES = {
    "windows",
    "linux",
    "macos",
    "ios",
    "android",
    "network_device",
    "firmware",
}

_VALID_DEPLOYMENT_STATUSES = {"success", "failed", "pending", "skipped"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PatchManagementEngine:
    """SQLite WAL-backed Patch Management engine."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS pm_patches (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    title          TEXT NOT NULL DEFAULT '',
                    cve_ids_json   TEXT NOT NULL DEFAULT '[]',
                    patch_type     TEXT NOT NULL DEFAULT 'security',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    vendor         TEXT NOT NULL DEFAULT '',
                    affected_os    TEXT NOT NULL DEFAULT '',
                    version        TEXT NOT NULL DEFAULT '',
                    release_date   DATETIME,
                    status         TEXT NOT NULL DEFAULT 'available',
                    test_results   TEXT NOT NULL DEFAULT '',
                    approved_by    TEXT NOT NULL DEFAULT '',
                    deployed_count INTEGER NOT NULL DEFAULT 0,
                    failed_count   INTEGER NOT NULL DEFAULT 0,
                    created_at     DATETIME
                );

                CREATE TABLE IF NOT EXISTS pm_deployments (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    patch_id       TEXT NOT NULL,
                    asset_id       TEXT NOT NULL DEFAULT '',
                    hostname       TEXT NOT NULL DEFAULT '',
                    os_type        TEXT NOT NULL DEFAULT 'linux',
                    status         TEXT NOT NULL DEFAULT 'pending',
                    failure_reason TEXT NOT NULL DEFAULT '',
                    deployed_at    DATETIME
                );
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
    # Patches
    # ------------------------------------------------------------------

    def register_patch(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new patch record."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required")

        patch_type = data.get("patch_type", "security")
        if patch_type not in _VALID_PATCH_TYPES:
            raise ValueError(
                f"patch_type must be one of {sorted(_VALID_PATCH_TYPES)}, got {patch_type!r}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {severity!r}"
            )

        cve_ids = data.get("cve_ids", [])
        cve_ids_json = json.dumps(cve_ids) if isinstance(cve_ids, list) else cve_ids

        patch_id = str(uuid.uuid4())
        now = _now_iso()

        row_data = {
            "id": patch_id,
            "org_id": org_id,
            "title": title,
            "cve_ids_json": cve_ids_json,
            "patch_type": patch_type,
            "severity": severity,
            "vendor": data.get("vendor", ""),
            "affected_os": data.get("affected_os", ""),
            "version": data.get("version", ""),
            "release_date": data.get("release_date"),
            "status": "available",
            "test_results": "",
            "approved_by": "",
            "deployed_count": 0,
            "failed_count": 0,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pm_patches
                        (id, org_id, title, cve_ids_json, patch_type, severity,
                         vendor, affected_os, version, release_date, status,
                         test_results, approved_by, deployed_count, failed_count, created_at)
                    VALUES
                        (:id, :org_id, :title, :cve_ids_json, :patch_type, :severity,
                         :vendor, :affected_os, :version, :release_date, :status,
                         :test_results, :approved_by, :deployed_count, :failed_count, :created_at)
                    """,
                    row_data,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "patch_management", "org_id": org_id, "source_engine": "patch_management"})
            except Exception:
                pass

        return row_data

    def list_patches(
        self,
        org_id: str,
        patch_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List patches with optional filters."""
        query = "SELECT * FROM pm_patches WHERE org_id = ?"
        params: List[Any] = [org_id]
        if patch_type:
            query += " AND patch_type = ?"
            params.append(patch_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_patch(self, org_id: str, patch_id: str) -> Optional[Dict[str, Any]]:
        """Return a single patch or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pm_patches WHERE id = ? AND org_id = ?",
                (patch_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_patch_status(
        self,
        org_id: str,
        patch_id: str,
        status: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Update patch status and optionally record notes in test_results."""
        if status not in _VALID_PATCH_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(_VALID_PATCH_STATUSES)}, got {status!r}"
            )

        with self._lock:
            with self._conn() as conn:
                # Check existence
                row = conn.execute(
                    "SELECT * FROM pm_patches WHERE id = ? AND org_id = ?",
                    (patch_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Patch {patch_id!r} not found for org {org_id!r}")

                updates: Dict[str, Any] = {"status": status, "id": patch_id, "org_id": org_id}
                sql = "UPDATE pm_patches SET status = :status"
                if notes:
                    updates["test_results"] = notes
                    sql += ", test_results = :test_results"
                sql += " WHERE id = :id AND org_id = :org_id"
                conn.execute(sql, updates)

                updated = conn.execute(
                    "SELECT * FROM pm_patches WHERE id = ? AND org_id = ?",
                    (patch_id, org_id),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Deployments
    # ------------------------------------------------------------------

    def record_deployment(
        self, org_id: str, patch_id: str, deployment_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a per-asset deployment and update patch counters."""
        dep_status = deployment_data.get("status", "pending")
        if dep_status not in _VALID_DEPLOYMENT_STATUSES:
            raise ValueError(
                f"deployment status must be one of {sorted(_VALID_DEPLOYMENT_STATUSES)}, got {dep_status!r}"
            )

        os_type = deployment_data.get("os_type", "linux")
        if os_type not in _VALID_OS_TYPES:
            raise ValueError(
                f"os_type must be one of {sorted(_VALID_OS_TYPES)}, got {os_type!r}"
            )

        dep_id = str(uuid.uuid4())
        now = _now_iso()

        row_data = {
            "id": dep_id,
            "org_id": org_id,
            "patch_id": patch_id,
            "asset_id": deployment_data.get("asset_id", ""),
            "hostname": deployment_data.get("hostname", ""),
            "os_type": os_type,
            "status": dep_status,
            "failure_reason": deployment_data.get("failure_reason", ""),
            "deployed_at": deployment_data.get("deployed_at", now),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pm_deployments
                        (id, org_id, patch_id, asset_id, hostname, os_type,
                         status, failure_reason, deployed_at)
                    VALUES
                        (:id, :org_id, :patch_id, :asset_id, :hostname, :os_type,
                         :status, :failure_reason, :deployed_at)
                    """,
                    row_data,
                )
                # Update patch counters
                if dep_status == "success":
                    conn.execute(
                        "UPDATE pm_patches SET deployed_count = deployed_count + 1 WHERE id = ? AND org_id = ?",
                        (patch_id, org_id),
                    )
                elif dep_status == "failed":
                    conn.execute(
                        "UPDATE pm_patches SET failed_count = failed_count + 1 WHERE id = ? AND org_id = ?",
                        (patch_id, org_id),
                    )
        return row_data

    def list_deployments(
        self,
        org_id: str,
        patch_id: Optional[str] = None,
        status: Optional[str] = None,
        os_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List deployment records with optional filters."""
        query = "SELECT * FROM pm_deployments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if patch_id:
            query += " AND patch_id = ?"
            params.append(patch_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        if os_type:
            query += " AND os_type = ?"
            params.append(os_type)
        query += " ORDER BY deployed_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_patch_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated patch management statistics."""
        with self._conn() as conn:
            total_patches = conn.execute(
                "SELECT COUNT(*) FROM pm_patches WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            critical_patches = conn.execute(
                "SELECT COUNT(*) FROM pm_patches WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            # Critical patches not yet deployed (deployed_count=0, status not in deployed/rollback)
            undeployed_critical = conn.execute(
                """
                SELECT COUNT(*) FROM pm_patches
                WHERE org_id = ? AND severity = 'critical'
                  AND deployed_count = 0
                  AND status NOT IN ('deployed', 'rollback')
                """,
                (org_id,),
            ).fetchone()[0]

            total_deployments = conn.execute(
                "SELECT COUNT(*) FROM pm_deployments WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            success_count = conn.execute(
                "SELECT COUNT(*) FROM pm_deployments WHERE org_id = ? AND status = 'success'",
                (org_id,),
            ).fetchone()[0]

            failed_count = conn.execute(
                "SELECT COUNT(*) FROM pm_deployments WHERE org_id = ? AND status = 'failed'",
                (org_id,),
            ).fetchone()[0]

            denom = success_count + failed_count
            deployment_success_rate = (success_count / denom * 100.0) if denom > 0 else 0.0

            # by_severity
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM pm_patches WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            # Patches needing attention: available or testing + critical
            attention_rows = conn.execute(
                """
                SELECT * FROM pm_patches
                WHERE org_id = ? AND severity = 'critical'
                  AND status IN ('available', 'testing')
                ORDER BY created_at DESC
                """,
                (org_id,),
            ).fetchall()
            patches_needing_attention = [self._row(r) for r in attention_rows]

        return {
            "total_patches": total_patches,
            "critical_patches": critical_patches,
            "undeployed_critical": undeployed_critical,
            "total_deployments": total_deployments,
            "deployment_success_rate": round(deployment_success_rate, 2),
            "by_severity": by_severity,
            "patches_needing_attention": patches_needing_attention,
        }
