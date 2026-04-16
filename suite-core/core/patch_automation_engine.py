"""Patch Automation Engine — ALDECI.

Automated patch management with CVE correlation across assets.

Capabilities:
  - Patch catalog management (vendor/product/version, CVE linkage)
  - Patch approval workflow (available → testing → approved → deployed)
  - Deployment tracking per asset with success/failure recording
  - Patch exception management (risk-accepted, time-limited)
  - Maintenance window scheduling (cron-based, batch controls)
  - CVE → patch reverse lookup
  - Stats aggregation per org

Compliance: CIS Controls v8 (Control 7), NIST SP 800-40, PCI-DSS Req 6.3
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

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_PATCH_TYPES = {"security", "critical", "important", "optional"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_PATCH_STATUSES = {"available", "testing", "approved", "deployed", "failed", "superseded"}
_VALID_DEPLOYMENT_TYPES = {"manual", "automated"}
_VALID_DEPLOYMENT_STATUSES = {"pending", "running", "success", "failed", "rolled_back"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PatchAutomationEngine:
    """SQLite WAL-backed patch automation engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org gets its own database file.
    """

    def __init__(self, org_id: str, db_dir: str = str(_DEFAULT_DB_DIR)) -> None:
        self.org_id = org_id
        db_path = Path(db_dir) / f"{org_id}_patch_automation.db"
        self.db_path = str(db_path)
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
                CREATE TABLE IF NOT EXISTS patch_catalog (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    patch_id        TEXT NOT NULL,
                    vendor          TEXT NOT NULL DEFAULT '',
                    product         TEXT NOT NULL DEFAULT '',
                    version         TEXT NOT NULL DEFAULT '',
                    patch_type      TEXT NOT NULL DEFAULT 'security',
                    cves_addressed  TEXT NOT NULL DEFAULT '[]',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    release_date    DATETIME,
                    kb_article      TEXT NOT NULL DEFAULT '',
                    download_url    TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'available',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pc_org_status
                    ON patch_catalog (org_id, status, severity);

                CREATE INDEX IF NOT EXISTS idx_pc_org_vendor
                    ON patch_catalog (org_id, vendor);

                CREATE TABLE IF NOT EXISTS patch_deployments (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    patch_id         TEXT NOT NULL,
                    asset_id         TEXT NOT NULL,
                    asset_name       TEXT NOT NULL DEFAULT '',
                    deployment_type  TEXT NOT NULL DEFAULT 'manual',
                    status           TEXT NOT NULL DEFAULT 'pending',
                    deployed_by      TEXT NOT NULL DEFAULT '',
                    started_at       DATETIME,
                    completed_at     DATETIME,
                    error_msg        TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pd_org_status
                    ON patch_deployments (org_id, status, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_pd_org_patch
                    ON patch_deployments (org_id, patch_id);

                CREATE TABLE IF NOT EXISTS patch_exceptions (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    patch_id     TEXT NOT NULL,
                    asset_id     TEXT NOT NULL,
                    reason       TEXT NOT NULL DEFAULT '',
                    approved_by  TEXT NOT NULL DEFAULT '',
                    expires_at   DATETIME,
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pe_org
                    ON patch_exceptions (org_id, patch_id, asset_id);

                CREATE TABLE IF NOT EXISTS patch_windows (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL DEFAULT '',
                    schedule_cron   TEXT NOT NULL DEFAULT '',
                    asset_groups    TEXT NOT NULL DEFAULT '[]',
                    auto_approve    INTEGER NOT NULL DEFAULT 0,
                    max_batch_pct   INTEGER NOT NULL DEFAULT 20,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pw_org
                    ON patch_windows (org_id);
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
    # Patch Catalog
    # ------------------------------------------------------------------

    def add_patch(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a patch to the catalog. Returns the created record."""
        patch_id = (data.get("patch_id") or "").strip()
        if not patch_id:
            raise ValueError("patch_id is required.")

        patch_type = data.get("patch_type", "security")
        if patch_type not in _VALID_PATCH_TYPES:
            raise ValueError(f"Invalid patch_type: {patch_type}. Must be one of {_VALID_PATCH_TYPES}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}.")

        status = data.get("status", "available")
        if status not in _VALID_PATCH_STATUSES:
            raise ValueError(f"Invalid status: {status}.")

        cves = data.get("cves_addressed", [])
        if isinstance(cves, list):
            cves_json = json.dumps(cves)
        else:
            cves_json = str(cves)

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "patch_id": patch_id,
            "vendor": data.get("vendor", ""),
            "product": data.get("product", ""),
            "version": data.get("version", ""),
            "patch_type": patch_type,
            "cves_addressed": cves_json,
            "severity": severity,
            "release_date": data.get("release_date"),
            "kb_article": data.get("kb_article", ""),
            "download_url": data.get("download_url", ""),
            "status": status,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO patch_catalog
                       (id, org_id, patch_id, vendor, product, version, patch_type,
                        cves_addressed, severity, release_date, kb_article, download_url,
                        status, created_at)
                       VALUES (:id, :org_id, :patch_id, :vendor, :product, :version, :patch_type,
                               :cves_addressed, :severity, :release_date, :kb_article, :download_url,
                               :status, :created_at)""",
                    record,
                )
        record["cves_addressed"] = cves
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("PLAYBOOK_EXECUTED", {"entity_type": "patch_automation", "org_id": org_id, "source_engine": "patch_automation"})
            except Exception:
                pass

        return record

    def list_patches(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        vendor: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List patches from catalog with optional filters."""
        sql = "SELECT * FROM patch_catalog WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if vendor:
            sql += " AND vendor = ?"
            params.append(vendor)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            d = self._row(row)
            try:
                d["cves_addressed"] = json.loads(d["cves_addressed"])
            except Exception:
                d["cves_addressed"] = []
            results.append(d)
        return results

    def approve_patch(self, org_id: str, patch_id: str) -> bool:
        """Approve a patch (sets status=approved). Returns True if found."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE patch_catalog SET status = 'approved' WHERE org_id = ? AND id = ?",
                    (org_id, patch_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Deployments
    # ------------------------------------------------------------------

    def deploy_patch(
        self,
        org_id: str,
        patch_id: str,
        asset_id: str,
        asset_name: str,
        deployed_by: str,
        deployment_type: str = "manual",
    ) -> Dict[str, Any]:
        """Create a deployment record with status=pending. Returns the record."""
        if deployment_type not in _VALID_DEPLOYMENT_TYPES:
            raise ValueError(f"Invalid deployment_type: {deployment_type}.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "patch_id": patch_id,
            "asset_id": asset_id,
            "asset_name": asset_name,
            "deployment_type": deployment_type,
            "status": "pending",
            "deployed_by": deployed_by,
            "started_at": now,
            "completed_at": None,
            "error_msg": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO patch_deployments
                       (id, org_id, patch_id, asset_id, asset_name, deployment_type,
                        status, deployed_by, started_at, completed_at, error_msg, created_at)
                       VALUES (:id, :org_id, :patch_id, :asset_id, :asset_name, :deployment_type,
                               :status, :deployed_by, :started_at, :completed_at, :error_msg, :created_at)""",
                    record,
                )
        return record

    def update_deployment(
        self,
        org_id: str,
        deployment_id: str,
        status: str,
        error_msg: Optional[str] = None,
    ) -> bool:
        """Update a deployment's status. Returns True if found and updated."""
        if status not in _VALID_DEPLOYMENT_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_DEPLOYMENT_STATUSES}")

        now = _now_iso()
        completed_at = now if status in ("success", "failed", "rolled_back") else None

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE patch_deployments
                       SET status = ?, completed_at = ?, error_msg = COALESCE(?, error_msg)
                       WHERE org_id = ? AND id = ?""",
                    (status, completed_at, error_msg, org_id, deployment_id),
                )
                return cur.rowcount > 0

    def list_deployments(
        self,
        org_id: str,
        status: Optional[str] = None,
        patch_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List deployments with optional filters."""
        sql = "SELECT * FROM patch_deployments WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if patch_id:
            sql += " AND patch_id = ?"
            params.append(patch_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Exceptions
    # ------------------------------------------------------------------

    def add_exception(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a patch exception (risk acceptance). Returns the created record."""
        patch_id = (data.get("patch_id") or "").strip()
        asset_id = (data.get("asset_id") or "").strip()
        if not patch_id or not asset_id:
            raise ValueError("patch_id and asset_id are required.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "patch_id": patch_id,
            "asset_id": asset_id,
            "reason": data.get("reason", ""),
            "approved_by": data.get("approved_by", ""),
            "expires_at": data.get("expires_at"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO patch_exceptions
                       (id, org_id, patch_id, asset_id, reason, approved_by, expires_at, created_at)
                       VALUES (:id, :org_id, :patch_id, :asset_id, :reason, :approved_by,
                               :expires_at, :created_at)""",
                    record,
                )
        return record

    def list_exceptions(self, org_id: str) -> List[Dict[str, Any]]:
        """List all patch exceptions for the org."""
        with self._conn() as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM patch_exceptions WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Maintenance Windows
    # ------------------------------------------------------------------

    def create_patch_window(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a maintenance window. Returns the created record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        asset_groups = data.get("asset_groups", [])
        if isinstance(asset_groups, list):
            asset_groups_json = json.dumps(asset_groups)
        else:
            asset_groups_json = str(asset_groups)

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "schedule_cron": data.get("schedule_cron", ""),
            "asset_groups": asset_groups_json,
            "auto_approve": 1 if data.get("auto_approve", False) else 0,
            "max_batch_pct": int(data.get("max_batch_pct", 20)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO patch_windows
                       (id, org_id, name, schedule_cron, asset_groups, auto_approve,
                        max_batch_pct, created_at)
                       VALUES (:id, :org_id, :name, :schedule_cron, :asset_groups,
                               :auto_approve, :max_batch_pct, :created_at)""",
                    record,
                )
        record["asset_groups"] = asset_groups
        record["auto_approve"] = bool(record["auto_approve"])
        return record

    def list_patch_windows(self, org_id: str) -> List[Dict[str, Any]]:
        """List all maintenance windows for the org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM patch_windows WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        results = []
        for row in rows:
            d = self._row(row)
            try:
                d["asset_groups"] = json.loads(d["asset_groups"])
            except Exception:
                d["asset_groups"] = []
            d["auto_approve"] = bool(d["auto_approve"])
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # CVE → Patch Mapping
    # ------------------------------------------------------------------

    def get_cve_patch_map(self, org_id: str, cve_id: str) -> List[Dict[str, Any]]:
        """Find all patches in the catalog that address the given CVE.

        Uses JSON text search (SQLite LIKE) on the cves_addressed column.
        """
        search_term = f'%"{cve_id}"%'
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM patch_catalog
                   WHERE org_id = ? AND cves_addressed LIKE ?
                   ORDER BY created_at DESC""",
                (org_id, search_term),
            ).fetchall()
        results = []
        for row in rows:
            d = self._row(row)
            try:
                d["cves_addressed"] = json.loads(d["cves_addressed"])
            except Exception:
                d["cves_addressed"] = []
            # Verify cve_id is actually in the list (avoid false LIKE matches)
            if cve_id in d["cves_addressed"]:
                results.append(d)
        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_patch_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated patch management stats for the org."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._conn() as conn:
            total_patches = conn.execute(
                "SELECT COUNT(*) FROM patch_catalog WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_severity_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM patch_catalog WHERE org_id = ?
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in by_severity_rows}

            by_status_rows = conn.execute(
                """SELECT status, COUNT(*) as cnt FROM patch_catalog WHERE org_id = ?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in by_status_rows}

            deployments_today = conn.execute(
                "SELECT COUNT(*) FROM patch_deployments WHERE org_id = ? AND created_at >= ?",
                (org_id, today),
            ).fetchone()[0]

            total_deployments = conn.execute(
                "SELECT COUNT(*) FROM patch_deployments WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            success_deployments = conn.execute(
                "SELECT COUNT(*) FROM patch_deployments WHERE org_id = ? AND status = 'success'",
                (org_id,),
            ).fetchone()[0]
            success_rate = round(
                (success_deployments / total_deployments * 100) if total_deployments > 0 else 0.0, 2
            )

            pending_critical = conn.execute(
                """SELECT COUNT(*) FROM patch_catalog
                   WHERE org_id = ? AND severity = 'critical' AND status IN ('available', 'testing')""",
                (org_id,),
            ).fetchone()[0]

            exceptions_count = conn.execute(
                "SELECT COUNT(*) FROM patch_exceptions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

        return {
            "total_patches": total_patches,
            "by_severity": by_severity,
            "by_status": by_status,
            "deployments_today": deployments_today,
            "success_rate": success_rate,
            "pending_critical": pending_critical,
            "exceptions_count": exceptions_count,
        }


# ---------------------------------------------------------------------------
# Module-level singleton registry (one engine per org_id)
# ---------------------------------------------------------------------------
_engines: Dict[str, PatchAutomationEngine] = {}
_engines_lock = threading.Lock()


def get_engine(org_id: str, db_dir: str = str(_DEFAULT_DB_DIR)) -> PatchAutomationEngine:
    """Return (or create) the PatchAutomationEngine for the given org."""
    with _engines_lock:
        if org_id not in _engines:
            _engines[org_id] = PatchAutomationEngine(org_id=org_id, db_dir=db_dir)
        return _engines[org_id]
