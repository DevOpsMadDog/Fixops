"""Attack Surface Engine — ALDECI.

External attack surface monitoring and management.

Capabilities:
  - Surface asset discovery and registry (domains, IPs, ports, certs, APIs, cloud resources)
  - Exposure finding management (open ports, weak SSL, subdomain takeover, etc.)
  - Scan job lifecycle (pending → running → completed/failed)
  - Change tracking for surface mutations
  - Surface score calculation (100 - weighted exposure count)
  - Stats aggregation per org

Compliance: NIST SP 800-115, CIS Controls v8 (Control 7), OWASP Attack Surface Analysis
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_ASSET_TYPES = {
    "domain", "subdomain", "ip", "open_port", "certificate",
    "service", "api_endpoint", "cloud_resource",
}
_VALID_ASSET_STATUSES = {"active", "inactive", "expired"}
_VALID_EXPOSURE_TYPES = {
    "open_port", "outdated_service", "weak_ssl", "exposed_admin",
    "sensitive_path", "cors_misconfiguration", "subdomain_takeover_risk", "public_bucket",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_EXPOSURE_STATUSES = {"open", "mitigated", "accepted", "fixed"}
_VALID_SCAN_TYPES = {"full", "incremental", "targeted"}
_VALID_SCAN_STATUSES = {"pending", "running", "completed", "failed"}
_VALID_CHANGE_TYPES = {
    "new_asset", "asset_removed", "exposure_added", "exposure_fixed",
    "ssl_changed", "port_opened", "port_closed",
}

# Severity weights for surface score calculation
_SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttackSurfaceEngine:
    """SQLite WAL-backed Attack Surface engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org gets its own database file at .fixops_data/{org_id}_attack_surface.db
    """

    def __init__(self, db_dir: Optional[str] = None) -> None:
        self._db_dir = Path(db_dir) if db_dir else _DEFAULT_DB_DIR
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}
        self._lock_lock = threading.Lock()

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._lock_lock:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _db_path(self, org_id: str) -> str:
        return str(self._db_dir / f"{org_id}_attack_surface.db")

    def _conn(self, org_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS surface_assets (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    asset_type          TEXT NOT NULL,
                    value               TEXT NOT NULL,
                    parent_asset_id     TEXT,
                    status              TEXT NOT NULL DEFAULT 'active',
                    risk_score          REAL NOT NULL DEFAULT 0.0,
                    first_discovered    DATETIME NOT NULL,
                    last_seen           DATETIME NOT NULL,
                    tags                TEXT NOT NULL DEFAULT '[]',
                    notes               TEXT NOT NULL DEFAULT '',
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_assets_org_type
                    ON surface_assets (org_id, asset_type, status);

                CREATE INDEX IF NOT EXISTS idx_assets_org_risk
                    ON surface_assets (org_id, risk_score DESC);

                CREATE TABLE IF NOT EXISTS surface_exposures (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    asset_id            TEXT NOT NULL,
                    exposure_type       TEXT NOT NULL,
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    title               TEXT NOT NULL,
                    description         TEXT NOT NULL DEFAULT '',
                    evidence            TEXT NOT NULL DEFAULT '',
                    cvss_score          REAL NOT NULL DEFAULT 0.0,
                    remediation         TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL DEFAULT 'open',
                    first_detected      DATETIME NOT NULL,
                    last_seen           DATETIME NOT NULL,
                    fixed_date          DATETIME,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_exposures_org_severity
                    ON surface_exposures (org_id, severity, status);

                CREATE INDEX IF NOT EXISTS idx_exposures_org_asset
                    ON surface_exposures (org_id, asset_id);

                CREATE TABLE IF NOT EXISTS surface_scans (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    scan_type           TEXT NOT NULL DEFAULT 'full',
                    target_scope        TEXT NOT NULL DEFAULT '[]',
                    status              TEXT NOT NULL DEFAULT 'pending',
                    assets_discovered   INTEGER NOT NULL DEFAULT 0,
                    new_assets          INTEGER NOT NULL DEFAULT 0,
                    new_exposures       INTEGER NOT NULL DEFAULT 0,
                    critical_exposures  INTEGER NOT NULL DEFAULT 0,
                    started_at          DATETIME,
                    completed_at        DATETIME,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scans_org_status
                    ON surface_scans (org_id, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS surface_changes (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    asset_id            TEXT NOT NULL,
                    change_type         TEXT NOT NULL,
                    description         TEXT NOT NULL DEFAULT '',
                    severity            TEXT NOT NULL DEFAULT 'info',
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_changes_org_time
                    ON surface_changes (org_id, created_at DESC);
            """)

    def _ensure_db(self, org_id: str) -> None:
        """Ensure DB exists and is initialized for this org."""
        self._init_db(org_id)

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("tags", "target_scope"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    def _record_change(
        self,
        org_id: str,
        asset_id: str,
        change_type: str,
        description: str,
        severity: str = "info",
    ) -> None:
        """Record a surface change event."""
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "change_type": change_type,
            "description": description,
            "severity": severity,
            "created_at": _now_iso(),
        }
        with self._conn(org_id) as conn:
            conn.execute(
                """INSERT INTO surface_changes
                   (id, org_id, asset_id, change_type, description, severity, created_at)
                   VALUES (:id, :org_id, :asset_id, :change_type, :description, :severity, :created_at)""",
                record,
            )

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def add_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a surface asset."""
        self._ensure_db(org_id)
        asset_type = data.get("asset_type", "domain")
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(f"Invalid asset_type: {asset_type}. Must be one of {_VALID_ASSET_TYPES}")

        value = (data.get("value") or "").strip()
        if not value:
            raise ValueError("value is required.")

        status = data.get("status", "active")
        if status not in _VALID_ASSET_STATUSES:
            raise ValueError(f"Invalid status: {status}.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_type": asset_type,
            "value": value,
            "parent_asset_id": data.get("parent_asset_id"),
            "status": status,
            "risk_score": float(data.get("risk_score", 0.0)),
            "first_discovered": data.get("first_discovered", now),
            "last_seen": data.get("last_seen", now),
            "tags": json.dumps(data.get("tags", [])),
            "notes": data.get("notes", ""),
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO surface_assets
                       (id, org_id, asset_type, value, parent_asset_id, status, risk_score,
                        first_discovered, last_seen, tags, notes, created_at)
                       VALUES (:id, :org_id, :asset_type, :value, :parent_asset_id, :status,
                               :risk_score, :first_discovered, :last_seen, :tags, :notes, :created_at)""",
                    record,
                )
        # Record change outside the write transaction to avoid SQLite contention
        self._record_change(
            org_id, record["id"], "new_asset",
            f"New {asset_type} asset discovered: {value}", "medium",
        )
        result = dict(record)
        result["tags"] = json.loads(record["tags"])
        return result

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        status: Optional[str] = None,
        min_risk: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """List surface assets with optional filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM surface_assets WHERE org_id = ?"
        params: list = [org_id]
        if asset_type:
            sql += " AND asset_type = ?"
            params.append(asset_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if min_risk is not None:
            sql += " AND risk_score >= ?"
            params.append(min_risk)
        sql += " ORDER BY risk_score DESC, last_seen DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get asset with its exposures."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM surface_assets WHERE org_id = ? AND id = ?",
                (org_id, asset_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            exposures = conn.execute(
                "SELECT * FROM surface_exposures WHERE org_id = ? AND asset_id = ? ORDER BY severity DESC",
                (org_id, asset_id),
            ).fetchall()
            result["exposures"] = [self._row(e) for e in exposures]
        return result

    # ------------------------------------------------------------------
    # Exposures
    # ------------------------------------------------------------------

    def add_exposure(self, org_id: str, asset_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an exposure finding for an asset."""
        self._ensure_db(org_id)
        exposure_type = data.get("exposure_type", "open_port")
        if exposure_type not in _VALID_EXPOSURE_TYPES:
            raise ValueError(f"Invalid exposure_type: {exposure_type}.")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}.")

        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "exposure_type": exposure_type,
            "severity": severity,
            "title": title,
            "description": data.get("description", ""),
            "evidence": data.get("evidence", ""),
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "remediation": data.get("remediation", ""),
            "status": "open",
            "first_detected": data.get("first_detected", now),
            "last_seen": data.get("last_seen", now),
            "fixed_date": None,
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO surface_exposures
                       (id, org_id, asset_id, exposure_type, severity, title, description,
                        evidence, cvss_score, remediation, status, first_detected, last_seen,
                        fixed_date, created_at)
                       VALUES (:id, :org_id, :asset_id, :exposure_type, :severity, :title,
                               :description, :evidence, :cvss_score, :remediation, :status,
                               :first_detected, :last_seen, :fixed_date, :created_at)""",
                    record,
                )
                # Update asset risk score
                conn.execute(
                    "UPDATE surface_assets SET risk_score = risk_score + ? WHERE org_id = ? AND id = ?",
                    (_SEVERITY_WEIGHTS.get(severity, 0), org_id, asset_id),
                )
        # Record change outside the write transaction to avoid SQLite contention
        self._record_change(
            org_id, asset_id, "exposure_added",
            f"New {severity} exposure: {title}", severity,
        )
        return record

    def list_exposures(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        exposure_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List exposures with optional filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM surface_exposures WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if exposure_type:
            sql += " AND exposure_type = ?"
            params.append(exposure_type)
        sql += " ORDER BY severity DESC, last_seen DESC LIMIT ?"
        params.append(limit)
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def fix_exposure(self, org_id: str, exposure_id: str) -> bool:
        """Mark an exposure as fixed. Returns True if found."""
        self._ensure_db(org_id)
        now = _now_iso()
        asset_id = None
        severity = None
        updated = False
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                row = conn.execute(
                    "SELECT asset_id, severity FROM surface_exposures WHERE org_id = ? AND id = ?",
                    (org_id, exposure_id),
                ).fetchone()
                if not row:
                    return False
                cur = conn.execute(
                    "UPDATE surface_exposures SET status = 'fixed', fixed_date = ? WHERE org_id = ? AND id = ?",
                    (now, org_id, exposure_id),
                )
                if cur.rowcount > 0:
                    updated = True
                    asset_id = row["asset_id"]
                    severity = row["severity"]
                    conn.execute(
                        "UPDATE surface_assets SET risk_score = MAX(0, risk_score - ?) WHERE org_id = ? AND id = ?",
                        (_SEVERITY_WEIGHTS.get(severity, 0), org_id, asset_id),
                    )
        # Record change outside the write transaction to avoid SQLite contention
        if updated and asset_id:
            self._record_change(
                org_id, asset_id, "exposure_fixed",
                f"Exposure fixed: {exposure_id}", "low",
            )
        return updated

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def create_scan(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a scan job."""
        self._ensure_db(org_id)
        scan_type = data.get("scan_type", "full")
        if scan_type not in _VALID_SCAN_TYPES:
            raise ValueError(f"Invalid scan_type: {scan_type}.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "scan_type": scan_type,
            "target_scope": json.dumps(data.get("target_scope", [])),
            "status": "pending",
            "assets_discovered": 0,
            "new_assets": 0,
            "new_exposures": 0,
            "critical_exposures": 0,
            "started_at": None,
            "completed_at": None,
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO surface_scans
                       (id, org_id, scan_type, target_scope, status, assets_discovered,
                        new_assets, new_exposures, critical_exposures, started_at,
                        completed_at, created_at)
                       VALUES (:id, :org_id, :scan_type, :target_scope, :status,
                               :assets_discovered, :new_assets, :new_exposures,
                               :critical_exposures, :started_at, :completed_at, :created_at)""",
                    record,
                )
        result = dict(record)
        result["target_scope"] = json.loads(record["target_scope"])
        return result

    def complete_scan(
        self,
        org_id: str,
        scan_id: str,
        results: Dict[str, Any],
    ) -> bool:
        """Mark scan complete with discovery metrics. Returns True if found."""
        self._ensure_db(org_id)
        now = _now_iso()
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE surface_scans
                       SET status = 'completed', completed_at = ?,
                           assets_discovered = ?, new_assets = ?,
                           new_exposures = ?, critical_exposures = ?
                       WHERE org_id = ? AND id = ?""",
                    (
                        now,
                        int(results.get("assets_discovered", 0)),
                        int(results.get("new_assets", 0)),
                        int(results.get("new_exposures", 0)),
                        int(results.get("critical_exposures", 0)),
                        org_id,
                        scan_id,
                    ),
                )
                return cur.rowcount > 0

    def list_scans(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List scans with optional status filter."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM surface_scans WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Changes
    # ------------------------------------------------------------------

    def list_changes(
        self,
        org_id: str,
        days: int = 7,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List recent surface changes."""
        self._ensure_db(org_id)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        sql = "SELECT * FROM surface_changes WHERE org_id = ? AND created_at >= ?"
        params: list = [org_id, cutoff]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_surface_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated attack surface stats for org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM surface_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            total_exposures = conn.execute(
                "SELECT COUNT(*) FROM surface_exposures WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            open_critical = conn.execute(
                "SELECT COUNT(*) FROM surface_exposures WHERE org_id = ? AND severity = 'critical' AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            by_type_rows = conn.execute(
                "SELECT asset_type, COUNT(*) as cnt FROM surface_assets WHERE org_id = ? GROUP BY asset_type",
                (org_id,),
            ).fetchall()
            by_severity_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM surface_exposures WHERE org_id = ? AND status = 'open' GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_exposure_type_rows = conn.execute(
                "SELECT exposure_type, COUNT(*) as cnt FROM surface_exposures WHERE org_id = ? AND status = 'open' GROUP BY exposure_type",
                (org_id,),
            ).fetchall()

            # Recent changes (last 7 days)
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            recent_changes = conn.execute(
                "SELECT COUNT(*) FROM surface_changes WHERE org_id = ? AND created_at >= ?",
                (org_id, cutoff),
            ).fetchone()[0]

        # Calculate surface score: 100 - weighted open exposure penalty
        by_severity = {r["severity"]: r["cnt"] for r in by_severity_rows}
        penalty = sum(
            by_severity.get(sev, 0) * weight
            for sev, weight in _SEVERITY_WEIGHTS.items()
        )
        surface_score = max(0, 100 - penalty)

        return {
            "total_assets": total_assets,
            "total_exposures": total_exposures,
            "open_critical": open_critical,
            "surface_score": surface_score,
            "recent_changes": recent_changes,
            "by_type": {r["asset_type"]: r["cnt"] for r in by_type_rows},
            "by_severity": by_severity,
            "by_exposure_type": {r["exposure_type"]: r["cnt"] for r in by_exposure_type_rows},
        }
