"""ServiceNow Sync Engine — ALDECI.

SQLite WAL-backed engine for tracking ServiceNow synchronization state,
field mappings, connection configs, and sync history.

Capabilities:
  - Store and manage ServiceNow instance connections (OAuth2 credentials)
  - Track CMDB sync state (last sync, CI counts, delta tracking)
  - Track incident sync state (pushed/pulled, sys_id mapping)
  - Track change request lifecycle
  - Field mapping configuration (ALDECI <-> ServiceNow)
  - Sync history with error logging
  - Multi-tenant org_id isolation

Compliance: ITIL v4, NIST CSF ID.AM, ISO 27001 A.8.1
"""

from __future__ import annotations

import hashlib
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "servicenow_sync.db"
)

_VALID_SYNC_TYPES = {"cmdb", "incident", "change_request", "full"}
_VALID_SYNC_STATUSES = {"pending", "running", "completed", "failed", "cancelled"}
_VALID_DIRECTIONS = {"pull", "push", "bidirectional"}
_VALID_CONNECTION_STATUSES = {"active", "inactive", "error", "testing"}
_VALID_CI_CLASSES = {
    "cmdb_ci_server",
    "cmdb_ci_vm_instance",
    "cmdb_ci_app_server",
    "cmdb_ci_database",
    "cmdb_ci_linux_server",
    "cmdb_ci_win_server",
    "cmdb_ci_cloud_service",
    "cmdb_ci_network_device",
    "cmdb_ci_storage_device",
    "cmdb_ci_endpoint",
}
_VALID_INCIDENT_STATES = {
    "new", "in_progress", "on_hold", "resolved", "closed", "cancelled",
}
_VALID_CHANGE_TYPES = {"standard", "normal", "emergency"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ServiceNowSyncEngine:
    """SQLite WAL-backed ServiceNow sync state engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/servicenow_sync.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS connections (
                    connection_id       TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    instance_url        TEXT NOT NULL,
                    client_id_hash      TEXT NOT NULL DEFAULT '',
                    client_secret_hash  TEXT NOT NULL DEFAULT '',
                    username            TEXT NOT NULL DEFAULT '',
                    auth_method         TEXT NOT NULL DEFAULT 'oauth2',
                    status              TEXT NOT NULL DEFAULT 'inactive',
                    last_health_check   TEXT,
                    last_health_ok      INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_connections_org
                    ON connections(org_id);

                CREATE TABLE IF NOT EXISTS sync_jobs (
                    job_id          TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    connection_id   TEXT NOT NULL,
                    sync_type       TEXT NOT NULL DEFAULT 'cmdb',
                    direction       TEXT NOT NULL DEFAULT 'pull',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    items_total     INTEGER NOT NULL DEFAULT 0,
                    items_synced    INTEGER NOT NULL DEFAULT 0,
                    items_failed    INTEGER NOT NULL DEFAULT 0,
                    error_message   TEXT,
                    started_at      TEXT,
                    completed_at    TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sync_jobs_org
                    ON sync_jobs(org_id);
                CREATE INDEX IF NOT EXISTS idx_sync_jobs_conn
                    ON sync_jobs(connection_id);

                CREATE TABLE IF NOT EXISTS cmdb_assets (
                    asset_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    connection_id   TEXT NOT NULL,
                    snow_sys_id     TEXT NOT NULL,
                    snow_ci_class   TEXT NOT NULL DEFAULT 'cmdb_ci_server',
                    name            TEXT NOT NULL DEFAULT '',
                    ip_address      TEXT,
                    os              TEXT,
                    environment     TEXT,
                    category        TEXT,
                    attributes      TEXT NOT NULL DEFAULT '{}',
                    aldeci_asset_id TEXT,
                    last_synced_at  TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cmdb_org
                    ON cmdb_assets(org_id);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_cmdb_snow_sys
                    ON cmdb_assets(org_id, connection_id, snow_sys_id);

                CREATE TABLE IF NOT EXISTS incident_mappings (
                    mapping_id          TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    connection_id       TEXT NOT NULL,
                    aldeci_alert_id     TEXT NOT NULL,
                    snow_sys_id         TEXT NOT NULL DEFAULT '',
                    snow_number         TEXT NOT NULL DEFAULT '',
                    snow_state          TEXT NOT NULL DEFAULT 'new',
                    direction           TEXT NOT NULL DEFAULT 'push',
                    last_synced_at      TEXT NOT NULL,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incident_map_org
                    ON incident_mappings(org_id);

                CREATE TABLE IF NOT EXISTS change_requests (
                    change_id           TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    connection_id       TEXT NOT NULL,
                    snow_sys_id         TEXT NOT NULL DEFAULT '',
                    snow_number         TEXT NOT NULL DEFAULT '',
                    change_type         TEXT NOT NULL DEFAULT 'standard',
                    short_description   TEXT NOT NULL DEFAULT '',
                    justification       TEXT NOT NULL DEFAULT '',
                    risk_level          TEXT NOT NULL DEFAULT 'medium',
                    state               TEXT NOT NULL DEFAULT 'new',
                    aldeci_remediation_id TEXT,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_change_req_org
                    ON change_requests(org_id);

                CREATE TABLE IF NOT EXISTS field_mappings (
                    mapping_id      TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    connection_id   TEXT NOT NULL,
                    sync_type       TEXT NOT NULL DEFAULT 'cmdb',
                    aldeci_field    TEXT NOT NULL,
                    snow_field      TEXT NOT NULL,
                    transform       TEXT NOT NULL DEFAULT 'direct',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_field_map_org
                    ON field_mappings(org_id);
            """)

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def create_connection(
        self,
        org_id: str,
        instance_url: str,
        *,
        client_id: str = "",
        client_secret: str = "",
        username: str = "",
        auth_method: str = "oauth2",
    ) -> Dict[str, Any]:
        """Register a new ServiceNow instance connection."""
        with self._lock:
            conn_id = str(uuid.uuid4())
            now = _now()
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO connections
                       (connection_id, org_id, instance_url, client_id_hash,
                        client_secret_hash, username, auth_method, status,
                        created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?)""",
                    (
                        conn_id,
                        org_id,
                        instance_url.rstrip("/"),
                        _hash_secret(client_id) if client_id else "",
                        _hash_secret(client_secret) if client_secret else "",
                        username,
                        auth_method,
                        now,
                        now,
                    ),
                )
            self._emit_event("SERVICENOW_CONNECTION_CREATED", {
                "org_id": org_id,
                "connection_id": conn_id,
                "instance_url": instance_url,
            })
            return {
                "connection_id": conn_id,
                "org_id": org_id,
                "instance_url": instance_url.rstrip("/"),
                "auth_method": auth_method,
                "status": "inactive",
                "created_at": now,
            }

    def get_connection(self, org_id: str, connection_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single connection by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """SELECT connection_id, org_id, instance_url, auth_method,
                              status, last_health_check, last_health_ok,
                              created_at, updated_at
                       FROM connections
                       WHERE connection_id = ? AND org_id = ?""",
                    (connection_id, org_id),
                ).fetchone()
            if row is None:
                return None
            return dict(row)

    def list_connections(self, org_id: str) -> List[Dict[str, Any]]:
        """List all connections for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT connection_id, org_id, instance_url, auth_method,
                              status, last_health_check, last_health_ok,
                              created_at, updated_at
                       FROM connections
                       WHERE org_id = ?
                       ORDER BY created_at DESC""",
                    (org_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    def update_connection_status(
        self, org_id: str, connection_id: str, status: str, *, health_ok: bool = False
    ) -> bool:
        """Update connection status after health check."""
        if status not in _VALID_CONNECTION_STATUSES:
            return False
        with self._lock:
            now = _now()
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE connections
                       SET status = ?, last_health_check = ?,
                           last_health_ok = ?, updated_at = ?
                       WHERE connection_id = ? AND org_id = ?""",
                    (status, now, int(health_ok), now, connection_id, org_id),
                )
            return cur.rowcount > 0

    def delete_connection(self, org_id: str, connection_id: str) -> bool:
        """Delete a connection and all associated data."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "DELETE FROM connections WHERE connection_id = ? AND org_id = ?",
                    (connection_id, org_id),
                )
                if cur.rowcount == 0:
                    return False
                conn.execute(
                    "DELETE FROM sync_jobs WHERE connection_id = ? AND org_id = ?",
                    (connection_id, org_id),
                )
                conn.execute(
                    "DELETE FROM cmdb_assets WHERE connection_id = ? AND org_id = ?",
                    (connection_id, org_id),
                )
                conn.execute(
                    "DELETE FROM incident_mappings WHERE connection_id = ? AND org_id = ?",
                    (connection_id, org_id),
                )
                conn.execute(
                    "DELETE FROM change_requests WHERE connection_id = ? AND org_id = ?",
                    (connection_id, org_id),
                )
                conn.execute(
                    "DELETE FROM field_mappings WHERE connection_id = ? AND org_id = ?",
                    (connection_id, org_id),
                )
            return True

    # ------------------------------------------------------------------
    # Sync jobs
    # ------------------------------------------------------------------

    def create_sync_job(
        self,
        org_id: str,
        connection_id: str,
        sync_type: str = "cmdb",
        direction: str = "pull",
    ) -> Dict[str, Any]:
        """Create a new sync job."""
        if sync_type not in _VALID_SYNC_TYPES:
            raise ValueError(f"Invalid sync_type: {sync_type}")
        if direction not in _VALID_DIRECTIONS:
            raise ValueError(f"Invalid direction: {direction}")
        with self._lock:
            job_id = str(uuid.uuid4())
            now = _now()
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sync_jobs
                       (job_id, org_id, connection_id, sync_type, direction,
                        status, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)""",
                    (job_id, org_id, connection_id, sync_type, direction, now, now),
                )
            return {
                "job_id": job_id,
                "org_id": org_id,
                "connection_id": connection_id,
                "sync_type": sync_type,
                "direction": direction,
                "status": "pending",
                "created_at": now,
            }

    def update_sync_job(
        self,
        org_id: str,
        job_id: str,
        *,
        status: Optional[str] = None,
        items_total: Optional[int] = None,
        items_synced: Optional[int] = None,
        items_failed: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        """Update sync job progress."""
        if status is not None and status not in _VALID_SYNC_STATUSES:
            return False
        with self._lock:
            now = _now()
            sets: List[str] = ["updated_at = ?"]
            params: List[Any] = [now]
            if status is not None:
                sets.append("status = ?")
                params.append(status)
                if status == "running":
                    sets.append("started_at = ?")
                    params.append(now)
                elif status in ("completed", "failed", "cancelled"):
                    sets.append("completed_at = ?")
                    params.append(now)
            if items_total is not None:
                sets.append("items_total = ?")
                params.append(items_total)
            if items_synced is not None:
                sets.append("items_synced = ?")
                params.append(items_synced)
            if items_failed is not None:
                sets.append("items_failed = ?")
                params.append(items_failed)
            if error_message is not None:
                sets.append("error_message = ?")
                params.append(error_message)
            params.extend([job_id, org_id])
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE sync_jobs SET {', '.join(sets)} WHERE job_id = ? AND org_id = ?",
                    params,
                )
            return cur.rowcount > 0

    def get_sync_job(self, org_id: str, job_id: str) -> Optional[Dict[str, Any]]:
        """Get a single sync job."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM sync_jobs WHERE job_id = ? AND org_id = ?",
                    (job_id, org_id),
                ).fetchone()
            return dict(row) if row else None

    def list_sync_jobs(
        self, org_id: str, *, connection_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List sync jobs, optionally filtered by connection."""
        with self._lock:
            q = "SELECT * FROM sync_jobs WHERE org_id = ?"
            params: List[Any] = [org_id]
            if connection_id:
                q += " AND connection_id = ?"
                params.append(connection_id)
            q += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            with self._conn() as conn:
                rows = conn.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # CMDB assets
    # ------------------------------------------------------------------

    def upsert_cmdb_asset(
        self,
        org_id: str,
        connection_id: str,
        snow_sys_id: str,
        *,
        snow_ci_class: str = "cmdb_ci_server",
        name: str = "",
        ip_address: Optional[str] = None,
        os: Optional[str] = None,
        environment: Optional[str] = None,
        category: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        aldeci_asset_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Upsert a CMDB CI as an ALDECI asset (INSERT OR REPLACE on sys_id)."""
        if snow_ci_class not in _VALID_CI_CLASSES:
            snow_ci_class = "cmdb_ci_server"
        with self._lock:
            now = _now()
            attrs_json = json.dumps(attributes or {})
            with self._conn() as conn:
                existing = conn.execute(
                    """SELECT asset_id FROM cmdb_assets
                       WHERE org_id = ? AND connection_id = ? AND snow_sys_id = ?""",
                    (org_id, connection_id, snow_sys_id),
                ).fetchone()
                if existing:
                    asset_id = existing["asset_id"]
                    conn.execute(
                        """UPDATE cmdb_assets
                           SET name = ?, snow_ci_class = ?, ip_address = ?,
                               os = ?, environment = ?, category = ?,
                               attributes = ?, aldeci_asset_id = ?,
                               last_synced_at = ?, updated_at = ?
                           WHERE asset_id = ? AND org_id = ?""",
                        (
                            name, snow_ci_class, ip_address, os,
                            environment, category, attrs_json,
                            aldeci_asset_id, now, now, asset_id, org_id,
                        ),
                    )
                else:
                    asset_id = str(uuid.uuid4())
                    conn.execute(
                        """INSERT INTO cmdb_assets
                           (asset_id, org_id, connection_id, snow_sys_id,
                            snow_ci_class, name, ip_address, os, environment,
                            category, attributes, aldeci_asset_id,
                            last_synced_at, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            asset_id, org_id, connection_id, snow_sys_id,
                            snow_ci_class, name, ip_address, os,
                            environment, category, attrs_json,
                            aldeci_asset_id, now, now, now,
                        ),
                    )
            self._emit_event("CMDB_ASSET_SYNCED", {
                "org_id": org_id,
                "asset_id": asset_id,
                "snow_sys_id": snow_sys_id,
                "snow_ci_class": snow_ci_class,
            })
            return {
                "asset_id": asset_id,
                "snow_sys_id": snow_sys_id,
                "name": name,
                "snow_ci_class": snow_ci_class,
                "last_synced_at": now,
            }

    def list_cmdb_assets(
        self, org_id: str, *, connection_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List synced CMDB assets."""
        with self._lock:
            q = "SELECT * FROM cmdb_assets WHERE org_id = ?"
            params: List[Any] = [org_id]
            if connection_id:
                q += " AND connection_id = ?"
                params.append(connection_id)
            q += " ORDER BY last_synced_at DESC LIMIT ?"
            params.append(limit)
            with self._conn() as conn:
                rows = conn.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    def get_cmdb_stats(self, org_id: str, connection_id: str) -> Dict[str, Any]:
        """Get CMDB sync statistics."""
        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM cmdb_assets WHERE org_id = ? AND connection_id = ?",
                    (org_id, connection_id),
                ).fetchone()[0]
                by_class = conn.execute(
                    """SELECT snow_ci_class, COUNT(*) as cnt
                       FROM cmdb_assets
                       WHERE org_id = ? AND connection_id = ?
                       GROUP BY snow_ci_class
                       ORDER BY cnt DESC""",
                    (org_id, connection_id),
                ).fetchall()
                last_sync = conn.execute(
                    """SELECT MAX(last_synced_at) FROM cmdb_assets
                       WHERE org_id = ? AND connection_id = ?""",
                    (org_id, connection_id),
                ).fetchone()[0]
            return {
                "total_assets": total,
                "by_class": {r["snow_ci_class"]: r["cnt"] for r in by_class},
                "last_synced_at": last_sync,
            }

    # ------------------------------------------------------------------
    # Incident mappings
    # ------------------------------------------------------------------

    def create_incident_mapping(
        self,
        org_id: str,
        connection_id: str,
        aldeci_alert_id: str,
        *,
        snow_sys_id: str = "",
        snow_number: str = "",
        snow_state: str = "new",
        direction: str = "push",
    ) -> Dict[str, Any]:
        """Record a mapping between ALDECI alert and ServiceNow incident."""
        with self._lock:
            mapping_id = str(uuid.uuid4())
            now = _now()
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incident_mappings
                       (mapping_id, org_id, connection_id, aldeci_alert_id,
                        snow_sys_id, snow_number, snow_state, direction,
                        last_synced_at, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        mapping_id, org_id, connection_id, aldeci_alert_id,
                        snow_sys_id, snow_number, snow_state, direction,
                        now, now, now,
                    ),
                )
            self._emit_event("INCIDENT_MAPPING_CREATED", {
                "org_id": org_id,
                "mapping_id": mapping_id,
                "aldeci_alert_id": aldeci_alert_id,
                "snow_number": snow_number,
            })
            return {
                "mapping_id": mapping_id,
                "aldeci_alert_id": aldeci_alert_id,
                "snow_sys_id": snow_sys_id,
                "snow_number": snow_number,
                "snow_state": snow_state,
                "direction": direction,
                "last_synced_at": now,
            }

    def update_incident_mapping(
        self,
        org_id: str,
        mapping_id: str,
        *,
        snow_sys_id: Optional[str] = None,
        snow_number: Optional[str] = None,
        snow_state: Optional[str] = None,
    ) -> bool:
        """Update an incident mapping after ServiceNow response."""
        with self._lock:
            now = _now()
            sets: List[str] = ["last_synced_at = ?", "updated_at = ?"]
            params: List[Any] = [now, now]
            if snow_sys_id is not None:
                sets.append("snow_sys_id = ?")
                params.append(snow_sys_id)
            if snow_number is not None:
                sets.append("snow_number = ?")
                params.append(snow_number)
            if snow_state is not None:
                if snow_state not in _VALID_INCIDENT_STATES:
                    return False
                sets.append("snow_state = ?")
                params.append(snow_state)
            params.extend([mapping_id, org_id])
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE incident_mappings SET {', '.join(sets)} WHERE mapping_id = ? AND org_id = ?",
                    params,
                )
            return cur.rowcount > 0

    def list_incident_mappings(
        self, org_id: str, *, connection_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List incident mappings."""
        with self._lock:
            q = "SELECT * FROM incident_mappings WHERE org_id = ?"
            params: List[Any] = [org_id]
            if connection_id:
                q += " AND connection_id = ?"
                params.append(connection_id)
            q += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            with self._conn() as conn:
                rows = conn.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Change requests
    # ------------------------------------------------------------------

    def create_change_request(
        self,
        org_id: str,
        connection_id: str,
        short_description: str,
        *,
        change_type: str = "standard",
        justification: str = "",
        risk_level: str = "medium",
        aldeci_remediation_id: Optional[str] = None,
        snow_sys_id: str = "",
        snow_number: str = "",
    ) -> Dict[str, Any]:
        """Record a change request linked to ServiceNow."""
        if change_type not in _VALID_CHANGE_TYPES:
            change_type = "standard"
        with self._lock:
            change_id = str(uuid.uuid4())
            now = _now()
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO change_requests
                       (change_id, org_id, connection_id, snow_sys_id, snow_number,
                        change_type, short_description, justification, risk_level,
                        state, aldeci_remediation_id, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?)""",
                    (
                        change_id, org_id, connection_id, snow_sys_id, snow_number,
                        change_type, short_description, justification, risk_level,
                        aldeci_remediation_id, now, now,
                    ),
                )
            self._emit_event("CHANGE_REQUEST_CREATED", {
                "org_id": org_id,
                "change_id": change_id,
                "change_type": change_type,
            })
            return {
                "change_id": change_id,
                "change_type": change_type,
                "short_description": short_description,
                "risk_level": risk_level,
                "state": "new",
                "snow_sys_id": snow_sys_id,
                "snow_number": snow_number,
                "created_at": now,
            }

    def list_change_requests(
        self, org_id: str, *, connection_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List change requests."""
        with self._lock:
            q = "SELECT * FROM change_requests WHERE org_id = ?"
            params: List[Any] = [org_id]
            if connection_id:
                q += " AND connection_id = ?"
                params.append(connection_id)
            q += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            with self._conn() as conn:
                rows = conn.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Field mappings
    # ------------------------------------------------------------------

    def set_field_mapping(
        self,
        org_id: str,
        connection_id: str,
        sync_type: str,
        aldeci_field: str,
        snow_field: str,
        *,
        transform: str = "direct",
    ) -> Dict[str, Any]:
        """Create or update a field mapping."""
        if sync_type not in _VALID_SYNC_TYPES:
            raise ValueError(f"Invalid sync_type: {sync_type}")
        with self._lock:
            now = _now()
            with self._conn() as conn:
                existing = conn.execute(
                    """SELECT mapping_id FROM field_mappings
                       WHERE org_id = ? AND connection_id = ?
                         AND sync_type = ? AND aldeci_field = ?""",
                    (org_id, connection_id, sync_type, aldeci_field),
                ).fetchone()
                if existing:
                    mapping_id = existing["mapping_id"]
                    conn.execute(
                        """UPDATE field_mappings
                           SET snow_field = ?, transform = ?, updated_at = ?
                           WHERE mapping_id = ?""",
                        (snow_field, transform, now, mapping_id),
                    )
                else:
                    mapping_id = str(uuid.uuid4())
                    conn.execute(
                        """INSERT INTO field_mappings
                           (mapping_id, org_id, connection_id, sync_type,
                            aldeci_field, snow_field, transform, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            mapping_id, org_id, connection_id, sync_type,
                            aldeci_field, snow_field, transform, now, now,
                        ),
                    )
            return {
                "mapping_id": mapping_id,
                "aldeci_field": aldeci_field,
                "snow_field": snow_field,
                "sync_type": sync_type,
                "transform": transform,
            }

    def list_field_mappings(
        self, org_id: str, *, connection_id: Optional[str] = None, sync_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List field mappings."""
        with self._lock:
            q = "SELECT * FROM field_mappings WHERE org_id = ?"
            params: List[Any] = [org_id]
            if connection_id:
                q += " AND connection_id = ?"
                params.append(connection_id)
            if sync_type:
                q += " AND sync_type = ?"
                params.append(sync_type)
            q += " ORDER BY sync_type, aldeci_field"
            with self._conn() as conn:
                rows = conn.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    def get_default_field_mappings(self, sync_type: str = "cmdb") -> List[Dict[str, str]]:
        """Return the recommended default field mappings."""
        if sync_type == "cmdb":
            return [
                {"aldeci_field": "name", "snow_field": "name", "transform": "direct"},
                {"aldeci_field": "ip_address", "snow_field": "ip_address", "transform": "direct"},
                {"aldeci_field": "os", "snow_field": "os", "transform": "direct"},
                {"aldeci_field": "environment", "snow_field": "u_environment", "transform": "direct"},
                {"aldeci_field": "category", "snow_field": "category", "transform": "direct"},
                {"aldeci_field": "asset_type", "snow_field": "sys_class_name", "transform": "direct"},
                {"aldeci_field": "serial_number", "snow_field": "serial_number", "transform": "direct"},
                {"aldeci_field": "owner", "snow_field": "assigned_to", "transform": "display_value"},
            ]
        elif sync_type == "incident":
            return [
                {"aldeci_field": "title", "snow_field": "short_description", "transform": "direct"},
                {"aldeci_field": "description", "snow_field": "description", "transform": "direct"},
                {"aldeci_field": "severity", "snow_field": "urgency", "transform": "severity_to_urgency"},
                {"aldeci_field": "priority", "snow_field": "impact", "transform": "priority_to_impact"},
                {"aldeci_field": "status", "snow_field": "state", "transform": "state_mapping"},
                {"aldeci_field": "assignee", "snow_field": "assigned_to", "transform": "display_value"},
            ]
        return []

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_sync_stats(self, org_id: str, connection_id: str) -> Dict[str, Any]:
        """Get overall sync statistics for a connection."""
        with self._lock:
            with self._conn() as conn:
                cmdb_count = conn.execute(
                    "SELECT COUNT(*) FROM cmdb_assets WHERE org_id = ? AND connection_id = ?",
                    (org_id, connection_id),
                ).fetchone()[0]
                incident_count = conn.execute(
                    "SELECT COUNT(*) FROM incident_mappings WHERE org_id = ? AND connection_id = ?",
                    (org_id, connection_id),
                ).fetchone()[0]
                change_count = conn.execute(
                    "SELECT COUNT(*) FROM change_requests WHERE org_id = ? AND connection_id = ?",
                    (org_id, connection_id),
                ).fetchone()[0]
                last_job = conn.execute(
                    """SELECT * FROM sync_jobs
                       WHERE org_id = ? AND connection_id = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (org_id, connection_id),
                ).fetchone()
                total_jobs = conn.execute(
                    "SELECT COUNT(*) FROM sync_jobs WHERE org_id = ? AND connection_id = ?",
                    (org_id, connection_id),
                ).fetchone()[0]
            return {
                "cmdb_assets": cmdb_count,
                "incident_mappings": incident_count,
                "change_requests": change_count,
                "total_sync_jobs": total_jobs,
                "last_sync_job": dict(last_job) if last_job else None,
            }

    # ------------------------------------------------------------------
    # TrustGraph event bus
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus:
                bus.emit(event_type, data)
        except Exception:
            _logger.debug("TrustGraph emit failed for %s", event_type, exc_info=True)
