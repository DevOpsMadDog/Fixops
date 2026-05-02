"""API Discovery Engine — ALDECI.

Discovers and catalogs API endpoints, detects shadow APIs, and tracks
API security posture across services.

Capabilities:
  - Endpoint registry with shadow API detection and org isolation
  - Scan management (passive/active/spider/import) with completion tracking
  - Change tracking (added/removed/modified/deprecated)
  - Stats: totals, by_service, by_method, unauthenticated, shadow count

Compliance: OWASP API Security Top 10, NIST SP 800-204
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "api_discovery.db"
)

_VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_VALID_API_TYPES = {"rest", "graphql", "grpc", "websocket", "soap"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "none"}
_VALID_SCAN_TYPES = {"passive", "active", "spider", "import"}
_VALID_SCAN_STATUSES = {"running", "completed", "failed"}
_VALID_CHANGE_TYPES = {"added", "removed", "modified", "deprecated"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class APIDiscoveryEngine:
    """SQLite WAL-backed API Discovery engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/api_discovery.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = _DEFAULT_DB_PATH
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_endpoints (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    service_name    TEXT NOT NULL,
                    endpoint_path   TEXT NOT NULL,
                    http_method     TEXT NOT NULL,
                    version         TEXT NOT NULL DEFAULT '',
                    api_type        TEXT NOT NULL DEFAULT 'rest',
                    auth_required   INTEGER NOT NULL DEFAULT 1,
                    is_documented   INTEGER NOT NULL DEFAULT 0,
                    is_shadow       INTEGER NOT NULL DEFAULT 0,
                    risk_level      TEXT NOT NULL DEFAULT 'none',
                    last_observed   TEXT NOT NULL,
                    discovered_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ep_org
                    ON api_endpoints (org_id, service_name, is_shadow, risk_level, api_type);

                CREATE TABLE IF NOT EXISTS api_scans (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    scan_name          TEXT NOT NULL,
                    scan_target        TEXT NOT NULL,
                    scan_type          TEXT NOT NULL DEFAULT 'passive',
                    status             TEXT NOT NULL DEFAULT 'running',
                    endpoints_found    INTEGER NOT NULL DEFAULT 0,
                    shadow_apis_found  INTEGER NOT NULL DEFAULT 0,
                    started_at         TEXT NOT NULL,
                    completed_at       TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_scans_org
                    ON api_scans (org_id, status, started_at DESC);

                CREATE TABLE IF NOT EXISTS api_changes (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    endpoint_id        TEXT NOT NULL,
                    change_type        TEXT NOT NULL,
                    change_description TEXT NOT NULL DEFAULT '',
                    detected_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_changes_org
                    ON api_changes (org_id, endpoint_id, change_type, detected_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    def register_endpoint(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a discovered API endpoint."""
        service_name = (data.get("service_name") or "").strip()
        if not service_name:
            raise ValueError("service_name is required.")
        endpoint_path = (data.get("endpoint_path") or "").strip()
        if not endpoint_path:
            raise ValueError("endpoint_path is required.")
        http_method = (data.get("http_method") or "").strip().upper()
        if http_method not in _VALID_HTTP_METHODS:
            raise ValueError(
                f"Invalid http_method: {http_method}. "
                f"Must be one of {_VALID_HTTP_METHODS}"
            )

        api_type = data.get("api_type", "rest")
        if api_type not in _VALID_API_TYPES:
            raise ValueError(
                f"Invalid api_type: {api_type}. Must be one of {_VALID_API_TYPES}"
            )

        risk_level = data.get("risk_level", "none")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level: {risk_level}. Must be one of {_VALID_RISK_LEVELS}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "service_name": service_name,
            "endpoint_path": endpoint_path,
            "http_method": http_method,
            "version": data.get("version", ""),
            "api_type": api_type,
            "auth_required": int(bool(data.get("auth_required", True))),
            "is_documented": int(bool(data.get("is_documented", False))),
            "is_shadow": int(bool(data.get("is_shadow", False))),
            "risk_level": risk_level,
            "last_observed": now,
            "discovered_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO api_endpoints
                       (id, org_id, service_name, endpoint_path, http_method, version,
                        api_type, auth_required, is_documented, is_shadow, risk_level,
                        last_observed, discovered_at)
                       VALUES (:id, :org_id, :service_name, :endpoint_path, :http_method,
                               :version, :api_type, :auth_required, :is_documented,
                               :is_shadow, :risk_level, :last_observed, :discovered_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "api_discovery", "org_id": org_id, "source_engine": "api_discovery"})
            except Exception:
                pass

        return record

    def list_endpoints(
        self,
        org_id: str,
        service_name: Optional[str] = None,
        is_shadow: Optional[bool] = None,
        risk_level: Optional[str] = None,
        api_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List endpoints with optional filters."""
        sql = "SELECT * FROM api_endpoints WHERE org_id = ?"
        params: List[Any] = [org_id]
        if service_name is not None:
            sql += " AND service_name = ?"
            params.append(service_name)
        if is_shadow is not None:
            sql += " AND is_shadow = ?"
            params.append(int(is_shadow))
        if risk_level is not None:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        if api_type is not None:
            sql += " AND api_type = ?"
            params.append(api_type)
        sql += " ORDER BY discovered_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_endpoint(self, org_id: str, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Get endpoint by UUID. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM api_endpoints WHERE id = ? AND org_id = ?",
                (endpoint_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def mark_as_shadow(self, org_id: str, endpoint_id: str) -> Dict[str, Any]:
        """Mark an endpoint as a shadow API and set risk_level=high."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE api_endpoints
                       SET is_shadow = 1, risk_level = 'high'
                       WHERE id = ? AND org_id = ?""",
                    (endpoint_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Endpoint '{endpoint_id}' not found in org '{org_id}'."
                    )
                row = conn.execute(
                    "SELECT * FROM api_endpoints WHERE id = ?", (endpoint_id,)
                ).fetchone()
        return self._row(row)

    def mark_as_documented(self, org_id: str, endpoint_id: str) -> Dict[str, Any]:
        """Mark an endpoint as documented."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE api_endpoints SET is_documented = 1 WHERE id = ? AND org_id = ?",
                    (endpoint_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Endpoint '{endpoint_id}' not found in org '{org_id}'."
                    )
                row = conn.execute(
                    "SELECT * FROM api_endpoints WHERE id = ?", (endpoint_id,)
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def create_scan(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new API discovery scan."""
        scan_name = (data.get("scan_name") or "").strip()
        if not scan_name:
            raise ValueError("scan_name is required.")
        scan_target = (data.get("scan_target") or "").strip()
        if not scan_target:
            raise ValueError("scan_target is required.")

        scan_type = data.get("scan_type", "passive")
        if scan_type not in _VALID_SCAN_TYPES:
            raise ValueError(
                f"Invalid scan_type: {scan_type}. Must be one of {_VALID_SCAN_TYPES}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "scan_name": scan_name,
            "scan_target": scan_target,
            "scan_type": scan_type,
            "status": "running",
            "endpoints_found": 0,
            "shadow_apis_found": 0,
            "started_at": now,
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO api_scans
                       (id, org_id, scan_name, scan_target, scan_type, status,
                        endpoints_found, shadow_apis_found, started_at, completed_at)
                       VALUES (:id, :org_id, :scan_name, :scan_target, :scan_type,
                               :status, :endpoints_found, :shadow_apis_found,
                               :started_at, :completed_at)""",
                    record,
                )
        return record

    def complete_scan(
        self, org_id: str, scan_id: str, results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mark a scan as completed with results."""
        now = _now_iso()
        endpoints_found = int(results.get("endpoints_found", 0))
        shadow_apis_found = int(results.get("shadow_apis_found", 0))
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE api_scans
                       SET status = 'completed', completed_at = ?,
                           endpoints_found = ?, shadow_apis_found = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, endpoints_found, shadow_apis_found, scan_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Scan '{scan_id}' not found in org '{org_id}'.")
                row = conn.execute(
                    "SELECT * FROM api_scans WHERE id = ?", (scan_id,)
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Changes
    # ------------------------------------------------------------------

    def record_change(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an API change event."""
        endpoint_id = (data.get("endpoint_id") or "").strip()
        if not endpoint_id:
            raise ValueError("endpoint_id is required.")

        # Verify endpoint exists in org
        existing = self.get_endpoint(org_id, endpoint_id)
        if existing is None:
            raise ValueError(
                f"Endpoint '{endpoint_id}' not found in org '{org_id}'."
            )

        change_type = data.get("change_type", "")
        if change_type not in _VALID_CHANGE_TYPES:
            raise ValueError(
                f"Invalid change_type: {change_type}. Must be one of {_VALID_CHANGE_TYPES}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "endpoint_id": endpoint_id,
            "change_type": change_type,
            "change_description": data.get("change_description", ""),
            "detected_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO api_changes
                       (id, org_id, endpoint_id, change_type, change_description, detected_at)
                       VALUES (:id, :org_id, :endpoint_id, :change_type,
                               :change_description, :detected_at)""",
                    record,
                )
        return record

    def list_changes(
        self,
        org_id: str,
        endpoint_id: Optional[str] = None,
        change_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List API changes with optional filters."""
        sql = "SELECT * FROM api_changes WHERE org_id = ?"
        params: List[Any] = [org_id]
        if endpoint_id is not None:
            sql += " AND endpoint_id = ?"
            params.append(endpoint_id)
        if change_type is not None:
            sql += " AND change_type = ?"
            params.append(change_type)
        sql += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_api_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate API discovery stats for an org."""
        seven_days_ago = (
            datetime.now(timezone.utc) - timedelta(days=7)
        ).isoformat()

        with self._conn() as conn:
            total_endpoints = conn.execute(
                "SELECT COUNT(*) FROM api_endpoints WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            shadow_apis = conn.execute(
                "SELECT COUNT(*) FROM api_endpoints WHERE org_id = ? AND is_shadow = 1",
                (org_id,),
            ).fetchone()[0]
            documented_count = conn.execute(
                "SELECT COUNT(*) FROM api_endpoints WHERE org_id = ? AND is_documented = 1",
                (org_id,),
            ).fetchone()[0]
            undocumented_count = conn.execute(
                "SELECT COUNT(*) FROM api_endpoints WHERE org_id = ? AND is_documented = 0",
                (org_id,),
            ).fetchone()[0]
            unauthenticated_endpoints = conn.execute(
                "SELECT COUNT(*) FROM api_endpoints WHERE org_id = ? AND auth_required = 0",
                (org_id,),
            ).fetchone()[0]
            total_scans = conn.execute(
                "SELECT COUNT(*) FROM api_scans WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            recent_changes = conn.execute(
                "SELECT COUNT(*) FROM api_changes WHERE org_id = ? AND detected_at >= ?",
                (org_id, seven_days_ago),
            ).fetchone()[0]

            by_service_rows = conn.execute(
                """SELECT service_name, COUNT(*) as cnt
                   FROM api_endpoints WHERE org_id = ?
                   GROUP BY service_name""",
                (org_id,),
            ).fetchall()
            by_method_rows = conn.execute(
                """SELECT http_method, COUNT(*) as cnt
                   FROM api_endpoints WHERE org_id = ?
                   GROUP BY http_method""",
                (org_id,),
            ).fetchall()

        by_service = {r["service_name"]: r["cnt"] for r in by_service_rows}
        by_method = {r["http_method"]: r["cnt"] for r in by_method_rows}

        return {
            "total_endpoints": total_endpoints,
            "shadow_apis": shadow_apis,
            "documented_count": documented_count,
            "undocumented_count": undocumented_count,
            "by_service": by_service,
            "by_method": by_method,
            "unauthenticated_endpoints": unauthenticated_endpoints,
            "total_scans": total_scans,
            "recent_changes": recent_changes,
        }

    # ------------------------------------------------------------------
    # GAP-065 — Architecture-aware graph: link API endpoint to layer
    # ------------------------------------------------------------------

    def link_to_layer(
        self,
        org_id: str,
        endpoint_path: str,
        layer: str = "api",
    ) -> Dict[str, Any]:
        """Associate an API endpoint with its architecture layer.

        Delegates the write to SecurityDependencyMappingEngine's
        layer_classifications table — no schema change on this engine.

        Fails gracefully if the dependency mapping engine is unavailable.
        """
        if not endpoint_path:
            raise ValueError("endpoint_path is required")
        try:
            from core.security_dependency_mapping_engine import (
                SecurityDependencyMappingEngine,
            )
        except ImportError:
            _logger.warning(
                "api_discovery.link_to_layer.dep_map_missing org=%s endpoint=%s",
                org_id, endpoint_path,
            )
            return {
                "node_ref": endpoint_path,
                "layer": layer,
                "confidence": 0.0,
                "signals": ["dep_map_unavailable"],
                "linked": False,
            }

        dep = SecurityDependencyMappingEngine()
        record = dep.upsert_layer(
            org_id=org_id,
            node_ref=endpoint_path,
            layer=layer,
            confidence=0.95,
            signals=["api_discovery_link"],
        )
        record["linked"] = True
        _logger.info(
            "api_discovery.linked org=%s endpoint=%s layer=%s", org_id, endpoint_path, layer,
        )
        return record
