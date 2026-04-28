"""API Inventory Engine — ALDECI.

Manages API registration, endpoint tracking, and security posture.

Capabilities:
  - API registry with type, auth, and status tracking
  - Endpoint discovery and risk tracking per API
  - Automatic endpoint_count update on add_endpoint
  - Stats aggregation per org (unauthenticated/undocumented endpoints, by_type)

Compliance: OWASP API Security Top 10, NIST SP 800-95
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "api_inventory.db")

_VALID_API_TYPES = {"rest", "graphql", "grpc", "soap", "websocket", "event"}
_VALID_AUTH_TYPES = {"api_key", "oauth2", "jwt", "basic", "none", "mutual_tls"}
_VALID_API_STATUSES = {"active", "deprecated", "retired", "beta", "internal"}
_VALID_ENDPOINT_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "none"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class APIInventoryEngine:
    """SQLite WAL-backed API Inventory engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Database stored at .fixops_data/api_inventory.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS apis (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    api_name          TEXT NOT NULL DEFAULT '',
                    api_type          TEXT NOT NULL DEFAULT 'rest',
                    version           TEXT NOT NULL DEFAULT '',
                    base_url          TEXT NOT NULL DEFAULT '',
                    auth_type         TEXT NOT NULL DEFAULT 'none',
                    api_status        TEXT NOT NULL DEFAULT 'active',
                    owner_team        TEXT NOT NULL DEFAULT '',
                    documentation_url TEXT NOT NULL DEFAULT '',
                    endpoint_count    INTEGER NOT NULL DEFAULT 0,
                    risk_level        TEXT NOT NULL DEFAULT 'none',
                    last_scanned      DATETIME,
                    created_at        DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_apis_org
                    ON apis(org_id, api_type, api_status, risk_level);

                CREATE TABLE IF NOT EXISTS api_endpoints (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    api_id           TEXT NOT NULL,
                    method           TEXT NOT NULL DEFAULT 'GET',
                    path             TEXT NOT NULL DEFAULT '',
                    description      TEXT NOT NULL DEFAULT '',
                    is_authenticated INTEGER NOT NULL DEFAULT 1,
                    is_documented    INTEGER NOT NULL DEFAULT 1,
                    risk_level       TEXT NOT NULL DEFAULT 'none',
                    request_count    INTEGER NOT NULL DEFAULT 0,
                    created_at       DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_api_endpoints_org
                    ON api_endpoints(org_id, api_id, method, risk_level, is_authenticated, is_documented);
            """)

    @staticmethod
    def _row(row) -> dict:
        return dict(row)

    # ------------------------------------------------------------------
    # API CRUD
    # ------------------------------------------------------------------

    def register_api(self, org_id: str, data: dict) -> dict:
        """Register a new API."""
        api_name = (data.get("api_name") or "").strip()
        if not api_name:
            raise ValueError("api_name is required")
        api_type = (data.get("api_type") or "rest").strip().lower()
        if api_type not in _VALID_API_TYPES:
            raise ValueError(f"api_type must be one of {sorted(_VALID_API_TYPES)}")
        auth_type = (data.get("auth_type") or "none").strip().lower()
        if auth_type not in _VALID_AUTH_TYPES:
            raise ValueError(f"auth_type must be one of {sorted(_VALID_AUTH_TYPES)}")

        api_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": api_id,
            "org_id": org_id,
            "api_name": api_name,
            "api_type": api_type,
            "version": (data.get("version") or "").strip(),
            "base_url": (data.get("base_url") or "").strip(),
            "auth_type": auth_type,
            "api_status": "active",
            "owner_team": (data.get("owner_team") or "").strip(),
            "documentation_url": (data.get("documentation_url") or "").strip(),
            "endpoint_count": 0,
            "risk_level": (data.get("risk_level") or "none").strip().lower(),
            "last_scanned": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO apis
                       (id, org_id, api_name, api_type, version, base_url, auth_type,
                        api_status, owner_team, documentation_url, endpoint_count,
                        risk_level, last_scanned, created_at)
                       VALUES (:id, :org_id, :api_name, :api_type, :version, :base_url, :auth_type,
                               :api_status, :owner_team, :documentation_url, :endpoint_count,
                               :risk_level, :last_scanned, :created_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "api_inventory", "org_id": org_id, "source_engine": "api_inventory"})
            except Exception:
                pass

        return row

    def list_apis(
        self,
        org_id: str,
        api_type: Optional[str] = None,
        api_status: Optional[str] = None,
    ) -> List[dict]:
        """List APIs with optional filters."""
        sql = "SELECT * FROM apis WHERE org_id=?"
        params: list = [org_id]
        if api_type:
            sql += " AND api_type=?"
            params.append(api_type)
        if api_status:
            sql += " AND api_status=?"
            params.append(api_status)
        sql += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_api(self, org_id: str, api_id: str) -> Optional[dict]:
        """Get a single API by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM apis WHERE id=? AND org_id=?",
                    (api_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    def update_api_status(self, org_id: str, api_id: str, new_status: str) -> Optional[dict]:
        """Update an API's status. Returns updated record or None if not found."""
        new_status = new_status.strip().lower()
        if new_status not in _VALID_API_STATUSES:
            raise ValueError(f"api_status must be one of {sorted(_VALID_API_STATUSES)}")
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE apis SET api_status=? WHERE id=? AND org_id=?",
                    (new_status, api_id, org_id),
                )
        return self.get_api(org_id, api_id)

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    def add_endpoint(self, org_id: str, api_id: str, data: dict) -> dict:
        """Add an endpoint to an API. Increments api.endpoint_count."""
        method = (data.get("method") or "GET").strip().upper()
        if method not in _VALID_ENDPOINT_METHODS:
            raise ValueError(f"method must be one of {sorted(_VALID_ENDPOINT_METHODS)}")
        risk_level = (data.get("risk_level") or "none").strip().lower()
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(f"risk_level must be one of {sorted(_VALID_RISK_LEVELS)}")

        endpoint_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": endpoint_id,
            "org_id": org_id,
            "api_id": api_id,
            "method": method,
            "path": (data.get("path") or "").strip(),
            "description": (data.get("description") or "").strip(),
            "is_authenticated": int(bool(data.get("is_authenticated", True))),
            "is_documented": int(bool(data.get("is_documented", True))),
            "risk_level": risk_level,
            "request_count": int(data.get("request_count") or 0),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO api_endpoints
                       (id, org_id, api_id, method, path, description,
                        is_authenticated, is_documented, risk_level, request_count, created_at)
                       VALUES (:id, :org_id, :api_id, :method, :path, :description,
                               :is_authenticated, :is_documented, :risk_level, :request_count, :created_at)""",
                    row,
                )
                # Increment endpoint_count on parent API
                conn.execute(
                    "UPDATE apis SET endpoint_count = endpoint_count + 1 WHERE id=? AND org_id=?",
                    (api_id, org_id),
                )
        return row

    def list_endpoints(
        self,
        org_id: str,
        api_id: Optional[str] = None,
        method: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[dict]:
        """List endpoints with optional filters."""
        sql = "SELECT * FROM api_endpoints WHERE org_id=?"
        params: list = [org_id]
        if api_id:
            sql += " AND api_id=?"
            params.append(api_id)
        if method:
            sql += " AND method=?"
            params.append(method.upper())
        if risk_level:
            sql += " AND risk_level=?"
            params.append(risk_level)
        sql += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_api_stats(self, org_id: str) -> dict:
        """Return aggregated API inventory statistics for the org."""
        with self._lock:
            with self._conn() as conn:
                total_apis = conn.execute(
                    "SELECT COUNT(*) FROM apis WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                active_apis = conn.execute(
                    "SELECT COUNT(*) FROM apis WHERE org_id=? AND api_status='active'",
                    (org_id,),
                ).fetchone()[0]

                deprecated_apis = conn.execute(
                    "SELECT COUNT(*) FROM apis WHERE org_id=? AND api_status='deprecated'",
                    (org_id,),
                ).fetchone()[0]

                total_endpoints = conn.execute(
                    "SELECT COUNT(*) FROM api_endpoints WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                unauthenticated_endpoints = conn.execute(
                    "SELECT COUNT(*) FROM api_endpoints WHERE org_id=? AND is_authenticated=0",
                    (org_id,),
                ).fetchone()[0]

                undocumented_endpoints = conn.execute(
                    "SELECT COUNT(*) FROM api_endpoints WHERE org_id=? AND is_documented=0",
                    (org_id,),
                ).fetchone()[0]

                # By type
                type_rows = conn.execute(
                    """SELECT api_type, COUNT(*) as cnt
                       FROM apis WHERE org_id=? GROUP BY api_type""",
                    (org_id,),
                ).fetchall()
                by_type = {r["api_type"]: r["cnt"] for r in type_rows}

        return {
            "org_id": org_id,
            "total_apis": total_apis,
            "active_apis": active_apis,
            "deprecated_apis": deprecated_apis,
            "total_endpoints": total_endpoints,
            "unauthenticated_endpoints": unauthenticated_endpoints,
            "undocumented_endpoints": undocumented_endpoints,
            "by_type": by_type,
        }
