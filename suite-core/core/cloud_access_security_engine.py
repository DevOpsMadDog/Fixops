"""Cloud Access Security Engine — ALDECI.

Provides CASB-style visibility and control over cloud application access:
  - Cloud app registry (sanctioned/unsanctioned SaaS/PaaS/IaaS)
  - Access event recording with user tracking
  - Policy management (allow/block/monitor/require_mfa/limit_data)
  - Stats aggregation (risk distribution, category breakdown)

Compliance: CASB frameworks, NIST CSF, ISO 27001 A.9
"""

from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_access_security.db"
)

_VALID_APP_CATEGORIES = {
    "saas", "paas", "iaas", "collaboration", "storage",
    "communication", "productivity", "security",
}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_ACCESS_TYPES = {"oauth", "saml", "api_key", "password", "sso"}
_VALID_POLICY_ACTIONS = {"allow", "block", "monitor", "require_mfa", "limit_data"}
_VALID_DATA_EXPOSURE = {"public", "internal", "confidential", "restricted"}

_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS cas_apps (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL,
    name                TEXT NOT NULL DEFAULT '',
    app_category        TEXT NOT NULL DEFAULT 'saas',
    vendor              TEXT NOT NULL DEFAULT '',
    risk_level          TEXT NOT NULL DEFAULT 'medium',
    users_count         INTEGER NOT NULL DEFAULT 0,
    data_exposure_level TEXT NOT NULL DEFAULT 'internal',
    sanctioned          INTEGER NOT NULL DEFAULT 1,
    discovered_at       DATETIME,
    last_activity       DATETIME,
    created_at          DATETIME
);

CREATE TABLE IF NOT EXISTS cas_events (
    id                TEXT PRIMARY KEY,
    org_id            TEXT NOT NULL,
    app_id            TEXT NOT NULL,
    user_id           TEXT NOT NULL DEFAULT '',
    access_type       TEXT NOT NULL DEFAULT 'oauth',
    data_accessed     TEXT NOT NULL DEFAULT '',
    bytes_transferred INTEGER NOT NULL DEFAULT 0,
    source_ip         TEXT NOT NULL DEFAULT '',
    success           INTEGER NOT NULL DEFAULT 1,
    occurred_at       DATETIME
);

CREATE TABLE IF NOT EXISTS cas_policies (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    app_category    TEXT NOT NULL DEFAULT 'saas',
    policy_action   TEXT NOT NULL DEFAULT 'monitor',
    conditions_json TEXT NOT NULL DEFAULT '{}',
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      DATETIME
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CloudAccessSecurityEngine:
    """SQLite WAL-backed CASB-style cloud access security engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
    """

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
            conn.executescript(_DDL)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Cloud App Registry
    # ------------------------------------------------------------------

    def register_cloud_app(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a cloud application."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")

        app_category = data.get("app_category", "saas")
        if app_category not in _VALID_APP_CATEGORIES:
            raise ValueError(
                f"Invalid app_category {app_category!r}. "
                f"Must be one of {sorted(_VALID_APP_CATEGORIES)}"
            )

        risk_level = data.get("risk_level", "medium")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level {risk_level!r}. "
                f"Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )

        data_exposure_level = data.get("data_exposure_level", "internal")
        if data_exposure_level not in _VALID_DATA_EXPOSURE:
            data_exposure_level = "internal"

        app_id = str(uuid.uuid4())
        now = _now_iso()
        sanctioned = 1 if data.get("sanctioned", True) else 0

        row = {
            "id": app_id,
            "org_id": org_id,
            "name": name,
            "app_category": app_category,
            "vendor": data.get("vendor", ""),
            "risk_level": risk_level,
            "users_count": 0,
            "data_exposure_level": data_exposure_level,
            "sanctioned": sanctioned,
            "discovered_at": data.get("discovered_at") or now,
            "last_activity": None,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cas_apps
                       (id, org_id, name, app_category, vendor, risk_level,
                        users_count, data_exposure_level, sanctioned,
                        discovered_at, last_activity, created_at)
                       VALUES
                       (:id, :org_id, :name, :app_category, :vendor, :risk_level,
                        :users_count, :data_exposure_level, :sanctioned,
                        :discovered_at, :last_activity, :created_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_access_security", "org_id": org_id, "source_engine": "cloud_access_security"})
            except Exception:
                pass

        return row

    def list_cloud_apps(
        self,
        org_id: str,
        app_category: Optional[str] = None,
        risk_level: Optional[str] = None,
        sanctioned: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List cloud apps with optional filters."""
        sql = "SELECT * FROM cas_apps WHERE org_id = ?"
        params: list = [org_id]

        if app_category is not None:
            sql += " AND app_category = ?"
            params.append(app_category)
        if risk_level is not None:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        if sanctioned is not None:
            sql += " AND sanctioned = ?"
            params.append(1 if sanctioned else 0)

        sql += " ORDER BY created_at DESC"

        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_cloud_app(self, org_id: str, app_id: str) -> Optional[Dict[str, Any]]:
        """Return a single cloud app or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cas_apps WHERE org_id = ? AND id = ?",
                (org_id, app_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Access Events
    # ------------------------------------------------------------------

    def record_access_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a cloud app access event."""
        app_id = (data.get("app_id") or "").strip()
        if not app_id:
            raise ValueError("app_id is required")

        access_type = data.get("access_type", "oauth")
        if access_type not in _VALID_ACCESS_TYPES:
            raise ValueError(
                f"Invalid access_type {access_type!r}. "
                f"Must be one of {sorted(_VALID_ACCESS_TYPES)}"
            )

        event_id = str(uuid.uuid4())
        now = _now_iso()
        user_id = data.get("user_id", "")

        row = {
            "id": event_id,
            "org_id": org_id,
            "app_id": app_id,
            "user_id": user_id,
            "access_type": access_type,
            "data_accessed": data.get("data_accessed", ""),
            "bytes_transferred": int(data.get("bytes_transferred", 0)),
            "source_ip": data.get("source_ip", ""),
            "success": 1 if data.get("success", True) else 0,
            "occurred_at": data.get("occurred_at") or now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cas_events
                       (id, org_id, app_id, user_id, access_type, data_accessed,
                        bytes_transferred, source_ip, success, occurred_at)
                       VALUES
                       (:id, :org_id, :app_id, :user_id, :access_type, :data_accessed,
                        :bytes_transferred, :source_ip, :success, :occurred_at)""",
                    row,
                )
                # Update app last_activity
                conn.execute(
                    "UPDATE cas_apps SET last_activity = ? WHERE org_id = ? AND id = ?",
                    (now, org_id, app_id),
                )
                # Increment users_count if this user has only 1 event for this app
                count = conn.execute(
                    "SELECT COUNT(*) FROM cas_events WHERE org_id = ? AND app_id = ? AND user_id = ?",
                    (org_id, app_id, user_id),
                ).fetchone()[0]
                if count == 1 and user_id:
                    conn.execute(
                        "UPDATE cas_apps SET users_count = users_count + 1 WHERE org_id = ? AND id = ?",
                        (org_id, app_id),
                    )
        return row

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a cloud access policy."""
        policy_action = data.get("policy_action", "monitor")
        if policy_action not in _VALID_POLICY_ACTIONS:
            raise ValueError(
                f"Invalid policy_action {policy_action!r}. "
                f"Must be one of {sorted(_VALID_POLICY_ACTIONS)}"
            )

        import json as _json

        conditions = data.get("conditions_json", data.get("conditions", {}))
        if isinstance(conditions, dict):
            conditions_json = _json.dumps(conditions)
        else:
            conditions_json = str(conditions)

        policy_id = str(uuid.uuid4())
        now = _now_iso()

        app_category = data.get("app_category", "saas")
        if app_category not in _VALID_APP_CATEGORIES:
            app_category = "saas"

        row = {
            "id": policy_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "app_category": app_category,
            "policy_action": policy_action,
            "conditions_json": conditions_json,
            "enabled": 1 if data.get("enabled", True) else 0,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cas_policies
                       (id, org_id, name, app_category, policy_action,
                        conditions_json, enabled, created_at)
                       VALUES
                       (:id, :org_id, :name, :app_category, :policy_action,
                        :conditions_json, :enabled, :created_at)""",
                    row,
                )
        return row

    def list_policies(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
        app_category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List policies with optional filters."""
        sql = "SELECT * FROM cas_policies WHERE org_id = ?"
        params: list = [org_id]

        if enabled is not None:
            sql += " AND enabled = ?"
            params.append(1 if enabled else 0)
        if app_category is not None:
            sql += " AND app_category = ?"
            params.append(app_category)

        sql += " ORDER BY created_at DESC"

        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cloud_access_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated stats for an org."""
        with self._conn() as conn:
            total_apps = conn.execute(
                "SELECT COUNT(*) FROM cas_apps WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            unsanctioned_apps = conn.execute(
                "SELECT COUNT(*) FROM cas_apps WHERE org_id = ? AND sanctioned = 0",
                (org_id,),
            ).fetchone()[0]

            high_risk_apps = conn.execute(
                "SELECT COUNT(*) FROM cas_apps WHERE org_id = ? AND risk_level IN ('high','critical')",
                (org_id,),
            ).fetchone()[0]

            total_events = conn.execute(
                "SELECT COUNT(*) FROM cas_events WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            unique_users = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM cas_events WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            cat_rows = conn.execute(
                "SELECT app_category, COUNT(*) as cnt FROM cas_apps WHERE org_id = ? GROUP BY app_category",
                (org_id,),
            ).fetchall()
            by_category = {r["app_category"]: r["cnt"] for r in cat_rows}

        return {
            "total_apps": total_apps,
            "unsanctioned_apps": unsanctioned_apps,
            "high_risk_apps": high_risk_apps,
            "total_events": total_events,
            "unique_users": unique_users,
            "by_category": by_category,
        }
