"""Browser Security Engine — browser policy, event, and extension management for ALDECI.

Manages browser security policies, security events (malicious downloads, phishing
attempts, extension installs, etc.), and extension inventory with risk classification.

Capabilities:
  - Policy CRUD (chrome/firefox/edge/safari/all × mandatory/recommended/optional)
  - Security event recording with block tracking and org isolation
  - Extension registry with risk classification and status lifecycle
  - Stats aggregation: policy counts, event totals, by_event_type, by_risk_level

Compliance: CIS Browser Benchmarks, NIST SP 800-128, STIG V-Browser
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "browser_security.db"
)

_VALID_BROWSER_TYPES = {"chrome", "firefox", "edge", "safari", "all"}
_VALID_ENFORCEMENT_LEVELS = {"mandatory", "recommended", "optional"}
_VALID_STATUSES = {"active", "inactive", "draft"}
_VALID_EVENT_TYPES = {
    "malicious_download",
    "phishing_attempt",
    "extension_install",
    "data_exfil_attempt",
    "cert_error",
    "mixed_content",
    "unsafe_navigation",
    "credential_leak",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "safe"}
_VALID_EXT_STATUSES = {"approved", "blocked", "under_review", "deprecated"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BrowserSecurityEngine:
    """SQLite WAL-backed browser security management engine.

    Thread-safe via RLock. Multi-tenant via org_id filtering on a shared DB.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS browser_policies (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    policy_name         TEXT NOT NULL,
                    browser_type        TEXT NOT NULL DEFAULT 'all',
                    enforcement_level   TEXT NOT NULL DEFAULT 'recommended',
                    settings            TEXT NOT NULL DEFAULT '{}',
                    status              TEXT NOT NULL DEFAULT 'active',
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bp_org
                    ON browser_policies (org_id, browser_type, status);

                CREATE TABLE IF NOT EXISTS browser_events (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    policy_id   TEXT NOT NULL DEFAULT '',
                    event_type  TEXT NOT NULL,
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    user_id     TEXT NOT NULL DEFAULT '',
                    device_id   TEXT NOT NULL DEFAULT '',
                    url         TEXT NOT NULL DEFAULT '',
                    details     TEXT NOT NULL DEFAULT '',
                    blocked     INTEGER NOT NULL DEFAULT 0,
                    event_at    TEXT NOT NULL,
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_be_org_type
                    ON browser_events (org_id, event_type, severity);

                CREATE INDEX IF NOT EXISTS idx_be_org_blocked
                    ON browser_events (org_id, blocked);

                CREATE TABLE IF NOT EXISTS browser_extensions (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    extension_id    TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    version         TEXT NOT NULL DEFAULT '',
                    browser_type    TEXT NOT NULL DEFAULT 'all',
                    risk_level      TEXT NOT NULL DEFAULT 'medium',
                    permissions     TEXT NOT NULL DEFAULT '[]',
                    status          TEXT NOT NULL DEFAULT 'under_review',
                    publisher       TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ext_org
                    ON browser_extensions (org_id, risk_level, status);
                """
            )

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialise JSON fields if present
        for field in ("settings", "permissions"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Coerce blocked integer → bool
        if "blocked" in d:
            d["blocked"] = bool(d["blocked"])
        return d

    # ------------------------------------------------------------------
    # Browser Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a browser security policy."""
        browser_type = data.get("browser_type", "all")
        if browser_type not in _VALID_BROWSER_TYPES:
            raise ValueError(
                f"Invalid browser_type: {browser_type!r}. Valid: {sorted(_VALID_BROWSER_TYPES)}"
            )
        enforcement_level = data.get("enforcement_level", "recommended")
        if enforcement_level not in _VALID_ENFORCEMENT_LEVELS:
            raise ValueError(
                f"Invalid enforcement_level: {enforcement_level!r}. Valid: {sorted(_VALID_ENFORCEMENT_LEVELS)}"
            )
        status = data.get("status", "active")
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid status: {status!r}. Valid: {sorted(_VALID_STATUSES)}"
            )

        now = _now_iso()
        policy_id = str(uuid.uuid4())
        settings = data.get("settings", {})
        settings_str = json.dumps(settings) if isinstance(settings, (dict, list)) else str(settings)

        row: Dict[str, Any] = {
            "id": policy_id,
            "org_id": org_id,
            "policy_name": data.get("policy_name", "Unnamed Policy"),
            "browser_type": browser_type,
            "enforcement_level": enforcement_level,
            "settings": settings_str,
            "status": status,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO browser_policies
                   (id, org_id, policy_name, browser_type, enforcement_level,
                    settings, status, created_at, updated_at)
                   VALUES (:id, :org_id, :policy_name, :browser_type, :enforcement_level,
                           :settings, :status, :created_at, :updated_at)""",
                row,
            )
        result = dict(row)
        result["settings"] = settings
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "browser_security", "org_id": org_id, "source_engine": "browser_security"})
            except Exception:
                pass

        return result

    def list_policies(
        self,
        org_id: str,
        browser_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List browser policies for the org with optional filters."""
        query = "SELECT * FROM browser_policies WHERE org_id = ?"
        params: List[Any] = [org_id]
        if browser_type is not None:
            query += " AND browser_type = ?"
            params.append(browser_type)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_policy(self, org_id: str, policy_id: str) -> Optional[Dict[str, Any]]:
        """Return a single policy or None (with org isolation)."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM browser_policies WHERE id = ? AND org_id = ?",
                (policy_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Browser Events
    # ------------------------------------------------------------------

    def record_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a browser security event."""
        event_type = data.get("event_type", "")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type: {event_type!r}. Valid: {sorted(_VALID_EVENT_TYPES)}"
            )
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. Valid: {sorted(_VALID_SEVERITIES)}"
            )

        now = _now_iso()
        event_id = str(uuid.uuid4())
        blocked = bool(data.get("blocked", False))

        row: Dict[str, Any] = {
            "id": event_id,
            "org_id": org_id,
            "policy_id": data.get("policy_id", ""),
            "event_type": event_type,
            "severity": severity,
            "user_id": data.get("user_id", ""),
            "device_id": data.get("device_id", ""),
            "url": data.get("url", ""),
            "details": data.get("details", ""),
            "blocked": 1 if blocked else 0,
            "event_at": data.get("event_at", now),
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO browser_events
                   (id, org_id, policy_id, event_type, severity, user_id, device_id,
                    url, details, blocked, event_at, created_at)
                   VALUES (:id, :org_id, :policy_id, :event_type, :severity, :user_id,
                           :device_id, :url, :details, :blocked, :event_at, :created_at)""",
                row,
            )
        result = dict(row)
        result["blocked"] = blocked
        return result

    def list_events(
        self,
        org_id: str,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        blocked: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List browser events for the org with optional filters."""
        query = "SELECT * FROM browser_events WHERE org_id = ?"
        params: List[Any] = [org_id]
        if event_type is not None:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)
        if blocked is not None:
            query += " AND blocked = ?"
            params.append(1 if blocked else 0)
        query += " ORDER BY event_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Browser Extensions
    # ------------------------------------------------------------------

    def register_extension(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a browser extension for review."""
        risk_level = data.get("risk_level", "medium")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level: {risk_level!r}. Valid: {sorted(_VALID_RISK_LEVELS)}"
            )
        status = data.get("status", "under_review")
        if status not in _VALID_EXT_STATUSES:
            raise ValueError(
                f"Invalid status: {status!r}. Valid: {sorted(_VALID_EXT_STATUSES)}"
            )

        now = _now_iso()
        rec_id = str(uuid.uuid4())
        permissions = data.get("permissions", [])
        permissions_str = json.dumps(permissions) if isinstance(permissions, (dict, list)) else str(permissions)

        row: Dict[str, Any] = {
            "id": rec_id,
            "org_id": org_id,
            "extension_id": data.get("extension_id", str(uuid.uuid4())),
            "name": data.get("name", "Unknown Extension"),
            "version": data.get("version", ""),
            "browser_type": data.get("browser_type", "all"),
            "risk_level": risk_level,
            "permissions": permissions_str,
            "status": status,
            "publisher": data.get("publisher", ""),
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO browser_extensions
                   (id, org_id, extension_id, name, version, browser_type,
                    risk_level, permissions, status, publisher, created_at)
                   VALUES (:id, :org_id, :extension_id, :name, :version, :browser_type,
                           :risk_level, :permissions, :status, :publisher, :created_at)""",
                row,
            )
        result = dict(row)
        result["permissions"] = permissions
        return result

    def list_extensions(
        self,
        org_id: str,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List extensions for the org with optional filters."""
        query = "SELECT * FROM browser_extensions WHERE org_id = ?"
        params: List[Any] = [org_id]
        if risk_level is not None:
            query += " AND risk_level = ?"
            params.append(risk_level)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_extension_status(
        self, org_id: str, ext_id: str, status: str
    ) -> Optional[Dict[str, Any]]:
        """Update extension status. Returns updated record or None if not found."""
        if status not in _VALID_EXT_STATUSES:
            raise ValueError(
                f"Invalid status: {status!r}. Valid: {sorted(_VALID_EXT_STATUSES)}"
            )
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE browser_extensions SET status = ? WHERE id = ? AND org_id = ?",
                (status, ext_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM browser_extensions WHERE id = ? AND org_id = ?",
                (ext_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_browser_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate browser security statistics for the org."""
        with self._lock, self._conn() as conn:
            total_policies = conn.execute(
                "SELECT COUNT(*) FROM browser_policies WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_policies = conn.execute(
                "SELECT COUNT(*) FROM browser_policies WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            total_events = conn.execute(
                "SELECT COUNT(*) FROM browser_events WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            blocked_events = conn.execute(
                "SELECT COUNT(*) FROM browser_events WHERE org_id = ? AND blocked = 1",
                (org_id,),
            ).fetchone()[0]

            critical_events = conn.execute(
                "SELECT COUNT(*) FROM browser_events WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            by_event_type_rows = conn.execute(
                "SELECT event_type, COUNT(*) as cnt FROM browser_events WHERE org_id = ? GROUP BY event_type",
                (org_id,),
            ).fetchall()

            by_risk_level_rows = conn.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM browser_extensions WHERE org_id = ? GROUP BY risk_level",
                (org_id,),
            ).fetchall()

            ext_status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM browser_extensions WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()

        return {
            "org_id": org_id,
            "total_policies": total_policies,
            "active_policies": active_policies,
            "total_events": total_events,
            "blocked_events": blocked_events,
            "critical_events": critical_events,
            "by_event_type": {r["event_type"]: r["cnt"] for r in by_event_type_rows},
            "by_risk_level": {r["risk_level"]: r["cnt"] for r in by_risk_level_rows},
            "extension_counts": {r["status"]: r["cnt"] for r in ext_status_rows},
        }
