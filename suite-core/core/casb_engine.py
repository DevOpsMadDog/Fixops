"""Cloud Access Security Broker (CASB) Engine.

Monitors and controls cloud app usage, shadow IT discovery, data sharing,
and OAuth app risks across the organisation.

Usage:
    from core.casb_engine import CASBEngine
    engine = CASBEngine()
    engine.discover_app("org1", {"app_name": "Dropbox", "app_category": "storage", ...})
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_CASB_DB", ".fixops_data/casb.db")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_CATEGORIES = {"productivity", "collaboration", "storage", "crm", "devtools", "social", "other"}
VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
VALID_ACTIVITY_TYPES = {"upload", "download", "share", "delete"}
VALID_DESTINATIONS = {"internal", "external", "public"}
VALID_CLASSIFICATIONS = {"public", "internal", "confidential", "secret"}
VALID_POLICY_TYPES = {"data_loss", "app_block", "oauth_restrict"}
VALID_ACTIONS = {"block", "alert", "encrypt"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class CASBEngine:
    """Cloud Access Security Broker engine.

    Thread-safe SQLite-backed engine for shadow IT discovery, data activity
    monitoring, CASB policy enforcement, and violation tracking.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS casb_apps (
                    app_id              TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    app_name            TEXT NOT NULL,
                    app_category        TEXT NOT NULL DEFAULT 'other',
                    risk_level          TEXT NOT NULL DEFAULT 'medium',
                    users_count         INTEGER NOT NULL DEFAULT 0,
                    data_uploaded_gb    REAL NOT NULL DEFAULT 0.0,
                    is_sanctioned       INTEGER NOT NULL DEFAULT 0,
                    oauth_scopes        TEXT NOT NULL DEFAULT '[]',
                    sanctioned_by       TEXT,
                    unsanction_reason   TEXT,
                    discovered_at       TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_casb_apps_org
                    ON casb_apps (org_id);

                CREATE TABLE IF NOT EXISTS casb_data_activities (
                    activity_id         TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    app_name            TEXT NOT NULL,
                    user_id             TEXT NOT NULL,
                    activity_type       TEXT NOT NULL,
                    file_type           TEXT NOT NULL DEFAULT '',
                    size_bytes          INTEGER NOT NULL DEFAULT 0,
                    destination         TEXT NOT NULL DEFAULT 'internal',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    recorded_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_casb_activities_org
                    ON casb_data_activities (org_id);
                CREATE INDEX IF NOT EXISTS idx_casb_activities_app
                    ON casb_data_activities (org_id, app_name);

                CREATE TABLE IF NOT EXISTS casb_policies (
                    policy_id           TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    policy_type         TEXT NOT NULL,
                    conditions          TEXT NOT NULL DEFAULT '{}',
                    action              TEXT NOT NULL DEFAULT 'alert',
                    is_active           INTEGER NOT NULL DEFAULT 1,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_casb_policies_org
                    ON casb_policies (org_id);

                CREATE TABLE IF NOT EXISTS casb_violations (
                    violation_id        TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    policy_id           TEXT NOT NULL,
                    user_id             TEXT NOT NULL,
                    app_name            TEXT NOT NULL,
                    violation_detail    TEXT NOT NULL DEFAULT '',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    recorded_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_casb_violations_org
                    ON casb_violations (org_id);
            """)
            self._conn.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_app(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["is_sanctioned"] = bool(d["is_sanctioned"])
        d["oauth_scopes"] = json.loads(d.get("oauth_scopes") or "[]")
        return d

    @staticmethod
    def _row_to_activity(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _row_to_policy(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["conditions"] = json.loads(d.get("conditions") or "{}")
        d["is_active"] = bool(d["is_active"])
        return d

    @staticmethod
    def _row_to_violation(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # App discovery
    # ------------------------------------------------------------------

    def discover_app(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register or update a discovered cloud app.

        Required fields in data: app_name.
        Optional: app_category, risk_level, users_count, data_uploaded_gb,
                  is_sanctioned, oauth_scopes.
        Returns the full app record.
        """
        app_name = data.get("app_name", "").strip()
        if not app_name:
            raise ValueError("app_name is required")

        app_category = data.get("app_category", "other")
        if app_category not in VALID_CATEGORIES:
            app_category = "other"

        risk_level = data.get("risk_level", "medium")
        if risk_level not in VALID_RISK_LEVELS:
            risk_level = "medium"

        users_count = int(data.get("users_count", 0))
        data_uploaded_gb = float(data.get("data_uploaded_gb", 0.0))
        is_sanctioned = int(bool(data.get("is_sanctioned", False)))
        oauth_scopes = json.dumps(data.get("oauth_scopes", []))
        now = self._now()

        with self._lock:
            # Check if app already exists for this org
            existing = self._conn.execute(
                "SELECT app_id FROM casb_apps WHERE org_id=? AND app_name=?",
                (org_id, app_name),
            ).fetchone()

            if existing:
                app_id = existing["app_id"]
                self._conn.execute(
                    """UPDATE casb_apps
                       SET app_category=?, risk_level=?, users_count=?,
                           data_uploaded_gb=?, oauth_scopes=?, updated_at=?
                       WHERE app_id=?""",
                    (app_category, risk_level, users_count, data_uploaded_gb,
                     oauth_scopes, now, app_id),
                )
            else:
                app_id = str(uuid.uuid4())
                self._conn.execute(
                    """INSERT INTO casb_apps
                       (app_id, org_id, app_name, app_category, risk_level,
                        users_count, data_uploaded_gb, is_sanctioned,
                        oauth_scopes, discovered_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (app_id, org_id, app_name, app_category, risk_level,
                     users_count, data_uploaded_gb, is_sanctioned,
                     oauth_scopes, now, now),
                )
            self._conn.commit()

            row = self._conn.execute(
                "SELECT * FROM casb_apps WHERE app_id=?", (app_id,)
            ).fetchone()
            return self._row_to_app(row)

    def list_apps(
        self,
        org_id: str,
        category: Optional[str] = None,
        is_sanctioned: Optional[bool] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List cloud apps for org with optional filters."""
        query = "SELECT * FROM casb_apps WHERE org_id=?"
        params: List[Any] = [org_id]

        if category is not None:
            query += " AND app_category=?"
            params.append(category)
        if is_sanctioned is not None:
            query += " AND is_sanctioned=?"
            params.append(int(is_sanctioned))
        if risk_level is not None:
            query += " AND risk_level=?"
            params.append(risk_level)

        query += " ORDER BY app_name"

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_app(r) for r in rows]

    def sanction_app(self, org_id: str, app_id: str, sanctioned_by: str) -> Dict[str, Any]:
        """Mark an app as sanctioned (approved for use)."""
        now = self._now()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM casb_apps WHERE app_id=? AND org_id=?",
                (app_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"App '{app_id}' not found for org '{org_id}'")

            self._conn.execute(
                """UPDATE casb_apps
                   SET is_sanctioned=1, sanctioned_by=?, unsanction_reason=NULL, updated_at=?
                   WHERE app_id=? AND org_id=?""",
                (sanctioned_by, now, app_id, org_id),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM casb_apps WHERE app_id=?", (app_id,)
            ).fetchone()
            return self._row_to_app(row)

    def unsanction_app(self, org_id: str, app_id: str, reason: str) -> Dict[str, Any]:
        """Mark an app as unsanctioned (shadow IT / blocked)."""
        now = self._now()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM casb_apps WHERE app_id=? AND org_id=?",
                (app_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"App '{app_id}' not found for org '{org_id}'")

            self._conn.execute(
                """UPDATE casb_apps
                   SET is_sanctioned=0, unsanction_reason=?, sanctioned_by=NULL, updated_at=?
                   WHERE app_id=? AND org_id=?""",
                (reason, now, app_id, org_id),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM casb_apps WHERE app_id=?", (app_id,)
            ).fetchone()
            return self._row_to_app(row)

    # ------------------------------------------------------------------
    # Data activity monitoring
    # ------------------------------------------------------------------

    def record_data_activity(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a data activity event (upload/download/share/delete).

        Required: app_name, user, activity_type.
        Optional: file_type, size_bytes, destination, data_classification.
        """
        app_name = data.get("app_name", "").strip()
        user = data.get("user", "").strip()
        activity_type = data.get("activity_type", "upload")

        if not app_name:
            raise ValueError("app_name is required")
        if not user:
            raise ValueError("user is required")
        if activity_type not in VALID_ACTIVITY_TYPES:
            raise ValueError(f"activity_type must be one of {VALID_ACTIVITY_TYPES}")

        destination = data.get("destination", "internal")
        if destination not in VALID_DESTINATIONS:
            destination = "internal"

        data_classification = data.get("data_classification", "internal")
        if data_classification not in VALID_CLASSIFICATIONS:
            data_classification = "internal"

        activity_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            self._conn.execute(
                """INSERT INTO casb_data_activities
                   (activity_id, org_id, app_name, user_id, activity_type,
                    file_type, size_bytes, destination, data_classification, recorded_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    activity_id, org_id, app_name, user, activity_type,
                    data.get("file_type", ""),
                    int(data.get("size_bytes", 0)),
                    destination,
                    data_classification,
                    now,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM casb_data_activities WHERE activity_id=?", (activity_id,)
            ).fetchone()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "casb", "org_id": org_id, "source_engine": "casb"})
            except Exception:
                pass

            return self._row_to_activity(row)

    def list_data_activities(
        self,
        org_id: str,
        app_name: Optional[str] = None,
        data_classification: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List data activities with optional filters."""
        query = "SELECT * FROM casb_data_activities WHERE org_id=?"
        params: List[Any] = [org_id]

        if app_name is not None:
            query += " AND app_name=?"
            params.append(app_name)
        if data_classification is not None:
            query += " AND data_classification=?"
            params.append(data_classification)

        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_activity(r) for r in rows]

    # ------------------------------------------------------------------
    # Policy management
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a CASB policy.

        Required: name, policy_type.
        Optional: conditions (dict), action.
        """
        name = data.get("name", "").strip()
        policy_type = data.get("policy_type", "")

        if not name:
            raise ValueError("name is required")
        if policy_type not in VALID_POLICY_TYPES:
            raise ValueError(f"policy_type must be one of {VALID_POLICY_TYPES}")

        action = data.get("action", "alert")
        if action not in VALID_ACTIONS:
            action = "alert"

        policy_id = str(uuid.uuid4())
        now = self._now()
        conditions = json.dumps(data.get("conditions", {}))

        with self._lock:
            self._conn.execute(
                """INSERT INTO casb_policies
                   (policy_id, org_id, name, policy_type, conditions, action, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (policy_id, org_id, name, policy_type, conditions, action, now, now),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM casb_policies WHERE policy_id=?", (policy_id,)
            ).fetchone()
            return self._row_to_policy(row)

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all CASB policies for org."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM casb_policies WHERE org_id=? ORDER BY name",
                (org_id,),
            ).fetchall()
        return [self._row_to_policy(r) for r in rows]

    # ------------------------------------------------------------------
    # Violation tracking
    # ------------------------------------------------------------------

    def record_policy_violation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a CASB policy violation.

        Required: policy_id, user, app_name.
        Optional: violation_detail, severity.
        """
        policy_id = data.get("policy_id", "").strip()
        user = data.get("user", "").strip()
        app_name = data.get("app_name", "").strip()

        if not policy_id:
            raise ValueError("policy_id is required")
        if not user:
            raise ValueError("user is required")
        if not app_name:
            raise ValueError("app_name is required")

        severity = data.get("severity", "medium")
        if severity not in VALID_SEVERITIES:
            severity = "medium"

        violation_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            self._conn.execute(
                """INSERT INTO casb_violations
                   (violation_id, org_id, policy_id, user_id, app_name,
                    violation_detail, severity, recorded_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    violation_id, org_id, policy_id, user, app_name,
                    data.get("violation_detail", ""),
                    severity,
                    now,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM casb_violations WHERE violation_id=?", (violation_id,)
            ).fetchone()
            return self._row_to_violation(row)

    def list_violations(
        self,
        org_id: str,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List policy violations with optional severity filter."""
        query = "SELECT * FROM casb_violations WHERE org_id=?"
        params: List[Any] = [org_id]

        if severity is not None:
            query += " AND severity=?"
            params.append(severity)

        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_violation(r) for r in rows]

    # ------------------------------------------------------------------
    # Reports & stats
    # ------------------------------------------------------------------

    def get_shadow_it_report(self, org_id: str) -> Dict[str, Any]:
        """Return shadow IT discovery report for the org."""
        with self._lock:
            total_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM casb_apps WHERE org_id=?", (org_id,)
            ).fetchone()
            total_apps = total_row["cnt"] if total_row else 0

            sanctioned_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM casb_apps WHERE org_id=? AND is_sanctioned=1",
                (org_id,),
            ).fetchone()
            sanctioned_count = sanctioned_row["cnt"] if sanctioned_row else 0

            unsanctioned_count = total_apps - sanctioned_count
            shadow_it_count = unsanctioned_count  # unsanctioned == shadow IT

            # By category breakdown
            cat_rows = self._conn.execute(
                """SELECT app_category, COUNT(*) as cnt
                   FROM casb_apps WHERE org_id=?
                   GROUP BY app_category""",
                (org_id,),
            ).fetchall()
            by_category = {r["app_category"]: r["cnt"] for r in cat_rows}

            # High risk apps (critical or high risk, unsanctioned)
            high_risk_rows = self._conn.execute(
                """SELECT app_id, app_name, risk_level, users_count, app_category
                   FROM casb_apps
                   WHERE org_id=? AND risk_level IN ('critical','high') AND is_sanctioned=0
                   ORDER BY CASE risk_level
                       WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, users_count DESC
                   LIMIT 10""",
                (org_id,),
            ).fetchall()
            high_risk_apps = [dict(r) for r in high_risk_rows]

            # Top data uploaders (users with most upload bytes)
            uploader_rows = self._conn.execute(
                """SELECT user_id, SUM(size_bytes) as total_bytes
                   FROM casb_data_activities
                   WHERE org_id=? AND activity_type='upload'
                   GROUP BY user_id
                   ORDER BY total_bytes DESC
                   LIMIT 10""",
                (org_id,),
            ).fetchall()
            top_data_uploaders = [dict(r) for r in uploader_rows]

        return {
            "total_apps": total_apps,
            "sanctioned_count": sanctioned_count,
            "unsanctioned_count": unsanctioned_count,
            "shadow_it_count": shadow_it_count,
            "by_category": by_category,
            "high_risk_apps": high_risk_apps,
            "top_data_uploaders": top_data_uploaders,
        }

    def get_casb_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated CASB statistics for the org."""
        cutoff_24h = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        with self._lock:
            total_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM casb_apps WHERE org_id=?", (org_id,)
            ).fetchone()
            total_apps = total_row["cnt"] if total_row else 0

            shadow_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM casb_apps WHERE org_id=? AND is_sanctioned=0",
                (org_id,),
            ).fetchone()
            shadow_count = shadow_row["cnt"] if shadow_row else 0

            shadow_it_pct = round(shadow_count / total_apps * 100, 1) if total_apps > 0 else 0.0

            activities_24h_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM casb_data_activities WHERE org_id=? AND recorded_at>=?",
                (org_id, cutoff_24h),
            ).fetchone()
            data_activities_24h = activities_24h_row["cnt"] if activities_24h_row else 0

            violations_24h_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM casb_violations WHERE org_id=? AND recorded_at>=?",
                (org_id, cutoff_24h),
            ).fetchone()
            violations_24h = violations_24h_row["cnt"] if violations_24h_row else 0

            # By risk level
            risk_rows = self._conn.execute(
                """SELECT risk_level, COUNT(*) as cnt
                   FROM casb_apps WHERE org_id=?
                   GROUP BY risk_level""",
                (org_id,),
            ).fetchall()
            by_risk_level = {r["risk_level"]: r["cnt"] for r in risk_rows}

            policy_row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM casb_policies WHERE org_id=?", (org_id,)
            ).fetchone()
            policy_count = policy_row["cnt"] if policy_row else 0

        return {
            "total_apps": total_apps,
            "shadow_it_pct": shadow_it_pct,
            "data_activities_24h": data_activities_24h,
            "violations_24h": violations_24h,
            "by_risk_level": by_risk_level,
            "policy_count": policy_count,
        }
