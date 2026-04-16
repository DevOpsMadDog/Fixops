"""User Behavior Analytics (UBA) Engine — ALDECI.

Detects insider threats and anomalous user behavior via event ingestion,
risk scoring, peer comparison, and alert lifecycle management.

Compliance: NIST SP 800-53 AU-*, UEBA controls, ISO 27001 A.12.4
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "uba.db"
)

_VALID_EVENT_TYPES = {
    "login", "file_access", "email_send", "data_download",
    "usb_use", "vpn_login", "after_hours_access",
    "privilege_use", "failed_login",
}

_VALID_ALERT_STATUSES = {"open", "investigating", "resolved", "false_positive"}
_VALID_ALERT_SEVERITIES = {"low", "medium", "high", "critical"}
_LARGE_DOWNLOAD_BYTES = 1_073_741_824  # 1 GB

# Risk weight per indicator (summed, capped at 100)
_RISK_WEIGHTS = {
    "after_hours_access": 15,
    "failed_logins": 20,
    "large_downloads": 25,
    "usb_events": 20,
    "privilege_abuse": 30,
}


class UBAEngine:
    """SQLite WAL-backed User Behavior Analytics engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
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
                CREATE TABLE IF NOT EXISTS user_profiles (
                    user_id     TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    username    TEXT NOT NULL,
                    department  TEXT NOT NULL DEFAULT '',
                    role        TEXT NOT NULL DEFAULT '',
                    manager     TEXT NOT NULL DEFAULT '',
                    risk_score  INTEGER NOT NULL DEFAULT 0,
                    status      TEXT NOT NULL DEFAULT 'active',
                    last_seen   DATETIME,
                    created_at  DATETIME NOT NULL,
                    updated_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_uba_users_org
                    ON user_profiles (org_id, status, risk_score);

                CREATE TABLE IF NOT EXISTS user_events (
                    event_id         TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    user_id          TEXT NOT NULL,
                    event_type       TEXT NOT NULL,
                    source_ip        TEXT NOT NULL DEFAULT '',
                    device           TEXT NOT NULL DEFAULT '',
                    timestamp        DATETIME NOT NULL,
                    bytes_transferred INTEGER NOT NULL DEFAULT 0,
                    is_anomalous     INTEGER NOT NULL DEFAULT 0,
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_uba_events_org_user
                    ON user_events (org_id, user_id, event_type);

                CREATE INDEX IF NOT EXISTS idx_uba_events_timestamp
                    ON user_events (org_id, timestamp);

                CREATE TABLE IF NOT EXISTS uba_alerts (
                    alert_id    TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    alert_type  TEXT NOT NULL,
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    description TEXT NOT NULL DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'open',
                    created_at  DATETIME NOT NULL,
                    updated_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_uba_alerts_org
                    ON uba_alerts (org_id, status, severity);

                CREATE TABLE IF NOT EXISTS risk_scores (
                    score_id    TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    score       INTEGER NOT NULL DEFAULT 0,
                    indicators  TEXT NOT NULL DEFAULT '{}',
                    computed_at DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_risk_scores_org_user
                    ON risk_scores (org_id, user_id, computed_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "is_anomalous" in d:
            d["is_anomalous"] = bool(d["is_anomalous"])
        return d

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    def register_user(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new user profile. Returns the full profile dict."""
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        username = data.get("username", "")
        if not username:
            raise ValueError("username is required")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO user_profiles
                        (user_id, org_id, username, department, role, manager,
                         risk_score, status, last_seen, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        user_id,
                        org_id,
                        username,
                        data.get("department", ""),
                        data.get("role", ""),
                        data.get("manager", ""),
                        0,
                        data.get("status", "active"),
                        data.get("last_seen"),
                        now,
                        now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "uba", "org_id": org_id, "source_engine": "uba"})
            except Exception:
                pass

        return {
            "user_id": user_id,
            "org_id": org_id,
            "username": username,
            "department": data.get("department", ""),
            "role": data.get("role", ""),
            "manager": data.get("manager", ""),
            "risk_score": 0,
            "status": data.get("status", "active"),
            "last_seen": data.get("last_seen"),
            "created_at": now,
            "updated_at": now,
        }

    def list_users(
        self,
        org_id: str,
        status: Optional[str] = None,
        min_risk_score: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List user profiles for an org with optional filters."""
        query = "SELECT * FROM user_profiles WHERE org_id=?"
        params: list = [org_id]

        if status is not None:
            query += " AND status=?"
            params.append(status)
        if min_risk_score is not None:
            query += " AND risk_score>=?"
            params.append(min_risk_score)

        query += " ORDER BY risk_score DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_user(self, org_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single user profile scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM user_profiles WHERE user_id=? AND org_id=?",
                (user_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def ingest_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a user behavior event. Returns the stored event dict."""
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        user_id = data.get("user_id", "")
        if not user_id:
            raise ValueError("user_id is required")

        event_type = data.get("event_type", "")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(f"event_type must be one of {sorted(_VALID_EVENT_TYPES)}")

        timestamp = data.get("timestamp", now)
        bytes_transferred = int(data.get("bytes_transferred", 0))
        is_anomalous = bool(data.get("is_anomalous", False))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO user_events
                        (event_id, org_id, user_id, event_type, source_ip,
                         device, timestamp, bytes_transferred, is_anomalous, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        event_id,
                        org_id,
                        user_id,
                        event_type,
                        data.get("source_ip", ""),
                        data.get("device", ""),
                        timestamp,
                        bytes_transferred,
                        1 if is_anomalous else 0,
                        now,
                    ),
                )
                # Update last_seen on user profile
                conn.execute(
                    """
                    UPDATE user_profiles SET last_seen=?, updated_at=?
                    WHERE user_id=? AND org_id=?
                    """,
                    (timestamp, now, user_id, org_id),
                )

        return {
            "event_id": event_id,
            "org_id": org_id,
            "user_id": user_id,
            "event_type": event_type,
            "source_ip": data.get("source_ip", ""),
            "device": data.get("device", ""),
            "timestamp": timestamp,
            "bytes_transferred": bytes_transferred,
            "is_anomalous": is_anomalous,
            "created_at": now,
        }

    def list_events(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        is_anomalous: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List events for an org with optional filters."""
        query = "SELECT * FROM user_events WHERE org_id=?"
        params: list = [org_id]

        if user_id is not None:
            query += " AND user_id=?"
            params.append(user_id)
        if event_type is not None:
            query += " AND event_type=?"
            params.append(event_type)
        if is_anomalous is not None:
            query += " AND is_anomalous=?"
            params.append(1 if is_anomalous else 0)

        query += " ORDER BY timestamp DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Risk analysis
    # ------------------------------------------------------------------

    def analyze_user(self, org_id: str, user_id: str) -> Dict[str, Any]:
        """Compute risk indicators for a user, update their risk_score, persist score history.

        Returns an analysis dict with risk indicators, score, and peer comparison.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            # Fetch all events for this user in this org
            events = conn.execute(
                "SELECT * FROM user_events WHERE org_id=? AND user_id=?",
                (org_id, user_id),
            ).fetchall()

            user_row = conn.execute(
                "SELECT * FROM user_profiles WHERE user_id=? AND org_id=?",
                (user_id, org_id),
            ).fetchone()

        if user_row is None:
            raise ValueError(f"User {user_id} not found in org {org_id}")

        user = dict(user_row)
        department = user.get("department", "")

        # Count indicators
        after_hours_count = sum(1 for e in events if dict(e)["event_type"] == "after_hours_access")
        failed_logins_count = sum(1 for e in events if dict(e)["event_type"] == "failed_login")
        large_downloads_count = sum(
            1 for e in events
            if dict(e)["event_type"] == "data_download"
            and dict(e)["bytes_transferred"] >= _LARGE_DOWNLOAD_BYTES
        )
        usb_events_count = sum(1 for e in events if dict(e)["event_type"] == "usb_use")
        privilege_abuse_count = sum(1 for e in events if dict(e)["event_type"] == "privilege_use")

        # Build risk score from weighted indicators (cap at 100)
        raw_score = (
            min(after_hours_count, 3) * (_RISK_WEIGHTS["after_hours_access"] // 3)
            + min(failed_logins_count, 5) * (_RISK_WEIGHTS["failed_logins"] // 5)
            + min(large_downloads_count, 3) * (_RISK_WEIGHTS["large_downloads"] // 3)
            + min(usb_events_count, 3) * (_RISK_WEIGHTS["usb_events"] // 3)
            + min(privilege_abuse_count, 3) * (_RISK_WEIGHTS["privilege_abuse"] // 3)
        )
        risk_score = min(raw_score, 100)

        # Peer comparison: avg risk_score in same department
        with self._conn() as conn:
            dept_row = conn.execute(
                """
                SELECT AVG(risk_score) as avg_score FROM user_profiles
                WHERE org_id=? AND department=? AND user_id != ?
                """,
                (org_id, department, user_id),
            ).fetchone()
            dept_avg = float(dept_row["avg_score"] or 0) if dept_row else 0.0

            # Update user risk_score
            conn.execute(
                "UPDATE user_profiles SET risk_score=?, updated_at=? WHERE user_id=? AND org_id=?",
                (risk_score, now, user_id, org_id),
            )

            # Persist score history
            score_id = str(uuid.uuid4())
            indicators = {
                "after_hours_access": after_hours_count,
                "failed_logins": failed_logins_count,
                "large_downloads": large_downloads_count,
                "usb_events": usb_events_count,
                "privilege_abuse": privilege_abuse_count,
            }
            conn.execute(
                """
                INSERT INTO risk_scores (score_id, org_id, user_id, score, indicators, computed_at)
                VALUES (?,?,?,?,?,?)
                """,
                (score_id, org_id, user_id, risk_score, json.dumps(indicators), now),
            )

        return {
            "user_id": user_id,
            "org_id": org_id,
            "username": user.get("username"),
            "department": department,
            "risk_score": risk_score,
            "indicators": indicators,
            "peer_comparison": {
                "department_avg_risk": round(dept_avg, 2),
                "above_peer_avg": risk_score > dept_avg,
                "delta": round(risk_score - dept_avg, 2),
            },
            "total_events": len(events),
            "computed_at": now,
        }

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def create_alert(
        self,
        org_id: str,
        user_id: str,
        alert_type: str,
        severity: str,
        description: str,
    ) -> Dict[str, Any]:
        """Create a UBA alert. Returns the alert dict."""
        if severity not in _VALID_ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_VALID_ALERT_SEVERITIES)}")

        alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO uba_alerts
                        (alert_id, org_id, user_id, alert_type, severity,
                         description, status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        alert_id, org_id, user_id, alert_type,
                        severity, description, "open", now, now,
                    ),
                )

        return {
            "alert_id": alert_id,
            "org_id": org_id,
            "user_id": user_id,
            "alert_type": alert_type,
            "severity": severity,
            "description": description,
            "status": "open",
            "created_at": now,
            "updated_at": now,
        }

    def list_alerts(
        self,
        org_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List alerts for an org, optionally filtered by status."""
        query = "SELECT * FROM uba_alerts WHERE org_id=?"
        params: list = [org_id]

        if status is not None:
            query += " AND status=?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_alert_status(
        self,
        org_id: str,
        alert_id: str,
        status: str,
    ) -> bool:
        """Update alert status. Returns True if updated."""
        if status not in _VALID_ALERT_STATUSES:
            raise ValueError(f"status must be one of {sorted(_VALID_ALERT_STATUSES)}")

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE uba_alerts SET status=?, updated_at=? WHERE alert_id=? AND org_id=?",
                    (status, now, alert_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_uba_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate UBA statistics for an org."""
        today = datetime.now(timezone.utc).date().isoformat()

        with self._conn() as conn:
            total_users = conn.execute(
                "SELECT COUNT(*) FROM user_profiles WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            high_risk_count = conn.execute(
                "SELECT COUNT(*) FROM user_profiles WHERE org_id=? AND risk_score>=70",
                (org_id,),
            ).fetchone()[0]

            alerts_open = conn.execute(
                "SELECT COUNT(*) FROM uba_alerts WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            anomalous_events_today = conn.execute(
                """
                SELECT COUNT(*) FROM user_events
                WHERE org_id=? AND is_anomalous=1
                AND DATE(timestamp)=?
                """,
                (org_id, today),
            ).fetchone()[0]

            top_risk_rows = conn.execute(
                """
                SELECT user_id, username, department, risk_score
                FROM user_profiles WHERE org_id=?
                ORDER BY risk_score DESC LIMIT 5
                """,
                (org_id,),
            ).fetchall()

        return {
            "total_users": total_users,
            "high_risk_count": high_risk_count,
            "alerts_open": alerts_open,
            "anomalous_events_today": anomalous_events_today,
            "top_risk_users": [dict(r) for r in top_risk_rows],
        }
