"""Security Champions Program Engine — ALDECI.

Manages a security champions program across departments and teams, tracking
champions, their activities, certifications, awareness campaigns, and
program-wide statistics.

Capabilities:
  - Champion registry (multi-department, level progression)
  - Activity logging with auto-point-award and auto-level promotion
  - Certification tracking (valid/expired/expiring_soon)
  - Awareness campaign management
  - Program-wide stats and top-performers

Compliance: NIST SP 800-50, CIS Controls v8 (Control 14), ISO 27001 A.7.2.2
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_ROLES = {"champion", "lead", "coordinator"}
_VALID_LEVELS = {"bronze", "silver", "gold", "platinum"}
_VALID_STATUSES = {"active", "inactive", "graduated"}
_VALID_ACTIVITY_TYPES = {
    "training", "mentoring", "code_review", "incident_response",
    "awareness_campaign", "vulnerability_report", "tool_contribution",
}
_VALID_CERT_STATUSES = {"valid", "expired", "expiring_soon"}
_VALID_CAMPAIGN_TYPES = {"phishing_simulation", "awareness", "training"}
_VALID_CAMPAIGN_STATUSES = {"planned", "active", "completed", "cancelled"}

# Level thresholds (cumulative points)
_LEVEL_THRESHOLDS = [
    (1500, "platinum"),
    (500, "gold"),
    (100, "silver"),
    (0, "bronze"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_level(points: int) -> str:
    for threshold, level in _LEVEL_THRESHOLDS:
        if points >= threshold:
            return level
    return "bronze"


class SecurityChampionsEngine:
    """SQLite WAL-backed Security Champions Program engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/{org_id}_security_champions.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._engines: Dict[str, str] = {}  # org_id -> db_path
        if db_path:
            self._init_db(db_path)

    def _get_db_path(self, org_id: str) -> str:
        if self._db_path:
            return self._db_path
        if org_id not in self._engines:
            path = str(Path(_DEFAULT_DB_DIR) / f"{org_id}_security_champions.db")
            self._engines[org_id] = path
            self._init_db(path)
        return self._engines[org_id]

    def _init_db(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn(db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS champions (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    email        TEXT NOT NULL DEFAULT '',
                    department   TEXT NOT NULL DEFAULT '',
                    team         TEXT NOT NULL DEFAULT '',
                    role         TEXT NOT NULL DEFAULT 'champion',
                    level        TEXT NOT NULL DEFAULT 'bronze',
                    points       INTEGER NOT NULL DEFAULT 0,
                    joined_at    DATETIME NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'active'
                );

                CREATE INDEX IF NOT EXISTS idx_champ_org_status
                    ON champions (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_champ_org_dept
                    ON champions (org_id, department);

                CREATE TABLE IF NOT EXISTS activities (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    champion_id    TEXT NOT NULL,
                    activity_type  TEXT NOT NULL,
                    points_awarded INTEGER NOT NULL DEFAULT 0,
                    description    TEXT NOT NULL DEFAULT '',
                    completed_at   DATETIME NOT NULL,
                    verified_by    TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_act_org_champ
                    ON activities (org_id, champion_id, completed_at DESC);

                CREATE TABLE IF NOT EXISTS certifications (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    champion_id   TEXT NOT NULL,
                    cert_name     TEXT NOT NULL,
                    cert_provider TEXT NOT NULL DEFAULT '',
                    issued_at     DATETIME NOT NULL,
                    expires_at    DATETIME,
                    status        TEXT NOT NULL DEFAULT 'valid'
                );

                CREATE INDEX IF NOT EXISTS idx_cert_org_champ
                    ON certifications (org_id, champion_id);

                CREATE TABLE IF NOT EXISTS campaigns (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    title              TEXT NOT NULL,
                    campaign_type      TEXT NOT NULL DEFAULT 'awareness',
                    start_date         TEXT NOT NULL DEFAULT '',
                    end_date           TEXT NOT NULL DEFAULT '',
                    target_department  TEXT NOT NULL DEFAULT '',
                    participants_count INTEGER NOT NULL DEFAULT 0,
                    completion_rate    REAL NOT NULL DEFAULT 0.0,
                    status             TEXT NOT NULL DEFAULT 'planned'
                );

                CREATE INDEX IF NOT EXISTS idx_camp_org_status
                    ON campaigns (org_id, status);
                """
            )

    def _conn(self, db_path: str) -> sqlite3.Connection:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Champions
    # ------------------------------------------------------------------

    def add_champion(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new security champion. Returns the created record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        role = data.get("role", "champion")
        if role not in _VALID_ROLES:
            raise ValueError(f"Invalid role: {role}. Must be one of {_VALID_ROLES}")

        status = data.get("status", "active")
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_STATUSES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "email": data.get("email", ""),
            "department": data.get("department", ""),
            "team": data.get("team", ""),
            "role": role,
            "level": "bronze",
            "points": 0,
            "joined_at": data.get("joined_at", now),
            "status": status,
        }
        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                conn.execute(
                    """INSERT INTO champions
                       (id, org_id, name, email, department, team, role,
                        level, points, joined_at, status)
                       VALUES (:id, :org_id, :name, :email, :department, :team, :role,
                               :level, :points, :joined_at, :status)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_champions", "org_id": org_id, "source_engine": "security_champions"})
            except Exception:
                pass

        return record

    def list_champions(
        self,
        org_id: str,
        status: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List champions, optionally filtered by status and/or department."""
        sql = "SELECT * FROM champions WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if department:
            sql += " AND department = ?"
            params.append(department)
        sql += " ORDER BY points DESC"
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_champion(self, org_id: str, champion_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single champion by ID."""
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            row = conn.execute(
                "SELECT * FROM champions WHERE org_id = ? AND id = ?",
                (org_id, champion_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Activities
    # ------------------------------------------------------------------

    def log_activity(
        self, org_id: str, champion_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Log an activity for a champion. Auto-awards points and auto-promotes level.

        Points by activity type:
          training: 20, mentoring: 30, code_review: 15, incident_response: 50,
          awareness_campaign: 25, vulnerability_report: 40, tool_contribution: 35

        Level thresholds (cumulative points):
          bronze: 0+, silver: 100+, gold: 500+, platinum: 1500+
        """
        activity_type = data.get("activity_type", "training")
        if activity_type not in _VALID_ACTIVITY_TYPES:
            raise ValueError(
                f"Invalid activity_type: {activity_type}. Must be one of {_VALID_ACTIVITY_TYPES}"
            )

        _POINTS_MAP = {
            "training": 20,
            "mentoring": 30,
            "code_review": 15,
            "incident_response": 50,
            "awareness_campaign": 25,
            "vulnerability_report": 40,
            "tool_contribution": 35,
        }
        points_awarded = int(data.get("points_awarded", _POINTS_MAP.get(activity_type, 10)))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "champion_id": champion_id,
            "activity_type": activity_type,
            "points_awarded": points_awarded,
            "description": data.get("description", ""),
            "completed_at": data.get("completed_at", now),
            "verified_by": data.get("verified_by", ""),
        }

        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                conn.execute(
                    """INSERT INTO activities
                       (id, org_id, champion_id, activity_type, points_awarded,
                        description, completed_at, verified_by)
                       VALUES (:id, :org_id, :champion_id, :activity_type, :points_awarded,
                               :description, :completed_at, :verified_by)""",
                    record,
                )
                # Update champion points
                conn.execute(
                    "UPDATE champions SET points = points + ? WHERE org_id = ? AND id = ?",
                    (points_awarded, org_id, champion_id),
                )
                # Re-read updated points and compute new level
                row = conn.execute(
                    "SELECT points FROM champions WHERE org_id = ? AND id = ?",
                    (org_id, champion_id),
                ).fetchone()
                if row:
                    new_level = _compute_level(row["points"])
                    conn.execute(
                        "UPDATE champions SET level = ? WHERE org_id = ? AND id = ?",
                        (new_level, org_id, champion_id),
                    )
                    record["_new_level"] = new_level
                    record["_total_points"] = row["points"]

        return record

    # ------------------------------------------------------------------
    # Certifications
    # ------------------------------------------------------------------

    def add_certification(
        self, org_id: str, champion_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a certification for a champion. Returns the created record."""
        cert_name = (data.get("cert_name") or "").strip()
        if not cert_name:
            raise ValueError("cert_name is required.")

        status = data.get("status", "valid")
        if status not in _VALID_CERT_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_CERT_STATUSES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "champion_id": champion_id,
            "cert_name": cert_name,
            "cert_provider": data.get("cert_provider", ""),
            "issued_at": data.get("issued_at", now),
            "expires_at": data.get("expires_at", None),
            "status": status,
        }
        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                conn.execute(
                    """INSERT INTO certifications
                       (id, org_id, champion_id, cert_name, cert_provider,
                        issued_at, expires_at, status)
                       VALUES (:id, :org_id, :champion_id, :cert_name, :cert_provider,
                               :issued_at, :expires_at, :status)""",
                    record,
                )
        return record

    def list_certifications(
        self, org_id: str, champion_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List certifications, optionally filtered by champion."""
        sql = "SELECT * FROM certifications WHERE org_id = ?"
        params: list = [org_id]
        if champion_id:
            sql += " AND champion_id = ?"
            params.append(champion_id)
        sql += " ORDER BY issued_at DESC"
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def create_campaign(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an awareness campaign. Returns the created record."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        campaign_type = data.get("campaign_type", "awareness")
        if campaign_type not in _VALID_CAMPAIGN_TYPES:
            raise ValueError(
                f"Invalid campaign_type: {campaign_type}. Must be one of {_VALID_CAMPAIGN_TYPES}"
            )

        status = data.get("status", "planned")
        if status not in _VALID_CAMPAIGN_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_CAMPAIGN_STATUSES}")

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "campaign_type": campaign_type,
            "start_date": data.get("start_date", ""),
            "end_date": data.get("end_date", ""),
            "target_department": data.get("target_department", ""),
            "participants_count": int(data.get("participants_count", 0)),
            "completion_rate": float(data.get("completion_rate", 0.0)),
            "status": status,
        }
        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                conn.execute(
                    """INSERT INTO campaigns
                       (id, org_id, title, campaign_type, start_date, end_date,
                        target_department, participants_count, completion_rate, status)
                       VALUES (:id, :org_id, :title, :campaign_type, :start_date, :end_date,
                               :target_department, :participants_count, :completion_rate, :status)""",
                    record,
                )
        return record

    def list_campaigns(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List campaigns, optionally filtered by status."""
        sql = "SELECT * FROM campaigns WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY start_date DESC"
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_program_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated program stats for org."""
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            champion_count = conn.execute(
                "SELECT COUNT(*) FROM champions WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            total_activities = conn.execute(
                "SELECT COUNT(*) FROM activities WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            # Certifications expiring soon (status = expiring_soon) or expired
            certs_expiring = conn.execute(
                "SELECT COUNT(*) FROM certifications WHERE org_id = ? AND status = 'expiring_soon'",
                (org_id,),
            ).fetchone()[0]

            active_campaigns = conn.execute(
                "SELECT COUNT(*) FROM campaigns WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            # Top 5 champions by points
            top_rows = conn.execute(
                """SELECT id, name, department, level, points
                   FROM champions WHERE org_id = ? AND status = 'active'
                   ORDER BY points DESC LIMIT 5""",
                (org_id,),
            ).fetchall()
            top_champions = [self._row(r) for r in top_rows]

            # Level distribution
            level_rows = conn.execute(
                """SELECT level, COUNT(*) as cnt
                   FROM champions WHERE org_id = ?
                   GROUP BY level""",
                (org_id,),
            ).fetchall()
            level_distribution = {r["level"]: r["cnt"] for r in level_rows}

        return {
            "champion_count": champion_count,
            "total_activities": total_activities,
            "certifications_expiring_soon": certs_expiring,
            "active_campaigns": active_campaigns,
            "top_champions": top_champions,
            "level_distribution": level_distribution,
        }
