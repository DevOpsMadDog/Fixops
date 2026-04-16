"""Awareness Campaign Engine — ALDECI.

Manages security awareness campaigns (phishing simulations, training,
quizzes, newsletters, videos, tabletops) and tracks individual
participation results per user/department.

Compliance: NIST CSF PR.AT-1, ISO/IEC 27001 A.7.2.2, NIST 800-50
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "awareness_campaign.db"
)

_VALID_CAMPAIGN_TYPES = {
    "phishing_sim", "training", "quiz", "newsletter", "video", "tabletop",
}
_VALID_CAMPAIGN_STATUSES = {
    "draft", "active", "completed", "paused", "cancelled",
}
_VALID_PARTICIPATION_RESULTS = {
    "pass", "fail", "incomplete", "click", "report",
}


class AwarenessCampaignEngine:
    """SQLite WAL-backed Awareness Campaign engine.

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
                CREATE TABLE IF NOT EXISTS awareness_campaigns (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    title             TEXT NOT NULL DEFAULT '',
                    campaign_type     TEXT NOT NULL DEFAULT 'training',
                    campaign_status   TEXT NOT NULL DEFAULT 'draft',
                    target_department TEXT NOT NULL DEFAULT '',
                    target_count      INTEGER NOT NULL DEFAULT 0,
                    participant_count INTEGER NOT NULL DEFAULT 0,
                    pass_count        INTEGER NOT NULL DEFAULT 0,
                    fail_count        INTEGER NOT NULL DEFAULT 0,
                    pass_rate         REAL NOT NULL DEFAULT 0.0,
                    start_date        TEXT NOT NULL DEFAULT '',
                    end_date          TEXT NOT NULL DEFAULT '',
                    created_by        TEXT NOT NULL DEFAULT '',
                    created_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ac_org
                    ON awareness_campaigns (org_id);
                CREATE INDEX IF NOT EXISTS idx_ac_org_type
                    ON awareness_campaigns (org_id, campaign_type);
                CREATE INDEX IF NOT EXISTS idx_ac_org_status
                    ON awareness_campaigns (org_id, campaign_status);

                CREATE TABLE IF NOT EXISTS campaign_participations (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    campaign_id         TEXT NOT NULL,
                    user_id             TEXT NOT NULL,
                    department          TEXT NOT NULL DEFAULT '',
                    result              TEXT NOT NULL DEFAULT 'incomplete',
                    score               REAL NOT NULL DEFAULT 0,
                    completed_at        DATETIME,
                    time_spent_minutes  REAL NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_cp_org_campaign
                    ON campaign_participations (org_id, campaign_id);
                CREATE INDEX IF NOT EXISTS idx_cp_org_user
                    ON campaign_participations (org_id, user_id);
                CREATE INDEX IF NOT EXISTS idx_cp_org_result
                    ON campaign_participations (org_id, result);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def create_campaign(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new awareness campaign.

        Required: title
        Validates: campaign_type, campaign_status
        """
        title = data.get("title", "")
        if not title:
            raise ValueError("'title' is required")

        campaign_type = data.get("campaign_type", "training")
        if campaign_type not in _VALID_CAMPAIGN_TYPES:
            raise ValueError(
                f"Invalid campaign_type '{campaign_type}'. "
                f"Valid: {sorted(_VALID_CAMPAIGN_TYPES)}"
            )

        campaign_status = data.get("campaign_status", "draft")
        if campaign_status not in _VALID_CAMPAIGN_STATUSES:
            raise ValueError(
                f"Invalid campaign_status '{campaign_status}'. "
                f"Valid: {sorted(_VALID_CAMPAIGN_STATUSES)}"
            )

        campaign_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO awareness_campaigns
                        (id, org_id, title, campaign_type, campaign_status,
                         target_department, target_count, participant_count,
                         pass_count, fail_count, pass_rate,
                         start_date, end_date, created_by, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        campaign_id,
                        org_id,
                        title,
                        campaign_type,
                        campaign_status,
                        data.get("target_department", ""),
                        int(data.get("target_count", 0)),
                        0,
                        0,
                        0,
                        0.0,
                        data.get("start_date", ""),
                        data.get("end_date", ""),
                        data.get("created_by", ""),
                        now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "awareness_campaign", "org_id": org_id, "source_engine": "awareness_campaign"})
            except Exception:
                pass

        return self.get_campaign(org_id, campaign_id)  # type: ignore[return-value]

    def list_campaigns(
        self,
        org_id: str,
        campaign_type: Optional[str] = None,
        campaign_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List campaigns with optional filters, newest first."""
        query = "SELECT * FROM awareness_campaigns WHERE org_id = ?"
        params: List[Any] = [org_id]

        if campaign_type:
            query += " AND campaign_type = ?"
            params.append(campaign_type)
        if campaign_status:
            query += " AND campaign_status = ?"
            params.append(campaign_status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_campaign(self, org_id: str, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single campaign by ID (org-scoped)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM awareness_campaigns WHERE id = ? AND org_id = ?",
                (campaign_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_campaign_status(
        self, org_id: str, campaign_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update campaign status. Validates new_status."""
        if new_status not in _VALID_CAMPAIGN_STATUSES:
            raise ValueError(
                f"Invalid campaign_status '{new_status}'. "
                f"Valid: {sorted(_VALID_CAMPAIGN_STATUSES)}"
            )

        campaign = self.get_campaign(org_id, campaign_id)
        if campaign is None:
            raise KeyError(f"Campaign '{campaign_id}' not found for org '{org_id}'")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE awareness_campaigns SET campaign_status = ? WHERE id = ? AND org_id = ?",
                    (new_status, campaign_id, org_id),
                )

        return self.get_campaign(org_id, campaign_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Participations
    # ------------------------------------------------------------------

    def record_participation(
        self, org_id: str, campaign_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a user participation result.

        Required: user_id, result
        Updates participant_count, pass_count, fail_count, pass_rate on campaign.
        """
        user_id = data.get("user_id", "")
        if not user_id:
            raise ValueError("'user_id' is required")

        result = data.get("result", "incomplete")
        if result not in _VALID_PARTICIPATION_RESULTS:
            raise ValueError(
                f"Invalid result '{result}'. Valid: {sorted(_VALID_PARTICIPATION_RESULTS)}"
            )

        participation_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO campaign_participations
                        (id, org_id, campaign_id, user_id, department,
                         result, score, completed_at, time_spent_minutes)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        participation_id,
                        org_id,
                        campaign_id,
                        user_id,
                        data.get("department", ""),
                        result,
                        float(data.get("score", 0)),
                        data.get("completed_at", now),
                        float(data.get("time_spent_minutes", 0)),
                    ),
                )

                # Update campaign counters
                pass_delta = 1 if result == "pass" else 0
                fail_delta = 1 if result == "fail" else 0

                conn.execute(
                    """
                    UPDATE awareness_campaigns
                    SET participant_count = participant_count + 1,
                        pass_count = pass_count + ?,
                        fail_count = fail_count + ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (pass_delta, fail_delta, campaign_id, org_id),
                )

                # Recompute pass_rate
                row = conn.execute(
                    "SELECT participant_count, pass_count FROM awareness_campaigns WHERE id = ? AND org_id = ?",
                    (campaign_id, org_id),
                ).fetchone()
                if row and row["participant_count"] > 0:
                    pass_rate = row["pass_count"] / row["participant_count"] * 100.0
                    conn.execute(
                        "UPDATE awareness_campaigns SET pass_rate = ? WHERE id = ? AND org_id = ?",
                        (pass_rate, campaign_id, org_id),
                    )

        with self._conn() as conn:
            part_row = conn.execute(
                "SELECT * FROM campaign_participations WHERE id = ?", (participation_id,)
            ).fetchone()
        return self._row(part_row)

    def list_participations(
        self,
        org_id: str,
        campaign_id: Optional[str] = None,
        result: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List participations with optional filters."""
        query = "SELECT * FROM campaign_participations WHERE org_id = ?"
        params: List[Any] = [org_id]

        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        if result:
            query += " AND result = ?"
            params.append(result)
        if department:
            query += " AND department = ?"
            params.append(department)

        query += " ORDER BY completed_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_campaign_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate campaign statistics for the org."""
        with self._conn() as conn:
            total_campaigns = conn.execute(
                "SELECT COUNT(*) FROM awareness_campaigns WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_campaigns = conn.execute(
                "SELECT COUNT(*) FROM awareness_campaigns WHERE org_id = ? AND campaign_status = 'active'",
                (org_id,),
            ).fetchone()[0]

            total_participations = conn.execute(
                "SELECT COUNT(*) FROM campaign_participations WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # overall_pass_rate: avg pass_rate across completed campaigns
            completed_rows = conn.execute(
                "SELECT pass_rate FROM awareness_campaigns WHERE org_id = ? AND campaign_status = 'completed'",
                (org_id,),
            ).fetchall()
            if completed_rows:
                overall_pass_rate = sum(r["pass_rate"] for r in completed_rows) / len(completed_rows)
            else:
                overall_pass_rate = 0.0

            # by_type
            type_rows = conn.execute(
                """
                SELECT campaign_type, COUNT(*) as cnt
                FROM awareness_campaigns WHERE org_id = ?
                GROUP BY campaign_type
                """,
                (org_id,),
            ).fetchall()
            by_type = {r["campaign_type"]: r["cnt"] for r in type_rows}

            # best campaign (highest pass_rate among those with participants)
            best_row = conn.execute(
                """
                SELECT id, title, pass_rate FROM awareness_campaigns
                WHERE org_id = ? AND participant_count > 0
                ORDER BY pass_rate DESC LIMIT 1
                """,
                (org_id,),
            ).fetchone()
            best_campaign = self._row(best_row) if best_row else None

            # worst campaign (lowest pass_rate among those with participants)
            worst_row = conn.execute(
                """
                SELECT id, title, pass_rate FROM awareness_campaigns
                WHERE org_id = ? AND participant_count > 0
                ORDER BY pass_rate ASC LIMIT 1
                """,
                (org_id,),
            ).fetchone()
            worst_campaign = self._row(worst_row) if worst_row else None

        return {
            "total_campaigns": total_campaigns,
            "active_campaigns": active_campaigns,
            "total_participations": total_participations,
            "overall_pass_rate": round(overall_pass_rate, 2),
            "by_type": by_type,
            "best_campaign": best_campaign,
            "worst_campaign": worst_campaign,
        }
