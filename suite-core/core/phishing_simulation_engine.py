"""Phishing Simulation Engine — ALDECI.

Manage employee security awareness campaigns: email, SMS, voice, and
spear-phishing simulations with per-target result tracking.

Compliance: NIST SP 800-50, CIS Controls v8 14.2, ISO/IEC 27001 A.7.2.2
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "phishing_simulation.db"
)

_VALID_CAMPAIGN_TYPES = {"email", "sms", "voice", "spear_phishing"}
_VALID_STATUSES = {"draft", "active", "completed", "paused"}
_VALID_ACTIONS = {"opened", "clicked", "reported", "data_submitted"}
_VALID_DIFFICULTIES = {"low", "medium", "high", "expert"}


class PhishingSimulationEngine:
    """SQLite WAL-backed phishing simulation engine.

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
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id    TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    campaign_type  TEXT NOT NULL DEFAULT 'email',
                    template_id    TEXT,
                    target_group   TEXT NOT NULL DEFAULT '',
                    status         TEXT NOT NULL DEFAULT 'draft',
                    launch_date    TEXT,
                    end_date       TEXT,
                    targets_count  INTEGER NOT NULL DEFAULT 0,
                    created_at     TEXT NOT NULL,
                    updated_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_campaign_org
                    ON campaigns (org_id, status);

                CREATE TABLE IF NOT EXISTS targets (
                    target_id      TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    campaign_id    TEXT NOT NULL,
                    email          TEXT NOT NULL,
                    department     TEXT NOT NULL DEFAULT '',
                    clicked        INTEGER NOT NULL DEFAULT 0,
                    reported       INTEGER NOT NULL DEFAULT 0,
                    opened         INTEGER NOT NULL DEFAULT 0,
                    data_submitted INTEGER NOT NULL DEFAULT 0,
                    click_time     TEXT,
                    created_at     TEXT NOT NULL,
                    updated_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_target_campaign
                    ON targets (org_id, campaign_id);

                CREATE TABLE IF NOT EXISTS campaign_results (
                    result_id      TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    campaign_id    TEXT NOT NULL,
                    target_id      TEXT NOT NULL,
                    action         TEXT NOT NULL,
                    recorded_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_result_campaign
                    ON campaign_results (org_id, campaign_id);

                CREATE TABLE IF NOT EXISTS phishing_templates (
                    template_id    TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    template_type  TEXT NOT NULL DEFAULT 'email',
                    subject        TEXT NOT NULL DEFAULT '',
                    sender_name    TEXT NOT NULL DEFAULT '',
                    click_rate_avg REAL NOT NULL DEFAULT 0.0,
                    difficulty     TEXT NOT NULL DEFAULT 'medium',
                    created_at     TEXT NOT NULL,
                    updated_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_template_org
                    ON phishing_templates (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for bool_col in ("clicked", "reported", "opened", "data_submitted"):
            if bool_col in d:
                d[bool_col] = bool(d[bool_col])
        return d

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def create_campaign(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new phishing campaign. Returns the campaign record."""
        campaign_id = str(uuid.uuid4())
        now = self._now()
        campaign_type = data.get("campaign_type", "email")
        if campaign_type not in _VALID_CAMPAIGN_TYPES:
            campaign_type = "email"
        status = data.get("status", "draft")
        if status not in _VALID_STATUSES:
            status = "draft"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO campaigns
                        (campaign_id, org_id, name, campaign_type, template_id,
                         target_group, status, launch_date, end_date,
                         targets_count, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        campaign_id,
                        org_id,
                        data.get("name", "Unnamed Campaign"),
                        campaign_type,
                        data.get("template_id"),
                        data.get("target_group", ""),
                        status,
                        data.get("launch_date"),
                        data.get("end_date"),
                        int(data.get("targets_count", 0)),
                        now,
                        now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "phishing_simulation", "org_id": org_id, "source_engine": "phishing_simulation"})
            except Exception:
                pass

        return self._get_campaign(campaign_id, org_id)  # type: ignore[return-value]

    def _get_campaign(self, campaign_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM campaigns WHERE campaign_id=? AND org_id=?",
                (campaign_id, org_id),
            ).fetchone()
        return dict(row) if row else None

    def list_campaigns(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List campaigns for an org, optionally filtered by status."""
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM campaigns WHERE org_id=? AND status=? ORDER BY created_at DESC",
                    (org_id, status),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM campaigns WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def add_target(self, org_id: str, campaign_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a target to a campaign. Returns the target record."""
        target_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO targets
                        (target_id, org_id, campaign_id, email, department,
                         clicked, reported, opened, data_submitted, click_time,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        target_id,
                        org_id,
                        campaign_id,
                        data.get("email", ""),
                        data.get("department", ""),
                        0,
                        0,
                        0,
                        0,
                        None,
                        now,
                        now,
                    ),
                )
                # bump targets_count on the parent campaign
                conn.execute(
                    "UPDATE campaigns SET targets_count = targets_count + 1, updated_at=? "
                    "WHERE campaign_id=? AND org_id=?",
                    (now, campaign_id, org_id),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM targets WHERE target_id=?", (target_id,)
            ).fetchone()
        return self._row(row)

    def list_targets(self, org_id: str, campaign_id: str) -> List[Dict[str, Any]]:
        """List all targets for a campaign, scoped to org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM targets WHERE org_id=? AND campaign_id=? ORDER BY created_at ASC",
                (org_id, campaign_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def record_result(self, org_id: str, target_id: str, action: str) -> bool:
        """Record an action taken by a target (opened/clicked/reported/data_submitted).

        Updates the corresponding boolean column on the target row and
        inserts into campaign_results. Returns True on success.
        """
        if action not in _VALID_ACTIONS:
            return False

        now = self._now()
        col_map = {
            "opened": "opened",
            "clicked": "clicked",
            "reported": "reported",
            "data_submitted": "data_submitted",
        }
        col = col_map[action]

        with self._lock:
            with self._conn() as conn:
                # Fetch target to get campaign_id and verify org ownership
                row = conn.execute(
                    "SELECT * FROM targets WHERE target_id=? AND org_id=?",
                    (target_id, org_id),
                ).fetchone()
                if not row:
                    return False

                campaign_id = row["campaign_id"]

                # Set the action column and click_time for clicked action
                if action == "clicked":
                    conn.execute(
                        f"UPDATE targets SET {col}=1, click_time=?, updated_at=? "  # nosec B608
                        "WHERE target_id=? AND org_id=?",
                        (now, now, target_id, org_id),
                    )
                else:
                    conn.execute(
                        f"UPDATE targets SET {col}=1, updated_at=? "  # nosec B608
                        "WHERE target_id=? AND org_id=?",
                        (now, target_id, org_id),
                    )

                # Insert result log
                conn.execute(
                    """
                    INSERT INTO campaign_results
                        (result_id, org_id, campaign_id, target_id, action, recorded_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (str(uuid.uuid4()), org_id, campaign_id, target_id, action, now),
                )
        return True

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def create_template(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a phishing template. Returns the template record."""
        template_id = str(uuid.uuid4())
        now = self._now()
        difficulty = data.get("difficulty", "medium")
        if difficulty not in _VALID_DIFFICULTIES:
            difficulty = "medium"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO phishing_templates
                        (template_id, org_id, name, template_type, subject,
                         sender_name, click_rate_avg, difficulty,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        template_id,
                        org_id,
                        data.get("name", "Unnamed Template"),
                        data.get("template_type", "email"),
                        data.get("subject", ""),
                        data.get("sender_name", ""),
                        float(data.get("click_rate_avg", 0.0)),
                        difficulty,
                        now,
                        now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM phishing_templates WHERE template_id=?", (template_id,)
            ).fetchone()
        return dict(row)

    def list_templates(self, org_id: str) -> List[Dict[str, Any]]:
        """List all templates for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM phishing_templates WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_campaign_stats(
        self, org_id: str, campaign_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return aggregated stats for a campaign (or all campaigns if no campaign_id)."""
        with self._conn() as conn:
            if campaign_id:
                rows = conn.execute(
                    "SELECT * FROM targets WHERE org_id=? AND campaign_id=?",
                    (org_id, campaign_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM targets WHERE org_id=?",
                    (org_id,),
                ).fetchall()

        targets = [dict(r) for r in rows]
        total = len(targets)
        opened_count = sum(1 for t in targets if t.get("opened"))
        clicked_count = sum(1 for t in targets if t.get("clicked"))
        reported_count = sum(1 for t in targets if t.get("reported"))
        data_submitted_count = sum(1 for t in targets if t.get("data_submitted"))

        click_rate = round(clicked_count / total * 100, 2) if total else 0.0
        report_rate = round(reported_count / total * 100, 2) if total else 0.0

        # by_department breakdown
        dept_map: Dict[str, Dict[str, int]] = {}
        for t in targets:
            dept = t.get("department") or "Unknown"
            if dept not in dept_map:
                dept_map[dept] = {"total": 0, "clicked": 0, "reported": 0}
            dept_map[dept]["total"] += 1
            if t.get("clicked"):
                dept_map[dept]["clicked"] += 1
            if t.get("reported"):
                dept_map[dept]["reported"] += 1

        return {
            "total_targets": total,
            "opened_count": opened_count,
            "clicked_count": clicked_count,
            "reported_count": reported_count,
            "data_submitted_count": data_submitted_count,
            "click_rate": click_rate,
            "report_rate": report_rate,
            "by_department": dept_map,
        }

    def get_org_stats(self, org_id: str) -> Dict[str, Any]:
        """Return high-level org-wide phishing awareness statistics."""
        with self._conn() as conn:
            campaigns = conn.execute(
                "SELECT * FROM campaigns WHERE org_id=?", (org_id,)
            ).fetchall()
            targets = conn.execute(
                "SELECT * FROM targets WHERE org_id=?", (org_id,)
            ).fetchall()

        total_campaigns = len(campaigns)
        targets_list = [dict(r) for r in targets]
        total = len(targets_list)

        clicked_count = sum(1 for t in targets_list if t.get("clicked"))
        reported_count = sum(1 for t in targets_list if t.get("reported"))

        avg_click_rate = round(clicked_count / total * 100, 2) if total else 0.0
        avg_report_rate = round(reported_count / total * 100, 2) if total else 0.0

        # Most vulnerable department (highest click rate)
        dept_clicks: Dict[str, Dict[str, int]] = {}
        for t in targets_list:
            dept = t.get("department") or "Unknown"
            if dept not in dept_clicks:
                dept_clicks[dept] = {"total": 0, "clicked": 0}
            dept_clicks[dept]["total"] += 1
            if t.get("clicked"):
                dept_clicks[dept]["clicked"] += 1

        most_vulnerable = None
        best_rate = -1.0
        for dept, counts in dept_clicks.items():
            rate = counts["clicked"] / counts["total"] if counts["total"] else 0.0
            if rate > best_rate:
                best_rate = rate
                most_vulnerable = dept

        return {
            "total_campaigns": total_campaigns,
            "avg_click_rate": avg_click_rate,
            "avg_report_rate": avg_report_rate,
            "most_vulnerable_department": most_vulnerable,
        }
