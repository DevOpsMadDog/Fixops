"""Anti-Phishing Engine — URL analysis and phishing simulation for ALDECI.

Manages phishing URL submissions, verdict analysis, and phishing simulation
campaigns to measure user resilience.

Capabilities:
  - URL submission and verdict analysis (clean/phishing/suspicious/malware)
  - Phishing simulation campaigns with click-rate tracking
  - Stats aggregation: by verdict, avg confidence, avg click rate

Compliance: MITRE ATT&CK T1566, anti-phishing, security awareness
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "anti_phishing.db"
)

_VALID_SUBMISSION_SOURCES = {"user_report", "automated", "feed", "manual"}
_VALID_VERDICTS = {"clean", "phishing", "suspicious", "malware"}
_VALID_URL_STATUSES = {"pending", "analyzed"}
_VALID_SIMULATION_TYPES = {"credential_harvest", "malware_link", "attachment", "voice", "sms"}
_VALID_SIM_STATUSES = {"running", "completed", "cancelled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AntiPhishingEngine:
    """SQLite WAL-backed anti-phishing engine.

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
                CREATE TABLE IF NOT EXISTS phishing_urls (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    url                 TEXT NOT NULL,
                    submission_source   TEXT NOT NULL DEFAULT 'automated',
                    verdict             TEXT NOT NULL DEFAULT '',
                    confidence          INTEGER NOT NULL DEFAULT 0,
                    indicators          TEXT NOT NULL DEFAULT '[]',
                    status              TEXT NOT NULL DEFAULT 'pending',
                    submitted_at        TEXT NOT NULL,
                    analyzed_at         TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_phishing_urls_org
                    ON phishing_urls (org_id, verdict, status);

                CREATE TABLE IF NOT EXISTS phishing_simulations (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    campaign_name       TEXT NOT NULL,
                    target_department   TEXT NOT NULL DEFAULT '',
                    simulation_type     TEXT NOT NULL,
                    sent_count          INTEGER NOT NULL DEFAULT 0,
                    opened              INTEGER NOT NULL DEFAULT 0,
                    clicked             INTEGER NOT NULL DEFAULT 0,
                    reported            INTEGER NOT NULL DEFAULT 0,
                    click_rate          REAL NOT NULL DEFAULT 0.0,
                    status              TEXT NOT NULL DEFAULT 'running',
                    started_at          TEXT NOT NULL,
                    completed_at        TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_phishing_sims_org
                    ON phishing_simulations (org_id, status);
                """
            )

    # ------------------------------------------------------------------
    # URL Management
    # ------------------------------------------------------------------

    def submit_url(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a URL for phishing analysis."""
        url = data.get("url", "")
        if not url:
            raise ValueError("url is required")

        submission_source = data.get("submission_source", "automated")
        if submission_source not in _VALID_SUBMISSION_SOURCES:
            raise ValueError(
                f"Invalid submission_source: {submission_source!r}. Valid: {_VALID_SUBMISSION_SOURCES}"
            )

        url_id = str(uuid.uuid4())
        now = _now_iso()

        row = {
            "id": url_id,
            "org_id": org_id,
            "url": url,
            "submission_source": submission_source,
            "verdict": "",
            "confidence": 0,
            "indicators": "[]",
            "status": "pending",
            "submitted_at": data.get("submitted_at", now),
            "analyzed_at": "",
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO phishing_urls
                   (id, org_id, url, submission_source, verdict, confidence,
                    indicators, status, submitted_at, analyzed_at)
                   VALUES (:id, :org_id, :url, :submission_source, :verdict,
                           :confidence, :indicators, :status, :submitted_at, :analyzed_at)""",
                row,
            )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "anti_phishing", "org_id": org_id, "source_engine": "anti_phishing"})
            except Exception:
                pass

        return self._row_to_url(row)

    def analyze_url(
        self, org_id: str, url_id: str, analysis_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Record analysis verdict for a submitted URL."""
        verdict = analysis_data.get("verdict", "")
        if verdict not in _VALID_VERDICTS:
            raise ValueError(f"Invalid verdict: {verdict!r}. Valid: {_VALID_VERDICTS}")

        confidence = int(analysis_data.get("confidence", 0))
        confidence = max(0, min(100, confidence))

        indicators = analysis_data.get("indicators", [])
        indicators_json = json.dumps(indicators) if isinstance(indicators, list) else indicators

        now = _now_iso()

        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """UPDATE phishing_urls
                   SET verdict = ?, confidence = ?, indicators = ?,
                       status = 'analyzed', analyzed_at = ?
                   WHERE id = ? AND org_id = ?""",
                (verdict, confidence, indicators_json, now, url_id, org_id),
            )
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT * FROM phishing_urls WHERE id = ? AND org_id = ?",
                (url_id, org_id),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_url(dict(row))

    def list_urls(
        self,
        org_id: str,
        verdict: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List submitted URLs for the org, optionally filtered by verdict and status."""
        query = "SELECT * FROM phishing_urls WHERE org_id = ?"
        params: List[Any] = [org_id]
        if verdict is not None:
            query += " AND verdict = ?"
            params.append(verdict)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY submitted_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_url(dict(r)) for r in rows]

    def get_url(self, org_id: str, url_id: str) -> Optional[Dict[str, Any]]:
        """Get a single URL submission by ID for the org."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM phishing_urls WHERE id = ? AND org_id = ?",
                (url_id, org_id),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_url(dict(row))

    def _row_to_url(self, row: Dict[str, Any]) -> Dict[str, Any]:
        indicators = row.get("indicators", "[]")
        if isinstance(indicators, str):
            try:
                indicators = json.loads(indicators)
            except (json.JSONDecodeError, ValueError):
                indicators = []
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "url": row["url"],
            "submission_source": row["submission_source"],
            "verdict": row["verdict"],
            "confidence": row["confidence"],
            "indicators": indicators,
            "status": row["status"],
            "submitted_at": row["submitted_at"],
            "analyzed_at": row["analyzed_at"],
        }

    # ------------------------------------------------------------------
    # Simulations
    # ------------------------------------------------------------------

    def record_simulation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a phishing simulation campaign."""
        campaign_name = data.get("campaign_name", "")
        if not campaign_name:
            raise ValueError("campaign_name is required")

        simulation_type = data.get("simulation_type", "")
        if simulation_type not in _VALID_SIMULATION_TYPES:
            raise ValueError(
                f"Invalid simulation_type: {simulation_type!r}. Valid: {_VALID_SIMULATION_TYPES}"
            )

        sent_count = data.get("sent_count")
        if sent_count is None:
            raise ValueError("sent_count is required")
        sent_count = int(sent_count)

        sim_id = str(uuid.uuid4())
        now = _now_iso()

        row = {
            "id": sim_id,
            "org_id": org_id,
            "campaign_name": campaign_name,
            "target_department": data.get("target_department", ""),
            "simulation_type": simulation_type,
            "sent_count": sent_count,
            "opened": int(data.get("opened", 0)),
            "clicked": int(data.get("clicked", 0)),
            "reported": int(data.get("reported", 0)),
            "click_rate": 0.0,
            "status": "running",
            "started_at": data.get("started_at", now),
            "completed_at": "",
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO phishing_simulations
                   (id, org_id, campaign_name, target_department, simulation_type,
                    sent_count, opened, clicked, reported, click_rate, status,
                    started_at, completed_at)
                   VALUES (:id, :org_id, :campaign_name, :target_department,
                           :simulation_type, :sent_count, :opened, :clicked,
                           :reported, :click_rate, :status, :started_at, :completed_at)""",
                row,
            )
        return self._row_to_sim(row)

    def update_simulation_results(
        self,
        org_id: str,
        sim_id: str,
        opened: int,
        clicked: int,
        reported: int,
    ) -> Optional[Dict[str, Any]]:
        """Update simulation results and mark as completed."""
        now = _now_iso()

        with self._lock, self._conn() as conn:
            existing = conn.execute(
                "SELECT sent_count FROM phishing_simulations WHERE id = ? AND org_id = ?",
                (sim_id, org_id),
            ).fetchone()
            if existing is None:
                return None

            sent_count = existing["sent_count"]
            click_rate = (clicked / sent_count * 100) if sent_count > 0 else 0.0

            conn.execute(
                """UPDATE phishing_simulations
                   SET opened = ?, clicked = ?, reported = ?,
                       click_rate = ?, status = 'completed', completed_at = ?
                   WHERE id = ? AND org_id = ?""",
                (opened, clicked, reported, round(click_rate, 2), now, sim_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM phishing_simulations WHERE id = ? AND org_id = ?",
                (sim_id, org_id),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_sim(dict(row))

    def list_simulations(
        self,
        org_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List simulation campaigns for the org, optionally filtered by status."""
        query = "SELECT * FROM phishing_simulations WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY started_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_sim(dict(r)) for r in rows]

    def _row_to_sim(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "campaign_name": row["campaign_name"],
            "target_department": row["target_department"],
            "simulation_type": row["simulation_type"],
            "sent_count": row["sent_count"],
            "opened": row["opened"],
            "clicked": row["clicked"],
            "reported": row["reported"],
            "click_rate": row["click_rate"],
            "status": row["status"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_anti_phishing_stats(self, org_id: str) -> Dict[str, Any]:
        """Return anti-phishing statistics for the org."""
        with self._lock, self._conn() as conn:
            total_urls = conn.execute(
                "SELECT COUNT(*) FROM phishing_urls WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_verdict_rows = conn.execute(
                """SELECT verdict, COUNT(*) AS cnt
                   FROM phishing_urls WHERE org_id = ? AND verdict != ''
                   GROUP BY verdict""",
                (org_id,),
            ).fetchall()

            phishing_urls = conn.execute(
                "SELECT COUNT(*) FROM phishing_urls WHERE org_id = ? AND verdict = 'phishing'",
                (org_id,),
            ).fetchone()[0]

            avg_confidence_row = conn.execute(
                "SELECT AVG(confidence) FROM phishing_urls WHERE org_id = ? AND status = 'analyzed'",
                (org_id,),
            ).fetchone()
            avg_confidence = round(avg_confidence_row[0] or 0.0, 2)

            total_simulations = conn.execute(
                "SELECT COUNT(*) FROM phishing_simulations WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            avg_click_rate_row = conn.execute(
                "SELECT AVG(click_rate) FROM phishing_simulations WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()
            avg_click_rate = round(avg_click_rate_row[0] or 0.0, 2)

        return {
            "total_urls": total_urls,
            "by_verdict": {r["verdict"]: r["cnt"] for r in by_verdict_rows},
            "phishing_urls": phishing_urls,
            "avg_confidence": avg_confidence,
            "total_simulations": total_simulations,
            "avg_click_rate": avg_click_rate,
        }
