"""Threat Brief Engine — ALDECI.

Manages threat intelligence briefs lifecycle: authoring, distribution,
recipient tracking, and embedded threat records. Supports daily/weekly/
monthly operational cadence as well as executive and incident briefs.

Compliance: NIST CSF ID.RA-2, ISO/IEC 27001 A.6.1.4, MITRE ATT&CK
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_brief.db"
)

_VALID_BRIEF_TYPES = {"daily", "weekly", "monthly", "incident", "executive", "technical"}
_VALID_THREAT_LEVELS = {"critical", "high", "medium", "low", "informational"}
_VALID_DISTRIBUTION_STATUSES = {"draft", "pending", "distributed", "recalled"}
_VALID_RECIPIENT_TYPES = {"ciso", "soc", "executive", "all_staff", "team", "individual"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatBriefEngine:
    """SQLite WAL-backed Threat Brief engine.

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
                CREATE TABLE IF NOT EXISTS threat_briefs (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    title               TEXT NOT NULL DEFAULT '',
                    brief_type          TEXT NOT NULL DEFAULT 'daily',
                    threat_level        TEXT NOT NULL DEFAULT 'medium',
                    summary             TEXT NOT NULL DEFAULT '',
                    key_findings        TEXT NOT NULL DEFAULT '[]',
                    recommendations     TEXT NOT NULL DEFAULT '[]',
                    distribution_status TEXT NOT NULL DEFAULT 'draft',
                    author              TEXT NOT NULL DEFAULT '',
                    period_start        TEXT NOT NULL DEFAULT '',
                    period_end          TEXT NOT NULL DEFAULT '',
                    distributed_at      TEXT,
                    recipient_count     INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS brief_recipients (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    brief_id        TEXT NOT NULL,
                    recipient_type  TEXT NOT NULL DEFAULT 'individual',
                    recipient_id    TEXT NOT NULL DEFAULT '',
                    recipient_email TEXT NOT NULL DEFAULT '',
                    delivered_at    TEXT,
                    read_at         TEXT,
                    acknowledged    INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS brief_threats (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    brief_id         TEXT NOT NULL,
                    threat_name      TEXT NOT NULL DEFAULT '',
                    threat_actor     TEXT NOT NULL DEFAULT '',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    affected_sectors TEXT NOT NULL DEFAULT '[]',
                    ioc_count        INTEGER NOT NULL DEFAULT 0,
                    mitre_tactics    TEXT NOT NULL DEFAULT '[]',
                    added_at         TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("key_findings", "recommendations", "affected_sectors", "mitre_tactics"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    # ------------------------------------------------------------------
    # Briefs
    # ------------------------------------------------------------------

    def create_brief(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new threat brief. Title is required."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required")

        brief_type = data.get("brief_type", "daily")
        if brief_type not in _VALID_BRIEF_TYPES:
            raise ValueError(f"brief_type must be one of {_VALID_BRIEF_TYPES}")

        threat_level = data.get("threat_level", "medium")
        if threat_level not in _VALID_THREAT_LEVELS:
            raise ValueError(f"threat_level must be one of {_VALID_THREAT_LEVELS}")

        distribution_status = data.get("distribution_status", "draft")
        if distribution_status not in _VALID_DISTRIBUTION_STATUSES:
            raise ValueError(f"distribution_status must be one of {_VALID_DISTRIBUTION_STATUSES}")

        key_findings = data.get("key_findings", [])
        recommendations = data.get("recommendations", [])

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "brief_type": brief_type,
            "threat_level": threat_level,
            "summary": data.get("summary", ""),
            "key_findings": json.dumps(key_findings if isinstance(key_findings, list) else []),
            "recommendations": json.dumps(recommendations if isinstance(recommendations, list) else []),
            "distribution_status": distribution_status,
            "author": data.get("author", ""),
            "period_start": data.get("period_start", ""),
            "period_end": data.get("period_end", ""),
            "distributed_at": None,
            "recipient_count": 0,
            "created_at": _now(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO threat_briefs
                       (id, org_id, title, brief_type, threat_level, summary,
                        key_findings, recommendations, distribution_status, author,
                        period_start, period_end, distributed_at, recipient_count, created_at)
                       VALUES (:id, :org_id, :title, :brief_type, :threat_level, :summary,
                               :key_findings, :recommendations, :distribution_status, :author,
                               :period_start, :period_end, :distributed_at, :recipient_count, :created_at)
                    """,
                    record,
                )

        result = dict(record)
        result["key_findings"] = key_findings if isinstance(key_findings, list) else []
        result["recommendations"] = recommendations if isinstance(recommendations, list) else []
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_brief", "org_id": org_id, "source_engine": "threat_brief"})
            except Exception:
                pass

        return result

    def list_briefs(
        self,
        org_id: str,
        brief_type: Optional[str] = None,
        distribution_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threat briefs with optional filters."""
        query = "SELECT * FROM threat_briefs WHERE org_id = ?"
        params: List[Any] = [org_id]
        if brief_type:
            query += " AND brief_type = ?"
            params.append(brief_type)
        if distribution_status:
            query += " AND distribution_status = ?"
            params.append(distribution_status)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_brief(self, org_id: str, brief_id: str) -> Optional[Dict[str, Any]]:
        """Return a single brief or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM threat_briefs WHERE org_id = ? AND id = ?",
                (org_id, brief_id),
            ).fetchone()
        return self._row(row) if row else None

    def distribute_brief(
        self,
        org_id: str,
        brief_id: str,
        recipient_data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Mark brief as distributed and create recipient records.

        recipient_data: list of dicts with recipient_type, recipient_id, recipient_email.
        """
        with self._lock:
            brief = self.get_brief(org_id, brief_id)
            if brief is None:
                raise KeyError(f"Brief '{brief_id}' not found")

            now = _now()
            recipients_to_insert = []
            for rd in recipient_data:
                r_type = rd.get("recipient_type", "individual")
                if r_type not in _VALID_RECIPIENT_TYPES:
                    raise ValueError(f"recipient_type must be one of {_VALID_RECIPIENT_TYPES}")
                recipients_to_insert.append({
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "brief_id": brief_id,
                    "recipient_type": r_type,
                    "recipient_id": rd.get("recipient_id", ""),
                    "recipient_email": rd.get("recipient_email", ""),
                    "delivered_at": now,
                    "read_at": None,
                    "acknowledged": 0,
                })

            count = len(recipients_to_insert)

            with self._conn() as conn:
                if recipients_to_insert:
                    conn.executemany(
                        """INSERT INTO brief_recipients
                           (id, org_id, brief_id, recipient_type, recipient_id,
                            recipient_email, delivered_at, read_at, acknowledged)
                           VALUES (:id, :org_id, :brief_id, :recipient_type, :recipient_id,
                                   :recipient_email, :delivered_at, :read_at, :acknowledged)
                        """,
                        recipients_to_insert,
                    )
                conn.execute(
                    """UPDATE threat_briefs
                       SET distribution_status = 'distributed',
                           distributed_at = ?,
                           recipient_count = recipient_count + ?
                       WHERE org_id = ? AND id = ?
                    """,
                    (now, count, org_id, brief_id),
                )

        return self.get_brief(org_id, brief_id)

    def list_recipients(
        self,
        org_id: str,
        brief_id: Optional[str] = None,
        recipient_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List recipients with optional filters."""
        query = "SELECT * FROM brief_recipients WHERE org_id = ?"
        params: List[Any] = [org_id]
        if brief_id:
            query += " AND brief_id = ?"
            params.append(brief_id)
        if recipient_type:
            query += " AND recipient_type = ?"
            params.append(recipient_type)
        query += " ORDER BY delivered_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------

    def add_threat(self, org_id: str, brief_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a threat record to a brief."""
        threat_name = (data.get("threat_name") or "").strip()
        if not threat_name:
            raise ValueError("threat_name is required")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        affected_sectors = data.get("affected_sectors", [])
        mitre_tactics = data.get("mitre_tactics", [])

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "brief_id": brief_id,
            "threat_name": threat_name,
            "threat_actor": data.get("threat_actor", ""),
            "severity": severity,
            "affected_sectors": json.dumps(affected_sectors if isinstance(affected_sectors, list) else []),
            "ioc_count": int(data.get("ioc_count", 0)),
            "mitre_tactics": json.dumps(mitre_tactics if isinstance(mitre_tactics, list) else []),
            "added_at": _now(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO brief_threats
                       (id, org_id, brief_id, threat_name, threat_actor, severity,
                        affected_sectors, ioc_count, mitre_tactics, added_at)
                       VALUES (:id, :org_id, :brief_id, :threat_name, :threat_actor, :severity,
                               :affected_sectors, :ioc_count, :mitre_tactics, :added_at)
                    """,
                    record,
                )

        result = dict(record)
        result["affected_sectors"] = affected_sectors if isinstance(affected_sectors, list) else []
        result["mitre_tactics"] = mitre_tactics if isinstance(mitre_tactics, list) else []
        return result

    def list_threats(
        self,
        org_id: str,
        brief_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threats with optional brief_id filter."""
        query = "SELECT * FROM brief_threats WHERE org_id = ?"
        params: List[Any] = [org_id]
        if brief_id:
            query += " AND brief_id = ?"
            params.append(brief_id)
        query += " ORDER BY added_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_brief_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics for the org."""
        with self._conn() as conn:
            total_briefs = conn.execute(
                "SELECT COUNT(*) FROM threat_briefs WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            distributed_briefs = conn.execute(
                "SELECT COUNT(*) FROM threat_briefs WHERE org_id = ? AND distribution_status = 'distributed'",
                (org_id,),
            ).fetchone()[0]

            total_threats = conn.execute(
                "SELECT COUNT(*) FROM brief_threats WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            avg_row = conn.execute(
                "SELECT AVG(recipient_count) FROM threat_briefs WHERE org_id = ?", (org_id,)
            ).fetchone()
            avg_recipient_count = round(avg_row[0] or 0.0, 2)

            # by_type
            by_type_rows = conn.execute(
                "SELECT brief_type, COUNT(*) as cnt FROM threat_briefs WHERE org_id = ? GROUP BY brief_type",
                (org_id,),
            ).fetchall()
            by_type = {r["brief_type"]: r["cnt"] for r in by_type_rows}

            # by_threat_level
            by_level_rows = conn.execute(
                "SELECT threat_level, COUNT(*) as cnt FROM threat_briefs WHERE org_id = ? GROUP BY threat_level",
                (org_id,),
            ).fetchall()
            by_threat_level = {r["threat_level"]: r["cnt"] for r in by_level_rows}

            # critical briefs this month
            month_prefix = datetime.now(timezone.utc).strftime("%Y-%m")
            critical_this_month = conn.execute(
                """SELECT COUNT(*) FROM threat_briefs
                   WHERE org_id = ? AND threat_level = 'critical'
                   AND created_at LIKE ?""",
                (org_id, f"{month_prefix}%"),
            ).fetchone()[0]

        return {
            "total_briefs": total_briefs,
            "distributed_briefs": distributed_briefs,
            "total_threats": total_threats,
            "avg_recipient_count": avg_recipient_count,
            "by_type": by_type,
            "by_threat_level": by_threat_level,
            "critical_briefs_this_month": critical_this_month,
        }
