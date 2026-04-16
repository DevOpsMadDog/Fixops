"""Endpoint Threat Hunting Engine — ALDECI.

Manages hunt campaigns, findings, and IOCs for endpoint threat hunting.
Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "endpoint_threat_hunting.db"
)

_VALID_HUNT_TYPES = {"proactive", "reactive", "scheduled", "automated"}
_VALID_HUNT_STATUSES = {"planned", "active", "completed", "cancelled"}
_VALID_FINDING_TYPES = {
    "malware", "persistence", "lateral_movement", "credential_theft",
    "data_staging", "c2_communication", "privilege_escalation", "living_off_land",
}
_VALID_FINDING_STATUSES = {"new", "investigating", "confirmed", "false_positive", "remediated"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_IOC_TYPES = {
    "hash", "ip", "domain", "path", "registry_key", "mutex", "process_name", "user_agent"
}


class EndpointThreatHuntingEngine:
    """SQLite WAL-backed Endpoint Threat Hunting engine.

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
                CREATE TABLE IF NOT EXISTS eth_hunts (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    hunt_name         TEXT NOT NULL DEFAULT '',
                    hypothesis        TEXT NOT NULL DEFAULT '',
                    hunt_type         TEXT NOT NULL DEFAULT 'proactive',
                    technique_ids     TEXT NOT NULL DEFAULT '[]',
                    status            TEXT NOT NULL DEFAULT 'planned',
                    endpoints_scanned INTEGER NOT NULL DEFAULT 0,
                    findings_count    INTEGER NOT NULL DEFAULT 0,
                    started_at        DATETIME,
                    completed_at      DATETIME,
                    hunter            TEXT NOT NULL DEFAULT '',
                    created_at        DATETIME NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_eth_hunts_org
                    ON eth_hunts (org_id);

                CREATE TABLE IF NOT EXISTS eth_findings (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    hunt_id       TEXT NOT NULL,
                    endpoint_id   TEXT NOT NULL DEFAULT '',
                    finding_type  TEXT NOT NULL DEFAULT 'malware',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    process_name  TEXT NOT NULL DEFAULT '',
                    command_line  TEXT NOT NULL DEFAULT '',
                    file_path     TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'new',
                    detected_at   DATETIME,
                    created_at    DATETIME NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_eth_findings_org
                    ON eth_findings (org_id);
                CREATE INDEX IF NOT EXISTS idx_eth_findings_hunt
                    ON eth_findings (org_id, hunt_id);

                CREATE TABLE IF NOT EXISTS eth_iocs (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    hunt_id           TEXT NOT NULL,
                    ioc_value         TEXT NOT NULL DEFAULT '',
                    ioc_type          TEXT NOT NULL DEFAULT 'hash',
                    confidence_score  REAL NOT NULL DEFAULT 0.0,
                    endpoints_matched INTEGER NOT NULL DEFAULT 0,
                    created_at        DATETIME NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_eth_iocs_org
                    ON eth_iocs (org_id);
                CREATE INDEX IF NOT EXISTS idx_eth_iocs_hunt
                    ON eth_iocs (org_id, hunt_id);
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

    @staticmethod
    def _deserialize_hunt(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            row["technique_ids"] = json.loads(row.get("technique_ids") or "[]")
        except (json.JSONDecodeError, TypeError):
            row["technique_ids"] = []
        return row

    # ------------------------------------------------------------------
    # Hunts
    # ------------------------------------------------------------------

    def create_hunt(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new threat hunt campaign."""
        hunt_type = data.get("hunt_type", "proactive")
        if hunt_type not in _VALID_HUNT_TYPES:
            raise ValueError(f"Invalid hunt_type: {hunt_type}. Must be one of {_VALID_HUNT_TYPES}")

        hunt_id = str(uuid.uuid4())
        now = self._now()
        technique_ids = json.dumps(data.get("technique_ids", []))

        row = {
            "id": hunt_id,
            "org_id": org_id,
            "hunt_name": data.get("hunt_name", ""),
            "hypothesis": data.get("hypothesis", ""),
            "hunt_type": hunt_type,
            "technique_ids": technique_ids,
            "status": "planned",
            "endpoints_scanned": 0,
            "findings_count": 0,
            "started_at": None,
            "completed_at": None,
            "hunter": data.get("hunter", ""),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO eth_hunts
                       (id, org_id, hunt_name, hypothesis, hunt_type, technique_ids,
                        status, endpoints_scanned, findings_count, started_at, completed_at,
                        hunter, created_at)
                       VALUES (:id, :org_id, :hunt_name, :hypothesis, :hunt_type, :technique_ids,
                               :status, :endpoints_scanned, :findings_count, :started_at,
                               :completed_at, :hunter, :created_at)""",
                    row,
                )
        result = dict(row)
        result["technique_ids"] = data.get("technique_ids", [])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "endpoint_threat_hunting", "org_id": org_id, "source_engine": "endpoint_threat_hunting"})
            except Exception:
                pass

        return result

    def start_hunt(self, org_id: str, hunt_id: str) -> Dict[str, Any]:
        """Set hunt status to active with started_at timestamp."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM eth_hunts WHERE id=? AND org_id=?", (hunt_id, org_id)
                ).fetchone()
                if existing is None:
                    raise KeyError(f"Hunt {hunt_id} not found for org {org_id}")
                if existing["status"] == "active":
                    raise ValueError(f"Hunt {hunt_id} is already active")
                conn.execute(
                    "UPDATE eth_hunts SET status='active', started_at=? WHERE id=? AND org_id=?",
                    (now, hunt_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM eth_hunts WHERE id=? AND org_id=?", (hunt_id, org_id)
                ).fetchone()
                return self._deserialize_hunt(self._row(updated))

    def complete_hunt(self, org_id: str, hunt_id: str, endpoints_scanned: int = 0) -> Dict[str, Any]:
        """Mark hunt as completed with endpoint scan count."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM eth_hunts WHERE id=? AND org_id=?", (hunt_id, org_id)
                ).fetchone()
                if existing is None:
                    raise KeyError(f"Hunt {hunt_id} not found for org {org_id}")
                conn.execute(
                    """UPDATE eth_hunts
                       SET status='completed', completed_at=?, endpoints_scanned=?
                       WHERE id=? AND org_id=?""",
                    (now, endpoints_scanned, hunt_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM eth_hunts WHERE id=? AND org_id=?", (hunt_id, org_id)
                ).fetchone()
                return self._deserialize_hunt(self._row(updated))

    def list_hunts(
        self,
        org_id: str,
        status: Optional[str] = None,
        hunt_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List hunts with optional filters."""
        sql = "SELECT * FROM eth_hunts WHERE org_id=?"
        params: list = [org_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        if hunt_type:
            sql += " AND hunt_type=?"
            params.append(hunt_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_hunt(self._row(r)) for r in rows]

    def get_hunt(self, org_id: str, hunt_id: str) -> Optional[Dict[str, Any]]:
        """Get a single hunt by ID with org isolation."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM eth_hunts WHERE id=? AND org_id=?", (hunt_id, org_id)
            ).fetchone()
        if row is None:
            return None
        return self._deserialize_hunt(self._row(row))

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a threat finding and increment hunt's findings_count."""
        finding_type = data.get("finding_type", "malware")
        if finding_type not in _VALID_FINDING_TYPES:
            raise ValueError(f"Invalid finding_type: {finding_type}")
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        finding_id = str(uuid.uuid4())
        now = self._now()
        hunt_id = data.get("hunt_id", "")

        row = {
            "id": finding_id,
            "org_id": org_id,
            "hunt_id": hunt_id,
            "endpoint_id": data.get("endpoint_id", ""),
            "finding_type": finding_type,
            "severity": severity,
            "process_name": data.get("process_name", ""),
            "command_line": data.get("command_line", ""),
            "file_path": data.get("file_path", ""),
            "status": data.get("status", "new"),
            "detected_at": data.get("detected_at", now),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO eth_findings
                       (id, org_id, hunt_id, endpoint_id, finding_type, severity,
                        process_name, command_line, file_path, status, detected_at, created_at)
                       VALUES (:id, :org_id, :hunt_id, :endpoint_id, :finding_type, :severity,
                               :process_name, :command_line, :file_path, :status,
                               :detected_at, :created_at)""",
                    row,
                )
                if hunt_id:
                    conn.execute(
                        "UPDATE eth_hunts SET findings_count = findings_count + 1 WHERE id=? AND org_id=?",
                        (hunt_id, org_id),
                    )
        return dict(row)

    def list_findings(
        self,
        org_id: str,
        hunt_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        sql = "SELECT * FROM eth_findings WHERE org_id=?"
        params: list = [org_id]
        if hunt_id:
            sql += " AND hunt_id=?"
            params.append(hunt_id)
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def update_finding_status(self, org_id: str, finding_id: str, status: str) -> Dict[str, Any]:
        """Update the status of a finding."""
        if status not in _VALID_FINDING_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE eth_findings SET status=? WHERE id=? AND org_id=?",
                    (status, finding_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM eth_findings WHERE id=? AND org_id=?", (finding_id, org_id)
                ).fetchone()
        if row is None:
            raise KeyError(f"Finding {finding_id} not found for org {org_id}")
        return self._row(row)

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    def add_ioc(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an IOC associated with a hunt."""
        ioc_type = data.get("ioc_type", "hash")
        if ioc_type not in _VALID_IOC_TYPES:
            raise ValueError(f"Invalid ioc_type: {ioc_type}")

        confidence = float(data.get("confidence_score", 0.0))
        confidence = max(0.0, min(100.0, confidence))

        ioc_id = str(uuid.uuid4())
        now = self._now()

        row = {
            "id": ioc_id,
            "org_id": org_id,
            "hunt_id": data.get("hunt_id", ""),
            "ioc_value": data.get("ioc_value", ""),
            "ioc_type": ioc_type,
            "confidence_score": confidence,
            "endpoints_matched": int(data.get("endpoints_matched", 0)),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO eth_iocs
                       (id, org_id, hunt_id, ioc_value, ioc_type, confidence_score,
                        endpoints_matched, created_at)
                       VALUES (:id, :org_id, :hunt_id, :ioc_value, :ioc_type,
                               :confidence_score, :endpoints_matched, :created_at)""",
                    row,
                )
        return dict(row)

    def list_iocs(
        self,
        org_id: str,
        hunt_id: Optional[str] = None,
        ioc_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List IOCs with optional filters."""
        sql = "SELECT * FROM eth_iocs WHERE org_id=?"
        params: list = [org_id]
        if hunt_id:
            sql += " AND hunt_id=?"
            params.append(hunt_id)
        if ioc_type:
            sql += " AND ioc_type=?"
            params.append(ioc_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_hunting_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate hunting statistics for an org."""
        with self._conn() as conn:
            total_hunts = conn.execute(
                "SELECT COUNT(*) FROM eth_hunts WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            active_hunts = conn.execute(
                "SELECT COUNT(*) FROM eth_hunts WHERE org_id=? AND status='active'", (org_id,)
            ).fetchone()[0]
            completed_hunts = conn.execute(
                "SELECT COUNT(*) FROM eth_hunts WHERE org_id=? AND status='completed'", (org_id,)
            ).fetchone()[0]
            total_findings = conn.execute(
                "SELECT COUNT(*) FROM eth_findings WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            critical_findings = conn.execute(
                "SELECT COUNT(*) FROM eth_findings WHERE org_id=? AND severity='critical'",
                (org_id,),
            ).fetchone()[0]
            confirmed_findings = conn.execute(
                "SELECT COUNT(*) FROM eth_findings WHERE org_id=? AND status='confirmed'",
                (org_id,),
            ).fetchone()[0]
            total_iocs = conn.execute(
                "SELECT COUNT(*) FROM eth_iocs WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            by_hunt_type_rows = conn.execute(
                "SELECT hunt_type, COUNT(*) AS cnt FROM eth_hunts WHERE org_id=? GROUP BY hunt_type",
                (org_id,),
            ).fetchall()
            by_finding_type_rows = conn.execute(
                "SELECT finding_type, COUNT(*) AS cnt FROM eth_findings WHERE org_id=? GROUP BY finding_type",
                (org_id,),
            ).fetchall()

        return {
            "total_hunts": total_hunts,
            "active_hunts": active_hunts,
            "completed_hunts": completed_hunts,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "confirmed_findings": confirmed_findings,
            "total_iocs": total_iocs,
            "by_hunt_type": {r["hunt_type"]: r["cnt"] for r in by_hunt_type_rows},
            "by_finding_type": {r["finding_type"]: r["cnt"] for r in by_finding_type_rows},
        }
