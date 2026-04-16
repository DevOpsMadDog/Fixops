"""Digital Forensics Engine — ALDECI.

Manage forensic cases, evidence items, analysis results, and chain of custody
for incident response and digital investigations.

Compliance: NIST SP 800-86, ISO/IEC 27037, SWGDE guidelines
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "digital_forensics.db"
)

_CASE_TYPES = {"malware", "data_breach", "insider", "fraud", "ransom"}
_CASE_STATUSES = {"open", "active", "closed", "archived"}
_PRIORITIES = {"critical", "high", "medium", "low"}
_EVIDENCE_TYPES = {
    "memory_dump", "disk_image", "pcap", "log_file",
    "malware_sample", "registry_hive", "mobile_image",
}
_ANALYSIS_TYPES = {"static", "dynamic", "network", "timeline", "memory"}


class DigitalForensicsEngine:
    """SQLite WAL-backed Digital Forensics case management engine.

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
                CREATE TABLE IF NOT EXISTS forensic_cases (
                    case_id             TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    title               TEXT NOT NULL,
                    case_type           TEXT NOT NULL DEFAULT 'malware',
                    status              TEXT NOT NULL DEFAULT 'open',
                    priority            TEXT NOT NULL DEFAULT 'medium',
                    assigned_analyst    TEXT NOT NULL DEFAULT '',
                    related_incident_id TEXT NOT NULL DEFAULT '',
                    created_at          DATETIME NOT NULL,
                    closed_at           DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_case_org
                    ON forensic_cases (org_id, status);

                CREATE TABLE IF NOT EXISTS evidence_items (
                    evidence_id         TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    case_id             TEXT NOT NULL,
                    evidence_type       TEXT NOT NULL DEFAULT 'log_file',
                    filename            TEXT NOT NULL DEFAULT '',
                    size_bytes          INTEGER NOT NULL DEFAULT 0,
                    hash_md5            TEXT NOT NULL DEFAULT '',
                    hash_sha256         TEXT NOT NULL DEFAULT '',
                    collected_by        TEXT NOT NULL DEFAULT '',
                    collected_at        DATETIME NOT NULL,
                    storage_location    TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_case
                    ON evidence_items (case_id, org_id);

                CREATE TABLE IF NOT EXISTS analysis_results (
                    result_id           TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    case_id             TEXT NOT NULL,
                    evidence_id         TEXT NOT NULL DEFAULT '',
                    analysis_type       TEXT NOT NULL DEFAULT 'static',
                    findings            TEXT NOT NULL DEFAULT '[]',
                    iocs_extracted      TEXT NOT NULL DEFAULT '[]',
                    tool_used           TEXT NOT NULL DEFAULT '',
                    analyst             TEXT NOT NULL DEFAULT '',
                    completed_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_analysis_case
                    ON analysis_results (case_id, org_id);

                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    custody_id          TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    evidence_id         TEXT NOT NULL,
                    action              TEXT NOT NULL,
                    actor               TEXT NOT NULL,
                    notes               TEXT NOT NULL DEFAULT '',
                    timestamp           DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_custody_evidence
                    ON chain_of_custody (evidence_id, org_id);
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
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def create_case(self, org_id: str, data: dict) -> dict:
        """Create a new forensic investigation case."""
        case_id = str(uuid.uuid4())
        now = self._now()

        case_type = data.get("case_type", "malware")
        if case_type not in _CASE_TYPES:
            case_type = "malware"

        status = data.get("status", "open")
        if status not in _CASE_STATUSES:
            status = "open"

        priority = data.get("priority", "medium")
        if priority not in _PRIORITIES:
            priority = "medium"

        record = {
            "case_id": case_id,
            "org_id": org_id,
            "title": str(data.get("title", "")),
            "case_type": case_type,
            "status": status,
            "priority": priority,
            "assigned_analyst": str(data.get("assigned_analyst", "")),
            "related_incident_id": str(data.get("related_incident_id", "")),
            "created_at": now,
            "closed_at": None,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO forensic_cases
                        (case_id, org_id, title, case_type, status, priority,
                         assigned_analyst, related_incident_id, created_at, closed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["case_id"], record["org_id"], record["title"],
                        record["case_type"], record["status"], record["priority"],
                        record["assigned_analyst"], record["related_incident_id"],
                        record["created_at"], record["closed_at"],
                    ),
                )
        _logger.info("Created forensic case %s for org %s", case_id, org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "digital_forensics", "org_id": org_id, "source_engine": "digital_forensics"})
            except Exception:
                pass

        return record

    def list_cases(self, org_id: str, status: Optional[str] = None) -> List[dict]:
        """List forensic cases for an org with optional status filter."""
        query = "SELECT * FROM forensic_cases WHERE org_id=?"
        params: list = [org_id]

        if status:
            query += " AND status=?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_case(self, org_id: str, case_id: str) -> Optional[dict]:
        """Fetch a single forensic case by ID, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM forensic_cases WHERE case_id=? AND org_id=?",
                (case_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def close_case(self, org_id: str, case_id: str) -> bool:
        """Close a forensic case. Returns True if updated."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE forensic_cases SET status='closed', closed_at=? WHERE case_id=? AND org_id=?",
                    (now, case_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def add_evidence(self, org_id: str, case_id: str, data: dict) -> dict:
        """Add an evidence item to a forensic case."""
        evidence_id = str(uuid.uuid4())
        now = self._now()

        evidence_type = data.get("evidence_type", "log_file")
        if evidence_type not in _EVIDENCE_TYPES:
            evidence_type = "log_file"

        record = {
            "evidence_id": evidence_id,
            "org_id": org_id,
            "case_id": case_id,
            "evidence_type": evidence_type,
            "filename": str(data.get("filename", "")),
            "size_bytes": int(data.get("size_bytes", 0)),
            "hash_md5": str(data.get("hash_md5", "")),
            "hash_sha256": str(data.get("hash_sha256", "")),
            "collected_by": str(data.get("collected_by", "")),
            "collected_at": data.get("collected_at", now),
            "storage_location": str(data.get("storage_location", "")),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO evidence_items
                        (evidence_id, org_id, case_id, evidence_type, filename, size_bytes,
                         hash_md5, hash_sha256, collected_by, collected_at, storage_location)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["evidence_id"], record["org_id"], record["case_id"],
                        record["evidence_type"], record["filename"], record["size_bytes"],
                        record["hash_md5"], record["hash_sha256"], record["collected_by"],
                        record["collected_at"], record["storage_location"],
                    ),
                )

        # Auto-log chain of custody entry for collection
        self.log_chain_of_custody(
            org_id=org_id,
            evidence_id=evidence_id,
            action="collected",
            actor=record["collected_by"] or "system",
            notes=f"Evidence collected: {record['filename']}",
        )

        _logger.info("Added evidence %s to case %s", evidence_id, case_id)
        return record

    def list_evidence(self, org_id: str, case_id: str) -> List[dict]:
        """List all evidence items for a case."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence_items WHERE case_id=? AND org_id=? ORDER BY collected_at DESC",
                (case_id, org_id),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_evidence(self, org_id: str, evidence_id: str) -> Optional[dict]:
        """Fetch a single evidence item by ID, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM evidence_items WHERE evidence_id=? AND org_id=?",
                (evidence_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Analysis Results
    # ------------------------------------------------------------------

    def add_analysis_result(self, org_id: str, case_id: str, data: dict) -> dict:
        """Add an analysis result for a forensic case."""
        result_id = str(uuid.uuid4())
        now = self._now()

        analysis_type = data.get("analysis_type", "static")
        if analysis_type not in _ANALYSIS_TYPES:
            analysis_type = "static"

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = [str(findings)]

        iocs_extracted = data.get("iocs_extracted", [])
        if not isinstance(iocs_extracted, list):
            iocs_extracted = [str(iocs_extracted)]

        record = {
            "result_id": result_id,
            "org_id": org_id,
            "case_id": case_id,
            "evidence_id": str(data.get("evidence_id", "")),
            "analysis_type": analysis_type,
            "findings": findings,
            "iocs_extracted": iocs_extracted,
            "tool_used": str(data.get("tool_used", "")),
            "analyst": str(data.get("analyst", "")),
            "completed_at": data.get("completed_at", now),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO analysis_results
                        (result_id, org_id, case_id, evidence_id, analysis_type,
                         findings, iocs_extracted, tool_used, analyst, completed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["result_id"], record["org_id"], record["case_id"],
                        record["evidence_id"], record["analysis_type"],
                        json.dumps(record["findings"]),
                        json.dumps(record["iocs_extracted"]),
                        record["tool_used"], record["analyst"],
                        record["completed_at"],
                    ),
                )
        _logger.info("Added analysis result %s for case %s", result_id, case_id)
        return record

    def list_analysis_results(self, org_id: str, case_id: str) -> List[dict]:
        """List all analysis results for a case."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM analysis_results
                WHERE case_id=? AND org_id=?
                ORDER BY completed_at DESC
                """,
                (case_id, org_id),
            ).fetchall()

        results = []
        for r in rows:
            d = self._row_to_dict(r)
            d["findings"] = json.loads(d.get("findings") or "[]")
            d["iocs_extracted"] = json.loads(d.get("iocs_extracted") or "[]")
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # Chain of Custody
    # ------------------------------------------------------------------

    def log_chain_of_custody(
        self,
        org_id: str,
        evidence_id: str,
        action: str,
        actor: str,
        notes: str = "",
    ) -> dict:
        """Log a chain of custody entry for an evidence item."""
        custody_id = str(uuid.uuid4())
        now = self._now()

        record = {
            "custody_id": custody_id,
            "org_id": org_id,
            "evidence_id": evidence_id,
            "action": action,
            "actor": actor,
            "notes": notes,
            "timestamp": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO chain_of_custody
                        (custody_id, org_id, evidence_id, action, actor, notes, timestamp)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        record["custody_id"], record["org_id"], record["evidence_id"],
                        record["action"], record["actor"], record["notes"],
                        record["timestamp"],
                    ),
                )
        return record

    def get_chain_of_custody(self, org_id: str, evidence_id: str) -> List[dict]:
        """Get the full chain of custody for an evidence item."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM chain_of_custody
                WHERE evidence_id=? AND org_id=?
                ORDER BY timestamp ASC
                """,
                (evidence_id, org_id),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_forensics_stats(self, org_id: str) -> dict:
        """Return aggregate forensics statistics for an org."""
        with self._conn() as conn:
            open_cases = conn.execute(
                "SELECT COUNT(*) FROM forensic_cases WHERE org_id=? AND status IN ('open','active')",
                (org_id,),
            ).fetchone()[0]

            evidence_items = conn.execute(
                "SELECT COUNT(*) FROM evidence_items WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            analyses_completed = conn.execute(
                "SELECT COUNT(*) FROM analysis_results WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            # Average case duration (closed cases only, in days)
            duration_row = conn.execute(
                """
                SELECT AVG(
                    CAST(
                        (julianday(closed_at) - julianday(created_at))
                    AS REAL)
                )
                FROM forensic_cases
                WHERE org_id=? AND status='closed' AND closed_at IS NOT NULL
                """,
                (org_id,),
            ).fetchone()[0]

        avg_duration = round(float(duration_row), 2) if duration_row is not None else 0.0

        return {
            "open_cases": open_cases,
            "evidence_items": evidence_items,
            "analyses_completed": analyses_completed,
            "avg_case_duration_days": avg_duration,
        }
