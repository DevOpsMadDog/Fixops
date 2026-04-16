"""Cyber Threat Intelligence Engine — ALDECI.

Manages CTI reports, IOCs, and threat intelligence lifecycle.

Capabilities:
  - Intel report lifecycle: draft → published → archived/retracted
  - IOC management per report: ip, domain, hash, url, email, file_path, registry_key
  - Multi-tenant via org_id
  - Stats: totals, by_intel_type, by_tlp, by_source_type, high_confidence_reports

Compliance: NIST CSF ID.RA-2, ISO 27001 A.5.7 (Threat Intelligence), STIX 2.1
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cyber_threat_intelligence.db"
)

_VALID_INTEL_TYPES = {"strategic", "tactical", "operational", "technical"}
_VALID_TLP = {"white", "green", "amber", "red"}
_VALID_SOURCE_TYPES = {"osint", "isac", "commercial", "government", "internal", "partner"}
_VALID_REPORT_STATUSES = {"draft", "published", "archived", "retracted"}
_VALID_IOC_TYPES = {"ip", "domain", "hash", "url", "email", "file_path", "registry_key"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CyberThreatIntelligenceEngine:
    """SQLite WAL-backed Cyber Threat Intelligence engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/cyber_threat_intelligence.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path if db_path is not None else _DEFAULT_DB
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
                CREATE TABLE IF NOT EXISTS cti_reports (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    title            TEXT NOT NULL DEFAULT '',
                    intel_type       TEXT NOT NULL DEFAULT 'tactical',
                    tlp              TEXT NOT NULL DEFAULT 'amber',
                    source_type      TEXT NOT NULL DEFAULT 'osint',
                    summary          TEXT NOT NULL DEFAULT '',
                    content          TEXT NOT NULL DEFAULT '',
                    tags_json        TEXT NOT NULL DEFAULT '[]',
                    confidence_score REAL NOT NULL DEFAULT 0.5,
                    published_at     DATETIME,
                    status           TEXT NOT NULL DEFAULT 'draft',
                    created_at       DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_cti_reports_org
                    ON cti_reports (org_id, intel_type, tlp, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS cti_iocs (
                    id         TEXT PRIMARY KEY,
                    org_id     TEXT NOT NULL,
                    report_id  TEXT NOT NULL,
                    ioc_type   TEXT NOT NULL DEFAULT 'ip',
                    value      TEXT NOT NULL DEFAULT '',
                    context    TEXT NOT NULL DEFAULT '',
                    first_seen DATETIME,
                    last_seen  DATETIME,
                    confidence REAL NOT NULL DEFAULT 0.5,
                    created_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_cti_iocs_org
                    ON cti_iocs (org_id, report_id, ioc_type, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def create_intel_report(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new CTI report in draft status."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        intel_type = data.get("intel_type", "tactical")
        if intel_type not in _VALID_INTEL_TYPES:
            raise ValueError(
                f"Invalid intel_type: {intel_type!r}. "
                f"Must be one of {sorted(_VALID_INTEL_TYPES)}"
            )

        tlp = data.get("tlp", "amber")
        if tlp not in _VALID_TLP:
            raise ValueError(
                f"Invalid tlp: {tlp!r}. "
                f"Must be one of {sorted(_VALID_TLP)}"
            )

        source_type = data.get("source_type", "osint")
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(
                f"Invalid source_type: {source_type!r}. "
                f"Must be one of {sorted(_VALID_SOURCE_TYPES)}"
            )

        tags = data.get("tags_json", data.get("tags", []))
        if isinstance(tags, list):
            tags_json = json.dumps(tags)
        else:
            tags_json = str(tags)

        confidence_score = float(data.get("confidence_score", 0.5))
        confidence_score = max(0.0, min(1.0, confidence_score))

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "intel_type": intel_type,
            "tlp": tlp,
            "source_type": source_type,
            "summary": data.get("summary", ""),
            "content": data.get("content", ""),
            "tags_json": tags_json,
            "confidence_score": confidence_score,
            "published_at": None,
            "status": "draft",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cti_reports
                       (id, org_id, title, intel_type, tlp, source_type, summary,
                        content, tags_json, confidence_score, published_at, status, created_at)
                       VALUES (:id, :org_id, :title, :intel_type, :tlp, :source_type,
                               :summary, :content, :tags_json, :confidence_score,
                               :published_at, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "cyber_threat_intelligence", "org_id": org_id, "source_engine": "cyber_threat_intelligence"})
            except Exception:
                pass

        return record

    def list_reports(
        self,
        org_id: str,
        intel_type: Optional[str] = None,
        tlp: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List CTI reports with optional filters."""
        sql = "SELECT * FROM cti_reports WHERE org_id = ?"
        params: list = [org_id]
        if intel_type:
            sql += " AND intel_type = ?"
            params.append(intel_type)
        if tlp:
            sql += " AND tlp = ?"
            params.append(tlp)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_report(self, org_id: str, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single report by ID. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cti_reports WHERE org_id = ? AND id = ?",
                (org_id, report_id),
            ).fetchone()
        return self._row(row) if row else None

    def publish_report(self, org_id: str, report_id: str) -> Dict[str, Any]:
        """Publish a CTI report (status=published, published_at=now)."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE cti_reports SET status = 'published', published_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (now, org_id, report_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Report not found: {report_id}")
                row = conn.execute(
                    "SELECT * FROM cti_reports WHERE org_id = ? AND id = ?",
                    (org_id, report_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    def add_ioc_to_report(
        self, org_id: str, report_id: str, ioc_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add an IOC to an existing CTI report."""
        ioc_type = ioc_data.get("ioc_type", "ip")
        if ioc_type not in _VALID_IOC_TYPES:
            raise ValueError(
                f"Invalid ioc_type: {ioc_type!r}. "
                f"Must be one of {sorted(_VALID_IOC_TYPES)}"
            )

        value = (ioc_data.get("value") or "").strip()
        if not value:
            raise ValueError("value is required for IOC.")

        confidence = float(ioc_data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "report_id": report_id,
            "ioc_type": ioc_type,
            "value": value,
            "context": ioc_data.get("context", ""),
            "first_seen": ioc_data.get("first_seen", now),
            "last_seen": ioc_data.get("last_seen", now),
            "confidence": confidence,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cti_iocs
                       (id, org_id, report_id, ioc_type, value, context,
                        first_seen, last_seen, confidence, created_at)
                       VALUES (:id, :org_id, :report_id, :ioc_type, :value, :context,
                               :first_seen, :last_seen, :confidence, :created_at)""",
                    record,
                )
        return record

    def list_iocs(
        self,
        org_id: str,
        report_id: Optional[str] = None,
        ioc_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List IOCs with optional filters."""
        sql = "SELECT * FROM cti_iocs WHERE org_id = ?"
        params: list = [org_id]
        if report_id:
            sql += " AND report_id = ?"
            params.append(report_id)
        if ioc_type:
            sql += " AND ioc_type = ?"
            params.append(ioc_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_intel_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated CTI statistics for an org."""
        with self._conn() as conn:
            total_reports = conn.execute(
                "SELECT COUNT(*) FROM cti_reports WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            published_reports = conn.execute(
                "SELECT COUNT(*) FROM cti_reports WHERE org_id = ? AND status = 'published'",
                (org_id,),
            ).fetchone()[0]

            total_iocs = conn.execute(
                "SELECT COUNT(*) FROM cti_iocs WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_intel_type_rows = conn.execute(
                "SELECT intel_type, COUNT(*) as cnt FROM cti_reports "
                "WHERE org_id = ? GROUP BY intel_type",
                (org_id,),
            ).fetchall()

            by_tlp_rows = conn.execute(
                "SELECT tlp, COUNT(*) as cnt FROM cti_reports "
                "WHERE org_id = ? GROUP BY tlp",
                (org_id,),
            ).fetchall()

            by_source_type_rows = conn.execute(
                "SELECT source_type, COUNT(*) as cnt FROM cti_reports "
                "WHERE org_id = ? GROUP BY source_type",
                (org_id,),
            ).fetchall()

            high_confidence_reports = conn.execute(
                "SELECT COUNT(*) FROM cti_reports "
                "WHERE org_id = ? AND confidence_score >= 0.8",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_reports": total_reports,
            "published_reports": published_reports,
            "total_iocs": total_iocs,
            "by_intel_type": {r["intel_type"]: r["cnt"] for r in by_intel_type_rows},
            "by_tlp": {r["tlp"]: r["cnt"] for r in by_tlp_rows},
            "by_source_type": {r["source_type"]: r["cnt"] for r in by_source_type_rows},
            "high_confidence_reports": high_confidence_reports,
        }
