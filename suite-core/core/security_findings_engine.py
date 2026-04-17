"""Security Findings Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Unified findings aggregator across all security scanners and tools.
  - Centralizes security findings from SAST/DAST/SIEM/EDR/CSPM/etc.
  - Deduplicates findings (same title+source_tool+asset_id per org, status != resolved)
  - Tracks remediation lifecycle with evidence and suppression workflows
  - Full findings summary with per-severity and per-tool breakdowns

Compliance: NIST SP 800-53, CIS Controls, ISO 27001 A.12.6
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_findings_engine.db"
)

_VALID_FINDING_TYPES = {
    "vulnerability", "misconfiguration", "policy-violation", "anomaly",
    "secret-exposure", "compliance-gap", "malware", "data-leak",
}
_VALID_SOURCE_TOOLS = {
    "SAST", "DAST", "SIEM", "EDR", "CSPM", "CNAPP",
    "Nessus", "Qualys", "Burp", "Semgrep", "Trivy", "custom",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_VALID_EVIDENCE_TYPES = {
    "screenshot", "log", "network-capture", "code-snippet", "config", "report",
}
_VALID_STATUSES = {"open", "in-progress", "resolved", "suppressed", "false-positive"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityFindingsEngine:
    """SQLite WAL-backed Security Findings engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_findings_engine.db
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
                CREATE TABLE IF NOT EXISTS security_findings (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    title            TEXT NOT NULL DEFAULT '',
                    finding_type     TEXT NOT NULL DEFAULT 'vulnerability',
                    source_tool      TEXT NOT NULL DEFAULT 'custom',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    cvss_score       REAL NOT NULL DEFAULT 0.0,
                    asset_id         TEXT NOT NULL DEFAULT '',
                    asset_type       TEXT NOT NULL DEFAULT '',
                    description      TEXT NOT NULL DEFAULT '',
                    remediation      TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'open',
                    first_seen       TEXT NOT NULL DEFAULT '',
                    last_seen        TEXT NOT NULL DEFAULT '',
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    assigned_to      TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_sf_findings_org
                    ON security_findings (org_id, status, severity, source_tool);

                CREATE INDEX IF NOT EXISTS idx_sf_findings_asset
                    ON security_findings (org_id, asset_id);

                CREATE INDEX IF NOT EXISTS idx_sf_dedup
                    ON security_findings (org_id, title, source_tool, asset_id, status);

                CREATE TABLE IF NOT EXISTS finding_evidence (
                    id            TEXT PRIMARY KEY,
                    finding_id    TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    evidence_type TEXT NOT NULL DEFAULT 'log',
                    content       TEXT NOT NULL DEFAULT '',
                    collected_at  TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_sf_evidence_finding
                    ON finding_evidence (finding_id, org_id);

                CREATE TABLE IF NOT EXISTS finding_suppressions (
                    id             TEXT PRIMARY KEY,
                    finding_id     TEXT NOT NULL,
                    org_id         TEXT NOT NULL,
                    reason         TEXT NOT NULL DEFAULT '',
                    suppressed_by  TEXT NOT NULL DEFAULT '',
                    expires_at     TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_sf_suppressions_finding
                    ON finding_suppressions (finding_id, org_id);
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
    # Findings
    # ------------------------------------------------------------------

    def record_finding(
        self,
        org_id: str,
        title: str,
        finding_type: str,
        source_tool: str,
        severity: str,
        cvss_score: float,
        asset_id: str,
        asset_type: str,
        description: str,
        remediation: str,
    ) -> Dict[str, Any]:
        """Record a finding; dedup if same (org+title+source_tool+asset_id) and not resolved."""
        cvss_score = max(0.0, min(10.0, float(cvss_score)))
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                # Look for an existing non-resolved finding to dedup against
                existing = conn.execute(
                    """SELECT * FROM security_findings
                       WHERE org_id = ? AND title = ? AND source_tool = ? AND asset_id = ?
                         AND status != 'resolved'
                       LIMIT 1""",
                    (org_id, title, source_tool, asset_id),
                ).fetchone()

                if existing:
                    # Increment occurrence_count and update last_seen
                    conn.execute(
                        """UPDATE security_findings
                           SET occurrence_count = occurrence_count + 1,
                               last_seen = ?
                           WHERE id = ?""",
                        (now, existing["id"]),
                    )
                    updated = conn.execute(
                        "SELECT * FROM security_findings WHERE id = ?",
                        (existing["id"],),
                    ).fetchone()
                    return self._row(updated)

                # New finding
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "title": title,
                    "finding_type": finding_type,
                    "source_tool": source_tool,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "asset_id": asset_id,
                    "asset_type": asset_type,
                    "description": description,
                    "remediation": remediation,
                    "status": "open",
                    "first_seen": now,
                    "last_seen": now,
                    "occurrence_count": 1,
                    "assigned_to": "",
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO security_findings
                       (id, org_id, title, finding_type, source_tool, severity,
                        cvss_score, asset_id, asset_type, description, remediation,
                        status, first_seen, last_seen, occurrence_count, assigned_to, created_at)
                       VALUES (:id, :org_id, :title, :finding_type, :source_tool, :severity,
                               :cvss_score, :asset_id, :asset_type, :description, :remediation,
                               :status, :first_seen, :last_seen, :occurrence_count,
                               :assigned_to, :created_at)""",
                    record,
                )
                return record

    def update_status(
        self,
        finding_id: str,
        org_id: str,
        status: str,
        assigned_to: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update finding status; if resolved, update last_seen to now."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM security_findings WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    return None

                updates: Dict[str, Any] = {"status": status, "id": finding_id}
                if status == "resolved":
                    updates["last_seen"] = now
                else:
                    updates["last_seen"] = row["last_seen"]

                if assigned_to is not None:
                    updates["assigned_to"] = assigned_to
                else:
                    updates["assigned_to"] = row["assigned_to"]

                conn.execute(
                    """UPDATE security_findings
                       SET status = :status, last_seen = :last_seen, assigned_to = :assigned_to
                       WHERE id = :id""",
                    updates,
                )
                updated = conn.execute(
                    "SELECT * FROM security_findings WHERE id = ?",
                    (finding_id,),
                ).fetchone()
                return self._row(updated)

    def add_evidence(
        self,
        finding_id: str,
        org_id: str,
        evidence_type: str,
        content: str,
    ) -> Dict[str, Any]:
        """Add evidence to a finding."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "finding_id": finding_id,
            "org_id": org_id,
            "evidence_type": evidence_type,
            "content": content,
            "collected_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO finding_evidence
                       (id, finding_id, org_id, evidence_type, content, collected_at)
                       VALUES (:id, :finding_id, :org_id, :evidence_type, :content, :collected_at)""",
                    record,
                )
        return record

    def suppress_finding(
        self,
        finding_id: str,
        org_id: str,
        reason: str,
        suppressed_by: str,
        expires_at: str,
    ) -> Optional[Dict[str, Any]]:
        """Suppress a finding; updates finding status to suppressed."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "finding_id": finding_id,
            "org_id": org_id,
            "reason": reason,
            "suppressed_by": suppressed_by,
            "expires_at": expires_at,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO finding_suppressions
                       (id, finding_id, org_id, reason, suppressed_by, expires_at, created_at)
                       VALUES (:id, :finding_id, :org_id, :reason, :suppressed_by,
                               :expires_at, :created_at)""",
                    record,
                )
                conn.execute(
                    "UPDATE security_findings SET status = 'suppressed' WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                )
        return record

    def get_finding(self, finding_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a finding with its evidence and suppression."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM security_findings WHERE id = ? AND org_id = ?",
                (finding_id, org_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)

            evidence_rows = conn.execute(
                "SELECT * FROM finding_evidence WHERE finding_id = ? AND org_id = ? ORDER BY collected_at DESC",
                (finding_id, org_id),
            ).fetchall()
            result["evidence"] = [self._row(e) for e in evidence_rows]

            suppression_rows = conn.execute(
                "SELECT * FROM finding_suppressions WHERE finding_id = ? AND org_id = ? ORDER BY created_at DESC",
                (finding_id, org_id),
            ).fetchall()
            result["suppressions"] = [self._row(s) for s in suppression_rows]

        return result

    def list_findings(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source_tool: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        sql = "SELECT * FROM security_findings WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if source_tool:
            sql += " AND source_tool = ?"
            params.append(source_tool)
        sql += " ORDER BY cvss_score DESC, created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_asset_findings(self, org_id: str, asset_id: str) -> List[Dict[str, Any]]:
        """Get all findings for a specific asset."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM security_findings
                   WHERE org_id = ? AND asset_id = ?
                   ORDER BY cvss_score DESC, created_at DESC""",
                (org_id, asset_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_findings_summary(self, org_id: str) -> Dict[str, Any]:
        """Summary: counts, severity breakdown, source breakdown, avg cvss, top assets."""
        with self._conn() as conn:
            total_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM security_findings WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            total = total_row["cnt"] if total_row else 0

            status_rows = conn.execute(
                """SELECT status, COUNT(*) AS cnt
                   FROM security_findings WHERE org_id = ?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()
            status_counts: Dict[str, int] = {r["status"]: r["cnt"] for r in status_rows}

            severity_rows = conn.execute(
                """SELECT severity, COUNT(*) AS cnt
                   FROM security_findings WHERE org_id = ?
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            severity_breakdown: Dict[str, int] = {r["severity"]: r["cnt"] for r in severity_rows}

            tool_rows = conn.execute(
                """SELECT source_tool, COUNT(*) AS cnt
                   FROM security_findings WHERE org_id = ?
                   GROUP BY source_tool""",
                (org_id,),
            ).fetchall()
            by_source_tool: Dict[str, int] = {r["source_tool"]: r["cnt"] for r in tool_rows}

            avg_row = conn.execute(
                "SELECT AVG(cvss_score) AS avg_cvss FROM security_findings WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_cvss = round(avg_row["avg_cvss"] or 0.0, 2)

            top_asset_rows = conn.execute(
                """SELECT asset_id, COUNT(*) AS cnt
                   FROM security_findings
                   WHERE org_id = ? AND status = 'open'
                   GROUP BY asset_id
                   ORDER BY cnt DESC
                   LIMIT 5""",
                (org_id,),
            ).fetchall()
            top_assets = [{"asset_id": r["asset_id"], "open_findings": r["cnt"]} for r in top_asset_rows]

        return {
            "total": total,
            "open": status_counts.get("open", 0),
            "resolved": status_counts.get("resolved", 0),
            "suppressed": status_counts.get("suppressed", 0),
            "in_progress": status_counts.get("in-progress", 0),
            "false_positive": status_counts.get("false-positive", 0),
            "by_severity": severity_breakdown,
            "by_source_tool": by_source_tool,
            "avg_cvss_score": avg_cvss,
            "top_assets_by_open_findings": top_assets,
        }
