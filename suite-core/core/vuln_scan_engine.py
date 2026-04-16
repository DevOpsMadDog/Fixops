"""Vulnerability Scan Engine — ALDECI.

Manages vulnerability scan lifecycle and findings across Nessus, Qualys,
Rapid7, OpenVAS, Nuclei, Trivy, Grype, and custom scanners. Tracks severity
counters, finding status transitions, and provides aggregate statistics.

Compliance: NIST CSF ID.RA-1, ISO/IEC 27001 A.12.6.1, PCI-DSS 6.3.2
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "vuln_scan.db"
)

_VALID_SCANNER_TYPES = {
    "nessus", "qualys", "rapid7", "openvas", "nuclei", "trivy", "grype", "custom",
}
_VALID_SCAN_STATUSES = {
    "pending", "running", "completed", "failed", "cancelled",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_FINDING_STATUSES = {
    "open", "in_progress", "resolved", "accepted_risk", "false_positive",
}


class VulnScanEngine:
    """SQLite WAL-backed Vulnerability Scan engine.

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
                CREATE TABLE IF NOT EXISTS vuln_scans (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    scan_name       TEXT NOT NULL DEFAULT '',
                    scanner_type    TEXT NOT NULL DEFAULT 'custom',
                    target          TEXT NOT NULL DEFAULT '',
                    scan_status     TEXT NOT NULL DEFAULT 'pending',
                    started_at      DATETIME,
                    completed_at    DATETIME,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0,
                    scanner_version TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vuln_findings (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    scan_id         TEXT NOT NULL,
                    cve_id          TEXT NOT NULL DEFAULT '',
                    title           TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    cvss_score      REAL NOT NULL DEFAULT 0.0,
                    finding_status  TEXT NOT NULL DEFAULT 'open',
                    affected_asset  TEXT NOT NULL DEFAULT '',
                    plugin_id       TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    remediation     TEXT NOT NULL DEFAULT '',
                    detected_at     DATETIME,
                    resolved_at     DATETIME
                );
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
    # Scans
    # ------------------------------------------------------------------

    def create_scan(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new vulnerability scan.

        Required: scan_name, target.
        scanner_type defaults to 'custom'; scan_status defaults to 'pending'.
        """
        scan_name = (data.get("scan_name") or "").strip()
        if not scan_name:
            raise ValueError("scan_name is required")

        target = (data.get("target") or "").strip()
        if not target:
            raise ValueError("target is required")

        scanner_type = data.get("scanner_type", "custom")
        if scanner_type not in _VALID_SCANNER_TYPES:
            raise ValueError(
                f"Invalid scanner_type '{scanner_type}'. "
                f"Valid: {sorted(_VALID_SCANNER_TYPES)}"
            )

        scan_status = data.get("scan_status", "pending")
        if scan_status not in _VALID_SCAN_STATUSES:
            raise ValueError(
                f"Invalid scan_status '{scan_status}'. "
                f"Valid: {sorted(_VALID_SCAN_STATUSES)}"
            )

        now = self._now()
        rec = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "scan_name": scan_name,
            "scanner_type": scanner_type,
            "target": target,
            "scan_status": scan_status,
            "started_at": data.get("started_at"),
            "completed_at": data.get("completed_at"),
            "findings_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "scanner_version": data.get("scanner_version", ""),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vuln_scans
                        (id, org_id, scan_name, scanner_type, target, scan_status,
                         started_at, completed_at, findings_count, critical_count,
                         high_count, scanner_version, created_at)
                    VALUES
                        (:id, :org_id, :scan_name, :scanner_type, :target,
                         :scan_status, :started_at, :completed_at, :findings_count,
                         :critical_count, :high_count, :scanner_version, :created_at)
                    """,
                    rec,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "vuln_scan", "org_id": org_id, "source_engine": "vuln_scan"})
            except Exception:
                pass

        return rec

    def list_scans(
        self,
        org_id: str,
        scanner_type: Optional[str] = None,
        scan_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scans with optional filters."""
        query = "SELECT * FROM vuln_scans WHERE org_id = ?"
        params: List[Any] = [org_id]

        if scanner_type is not None:
            query += " AND scanner_type = ?"
            params.append(scanner_type)
        if scan_status is not None:
            query += " AND scan_status = ?"
            params.append(scan_status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_scan(self, org_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a single scan by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM vuln_scans WHERE org_id = ? AND id = ?",
                (org_id, scan_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_scan_status(
        self,
        org_id: str,
        scan_id: str,
        new_status: str,
        completed_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update scan_status; optionally set completed_at.

        Raises KeyError if scan not found, ValueError for invalid status.
        """
        if new_status not in _VALID_SCAN_STATUSES:
            raise ValueError(
                f"Invalid scan_status '{new_status}'. "
                f"Valid: {sorted(_VALID_SCAN_STATUSES)}"
            )

        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM vuln_scans WHERE org_id = ? AND id = ?",
                    (org_id, scan_id),
                ).fetchone()
                if existing is None:
                    raise KeyError(f"Scan '{scan_id}' not found")

                if completed_at is not None:
                    conn.execute(
                        """
                        UPDATE vuln_scans
                        SET scan_status = ?, completed_at = ?
                        WHERE org_id = ? AND id = ?
                        """,
                        (new_status, completed_at, org_id, scan_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE vuln_scans
                        SET scan_status = ?
                        WHERE org_id = ? AND id = ?
                        """,
                        (new_status, org_id, scan_id),
                    )

                row = conn.execute(
                    "SELECT * FROM vuln_scans WHERE org_id = ? AND id = ?",
                    (org_id, scan_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(
        self, org_id: str, scan_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a finding to a scan.

        Required: severity, title.
        finding_status defaults to 'open'; cvss_score defaults to 0.0.
        Increments scan.findings_count; also increments critical_count / high_count.
        """
        severity = data.get("severity", "")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Valid: {sorted(_VALID_SEVERITIES)}"
            )

        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required")

        finding_status = data.get("finding_status", "open")
        if finding_status not in _VALID_FINDING_STATUSES:
            raise ValueError(
                f"Invalid finding_status '{finding_status}'. "
                f"Valid: {sorted(_VALID_FINDING_STATUSES)}"
            )

        now = self._now()
        rec = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "scan_id": scan_id,
            "cve_id": data.get("cve_id", ""),
            "title": title,
            "severity": severity,
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "finding_status": finding_status,
            "affected_asset": data.get("affected_asset", ""),
            "plugin_id": data.get("plugin_id", ""),
            "description": data.get("description", ""),
            "remediation": data.get("remediation", ""),
            "detected_at": data.get("detected_at", now),
            "resolved_at": None,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vuln_findings
                        (id, org_id, scan_id, cve_id, title, severity, cvss_score,
                         finding_status, affected_asset, plugin_id, description,
                         remediation, detected_at, resolved_at)
                    VALUES
                        (:id, :org_id, :scan_id, :cve_id, :title, :severity,
                         :cvss_score, :finding_status, :affected_asset, :plugin_id,
                         :description, :remediation, :detected_at, :resolved_at)
                    """,
                    rec,
                )

                # Update parent scan counters
                conn.execute(
                    "UPDATE vuln_scans SET findings_count = findings_count + 1 "
                    "WHERE org_id = ? AND id = ?",
                    (org_id, scan_id),
                )
                if severity == "critical":
                    conn.execute(
                        "UPDATE vuln_scans SET critical_count = critical_count + 1 "
                        "WHERE org_id = ? AND id = ?",
                        (org_id, scan_id),
                    )
                elif severity == "high":
                    conn.execute(
                        "UPDATE vuln_scans SET high_count = high_count + 1 "
                        "WHERE org_id = ? AND id = ?",
                        (org_id, scan_id),
                    )

        return rec

    def list_findings(
        self,
        org_id: str,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        finding_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        query = "SELECT * FROM vuln_findings WHERE org_id = ?"
        params: List[Any] = [org_id]

        if scan_id is not None:
            query += " AND scan_id = ?"
            params.append(scan_id)
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)
        if finding_status is not None:
            query += " AND finding_status = ?"
            params.append(finding_status)

        query += " ORDER BY detected_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def update_finding_status(
        self, org_id: str, finding_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update finding_status; sets resolved_at if transitioning to 'resolved'.

        Raises KeyError if not found, ValueError for invalid status.
        """
        if new_status not in _VALID_FINDING_STATUSES:
            raise ValueError(
                f"Invalid finding_status '{new_status}'. "
                f"Valid: {sorted(_VALID_FINDING_STATUSES)}"
            )

        now = self._now()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM vuln_findings WHERE org_id = ? AND id = ?",
                    (org_id, finding_id),
                ).fetchone()
                if existing is None:
                    raise KeyError(f"Finding '{finding_id}' not found")

                resolved_at = now if new_status == "resolved" else None
                conn.execute(
                    """
                    UPDATE vuln_findings
                    SET finding_status = ?, resolved_at = ?
                    WHERE org_id = ? AND id = ?
                    """,
                    (new_status, resolved_at, org_id, finding_id),
                )

                row = conn.execute(
                    "SELECT * FROM vuln_findings WHERE org_id = ? AND id = ?",
                    (org_id, finding_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_scan_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate scan and finding statistics.

        Returns:
            total_scans, completed_scans, total_findings, open_findings,
            critical_open, by_scanner dict, by_severity dict.
        """
        with self._conn() as conn:
            total_scans: int = conn.execute(
                "SELECT COUNT(*) FROM vuln_scans WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            completed_scans: int = conn.execute(
                "SELECT COUNT(*) FROM vuln_scans WHERE org_id = ? AND scan_status = 'completed'",
                (org_id,),
            ).fetchone()[0]

            total_findings: int = conn.execute(
                "SELECT COUNT(*) FROM vuln_findings WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            open_findings: int = conn.execute(
                "SELECT COUNT(*) FROM vuln_findings WHERE org_id = ? AND finding_status = 'open'",
                (org_id,),
            ).fetchone()[0]

            critical_open: int = conn.execute(
                """
                SELECT COUNT(*) FROM vuln_findings
                WHERE org_id = ? AND finding_status = 'open' AND severity = 'critical'
                """,
                (org_id,),
            ).fetchone()[0]

            scanner_rows = conn.execute(
                """
                SELECT scanner_type, COUNT(*) as cnt
                FROM vuln_scans WHERE org_id = ?
                GROUP BY scanner_type
                """,
                (org_id,),
            ).fetchall()
            by_scanner = {r["scanner_type"]: r["cnt"] for r in scanner_rows}

            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM vuln_findings WHERE org_id = ?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_open": critical_open,
            "by_scanner": by_scanner,
            "by_severity": by_severity,
        }
