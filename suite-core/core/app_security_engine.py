"""Application Security (AppSec) Engine — ALDECI.

Track application inventory, SAST/DAST scan results, and individual
security findings with OWASP Top 10 categorisation.

Compliance: OWASP ASVS, PCI DSS 6.3, NIST SP 800-53 SA-11.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "app_security.db"
)

# Valid enum values — validated at write time so bad data is rejected early.
_APP_TYPES = {"web", "mobile", "api", "desktop"}
_RISK_RATINGS = {"critical", "high", "medium", "low"}
_SCAN_STATUSES = {"pending", "running", "completed", "failed"}
_SAST_TOOLS = {"semgrep", "sonarqube", "checkmarx", "bandit", "eslint"}
_DAST_TOOLS = {"zap", "burpsuite", "nikto", "nuclei"}
_VULN_TYPES = {
    "sqli", "xss", "rce", "idor", "ssrf", "xxe",
    "deserialization", "misconfig", "secrets_exposure",
}
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_FINDING_STATUSES = {"open", "false_positive", "accepted", "fixed"}

# OWASP Top 10 2021 categories
_OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# Map vuln_type → OWASP category
_VULN_TO_OWASP: Dict[str, str] = {
    "sqli": "A03",
    "xss": "A03",
    "rce": "A03",
    "idor": "A01",
    "ssrf": "A10",
    "xxe": "A03",
    "deserialization": "A08",
    "misconfig": "A05",
    "secrets_exposure": "A02",
}


class AppSecurityEngine:
    """SQLite WAL-backed Application Security engine.

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
                CREATE TABLE IF NOT EXISTS applications (
                    app_id           TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    app_type         TEXT NOT NULL DEFAULT 'web',
                    repo_url         TEXT NOT NULL DEFAULT '',
                    tech_stack       TEXT NOT NULL DEFAULT '[]',
                    risk_rating      TEXT NOT NULL DEFAULT 'medium',
                    last_scan        TEXT,
                    compliance_score REAL NOT NULL DEFAULT 0.0,
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_app_org
                    ON applications (org_id);

                CREATE TABLE IF NOT EXISTS sast_scans (
                    scan_id          TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    app_id           TEXT NOT NULL,
                    scan_type        TEXT NOT NULL DEFAULT 'sast',
                    tool             TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'pending',
                    findings_count   INTEGER NOT NULL DEFAULT 0,
                    critical_count   INTEGER NOT NULL DEFAULT 0,
                    high_count       INTEGER NOT NULL DEFAULT 0,
                    medium_count     INTEGER NOT NULL DEFAULT 0,
                    low_count        INTEGER NOT NULL DEFAULT 0,
                    started_at       TEXT,
                    completed_at     TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sast_org_app
                    ON sast_scans (org_id, app_id);

                CREATE TABLE IF NOT EXISTS dast_scans (
                    scan_id          TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    app_id           TEXT NOT NULL,
                    scan_type        TEXT NOT NULL DEFAULT 'dast',
                    tool             TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'pending',
                    findings_count   INTEGER NOT NULL DEFAULT 0,
                    critical_count   INTEGER NOT NULL DEFAULT 0,
                    high_count       INTEGER NOT NULL DEFAULT 0,
                    medium_count     INTEGER NOT NULL DEFAULT 0,
                    low_count        INTEGER NOT NULL DEFAULT 0,
                    started_at       TEXT,
                    completed_at     TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dast_org_app
                    ON dast_scans (org_id, app_id);

                CREATE TABLE IF NOT EXISTS app_findings (
                    finding_id       TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    app_id           TEXT NOT NULL,
                    scan_id          TEXT,
                    vuln_type        TEXT NOT NULL,
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    cwe_id           TEXT NOT NULL DEFAULT '',
                    description      TEXT NOT NULL DEFAULT '',
                    file_path        TEXT NOT NULL DEFAULT '',
                    line_number      INTEGER NOT NULL DEFAULT 0,
                    status           TEXT NOT NULL DEFAULT 'open',
                    owasp_category   TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_finding_org
                    ON app_findings (org_id, app_id);

                CREATE INDEX IF NOT EXISTS idx_finding_status
                    ON app_findings (org_id, status, severity);
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
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "tech_stack" in d:
            d["tech_stack"] = json.loads(d["tech_stack"] or "[]")
        return d

    # ------------------------------------------------------------------
    # Applications
    # ------------------------------------------------------------------

    def register_app(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new application. Returns the created record."""
        app_id = str(uuid.uuid4())
        now = self._now()
        app_type = data.get("app_type", "web")
        if app_type not in _APP_TYPES:
            app_type = "web"
        risk_rating = data.get("risk_rating", "medium")
        if risk_rating not in _RISK_RATINGS:
            risk_rating = "medium"

        record = {
            "app_id": app_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "app_type": app_type,
            "repo_url": data.get("repo_url", ""),
            "tech_stack": json.dumps(data.get("tech_stack", [])),
            "risk_rating": risk_rating,
            "last_scan": data.get("last_scan"),
            "compliance_score": float(data.get("compliance_score", 0.0)),
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO applications
                       (app_id, org_id, name, app_type, repo_url, tech_stack,
                        risk_rating, last_scan, compliance_score, created_at, updated_at)
                       VALUES (:app_id,:org_id,:name,:app_type,:repo_url,:tech_stack,
                               :risk_rating,:last_scan,:compliance_score,:created_at,:updated_at)
                    """,
                    record,
                )
        record["tech_stack"] = data.get("tech_stack", [])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "app_security", "org_id": org_id, "source_engine": "app_security"})
            except Exception:
                pass

        return record

    def list_apps(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all applications for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM applications WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # SAST scans
    # ------------------------------------------------------------------

    def create_sast_scan(self, org_id: str, app_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a SAST scan record. Returns the created record."""
        return self._create_scan(org_id, app_id, "sast", _SAST_TOOLS, data)

    # ------------------------------------------------------------------
    # DAST scans
    # ------------------------------------------------------------------

    def create_dast_scan(self, org_id: str, app_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a DAST scan record. Returns the created record."""
        return self._create_scan(org_id, app_id, "dast", _DAST_TOOLS, data)

    def _create_scan(
        self,
        org_id: str,
        app_id: str,
        scan_type: str,
        valid_tools: set,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        scan_id = str(uuid.uuid4())
        now = self._now()
        tool = data.get("tool", "")
        if tool not in valid_tools:
            tool = next(iter(valid_tools))
        status = data.get("status", "pending")
        if status not in _SCAN_STATUSES:
            status = "pending"
        table = "sast_scans" if scan_type == "sast" else "dast_scans"

        record = {
            "scan_id": scan_id,
            "org_id": org_id,
            "app_id": app_id,
            "scan_type": scan_type,
            "tool": tool,
            "status": status,
            "findings_count": int(data.get("findings_count", 0)),
            "critical_count": int(data.get("critical_count", 0)),
            "high_count": int(data.get("high_count", 0)),
            "medium_count": int(data.get("medium_count", 0)),
            "low_count": int(data.get("low_count", 0)),
            "started_at": data.get("started_at"),
            "completed_at": data.get("completed_at"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    f"""INSERT INTO {table}(scan_id, org_id, app_id, scan_type, tool, status,
                         findings_count, critical_count, high_count, medium_count,
                         low_count, started_at, completed_at, created_at)
                        VALUES (:scan_id,:org_id,:app_id,:scan_type,:tool,:status,
                                :findings_count,:critical_count,:high_count,:medium_count,
                                :low_count,:started_at,:completed_at,:created_at)
                    """,  # nosec B608
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Scan listing
    # ------------------------------------------------------------------

    def list_scans(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        scan_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return scans for an org, optionally filtered by app_id and/or scan_type."""
        results: List[Dict[str, Any]] = []

        tables = []
        if scan_type == "sast":
            tables = ["sast_scans"]
        elif scan_type == "dast":
            tables = ["dast_scans"]
        else:
            tables = ["sast_scans", "dast_scans"]

        for table in tables:
            query = f"SELECT * FROM {table} WHERE org_id=?"  # nosec B608
            params: list = [org_id]
            if app_id:
                query += " AND app_id=?"
                params.append(app_id)
            query += " ORDER BY created_at DESC"
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
            results.extend(dict(r) for r in rows)

        results.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def create_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an application security finding. Returns the created record."""
        finding_id = str(uuid.uuid4())
        now = self._now()
        vuln_type = data.get("vuln_type", "misconfig")
        if vuln_type not in _VULN_TYPES:
            vuln_type = "misconfig"
        severity = data.get("severity", "medium")
        if severity not in _SEVERITIES:
            severity = "medium"
        status = data.get("status", "open")
        if status not in _FINDING_STATUSES:
            status = "open"
        owasp_category = data.get("owasp_category") or _VULN_TO_OWASP.get(vuln_type, "A05")

        record = {
            "finding_id": finding_id,
            "org_id": org_id,
            "app_id": data.get("app_id", ""),
            "scan_id": data.get("scan_id"),
            "vuln_type": vuln_type,
            "severity": severity,
            "cwe_id": data.get("cwe_id", ""),
            "description": data.get("description", ""),
            "file_path": data.get("file_path", ""),
            "line_number": int(data.get("line_number", 0)),
            "status": status,
            "owasp_category": owasp_category,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO app_findings
                       (finding_id, org_id, app_id, scan_id, vuln_type, severity,
                        cwe_id, description, file_path, line_number, status,
                        owasp_category, created_at, updated_at)
                       VALUES (:finding_id,:org_id,:app_id,:scan_id,:vuln_type,:severity,
                               :cwe_id,:description,:file_path,:line_number,:status,
                               :owasp_category,:created_at,:updated_at)
                    """,
                    record,
                )
        return record

    def list_findings(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return findings for an org, optionally filtered."""
        query = "SELECT * FROM app_findings WHERE org_id=?"
        params: list = [org_id]
        if app_id:
            query += " AND app_id=?"
            params.append(app_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_finding_status(self, org_id: str, finding_id: str, status: str) -> bool:
        """Update the status of a finding. Returns True if updated."""
        if status not in _FINDING_STATUSES:
            return False
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE app_findings SET status=?, updated_at=? WHERE finding_id=? AND org_id=?",
                    (status, now, finding_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_appsec_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for an org."""
        with self._conn() as conn:
            total_apps = conn.execute(
                "SELECT COUNT(*) FROM applications WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            sast_count = conn.execute(
                "SELECT COUNT(*) FROM sast_scans WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            dast_count = conn.execute(
                "SELECT COUNT(*) FROM dast_scans WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            total_scans = sast_count + dast_count

            open_findings = conn.execute(
                "SELECT COUNT(*) FROM app_findings WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM app_findings
                   WHERE org_id=? GROUP BY severity""",
                (org_id,),
            ).fetchall()

            owasp_rows = conn.execute(
                """SELECT owasp_category, COUNT(*) as cnt FROM app_findings
                   WHERE org_id=? GROUP BY owasp_category""",
                (org_id,),
            ).fetchall()

            score_row = conn.execute(
                "SELECT AVG(compliance_score) FROM applications WHERE org_id=?",
                (org_id,),
            ).fetchone()

        by_severity = {r["severity"]: r["cnt"] for r in sev_rows}
        by_owasp_category = {r["owasp_category"]: r["cnt"] for r in owasp_rows}
        avg_compliance = round(score_row[0] or 0.0, 2)

        return {
            "total_apps": total_apps,
            "total_scans": total_scans,
            "open_findings": open_findings,
            "by_severity": by_severity,
            "by_owasp_category": by_owasp_category,
            "avg_compliance_score": avg_compliance,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_engine: Optional[AppSecurityEngine] = None
_engine_lock = threading.Lock()


def get_app_security_engine() -> AppSecurityEngine:
    """Return the module-level singleton AppSecurityEngine."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = AppSecurityEngine()
    return _engine
