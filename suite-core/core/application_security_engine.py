"""Application Security Engine — ALDECI.

Tracks applications, SAST/DAST findings, scan runs, and security scores.

Capabilities:
  - Application registry (web/mobile/api/desktop/microservice, multi-language)
  - SAST finding ingestion (Bandit, Semgrep, SonarQube, CodeQL, Snyk)
  - DAST finding ingestion (ZAP, Burp, Nuclei, Nikto)
  - Scan run logging with findings summary
  - Finding status lifecycle (open → fixed/false_positive/accepted)
  - Stats aggregation per org (top vulnerable apps, severity breakdown)

Compliance: OWASP Top 10, CWE/SANS Top 25, NIST SP 800-218 (SSDF)
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_APP_TYPES = {"web", "mobile", "api", "desktop", "microservice"}
_VALID_LANGUAGES = {"python", "javascript", "java", "go", "ruby", "rust", "other"}
_VALID_CRITICALITIES = {"critical", "high", "medium", "low"}
_VALID_APP_STATUSES = {"active", "deprecated", "archived"}

_VALID_SAST_TOOLS = {"bandit", "semgrep", "sonarqube", "codeql", "snyk"}
_VALID_DAST_TOOLS = {"zap", "burp", "nuclei", "nikto"}
_VALID_CATEGORIES = {
    "injection", "xss", "xxe", "ssrf", "broken_auth", "sensitive_exposure",
    "path_traversal", "deserialization", "logging", "crypto",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_FINDING_STATUSES = {"open", "fixed", "false_positive", "accepted"}

_VALID_SCAN_TYPES = {"sast", "dast", "sca", "secret_scan"}
_VALID_SCAN_STATUSES = {"running", "completed", "failed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApplicationSecurityEngine:
    """SQLite WAL-backed Application Security engine.

    Thread-safe via RLock. Multi-tenant via org_id — each org gets its own DB.
    """

    def __init__(self, org_id: str = "default", db_dir: str = _DEFAULT_DB_DIR) -> None:
        self.org_id = org_id
        db_path = str(Path(db_dir) / f"{org_id}_application_security.db")
        self.db_path = db_path
        self._lock = threading.RLock()
        # FEATURE-5: route through DBAdapter so DATABASE_URL switches to postgres.
        from core.db_adapter import get_adapter
        self._db = get_adapter(db_path)
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
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    app_type        TEXT NOT NULL DEFAULT 'web',
                    language        TEXT NOT NULL DEFAULT 'other',
                    repo_url        TEXT NOT NULL DEFAULT '',
                    owner_team      TEXT NOT NULL DEFAULT '',
                    criticality     TEXT NOT NULL DEFAULT 'medium',
                    security_score  REAL NOT NULL DEFAULT 0.0,
                    last_scan_at    DATETIME,
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_apps_org
                    ON applications (org_id, status);

                CREATE TABLE IF NOT EXISTS sast_findings (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    app_id          TEXT NOT NULL,
                    tool            TEXT NOT NULL DEFAULT 'bandit',
                    rule_id         TEXT NOT NULL DEFAULT '',
                    title           TEXT NOT NULL,
                    category        TEXT NOT NULL DEFAULT 'injection',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    file_path       TEXT NOT NULL DEFAULT '',
                    line_number     INTEGER NOT NULL DEFAULT 0,
                    code_snippet    TEXT NOT NULL DEFAULT '',
                    cwe_id          TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    found_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sast_org_app
                    ON sast_findings (org_id, app_id, severity);

                CREATE INDEX IF NOT EXISTS idx_sast_org_status
                    ON sast_findings (org_id, status);

                CREATE TABLE IF NOT EXISTS dast_findings (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    app_id          TEXT NOT NULL,
                    tool            TEXT NOT NULL DEFAULT 'zap',
                    endpoint        TEXT NOT NULL DEFAULT '',
                    method          TEXT NOT NULL DEFAULT 'GET',
                    title           TEXT NOT NULL,
                    category        TEXT NOT NULL DEFAULT 'injection',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    cvss_score      REAL NOT NULL DEFAULT 0.0,
                    request_sample  TEXT NOT NULL DEFAULT '',
                    response_sample TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    found_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dast_org_app
                    ON dast_findings (org_id, app_id, severity);

                CREATE INDEX IF NOT EXISTS idx_dast_org_status
                    ON dast_findings (org_id, status);

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    app_id          TEXT NOT NULL,
                    scan_type       TEXT NOT NULL DEFAULT 'sast',
                    tool            TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'running',
                    started_at      DATETIME NOT NULL,
                    completed_at    DATETIME,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_scans_org_app
                    ON scan_runs (org_id, app_id, started_at DESC);
                """
            )

    def _conn(self):  # type: ignore[no-untyped-def]
        """Return a fresh per-call connection.

        FEATURE-5: when DATABASE_URL is set the adapter returns a psycopg2.connection
        instead of sqlite3.Connection. Callers MUST close it (existing `with self._conn()`
        code does — sqlite3.Connection and psycopg2.connection both support the
        context-manager protocol with .commit()/.rollback() on exit).
        """
        if self._db.is_postgres:
            return self._db._psycopg2.connect(self._db.dsn)  # type: ignore[union-attr]
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Applications
    # ------------------------------------------------------------------

    def register_app(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new application. Returns the created record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        app_type = data.get("app_type", "web")
        if app_type not in _VALID_APP_TYPES:
            raise ValueError(f"Invalid app_type: {app_type}. Must be one of {_VALID_APP_TYPES}")

        language = data.get("language", "other")
        if language not in _VALID_LANGUAGES:
            raise ValueError(f"Invalid language: {language}. Must be one of {_VALID_LANGUAGES}")

        criticality = data.get("criticality", "medium")
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(f"Invalid criticality: {criticality}. Must be one of {_VALID_CRITICALITIES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "app_type": app_type,
            "language": language,
            "repo_url": data.get("repo_url", ""),
            "owner_team": data.get("owner_team", ""),
            "criticality": criticality,
            "security_score": float(data.get("security_score", 0.0)),
            "last_scan_at": data.get("last_scan_at"),
            "status": data.get("status", "active"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO applications
                       (id, org_id, name, app_type, language, repo_url, owner_team,
                        criticality, security_score, last_scan_at, status, created_at)
                       VALUES (:id, :org_id, :name, :app_type, :language, :repo_url, :owner_team,
                               :criticality, :security_score, :last_scan_at, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "application_security", "org_id": org_id, "source_engine": "application_security"})
            except Exception:
                pass

        return record

    def list_apps(
        self,
        org_id: str,
        app_type: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List applications, optionally filtered by app_type and/or criticality."""
        sql = "SELECT * FROM applications WHERE org_id = ?"
        params: list = [org_id]
        if app_type:
            sql += " AND app_type = ?"
            params.append(app_type)
        if criticality:
            sql += " AND criticality = ?"
            params.append(criticality)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_app(self, org_id: str, app_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single application with open findings summary."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM applications WHERE org_id = ? AND id = ?",
                (org_id, app_id),
            ).fetchone()
            if not row:
                return None
            record = self._row(row)

            # Attach open findings summary
            sast_summary = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM sast_findings
                   WHERE org_id = ? AND app_id = ? AND status = 'open'
                   GROUP BY severity""",
                (org_id, app_id),
            ).fetchall()
            dast_summary = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM dast_findings
                   WHERE org_id = ? AND app_id = ? AND status = 'open'
                   GROUP BY severity""",
                (org_id, app_id),
            ).fetchall()

            record["open_sast_by_severity"] = {r["severity"]: r["cnt"] for r in sast_summary}
            record["open_dast_by_severity"] = {r["severity"]: r["cnt"] for r in dast_summary}
        return record

    # ------------------------------------------------------------------
    # SAST Findings
    # ------------------------------------------------------------------

    def add_sast_finding(self, org_id: str, app_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a SAST finding to an application."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        tool = data.get("tool", "bandit")
        if tool not in _VALID_SAST_TOOLS:
            raise ValueError(f"Invalid tool: {tool}. Must be one of {_VALID_SAST_TOOLS}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}. Must be one of {_VALID_SEVERITIES}")

        category = data.get("category", "injection")
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid category: {category}. Must be one of {_VALID_CATEGORIES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "app_id": app_id,
            "tool": tool,
            "rule_id": data.get("rule_id", ""),
            "title": title,
            "category": category,
            "severity": severity,
            "file_path": data.get("file_path", ""),
            "line_number": int(data.get("line_number", 0)),
            "code_snippet": data.get("code_snippet", ""),
            "cwe_id": data.get("cwe_id", ""),
            "status": "open",
            "found_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sast_findings
                       (id, org_id, app_id, tool, rule_id, title, category, severity,
                        file_path, line_number, code_snippet, cwe_id, status, found_at)
                       VALUES (:id, :org_id, :app_id, :tool, :rule_id, :title, :category, :severity,
                               :file_path, :line_number, :code_snippet, :cwe_id, :status, :found_at)""",
                    record,
                )
        return record

    def list_sast_findings(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List SAST findings with optional filters."""
        sql = "SELECT * FROM sast_findings WHERE org_id = ?"
        params: list = [org_id]
        if app_id:
            sql += " AND app_id = ?"
            params.append(app_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY found_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # DAST Findings
    # ------------------------------------------------------------------

    def add_dast_finding(self, org_id: str, app_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a DAST finding to an application."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        tool = data.get("tool", "zap")
        if tool not in _VALID_DAST_TOOLS:
            raise ValueError(f"Invalid tool: {tool}. Must be one of {_VALID_DAST_TOOLS}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}. Must be one of {_VALID_SEVERITIES}")

        category = data.get("category", "injection")
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid category: {category}. Must be one of {_VALID_CATEGORIES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "app_id": app_id,
            "tool": tool,
            "endpoint": data.get("endpoint", ""),
            "method": data.get("method", "GET"),
            "title": title,
            "category": category,
            "severity": severity,
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "request_sample": data.get("request_sample", ""),
            "response_sample": data.get("response_sample", ""),
            "status": "open",
            "found_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO dast_findings
                       (id, org_id, app_id, tool, endpoint, method, title, category, severity,
                        cvss_score, request_sample, response_sample, status, found_at)
                       VALUES (:id, :org_id, :app_id, :tool, :endpoint, :method, :title, :category,
                               :severity, :cvss_score, :request_sample, :response_sample, :status, :found_at)""",
                    record,
                )
        return record

    def list_dast_findings(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List DAST findings with optional filters."""
        sql = "SELECT * FROM dast_findings WHERE org_id = ?"
        params: list = [org_id]
        if app_id:
            sql += " AND app_id = ?"
            params.append(app_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY found_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Scan Runs
    # ------------------------------------------------------------------

    def log_scan_run(self, org_id: str, app_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log a scan run for an application."""
        scan_type = data.get("scan_type", "sast")
        if scan_type not in _VALID_SCAN_TYPES:
            raise ValueError(f"Invalid scan_type: {scan_type}. Must be one of {_VALID_SCAN_TYPES}")

        scan_status = data.get("status", "running")
        if scan_status not in _VALID_SCAN_STATUSES:
            raise ValueError(f"Invalid status: {scan_status}. Must be one of {_VALID_SCAN_STATUSES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "app_id": app_id,
            "scan_type": scan_type,
            "tool": data.get("tool", ""),
            "status": scan_status,
            "started_at": data.get("started_at", now),
            "completed_at": data.get("completed_at"),
            "findings_count": int(data.get("findings_count", 0)),
            "critical_count": int(data.get("critical_count", 0)),
            "high_count": int(data.get("high_count", 0)),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scan_runs
                       (id, org_id, app_id, scan_type, tool, status, started_at,
                        completed_at, findings_count, critical_count, high_count)
                       VALUES (:id, :org_id, :app_id, :scan_type, :tool, :status, :started_at,
                               :completed_at, :findings_count, :critical_count, :high_count)""",
                    record,
                )
            # Update app last_scan_at
            if scan_status == "completed":
                with self._conn() as conn:
                    conn.execute(
                        "UPDATE applications SET last_scan_at = ? WHERE org_id = ? AND id = ?",
                        (now, org_id, app_id),
                    )
        return record

    # ------------------------------------------------------------------
    # Finding Status Update
    # ------------------------------------------------------------------

    def update_finding_status(
        self,
        org_id: str,
        finding_id: str,
        finding_type: str,
        status: str,
    ) -> Dict[str, Any]:
        """Update status of a SAST or DAST finding. Returns updated record."""
        if finding_type not in ("sast", "dast"):
            raise ValueError("finding_type must be 'sast' or 'dast'.")
        if status not in _VALID_FINDING_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_FINDING_STATUSES}")

        table = "sast_findings" if finding_type == "sast" else "dast_findings"
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE {table} SET status = ? WHERE org_id = ? AND id = ?",  # nosec B608
                    (status, org_id, finding_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Finding {finding_id} not found.")
                row = conn.execute(
                    f"SELECT * FROM {table} WHERE id = ?", (finding_id,)  # nosec B608
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated AppSec stats for org."""
        from datetime import timedelta
        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

        with self._conn() as conn:
            app_count = conn.execute(
                "SELECT COUNT(*) FROM applications WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            avg_score_row = conn.execute(
                "SELECT AVG(security_score) FROM applications WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]
            avg_security_score = round(float(avg_score_row or 0.0), 2)

            # SAST open by severity
            sast_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM sast_findings
                   WHERE org_id = ? AND status = 'open' GROUP BY severity""",
                (org_id,),
            ).fetchall()
            open_sast_by_severity = {r["severity"]: r["cnt"] for r in sast_rows}

            # DAST open by severity
            dast_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM dast_findings
                   WHERE org_id = ? AND status = 'open' GROUP BY severity""",
                (org_id,),
            ).fetchall()
            open_dast_by_severity = {r["severity"]: r["cnt"] for r in dast_rows}

            # Scans this week
            scans_this_week = conn.execute(
                "SELECT COUNT(*) FROM scan_runs WHERE org_id = ? AND started_at >= ?",
                (org_id, week_ago),
            ).fetchone()[0]

            # Top 5 vulnerable apps by open critical+high count
            top_rows = conn.execute(
                """SELECT a.id, a.name, a.criticality,
                          (SELECT COUNT(*) FROM sast_findings sf
                           WHERE sf.org_id = a.org_id AND sf.app_id = a.id
                             AND sf.status = 'open' AND sf.severity IN ('critical','high')) +
                          (SELECT COUNT(*) FROM dast_findings df
                           WHERE df.org_id = a.org_id AND df.app_id = a.id
                             AND df.status = 'open' AND df.severity IN ('critical','high'))
                          AS open_critical_high
                   FROM applications a
                   WHERE a.org_id = ?
                   ORDER BY open_critical_high DESC
                   LIMIT 5""",
                (org_id,),
            ).fetchall()
            top_vulnerable_apps = [self._row(r) for r in top_rows]

        return {
            "app_count": app_count,
            "avg_security_score": avg_security_score,
            "open_sast_by_severity": open_sast_by_severity,
            "open_dast_by_severity": open_dast_by_severity,
            "scans_this_week": scans_this_week,
            "top_vulnerable_apps": top_vulnerable_apps,
        }
