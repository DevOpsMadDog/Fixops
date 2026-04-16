"""Application Risk Engine — ALDECI.

Tracks application risk scoring, security findings, and risk posture
across web, API, mobile, desktop, and microservice applications.

Capabilities:
  - Application registration with type, environment, tech stack
  - Automated risk scoring from security control assessment
  - Security finding lifecycle (sast/dast/sca/manual)
  - Finding resolution workflow
  - Stats: totals, critical apps, findings breakdown

Compliance: OWASP ASVS, NIST SP 800-53, CWE Top 25
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

_VALID_APP_TYPES = {"web", "api", "mobile", "desktop", "microservice"}
_VALID_ENVIRONMENTS = {"prod", "staging", "dev", "test"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_FINDING_TYPES = {"sast", "dast", "sca", "manual"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_level_from_score(score: float) -> str:
    if score > 75:
        return "critical"
    if score > 50:
        return "high"
    if score > 25:
        return "medium"
    return "low"


class ApplicationRiskEngine:
    """SQLite WAL-backed Application Risk engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/application_risk.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "application_risk.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ar_applications (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL DEFAULT '',
                    app_type    TEXT NOT NULL DEFAULT 'web',
                    tech_stack  TEXT NOT NULL DEFAULT '',
                    owner_team  TEXT NOT NULL DEFAULT '',
                    environment TEXT NOT NULL DEFAULT 'prod',
                    risk_score  REAL NOT NULL DEFAULT 50.0,
                    risk_level  TEXT NOT NULL DEFAULT 'medium',
                    assessed_at DATETIME,
                    status      TEXT NOT NULL DEFAULT 'active',
                    created_at  DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ar_apps_org
                    ON ar_applications (org_id, app_type, environment, risk_level);

                CREATE TABLE IF NOT EXISTS ar_findings (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    app_id       TEXT NOT NULL,
                    title        TEXT NOT NULL DEFAULT '',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    finding_type TEXT NOT NULL DEFAULT 'sast',
                    cve_id       TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'open',
                    resolution   TEXT NOT NULL DEFAULT '',
                    resolved_at  DATETIME,
                    created_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ar_findings_org
                    ON ar_findings (org_id, app_id, severity, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Applications
    # ------------------------------------------------------------------

    def register_application(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new application."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")

        app_type = data.get("app_type", "web")
        if app_type not in _VALID_APP_TYPES:
            raise ValueError(
                f"Invalid app_type: {app_type}. "
                f"Must be one of {sorted(_VALID_APP_TYPES)}"
            )

        environment = data.get("environment", "prod")
        if environment not in _VALID_ENVIRONMENTS:
            raise ValueError(
                f"Invalid environment: {environment}. "
                f"Must be one of {sorted(_VALID_ENVIRONMENTS)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "app_type": app_type,
            "tech_stack": data.get("tech_stack", ""),
            "owner_team": data.get("owner_team", ""),
            "environment": environment,
            "risk_score": 50.0,
            "risk_level": "medium",
            "assessed_at": None,
            "status": "active",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ar_applications
                       (id, org_id, name, app_type, tech_stack, owner_team, environment,
                        risk_score, risk_level, assessed_at, status, created_at)
                       VALUES
                       (:id, :org_id, :name, :app_type, :tech_stack, :owner_team, :environment,
                        :risk_score, :risk_level, :assessed_at, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "application_risk", "org_id": org_id, "source_engine": "application_risk"})
            except Exception:
                pass

        return record

    def list_applications(
        self,
        org_id: str,
        app_type: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List applications with optional filters."""
        sql = "SELECT * FROM ar_applications WHERE org_id = ?"
        params: list = [org_id]
        if app_type is not None:
            sql += " AND app_type = ?"
            params.append(app_type)
        if environment is not None:
            sql += " AND environment = ?"
            params.append(environment)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_application(self, org_id: str, app_id: str) -> Optional[Dict[str, Any]]:
        """Get a single application by id, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ar_applications WHERE id = ? AND org_id = ?",
                (app_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def assess_risk(
        self, org_id: str, app_id: str, assessment_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compute and store risk score for an application.

        Score formula (base=50):
          - auth_controls present:    -10
          - input_validation present: -10
          - encryption present:       -10
          - dependency_scan missing:  +10
          - sast_findings (int):      +min(sast_findings*2, 20)
          - dast_findings (int):      +min(dast_findings*2, 20)
          - internet_exposed:         +15
          Clamped to [0, 100].
        """
        score = 50.0
        factors: Dict[str, Any] = {}

        if assessment_data.get("auth_controls"):
            score -= 10
            factors["auth_controls"] = -10
        if assessment_data.get("input_validation"):
            score -= 10
            factors["input_validation"] = -10
        if assessment_data.get("encryption"):
            score -= 10
            factors["encryption"] = -10
        if not assessment_data.get("dependency_scan", True):
            score += 10
            factors["no_dependency_scan"] = +10

        sast_findings = int(assessment_data.get("sast_findings", 0))
        sast_delta = min(sast_findings * 2, 20)
        score += sast_delta
        factors["sast_findings"] = sast_delta

        dast_findings = int(assessment_data.get("dast_findings", 0))
        dast_delta = min(dast_findings * 2, 20)
        score += dast_delta
        factors["dast_findings"] = dast_delta

        if assessment_data.get("internet_exposed"):
            score += 15
            factors["internet_exposed"] = +15

        score = max(0.0, min(100.0, score))
        risk_level = _risk_level_from_score(score)
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE ar_applications
                       SET risk_score = ?, risk_level = ?, assessed_at = ?
                       WHERE id = ? AND org_id = ?""",
                    (score, risk_level, now, app_id, org_id),
                )

        return {
            "app_id": app_id,
            "risk_score": score,
            "risk_level": risk_level,
            "factors": factors,
        }

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(
        self, org_id: str, app_id: str, finding_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a security finding to an application."""
        severity = finding_data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        finding_type = finding_data.get("finding_type", "sast")
        if finding_type not in _VALID_FINDING_TYPES:
            raise ValueError(
                f"Invalid finding_type: {finding_type}. "
                f"Must be one of {sorted(_VALID_FINDING_TYPES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "app_id": app_id,
            "title": finding_data.get("title", ""),
            "severity": severity,
            "finding_type": finding_type,
            "cve_id": finding_data.get("cve_id", ""),
            "status": "open",
            "resolution": "",
            "resolved_at": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ar_findings
                       (id, org_id, app_id, title, severity, finding_type, cve_id,
                        status, resolution, resolved_at, created_at)
                       VALUES
                       (:id, :org_id, :app_id, :title, :severity, :finding_type, :cve_id,
                        :status, :resolution, :resolved_at, :created_at)""",
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
        """List findings with optional filters."""
        sql = "SELECT * FROM ar_findings WHERE org_id = ?"
        params: list = [org_id]
        if app_id is not None:
            sql += " AND app_id = ?"
            params.append(app_id)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def resolve_finding(
        self, org_id: str, finding_id: str, resolution: str
    ) -> Dict[str, Any]:
        """Mark a finding as resolved with a resolution note."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE ar_findings
                       SET status = 'resolved', resolved_at = ?, resolution = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, resolution, finding_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Finding {finding_id} not found in org {org_id}"
                    )
                row = conn.execute(
                    "SELECT * FROM ar_findings WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_app_risk_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregated application risk statistics for an org."""
        with self._conn() as conn:
            total_apps = conn.execute(
                "SELECT COUNT(*) FROM ar_applications WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            critical_apps = conn.execute(
                "SELECT COUNT(*) FROM ar_applications WHERE org_id = ? AND risk_level = 'critical'",
                (org_id,),
            ).fetchone()[0]

            total_findings = conn.execute(
                "SELECT COUNT(*) FROM ar_findings WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_findings = conn.execute(
                "SELECT COUNT(*) FROM ar_findings WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt
                   FROM ar_findings WHERE org_id = ?
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            type_rows = conn.execute(
                """SELECT app_type, COUNT(*) as cnt
                   FROM ar_applications WHERE org_id = ?
                   GROUP BY app_type""",
                (org_id,),
            ).fetchall()
            by_app_type = {r["app_type"]: r["cnt"] for r in type_rows}

        return {
            "total_apps": total_apps,
            "critical_apps": critical_apps,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "by_severity": by_severity,
            "by_app_type": by_app_type,
        }
