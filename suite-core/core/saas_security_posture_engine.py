"""SaaS Security Posture Management (SSPM) Engine — ALDECI.

Manages SaaS application inventory, security assessments, and findings.

Capabilities:
  - SaaS app registry with risk and compliance tracking
  - Security assessment lifecycle with score-driven risk_level update
  - Finding tracking (open/resolved) per app
  - Stats aggregation per org (high_risk_apps, open_findings, compliance_rate)

Compliance: CSA CCM, NIST SP 800-53, ISO 27001 A.6.1
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

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "saas_security_posture.db")

_VALID_APP_CATEGORIES = {
    "productivity", "crm", "hrm", "finance", "security",
    "devops", "communication", "storage", "analytics",
}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_COMPLIANCE_STATUSES = {"compliant", "non_compliant", "partial", "unknown"}
_VALID_FINDING_SEVERITIES = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_level_from_score(score: float) -> str:
    """Derive risk_level from assessment score (higher score = lower risk)."""
    if score <= 25:
        return "critical"
    elif score <= 50:
        return "high"
    elif score <= 75:
        return "medium"
    else:
        return "low"


class SaasSecurityPostureEngine:
    """SQLite WAL-backed SaaS Security Posture Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Database stored at .fixops_data/saas_security_posture.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS saas_apps (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    app_name          TEXT NOT NULL DEFAULT '',
                    app_category      TEXT NOT NULL DEFAULT 'productivity',
                    vendor            TEXT NOT NULL DEFAULT '',
                    risk_level        TEXT NOT NULL DEFAULT 'medium',
                    compliance_status TEXT NOT NULL DEFAULT 'unknown',
                    user_count        INTEGER NOT NULL DEFAULT 0,
                    data_sensitivity  TEXT NOT NULL DEFAULT '',
                    oauth_scopes      TEXT NOT NULL DEFAULT '',
                    last_assessed     DATETIME,
                    status            TEXT NOT NULL DEFAULT 'active',
                    created_at        DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_saas_apps_org
                    ON saas_apps(org_id, app_category, risk_level, compliance_status, status);

                CREATE TABLE IF NOT EXISTS saas_assessments (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    app_id           TEXT NOT NULL,
                    assessment_date  DATETIME,
                    score            REAL NOT NULL DEFAULT 0.0,
                    risk_level       TEXT NOT NULL DEFAULT 'medium',
                    findings_count   INTEGER NOT NULL DEFAULT 0,
                    assessor         TEXT NOT NULL DEFAULT '',
                    notes            TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_saas_assessments_org
                    ON saas_assessments(org_id, app_id);

                CREATE TABLE IF NOT EXISTS saas_findings (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    app_id      TEXT NOT NULL,
                    finding_type TEXT NOT NULL DEFAULT '',
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    title       TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'open',
                    detected_at DATETIME,
                    resolved_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_saas_findings_org
                    ON saas_findings(org_id, app_id, severity, status);
            """)

    @staticmethod
    def _row(row) -> dict:
        return dict(row)

    # ------------------------------------------------------------------
    # App CRUD
    # ------------------------------------------------------------------

    def register_app(self, org_id: str, data: dict) -> dict:
        """Register a new SaaS application."""
        app_name = (data.get("app_name") or "").strip()
        if not app_name:
            raise ValueError("app_name is required")
        app_category = (data.get("app_category") or "").strip().lower()
        if app_category not in _VALID_APP_CATEGORIES:
            raise ValueError(f"app_category must be one of {sorted(_VALID_APP_CATEGORIES)}")

        app_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": app_id,
            "org_id": org_id,
            "app_name": app_name,
            "app_category": app_category,
            "vendor": (data.get("vendor") or "").strip(),
            "risk_level": "medium",
            "compliance_status": "unknown",
            "user_count": int(data.get("user_count") or 0),
            "data_sensitivity": (data.get("data_sensitivity") or "").strip(),
            "oauth_scopes": (data.get("oauth_scopes") or "").strip(),
            "last_assessed": None,
            "status": "active",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO saas_apps
                       (id, org_id, app_name, app_category, vendor, risk_level,
                        compliance_status, user_count, data_sensitivity, oauth_scopes,
                        last_assessed, status, created_at)
                       VALUES (:id, :org_id, :app_name, :app_category, :vendor, :risk_level,
                               :compliance_status, :user_count, :data_sensitivity, :oauth_scopes,
                               :last_assessed, :status, :created_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "saas_security_posture", "org_id": org_id, "source_engine": "saas_security_posture"})
            except Exception:
                pass

        return row

    def list_apps(
        self,
        org_id: str,
        app_category: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[dict]:
        """List SaaS apps with optional filters."""
        sql = "SELECT * FROM saas_apps WHERE org_id=?"
        params: list = [org_id]
        if app_category:
            sql += " AND app_category=?"
            params.append(app_category)
        if risk_level:
            sql += " AND risk_level=?"
            params.append(risk_level)
        sql += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # SSPM CONNECTOR FALLBACK (AppOmni)
    # ------------------------------------------------------------------

    def list_apps_with_appomni_fallback(
        self,
        org_id: str,
        app_category: Optional[str] = None,
        risk_level: Optional[str] = None,
        sspm_connector: Any = None,
    ) -> Dict[str, Any]:
        """List SaaS apps; fall back to AppOmni SSPM live findings.

        Behaviour (ranked):

        1. Org has registered apps → ``source="org_registered"``.
        2. Else if AppOmni connector is available *and* APPOMNI_API_KEY is
           present, call ``sync()`` and project unique app inventory from the
           findings stream → ``source="appomni"``.
        3. Else if creds *or* the SDK are missing → ``source="needs_credentials"``
           with a structured hint. NEVER mocks.
        4. Connector returned ``status != "ok"`` → ``source="connector_error"``.
        5. Connector OK but returned zero apps → ``source="needs_data"``.

        Filters apply against the projected rows in modes 2/4/5 too.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        org_rows = self.list_apps(
            org_id, app_category=app_category, risk_level=risk_level,
        )
        if org_rows:
            return {
                "apps": org_rows,
                "total": len(org_rows),
                "source": "org_registered",
            }

        creds_present = False
        connector_unavailable_reason: Optional[str] = None
        if sspm_connector is None:
            try:
                from connectors.appomni_connector import (  # type: ignore
                    _creds_present,
                    get_appomni_connector,
                )
                creds_present = bool(_creds_present())
                if creds_present:
                    sspm_connector = get_appomni_connector()
            except (ImportError, RuntimeError) as exc:
                connector_unavailable_reason = f"connector_import_failed: {exc}"
        else:
            creds_present = True

        if not creds_present or sspm_connector is None:
            return {
                "apps": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": (
                    "Set APPOMNI_API_KEY (and optionally APPOMNI_BASE_URL) to "
                    "enable live AppOmni SSPM inventory, or POST "
                    "/api/v1/sspm/apps to register a SaaS app manually."
                ),
                **({"reason": connector_unavailable_reason}
                   if connector_unavailable_reason else {}),
            }

        try:
            payload = sspm_connector.sync(org_id)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("AppOmni sync failed for org=%s: %s", org_id, exc)
            return {
                "apps": [],
                "total": 0,
                "source": "connector_error",
                "error": str(exc)[:500],
            }

        connector_status = (payload or {}).get("status", "")
        if connector_status == "needs_credentials":
            return {
                "apps": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": payload.get("hint", "AppOmni credentials missing."),
            }
        if connector_status != "ok":
            return {
                "apps": [],
                "total": 0,
                "source": "connector_error",
                "error": str(payload.get("error") or connector_status)[:500],
            }

        # Project unique apps from the findings stream.  Severity drives
        # risk_level; counts roll up to a derived risk_score.
        sev_weight = {"critical": 10, "high": 5, "medium": 2, "low": 1,
                      "informational": 0}
        per_app: Dict[str, Dict[str, Any]] = {}
        for finding in payload.get("findings") or []:
            app_id = str(finding.get("app_id") or "unknown")
            app_name = finding.get("app_name") or app_id
            severity = (finding.get("severity") or "low").lower()
            entry = per_app.setdefault(
                app_id,
                {
                    "id": app_id,
                    "org_id": org_id,
                    "app_name": app_name,
                    "app_category": (finding.get("category") or "saas").lower(),
                    "vendor": "",
                    "risk_level": "low",
                    "compliance_status": "unknown",
                    "user_count": 0,
                    "data_sensitivity": "",
                    "oauth_scopes": "",
                    "last_assessed": None,
                    "status": "active",
                    "created_at": payload.get("ingested_at"),
                    "_score": 0.0,
                    "source": "appomni",
                    "findings_total": 0,
                },
            )
            entry["_score"] += sev_weight.get(severity, 0)
            entry["findings_total"] += 1
            # Promote risk_level to highest seen for this app.
            order = ["low", "medium", "high", "critical"]
            if order.index(severity if severity in order else "low") > order.index(entry["risk_level"]):
                entry["risk_level"] = severity if severity in order else entry["risk_level"]

        derived = []
        for app_id, entry in per_app.items():
            entry["risk_score"] = round(min(entry.pop("_score"), 100.0), 1)
            derived.append(entry)

        # Apply filters against derived rows.
        if app_category:
            derived = [d for d in derived if d["app_category"] == app_category]
        if risk_level:
            derived = [d for d in derived if d["risk_level"] == risk_level]

        if not derived:
            return {
                "apps": [],
                "total": 0,
                "source": "needs_data",
                "hint": (
                    "AppOmni reachable but returned no SaaS apps matching the "
                    "requested filters."
                ),
            }

        return {
            "apps": derived,
            "total": len(derived),
            "source": "appomni",
        }

    def get_app(self, org_id: str, app_id: str) -> Optional[dict]:
        """Get a single SaaS app by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM saas_apps WHERE id=? AND org_id=?",
                    (app_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def assess_app(self, org_id: str, app_id: str, data: dict) -> dict:
        """Conduct a security assessment for a SaaS app.

        Updates app risk_level based on score:
          score <= 25  → critical
          score <= 50  → high
          score <= 75  → medium
          score > 75   → low
        """
        score = float(data.get("score") or 0.0)
        findings_count = int(data.get("findings_count") or 0)
        new_risk_level = _risk_level_from_score(score)

        assessment_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": assessment_id,
            "org_id": org_id,
            "app_id": app_id,
            "assessment_date": data.get("assessment_date") or now,
            "score": score,
            "risk_level": new_risk_level,
            "findings_count": findings_count,
            "assessor": (data.get("assessor") or "").strip(),
            "notes": (data.get("notes") or "").strip(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO saas_assessments
                       (id, org_id, app_id, assessment_date, score, risk_level,
                        findings_count, assessor, notes)
                       VALUES (:id, :org_id, :app_id, :assessment_date, :score, :risk_level,
                               :findings_count, :assessor, :notes)""",
                    row,
                )
                # Update app's risk_level and last_assessed
                conn.execute(
                    """UPDATE saas_apps
                       SET risk_level=?, last_assessed=?
                       WHERE id=? AND org_id=?""",
                    (new_risk_level, now, app_id, org_id),
                )
        return row

    def list_assessments(
        self,
        org_id: str,
        app_id: Optional[str] = None,
    ) -> List[dict]:
        """List assessments with optional app filter."""
        sql = "SELECT * FROM saas_assessments WHERE org_id=?"
        params: list = [org_id]
        if app_id:
            sql += " AND app_id=?"
            params.append(app_id)
        sql += " ORDER BY assessment_date DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_finding(self, org_id: str, app_id: str, data: dict) -> dict:
        """Record a security finding for a SaaS app."""
        severity = (data.get("severity") or "medium").strip().lower()
        if severity not in _VALID_FINDING_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_VALID_FINDING_SEVERITIES)}")

        finding_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": finding_id,
            "org_id": org_id,
            "app_id": app_id,
            "finding_type": (data.get("finding_type") or "").strip(),
            "severity": severity,
            "title": (data.get("title") or "").strip(),
            "description": (data.get("description") or "").strip(),
            "status": "open",
            "detected_at": now,
            "resolved_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO saas_findings
                       (id, org_id, app_id, finding_type, severity, title, description,
                        status, detected_at, resolved_at)
                       VALUES (:id, :org_id, :app_id, :finding_type, :severity, :title, :description,
                               :status, :detected_at, :resolved_at)""",
                    row,
                )
        return row

    def list_findings(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[dict]:
        """List findings with optional filters."""
        sql = "SELECT * FROM saas_findings WHERE org_id=?"
        params: list = [org_id]
        if app_id:
            sql += " AND app_id=?"
            params.append(app_id)
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_sspm_stats(self, org_id: str) -> dict:
        """Return aggregated SSPM statistics for the org."""
        with self._lock:
            with self._conn() as conn:
                total_apps = conn.execute(
                    "SELECT COUNT(*) FROM saas_apps WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                high_risk_apps = conn.execute(
                    """SELECT COUNT(*) FROM saas_apps
                       WHERE org_id=? AND risk_level IN ('critical', 'high')""",
                    (org_id,),
                ).fetchone()[0]

                open_findings = conn.execute(
                    "SELECT COUNT(*) FROM saas_findings WHERE org_id=? AND status='open'",
                    (org_id,),
                ).fetchone()[0]

                critical_findings = conn.execute(
                    """SELECT COUNT(*) FROM saas_findings
                       WHERE org_id=? AND severity='critical' AND status='open'""",
                    (org_id,),
                ).fetchone()[0]

                compliant_apps = conn.execute(
                    "SELECT COUNT(*) FROM saas_apps WHERE org_id=? AND compliance_status='compliant'",
                    (org_id,),
                ).fetchone()[0]

                compliance_rate = round(
                    (compliant_apps / total_apps * 100) if total_apps > 0 else 0.0, 2
                )

                # By category
                cat_rows = conn.execute(
                    """SELECT app_category, COUNT(*) as cnt
                       FROM saas_apps WHERE org_id=? GROUP BY app_category""",
                    (org_id,),
                ).fetchall()
                by_category = {r["app_category"]: r["cnt"] for r in cat_rows}

        return {
            "org_id": org_id,
            "total_apps": total_apps,
            "high_risk_apps": high_risk_apps,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "compliance_rate": compliance_rate,
            "by_category": by_category,
        }
