"""Red Team Management Engine — ALDECI.

Tracks red team engagements, findings, TTPs, and operators. Provides
statistics on detection rates, dwell time, and top techniques.

Capabilities:
  - Engagement lifecycle management (planned → active → completed)
  - Finding tracking with MITRE ATT&CK mapping
  - TTP (Tactics, Techniques, Procedures) logging with outcome tracking
  - Operator registry with specialization tracking
  - Aggregated statistics: detection rate, avg dwell time, top techniques

Compliance: MITRE ATT&CK, PTES, OWASP Testing Guide, NIST SP 800-115
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

_VALID_ENGAGEMENT_TYPES = {"internal", "external", "purple_team", "tabletop"}
_VALID_METHODOLOGIES = {"PTES", "OWASP", "custom"}
_VALID_ENGAGEMENT_STATUSES = {"planned", "active", "completed", "cancelled"}
_VALID_CLASSIFICATIONS = {"confidential", "secret"}
_VALID_FINDING_CATEGORIES = {
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "impact",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_FINDING_STATUSES = {"open", "accepted", "remediated", "false_positive"}
_VALID_SPECIALIZATIONS = {"network", "web", "social_engineering", "physical", "cloud"}
_VALID_TTP_OUTCOMES = {"successful", "detected", "failed", "partial"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RedTeamManagementEngine:
    """SQLite WAL-backed Red Team Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/{org_id}_red_team_mgmt.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._engines: Dict[str, str] = {}  # org_id -> db_path
        if db_path:
            self._init_db(db_path)

    def _get_db_path(self, org_id: str) -> str:
        if self._db_path:
            return self._db_path
        if org_id not in self._engines:
            path = str(Path(_DEFAULT_DB_DIR) / f"{org_id}_red_team_mgmt.db")
            self._engines[org_id] = path
            self._init_db(path)
        return self._engines[org_id]

    def _init_db(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn(db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS engagements (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    engagement_type     TEXT NOT NULL DEFAULT 'internal',
                    methodology         TEXT NOT NULL DEFAULT 'PTES',
                    scope_description   TEXT NOT NULL DEFAULT '',
                    start_date          TEXT NOT NULL DEFAULT '',
                    end_date            TEXT NOT NULL DEFAULT '',
                    lead_operator       TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL DEFAULT 'planned',
                    classification      TEXT NOT NULL DEFAULT 'confidential',
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_eng_org_status
                    ON engagements (org_id, status);

                CREATE TABLE IF NOT EXISTS findings (
                    id                        TEXT PRIMARY KEY,
                    org_id                    TEXT NOT NULL,
                    engagement_id             TEXT NOT NULL,
                    title                     TEXT NOT NULL,
                    category                  TEXT NOT NULL DEFAULT 'initial_access',
                    severity                  TEXT NOT NULL DEFAULT 'medium',
                    mitre_technique_id        TEXT NOT NULL DEFAULT '',
                    mitre_technique_name      TEXT NOT NULL DEFAULT '',
                    description               TEXT NOT NULL DEFAULT '',
                    evidence_path             TEXT NOT NULL DEFAULT '',
                    remediation_recommendation TEXT NOT NULL DEFAULT '',
                    status                    TEXT NOT NULL DEFAULT 'open',
                    created_at                DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_find_org_engagement
                    ON findings (org_id, engagement_id);

                CREATE INDEX IF NOT EXISTS idx_find_org_severity
                    ON findings (org_id, severity, status);

                CREATE TABLE IF NOT EXISTS operators (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    specialization      TEXT NOT NULL DEFAULT 'network',
                    certifications      TEXT NOT NULL DEFAULT '',
                    active_engagement_id TEXT,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_op_org
                    ON operators (org_id);

                CREATE TABLE IF NOT EXISTS ttps (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    engagement_id        TEXT NOT NULL,
                    tactic               TEXT NOT NULL DEFAULT '',
                    technique_id         TEXT NOT NULL DEFAULT '',
                    technique_name       TEXT NOT NULL DEFAULT '',
                    procedure_description TEXT NOT NULL DEFAULT '',
                    outcome              TEXT NOT NULL DEFAULT 'successful',
                    detection_time_seconds INTEGER,
                    created_at           DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ttp_org_engagement
                    ON ttps (org_id, engagement_id);

                CREATE INDEX IF NOT EXISTS idx_ttp_org_outcome
                    ON ttps (org_id, outcome);
                """
            )

    def _conn(self, db_path: str) -> sqlite3.Connection:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Engagements
    # ------------------------------------------------------------------

    def create_engagement(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new red team engagement. Returns the created record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        engagement_type = data.get("engagement_type", "internal")
        if engagement_type not in _VALID_ENGAGEMENT_TYPES:
            raise ValueError(
                f"Invalid engagement_type: {engagement_type}. Must be one of {_VALID_ENGAGEMENT_TYPES}"
            )

        methodology = data.get("methodology", "PTES")
        if methodology not in _VALID_METHODOLOGIES:
            raise ValueError(
                f"Invalid methodology: {methodology}. Must be one of {_VALID_METHODOLOGIES}"
            )

        classification = data.get("classification", "confidential")
        if classification not in _VALID_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid classification: {classification}. Must be one of {_VALID_CLASSIFICATIONS}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "engagement_type": engagement_type,
            "methodology": methodology,
            "scope_description": data.get("scope_description", ""),
            "start_date": data.get("start_date", ""),
            "end_date": data.get("end_date", ""),
            "lead_operator": data.get("lead_operator", ""),
            "status": "planned",
            "classification": classification,
            "created_at": now,
        }
        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                conn.execute(
                    """INSERT INTO engagements
                       (id, org_id, name, engagement_type, methodology, scope_description,
                        start_date, end_date, lead_operator, status, classification, created_at)
                       VALUES (:id, :org_id, :name, :engagement_type, :methodology,
                               :scope_description, :start_date, :end_date, :lead_operator,
                               :status, :classification, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "red_team_mgmt", "org_id": org_id, "source_engine": "red_team_mgmt"})
            except Exception:
                pass

        return record

    def list_engagements(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List engagements, optionally filtered by status."""
        sql = "SELECT * FROM engagements WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_engagement(self, org_id: str, engagement_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single engagement by ID, including findings summary."""
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            row = conn.execute(
                "SELECT * FROM engagements WHERE org_id = ? AND id = ?",
                (org_id, engagement_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)

            # Findings summary by severity
            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt
                   FROM findings WHERE org_id = ? AND engagement_id = ?
                   GROUP BY severity""",
                (org_id, engagement_id),
            ).fetchall()
            result["findings_by_severity"] = {r["severity"]: r["cnt"] for r in sev_rows}

            total_findings = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE org_id = ? AND engagement_id = ?",
                (org_id, engagement_id),
            ).fetchone()[0]
            result["total_findings"] = total_findings

        return result

    def update_engagement_status(
        self, org_id: str, engagement_id: str, status: str
    ) -> Dict[str, Any]:
        """Update engagement status. Returns updated record."""
        if status not in _VALID_ENGAGEMENT_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {_VALID_ENGAGEMENT_STATUSES}"
            )
        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                cur = conn.execute(
                    "UPDATE engagements SET status = ? WHERE org_id = ? AND id = ?",
                    (status, org_id, engagement_id),
                )
                if cur.rowcount == 0:
                    raise ValueError(f"Engagement {engagement_id} not found.")
        return {"engagement_id": engagement_id, "status": status, "updated": True}

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(
        self, org_id: str, engagement_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a finding to an engagement. Returns the created record."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        category = data.get("category", "initial_access")
        if category not in _VALID_FINDING_CATEGORIES:
            raise ValueError(
                f"Invalid category: {category}. Must be one of {_VALID_FINDING_CATEGORIES}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. Must be one of {_VALID_SEVERITIES}"
            )

        status = data.get("status", "open")
        if status not in _VALID_FINDING_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {_VALID_FINDING_STATUSES}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "engagement_id": engagement_id,
            "title": title,
            "category": category,
            "severity": severity,
            "mitre_technique_id": data.get("mitre_technique_id", ""),
            "mitre_technique_name": data.get("mitre_technique_name", ""),
            "description": data.get("description", ""),
            "evidence_path": data.get("evidence_path", ""),
            "remediation_recommendation": data.get("remediation_recommendation", ""),
            "status": status,
            "created_at": now,
        }
        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                conn.execute(
                    """INSERT INTO findings
                       (id, org_id, engagement_id, title, category, severity,
                        mitre_technique_id, mitre_technique_name, description,
                        evidence_path, remediation_recommendation, status, created_at)
                       VALUES (:id, :org_id, :engagement_id, :title, :category, :severity,
                               :mitre_technique_id, :mitre_technique_name, :description,
                               :evidence_path, :remediation_recommendation, :status, :created_at)""",
                    record,
                )
        return record

    def list_findings(
        self,
        org_id: str,
        engagement_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        sql = "SELECT * FROM findings WHERE org_id = ?"
        params: list = [org_id]
        if engagement_id:
            sql += " AND engagement_id = ?"
            params.append(engagement_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # TTPs
    # ------------------------------------------------------------------

    def add_ttp(
        self, org_id: str, engagement_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Log a TTP executed during an engagement. Returns the created record."""
        outcome = data.get("outcome", "successful")
        if outcome not in _VALID_TTP_OUTCOMES:
            raise ValueError(
                f"Invalid outcome: {outcome}. Must be one of {_VALID_TTP_OUTCOMES}"
            )

        detection_time = data.get("detection_time_seconds")
        if detection_time is not None:
            detection_time = int(detection_time)

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "engagement_id": engagement_id,
            "tactic": data.get("tactic", ""),
            "technique_id": data.get("technique_id", ""),
            "technique_name": data.get("technique_name", ""),
            "procedure_description": data.get("procedure_description", ""),
            "outcome": outcome,
            "detection_time_seconds": detection_time,
            "created_at": now,
        }
        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                conn.execute(
                    """INSERT INTO ttps
                       (id, org_id, engagement_id, tactic, technique_id, technique_name,
                        procedure_description, outcome, detection_time_seconds, created_at)
                       VALUES (:id, :org_id, :engagement_id, :tactic, :technique_id,
                               :technique_name, :procedure_description, :outcome,
                               :detection_time_seconds, :created_at)""",
                    record,
                )
        return record

    def list_ttps(
        self, org_id: str, engagement_id: str
    ) -> List[Dict[str, Any]]:
        """List TTPs for a specific engagement."""
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM ttps WHERE org_id = ? AND engagement_id = ? ORDER BY created_at DESC",
                    (org_id, engagement_id),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Operators
    # ------------------------------------------------------------------

    def add_operator(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a red team operator. Returns the created record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        specialization = data.get("specialization", "network")
        if specialization not in _VALID_SPECIALIZATIONS:
            raise ValueError(
                f"Invalid specialization: {specialization}. Must be one of {_VALID_SPECIALIZATIONS}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "specialization": specialization,
            "certifications": data.get("certifications", ""),
            "active_engagement_id": data.get("active_engagement_id", None),
            "created_at": now,
        }
        db = self._get_db_path(org_id)
        with self._lock:
            with self._conn(db) as conn:
                conn.execute(
                    """INSERT INTO operators
                       (id, org_id, name, specialization, certifications,
                        active_engagement_id, created_at)
                       VALUES (:id, :org_id, :name, :specialization, :certifications,
                               :active_engagement_id, :created_at)""",
                    record,
                )
        return record

    def list_operators(self, org_id: str) -> List[Dict[str, Any]]:
        """List all operators for the org."""
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM operators WHERE org_id = ? ORDER BY name ASC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated red team stats for org."""
        db = self._get_db_path(org_id)
        with self._conn(db) as conn:
            engagement_count = conn.execute(
                "SELECT COUNT(*) FROM engagements WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            # Open findings by severity
            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt
                   FROM findings WHERE org_id = ? AND status = 'open'
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            open_findings_by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            # Average dwell time (detection_time_seconds) for detected TTPs
            avg_row = conn.execute(
                """SELECT AVG(detection_time_seconds) as avg_dwell
                   FROM ttps WHERE org_id = ? AND outcome = 'detected'
                   AND detection_time_seconds IS NOT NULL""",
                (org_id,),
            ).fetchone()
            avg_dwell_time = avg_row["avg_dwell"] if avg_row and avg_row["avg_dwell"] else 0.0

            # Detection rate: detected / (detected + successful + partial) * 100
            total_ttps = conn.execute(
                "SELECT COUNT(*) FROM ttps WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            detected_ttps = conn.execute(
                "SELECT COUNT(*) FROM ttps WHERE org_id = ? AND outcome = 'detected'",
                (org_id,),
            ).fetchone()[0]
            detection_rate = (
                round((detected_ttps / total_ttps) * 100, 2) if total_ttps > 0 else 0.0
            )

            # Top 5 techniques by frequency
            tech_rows = conn.execute(
                """SELECT technique_id, technique_name, COUNT(*) as cnt
                   FROM ttps WHERE org_id = ? AND technique_id != ''
                   GROUP BY technique_id, technique_name
                   ORDER BY cnt DESC LIMIT 5""",
                (org_id,),
            ).fetchall()
            top_techniques = [self._row(r) for r in tech_rows]

        return {
            "engagement_count": engagement_count,
            "open_findings_by_severity": open_findings_by_severity,
            "avg_dwell_time": avg_dwell_time,
            "detection_rate": detection_rate,
            "top_techniques": top_techniques,
        }
