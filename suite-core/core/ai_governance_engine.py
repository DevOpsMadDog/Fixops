"""AI Governance Engine — ALDECI.

Tracks AI/ML model governance, risk assessments, and incident management.

Capabilities:
  - AI model registry with type, deployment status, risk level, and data classification
  - Model risk assessments (bias, fairness, security, privacy, performance)
  - AI incident management with lifecycle tracking
  - Governance stats: totals, by type, by risk level, open incidents

Compliance: NIST AI RMF, EU AI Act, ISO/IEC 42001
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

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_MODEL_TYPES = {
    "llm",
    "classification",
    "regression",
    "computer_vision",
    "nlp",
    "recommendation",
    "anomaly_detection",
}
_VALID_DEPLOYMENT_STATUSES = {"development", "staging", "production", "retired"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_DATA_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}
_VALID_ASSESSMENT_TYPES = {"bias", "fairness", "security", "privacy", "performance"}
_VALID_INCIDENT_TYPES = {
    "bias",
    "hallucination",
    "data_leak",
    "adversarial",
    "drift",
    "unauthorized_use",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_INCIDENT_STATUSES = {"open", "investigating", "resolved"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AIGovernanceEngine:
    """SQLite WAL-backed AI Governance engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/ai_governance.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "ai_governance.db")
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
                CREATE TABLE IF NOT EXISTS ai_models (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    model_name          TEXT NOT NULL,
                    model_type          TEXT NOT NULL,
                    vendor              TEXT NOT NULL DEFAULT '',
                    version             TEXT NOT NULL DEFAULT '',
                    deployment_status   TEXT NOT NULL DEFAULT 'development',
                    risk_level          TEXT NOT NULL DEFAULT 'medium',
                    use_case            TEXT NOT NULL DEFAULT '',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ai_models_org
                    ON ai_models (org_id, model_type, deployment_status, risk_level, created_at DESC);

                CREATE TABLE IF NOT EXISTS model_assessments (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    model_id        TEXT NOT NULL,
                    assessment_type TEXT NOT NULL,
                    score           REAL NOT NULL,
                    findings        TEXT NOT NULL DEFAULT '[]',
                    assessor        TEXT NOT NULL DEFAULT '',
                    assessed_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_assessments_org
                    ON model_assessments (org_id, model_id, assessment_type, assessed_at DESC);

                CREATE TABLE IF NOT EXISTS ai_incidents (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    model_id      TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    severity      TEXT NOT NULL,
                    description   TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'open',
                    reported_at   TEXT NOT NULL,
                    resolved_at   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_org
                    ON ai_incidents (org_id, model_id, status, severity, reported_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Parse JSON fields
        for field in ("findings",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        return d

    # ------------------------------------------------------------------
    # Models
    # ------------------------------------------------------------------

    def register_model(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new AI/ML model."""
        model_name = (data.get("model_name") or "").strip()
        if not model_name:
            raise ValueError("model_name is required.")

        model_type = data.get("model_type", "llm")
        if model_type not in _VALID_MODEL_TYPES:
            raise ValueError(
                f"Invalid model_type: {model_type}. "
                f"Must be one of {sorted(_VALID_MODEL_TYPES)}"
            )

        deployment_status = data.get("deployment_status", "development")
        if deployment_status not in _VALID_DEPLOYMENT_STATUSES:
            raise ValueError(
                f"Invalid deployment_status: {deployment_status}. "
                f"Must be one of {sorted(_VALID_DEPLOYMENT_STATUSES)}"
            )

        risk_level = data.get("risk_level", "medium")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level: {risk_level}. "
                f"Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )

        data_classification = data.get("data_classification", "internal")
        if data_classification not in _VALID_DATA_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid data_classification: {data_classification}. "
                f"Must be one of {sorted(_VALID_DATA_CLASSIFICATIONS)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "model_name": model_name,
            "model_type": model_type,
            "vendor": data.get("vendor", ""),
            "version": data.get("version", ""),
            "deployment_status": deployment_status,
            "risk_level": risk_level,
            "use_case": data.get("use_case", ""),
            "data_classification": data_classification,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ai_models
                       (id, org_id, model_name, model_type, vendor, version,
                        deployment_status, risk_level, use_case, data_classification, created_at)
                       VALUES (:id, :org_id, :model_name, :model_type, :vendor, :version,
                               :deployment_status, :risk_level, :use_case, :data_classification, :created_at)""",
                    record,
                )
        return record

    def list_models(
        self,
        org_id: str,
        model_type: Optional[str] = None,
        deployment_status: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List AI models with optional filters."""
        sql = "SELECT * FROM ai_models WHERE org_id = ?"
        params: list = [org_id]
        if model_type:
            sql += " AND model_type = ?"
            params.append(model_type)
        if deployment_status:
            sql += " AND deployment_status = ?"
            params.append(deployment_status)
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_model(self, org_id: str, model_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single model by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ai_models WHERE org_id = ? AND id = ?",
                (org_id, model_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_model_status(
        self, org_id: str, model_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update deployment status of a model."""
        if new_status not in _VALID_DEPLOYMENT_STATUSES:
            raise ValueError(
                f"Invalid deployment_status: {new_status}. "
                f"Must be one of {sorted(_VALID_DEPLOYMENT_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE ai_models SET deployment_status = ? WHERE org_id = ? AND id = ?",
                    (new_status, org_id, model_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Model {model_id} not found in org {org_id}")
                row = conn.execute(
                    "SELECT * FROM ai_models WHERE org_id = ? AND id = ?",
                    (org_id, model_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def record_assessment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a model risk assessment."""
        model_id = (data.get("model_id") or "").strip()
        if not model_id:
            raise ValueError("model_id is required.")

        # Validate model exists in org
        model = self.get_model(org_id, model_id)
        if model is None:
            raise KeyError(f"Model {model_id} not found in org {org_id}")

        assessment_type = data.get("assessment_type", "performance")
        if assessment_type not in _VALID_ASSESSMENT_TYPES:
            raise ValueError(
                f"Invalid assessment_type: {assessment_type}. "
                f"Must be one of {sorted(_VALID_ASSESSMENT_TYPES)}"
            )

        score = data.get("score")
        if score is None:
            raise ValueError("score is required.")
        try:
            score = float(score)
        except (TypeError, ValueError):
            raise ValueError("score must be a number.")
        if not (0.0 <= score <= 100.0):
            raise ValueError("score must be between 0 and 100.")

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "model_id": model_id,
            "assessment_type": assessment_type,
            "score": score,
            "findings": json.dumps(findings),
            "assessor": data.get("assessor", ""),
            "assessed_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO model_assessments
                       (id, org_id, model_id, assessment_type, score, findings, assessor, assessed_at)
                       VALUES (:id, :org_id, :model_id, :assessment_type, :score, :findings, :assessor, :assessed_at)""",
                    record,
                )
        record["findings"] = findings
        return record

    def list_assessments(
        self,
        org_id: str,
        model_id: Optional[str] = None,
        assessment_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assessments with optional filters."""
        sql = "SELECT * FROM model_assessments WHERE org_id = ?"
        params: list = [org_id]
        if model_id:
            sql += " AND model_id = ?"
            params.append(model_id)
        if assessment_type:
            sql += " AND assessment_type = ?"
            params.append(assessment_type)
        sql += " ORDER BY assessed_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def report_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Report an AI incident."""
        model_id = (data.get("model_id") or "").strip()
        if not model_id:
            raise ValueError("model_id is required.")

        # Validate model exists in org
        model = self.get_model(org_id, model_id)
        if model is None:
            raise KeyError(f"Model {model_id} not found in org {org_id}")

        incident_type = data.get("incident_type", "drift")
        if incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(
                f"Invalid incident_type: {incident_type}. "
                f"Must be one of {sorted(_VALID_INCIDENT_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "model_id": model_id,
            "incident_type": incident_type,
            "severity": severity,
            "description": data.get("description", ""),
            "status": "open",
            "reported_at": now,
            "resolved_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ai_incidents
                       (id, org_id, model_id, incident_type, severity, description, status, reported_at, resolved_at)
                       VALUES (:id, :org_id, :model_id, :incident_type, :severity, :description, :status, :reported_at, :resolved_at)""",
                    record,
                )
        return record

    def resolve_incident(self, org_id: str, incident_id: str) -> Dict[str, Any]:
        """Resolve an AI incident."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE ai_incidents SET status = 'resolved', resolved_at = ? WHERE org_id = ? AND id = ?",
                    (now, org_id, incident_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Incident {incident_id} not found in org {org_id}"
                    )
                row = conn.execute(
                    "SELECT * FROM ai_incidents WHERE org_id = ? AND id = ?",
                    (org_id, incident_id),
                ).fetchone()
        return self._row(row)

    def list_incidents(
        self,
        org_id: str,
        model_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List incidents with optional filters."""
        sql = "SELECT * FROM ai_incidents WHERE org_id = ?"
        params: list = [org_id]
        if model_id:
            sql += " AND model_id = ?"
            params.append(model_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY reported_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_governance_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated governance statistics."""
        with self._conn() as conn:
            total_models = conn.execute(
                "SELECT COUNT(*) FROM ai_models WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            production_models = conn.execute(
                "SELECT COUNT(*) FROM ai_models WHERE org_id = ? AND deployment_status = 'production'",
                (org_id,),
            ).fetchone()[0]

            by_type_rows = conn.execute(
                "SELECT model_type, COUNT(*) as cnt FROM ai_models WHERE org_id = ? GROUP BY model_type",
                (org_id,),
            ).fetchall()

            by_risk_rows = conn.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM ai_models WHERE org_id = ? GROUP BY risk_level",
                (org_id,),
            ).fetchall()

            total_assessments = conn.execute(
                "SELECT COUNT(*) FROM model_assessments WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_incidents = conn.execute(
                "SELECT COUNT(*) FROM ai_incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_incidents = conn.execute(
                "SELECT COUNT(*) FROM ai_incidents WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_models": total_models,
            "production_models": production_models,
            "by_type": {r["model_type"]: r["cnt"] for r in by_type_rows},
            "by_risk_level": {r["risk_level"]: r["cnt"] for r in by_risk_rows},
            "total_assessments": total_assessments,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
        }
