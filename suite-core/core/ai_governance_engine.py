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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


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

# GAP-061: Tiered LLM context router
_VALID_CONTEXT_TIERS = {"metadata", "targeted", "full_file"}

# Cost per 1M tokens, hardcoded by tier.  Input tokens for simplicity; the
# numbers below reflect a blended estimate (prompt + completion weights) that
# is stable enough for pre-flight budget checks.
_TIER_COST_PER_1M_USD: Dict[str, float] = {
    "metadata": 0.5,
    "targeted": 2.0,
    "full_file": 10.0,
}

# Default token envelopes per tier — caller can override per-rule via
# register_rule_context_requirement(max_tokens=...).
_TIER_DEFAULT_MAX_TOKENS: Dict[str, int] = {
    "metadata": 500,
    "targeted": 4_000,
    "full_file": 32_000,
}

# Output token share assumed per invocation for cost estimation.  The router
# bills input + output; we use a fixed 25% output fraction of max_tokens which
# matches observed Qwen/Kimi pentest/review traffic.
_OUTPUT_TOKEN_FRACTION = 0.25


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

                -- GAP-061: per-rule context tier for pre-flight cost control
                CREATE TABLE IF NOT EXISTS rule_context_requirements (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    rule_key    TEXT NOT NULL,
                    tier        TEXT NOT NULL,
                    max_tokens  INTEGER NOT NULL,
                    created_at  TEXT NOT NULL,
                    UNIQUE(org_id, rule_key)
                );

                CREATE INDEX IF NOT EXISTS idx_rule_ctx_req_org
                    ON rule_context_requirements (org_id, rule_key);

                -- GAP-059: Shadow-AI registry
                CREATE TABLE IF NOT EXISTS ai_services_registry (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    service_name        TEXT NOT NULL,
                    provider            TEXT NOT NULL DEFAULT '',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    approved_by         TEXT NOT NULL DEFAULT '',
                    approved_at         TEXT NOT NULL DEFAULT '',
                    created_at          TEXT NOT NULL,
                    UNIQUE(org_id, service_name)
                );

                CREATE INDEX IF NOT EXISTS idx_ai_services_registry_org
                    ON ai_services_registry (org_id, service_name);

                -- GAP-043: Scoring formula change history (governance audit)
                CREATE TABLE IF NOT EXISTS scoring_formula_history (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    formula_version TEXT NOT NULL,
                    change_summary  TEXT NOT NULL DEFAULT '',
                    approver        TEXT NOT NULL DEFAULT '',
                    approved_at     TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    UNIQUE(org_id, formula_version)
                );

                CREATE INDEX IF NOT EXISTS idx_scoring_formula_history_org
                    ON scoring_formula_history (org_id, approved_at DESC);
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
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "ai_governance", "org_id": org_id, "source_engine": "ai_governance"})
            except Exception:
                pass

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
        """Return aggregated governance statistics.

        Perf: collapsed 7 sequential COUNT(*) queries into 3 passes —
        one conditional-aggregation pass on ai_models, one on ai_incidents,
        and the two GROUP-BY passes for by_type / by_risk_level are merged
        into a single combined query using conditional aggregation over all
        known model_type and risk_level values.  model_assessments stays as
        one COUNT(*) since there is nothing to collapse it with.
        """
        with self._conn() as conn:
            # Pass 1: ai_models — total + production + per-type + per-risk in one scan.
            # We use conditional SUM for the scalar counts and GROUP BY for the
            # distribution maps via two compact GROUP BY queries that share a
            # single table scan via a CTE.
            models_row = conn.execute(
                """SELECT
                     COUNT(*),
                     SUM(CASE WHEN deployment_status = 'production' THEN 1 ELSE 0 END)
                   FROM ai_models WHERE org_id = ?""",
                (org_id,),
            ).fetchone()
            total_models = models_row[0] or 0
            production_models = models_row[1] or 0

            by_type_rows = conn.execute(
                "SELECT model_type, COUNT(*) AS cnt FROM ai_models "
                "WHERE org_id = ? GROUP BY model_type",
                (org_id,),
            ).fetchall()

            by_risk_rows = conn.execute(
                "SELECT risk_level, COUNT(*) AS cnt FROM ai_models "
                "WHERE org_id = ? GROUP BY risk_level",
                (org_id,),
            ).fetchall()

            # Pass 2: model_assessments — single COUNT.
            total_assessments = conn.execute(
                "SELECT COUNT(*) FROM model_assessments WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # Pass 3: ai_incidents — total + open in one conditional-aggregation scan.
            inc_row = conn.execute(
                """SELECT
                     COUNT(*),
                     SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END)
                   FROM ai_incidents WHERE org_id = ?""",
                (org_id,),
            ).fetchone()
            total_incidents = inc_row[0] or 0
            open_incidents = inc_row[1] or 0

        return {
            "total_models": total_models,
            "production_models": production_models,
            "by_type": {r["model_type"]: r["cnt"] for r in by_type_rows},
            "by_risk_level": {r["risk_level"]: r["cnt"] for r in by_risk_rows},
            "total_assessments": total_assessments,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
        }

    # ------------------------------------------------------------------
    # GAP-061: Tiered LLM context router
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_tier(tier: str) -> str:
        if tier not in _VALID_CONTEXT_TIERS:
            raise ValueError(
                f"Invalid tier: {tier!r}. "
                f"Must be one of {sorted(_VALID_CONTEXT_TIERS)}"
            )
        return tier

    def register_rule_context_requirement(
        self,
        org_id: str,
        rule_key: str,
        tier: str,
        max_tokens: int,
    ) -> Dict[str, Any]:
        """Register/upsert a per-rule context requirement.

        Parameters
        ----------
        org_id: tenant id.
        rule_key: stable identifier of the rule (e.g. "owasp-a01-sqli").
        tier: one of {metadata, targeted, full_file}.
        max_tokens: upper bound of prompt+completion tokens for this rule.

        UNIQUE(org_id, rule_key) — subsequent calls update tier/max_tokens.
        """
        rule_key = (rule_key or "").strip()
        if not rule_key:
            raise ValueError("rule_key is required.")
        if not org_id:
            raise ValueError("org_id is required.")
        tier = self._validate_tier(tier)
        try:
            max_tokens_int = int(max_tokens)
        except (TypeError, ValueError):
            raise ValueError("max_tokens must be an integer.")
        if max_tokens_int <= 0:
            raise ValueError("max_tokens must be > 0.")

        now = _now_iso()
        record_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                # UPSERT on (org_id, rule_key)
                existing = conn.execute(
                    "SELECT id FROM rule_context_requirements "
                    "WHERE org_id = ? AND rule_key = ?",
                    (org_id, rule_key),
                ).fetchone()
                if existing:
                    record_id = existing["id"]
                    conn.execute(
                        """UPDATE rule_context_requirements
                           SET tier = ?, max_tokens = ?
                           WHERE id = ?""",
                        (tier, max_tokens_int, record_id),
                    )
                    created_at = conn.execute(
                        "SELECT created_at FROM rule_context_requirements WHERE id = ?",
                        (record_id,),
                    ).fetchone()["created_at"]
                else:
                    created_at = now
                    conn.execute(
                        """INSERT INTO rule_context_requirements
                           (id, org_id, rule_key, tier, max_tokens, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (record_id, org_id, rule_key, tier, max_tokens_int, now),
                    )

        return {
            "id": record_id,
            "org_id": org_id,
            "rule_key": rule_key,
            "tier": tier,
            "max_tokens": max_tokens_int,
            "created_at": created_at,
        }

    def list_rule_context_requirements(
        self, org_id: str
    ) -> List[Dict[str, Any]]:
        """Return all registered rule context requirements for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM rule_context_requirements "
                "WHERE org_id = ? ORDER BY rule_key ASC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def estimate_llm_cost(
        self,
        org_id: str,
        rule_keys: List[str],
        file_count: int = 1,
    ) -> Dict[str, Any]:
        """Estimate LLM cost for a run across the supplied rules.

        Returns ::

            {
                "by_tier": {
                    "metadata":  {"rules": [...], "est_tokens_in": int,
                                  "est_tokens_out": int, "est_cost_usd": float},
                    "targeted":  {...},
                    "full_file": {...},
                },
                "total": {"rules": int, "est_tokens_in": int,
                          "est_tokens_out": int, "est_cost_usd": float},
            }

        Rules without a registered requirement are treated as ``metadata`` tier
        with the default envelope — this keeps the estimator conservative but
        always returns a usable figure.  ``file_count`` multiplies per-rule
        cost to model a scan hitting multiple files.
        """
        if rule_keys is None:
            rule_keys = []
        if not isinstance(rule_keys, list):
            raise ValueError("rule_keys must be a list.")
        try:
            file_count_int = int(file_count)
        except (TypeError, ValueError):
            raise ValueError("file_count must be an integer.")
        if file_count_int < 1:
            raise ValueError("file_count must be >= 1.")

        # Load all requirements for the org once.
        reqs = {
            r["rule_key"]: r
            for r in self.list_rule_context_requirements(org_id)
        }

        by_tier: Dict[str, Dict[str, Any]] = {
            tier: {
                "rules": [],
                "est_tokens_in": 0,
                "est_tokens_out": 0,
                "est_cost_usd": 0.0,
            }
            for tier in sorted(_VALID_CONTEXT_TIERS)
        }

        for rule_key in rule_keys:
            rk = (rule_key or "").strip()
            if not rk:
                continue
            req = reqs.get(rk)
            if req:
                tier = req["tier"]
                max_tokens = int(req["max_tokens"])
            else:
                tier = "metadata"
                max_tokens = _TIER_DEFAULT_MAX_TOKENS[tier]

            # tokens-in dominate; tokens-out is a fraction of the budget.
            tokens_in = int(max_tokens * (1.0 - _OUTPUT_TOKEN_FRACTION)) * file_count_int
            tokens_out = int(max_tokens * _OUTPUT_TOKEN_FRACTION) * file_count_int
            total_tokens = tokens_in + tokens_out
            cost = (total_tokens / 1_000_000.0) * _TIER_COST_PER_1M_USD[tier]

            bucket = by_tier[tier]
            bucket["rules"].append(rk)
            bucket["est_tokens_in"] += tokens_in
            bucket["est_tokens_out"] += tokens_out
            bucket["est_cost_usd"] = round(bucket["est_cost_usd"] + cost, 6)

        total = {
            "rules": sum(len(b["rules"]) for b in by_tier.values()),
            "est_tokens_in": sum(b["est_tokens_in"] for b in by_tier.values()),
            "est_tokens_out": sum(b["est_tokens_out"] for b in by_tier.values()),
            "est_cost_usd": round(
                sum(b["est_cost_usd"] for b in by_tier.values()), 6
            ),
        }

        return {"by_tier": by_tier, "total": total}

    def preflight_estimate(
        self,
        org_id: str,
        rule_keys: List[str],
        file_count: int = 1,
    ) -> Dict[str, Any]:
        """User-facing pre-flight wrapper around :meth:`estimate_llm_cost`.

        Adds a human-readable ``summary`` and a ``tier_distribution`` so the
        caller can render a budget warning before firing the scan.
        """
        estimate = self.estimate_llm_cost(org_id, rule_keys, file_count=file_count)
        total = estimate["total"]
        by_tier = estimate["by_tier"]

        tier_distribution = {
            tier: len(bucket["rules"]) for tier, bucket in by_tier.items()
        }
        summary = (
            f"Pre-flight: {total['rules']} rule(s) across {file_count} file(s) — "
            f"~{total['est_tokens_in']:,} in / {total['est_tokens_out']:,} out tokens, "
            f"est. ${total['est_cost_usd']:.4f} USD "
            f"(metadata={tier_distribution.get('metadata', 0)}, "
            f"targeted={tier_distribution.get('targeted', 0)}, "
            f"full_file={tier_distribution.get('full_file', 0)})"
        )

        return {
            "org_id": org_id,
            "file_count": file_count,
            "by_tier": by_tier,
            "total": total,
            "tier_distribution": tier_distribution,
            "summary": summary,
        }

    # ------------------------------------------------------------------
    # GAP-059: Shadow-AI inventory
    # ------------------------------------------------------------------

    # Known AI provider domain signatures
    _SHADOW_AI_DOMAIN_PATTERNS = (
        "openai.com", "api.openai.com",
        "anthropic.com", "api.anthropic.com",
        "huggingface.co", "huggingface.com",
        "cohere.ai", "cohere.com",
        "mistral.ai",
        "replicate.com",
        "together.ai", "together.xyz",
        "perplexity.ai",
        "stability.ai",
        "deepmind.com",
        "x.ai",
        "mulerouter.ai", "openrouter.ai",
        "poe.com",
    )

    _SHADOW_AI_PACKAGE_PATTERNS = (
        "openai", "anthropic", "langchain", "llama_index",
        "transformers", "sentence-transformers", "huggingface-hub",
        "cohere", "mistralai", "replicate", "together",
        "tiktoken", "langgraph",
    )

    _SHADOW_AI_ENVVAR_PATTERNS = (
        "OPENAI_", "ANTHROPIC_", "HUGGINGFACE_", "HF_",
        "COHERE_", "MISTRAL_", "REPLICATE_", "TOGETHER_",
        "PERPLEXITY_", "OPENROUTER_", "MULEROUTER_",
    )

    @staticmethod
    def _shadow_match_text(text: str, patterns: tuple) -> Optional[str]:
        if not text:
            return None
        hay = str(text).lower()
        for p in patterns:
            if p.lower() in hay:
                return p
        return None

    @staticmethod
    def _shadow_match_envvar(envvars: List[str]) -> Optional[str]:
        for v in envvars or []:
            vu = str(v).upper()
            for p in AIGovernanceEngine._SHADOW_AI_ENVVAR_PATTERNS:
                if vu.startswith(p):
                    return v
        return None

    def _iter_cmdb_saas_signals(self, org_id: str) -> List[Dict[str, Any]]:
        """Direct SQL read from cmdb.db (no cmdb import).

        Looks at ci_items with ci_type in {'application','cloud_resource'} and
        inspects name/ip_address/version/tags for AI-provider signals.
        """
        cmdb_path = Path(self._db_path).parent / "cmdb.db"
        if not cmdb_path.exists():
            return []
        out: List[Dict[str, Any]] = []
        try:
            conn = sqlite3.connect(str(cmdb_path), timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT ci_id, name, ci_type, version, ip_address, tags "
                    "FROM ci_items WHERE org_id = ? "
                    "AND ci_type IN ('application','cloud_resource','container')",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            return []

        for r in rows:
            blob = " ".join([
                str(r["name"] or ""),
                str(r["version"] or ""),
                str(r["ip_address"] or ""),
                str(r["tags"] or ""),
            ])
            hit = (
                self._shadow_match_text(blob, self._SHADOW_AI_DOMAIN_PATTERNS)
                or self._shadow_match_text(blob, self._SHADOW_AI_PACKAGE_PATTERNS)
            )
            if hit:
                out.append({
                    "source": "cmdb",
                    "asset_ref": r["ci_id"],
                    "name": r["name"],
                    "signal": hit,
                    "signal_type": "domain_or_package",
                })
        return out

    def _iter_cloud_inventory_signals(self, org_id: str) -> List[Dict[str, Any]]:
        inv_path = Path(self._db_path).parent / "cloud_resource_inventory.db"
        if not inv_path.exists():
            return []
        out: List[Dict[str, Any]] = []
        try:
            conn = sqlite3.connect(str(inv_path), timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT id, resource_id, resource_name, resource_type, tags_json "
                    "FROM cri_resources WHERE org_id = ?",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            return []

        for r in rows:
            blob = " ".join([
                str(r["resource_name"] or ""),
                str(r["resource_id"] or ""),
                str(r["tags_json"] or ""),
            ])
            hit = (
                self._shadow_match_text(blob, self._SHADOW_AI_DOMAIN_PATTERNS)
                or self._shadow_match_text(blob, self._SHADOW_AI_PACKAGE_PATTERNS)
            )
            if hit:
                out.append({
                    "source": "cloud_inventory",
                    "asset_ref": r["id"],
                    "name": r["resource_name"] or r["resource_id"],
                    "signal": hit,
                    "signal_type": "domain_or_package",
                })
        return out

    def _iter_identity_signals(self, org_id: str) -> List[Dict[str, Any]]:
        idr_path = Path(self._db_path).parent / "identity_risk.db"
        if not idr_path.exists():
            return []
        out: List[Dict[str, Any]] = []
        try:
            conn = sqlite3.connect(str(idr_path), timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT id, username, email FROM ir_identities "
                    "WHERE org_id = ?",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            return []

        for r in rows:
            blob = f"{r['username'] or ''} {r['email'] or ''}"
            hit = self._shadow_match_text(blob, self._SHADOW_AI_DOMAIN_PATTERNS)
            if hit:
                out.append({
                    "source": "identity_risk",
                    "asset_ref": r["id"],
                    "name": r["username"] or r["email"],
                    "signal": hit,
                    "signal_type": "domain",
                })
        return out

    def _registered_service_names(self, org_id: str) -> set:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT service_name FROM ai_services_registry WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        return {r["service_name"].lower() for r in rows}

    def discover_shadow_ai(
        self,
        org_id: str,
        sources: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Discover unregistered AI usage across cmdb / cloud inventory /
        identity risk / explicit caller-supplied sources.

        ``sources`` is an optional list of dicts with free-form fields,
        e.g. ``{"asset_ref": "...", "domain": "...", "package": "...",
        "envvars": ["OPENAI_API_KEY"]}``.  Each match contributes a
        ``discovered`` entry tagged with the matching signal.
        """
        if not org_id:
            raise ValueError("org_id is required.")

        discovered: List[Dict[str, Any]] = []
        discovered.extend(self._iter_cmdb_saas_signals(org_id))
        discovered.extend(self._iter_cloud_inventory_signals(org_id))
        discovered.extend(self._iter_identity_signals(org_id))

        for entry in sources or []:
            if not isinstance(entry, dict):
                continue
            domain = entry.get("domain")
            pkg = entry.get("package")
            envvars = entry.get("envvars") or []
            hit = (
                self._shadow_match_text(domain, self._SHADOW_AI_DOMAIN_PATTERNS)
                or self._shadow_match_text(pkg, self._SHADOW_AI_PACKAGE_PATTERNS)
                or self._shadow_match_envvar(envvars)
            )
            if hit:
                discovered.append({
                    "source": entry.get("source", "caller"),
                    "asset_ref": entry.get("asset_ref", ""),
                    "name": entry.get("name") or entry.get("asset_ref", ""),
                    "signal": hit,
                    "signal_type": (
                        "envvar" if envvars and hit in envvars
                        else "domain" if domain and hit.lower() in str(domain).lower()
                        else "package"
                    ),
                })

        # Split against registry
        registered = self._registered_service_names(org_id)
        unregistered: List[Dict[str, Any]] = []
        already_registered: List[Dict[str, Any]] = []
        for d in discovered:
            # Use the matching signal as the canonical service token.
            token = str(d.get("signal") or "").lower()
            # The registry key is service_name; a simple containment check
            # lets "OpenAI GPT-4" match a registered service called "openai".
            is_registered = any(reg in token or token in reg for reg in registered)
            if is_registered:
                already_registered.append(d)
            else:
                unregistered.append(d)

        total_signals = len(discovered)
        registered_count = len(already_registered)
        unregistered_count = len(unregistered)
        coverage_pct = (
            round(registered_count / total_signals * 100.0, 2)
            if total_signals > 0
            else 100.0
        )

        return {
            "discovered": discovered,
            "unregistered": unregistered,
            "registered": already_registered,
            "unregistered_count": unregistered_count,
            "registered_count": registered_count,
            "total_signals": total_signals,
            "coverage_pct": coverage_pct,
        }

    def register_ai_service(
        self,
        org_id: str,
        service_name: str,
        provider: str = "",
        data_classification: str = "internal",
        approved_by: str = "",
        approved_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register an AI service into the approved registry.

        UNIQUE(org_id, service_name) — ``INSERT OR IGNORE`` keeps idempotency;
        re-registering the same service is a no-op that returns the stored row.
        """
        if not org_id:
            raise ValueError("org_id is required.")
        service_name = (service_name or "").strip()
        if not service_name:
            raise ValueError("service_name is required.")
        if data_classification not in _VALID_DATA_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid data_classification: {data_classification}. "
                f"Must be one of {sorted(_VALID_DATA_CLASSIFICATIONS)}"
            )
        now = _now_iso()
        approved_at = approved_at or now
        record_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO ai_services_registry
                       (id, org_id, service_name, provider, data_classification,
                        approved_by, approved_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record_id, org_id, service_name, provider,
                        data_classification, approved_by, approved_at, now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM ai_services_registry "
                    "WHERE org_id = ? AND service_name = ?",
                    (org_id, service_name),
                ).fetchone()
        return dict(row) if row else {}

    def list_ai_services(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ai_services_registry "
                "WHERE org_id = ? ORDER BY service_name ASC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def ai_attack_paths(
        self,
        org_id: str,
        service_name: str,
    ) -> Dict[str, Any]:
        """Return likely attack paths involving an AI service.

        Graph shape:  identity → service → data_store

        The method composes paths from: registered/unregistered identities
        (best-effort from identity_risk.db), the service row (if registered),
        and CMDB data stores (ci_type='database'/'storage').  For unregistered
        services we still return a path — marked ``unregistered=True`` so
        the caller can surface the gap.
        """
        if not org_id:
            raise ValueError("org_id is required.")
        service_name = (service_name or "").strip()
        if not service_name:
            raise ValueError("service_name is required.")

        # Registry lookup
        with self._conn() as conn:
            svc = conn.execute(
                "SELECT * FROM ai_services_registry "
                "WHERE org_id = ? AND service_name = ?",
                (org_id, service_name),
            ).fetchone()
        service_row = dict(svc) if svc else None
        unregistered = service_row is None

        # Pull a handful of human/service-account identities as likely callers
        identities: List[Dict[str, Any]] = []
        idr_path = Path(self._db_path).parent / "identity_risk.db"
        if idr_path.exists():
            try:
                conn = sqlite3.connect(str(idr_path), timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute(
                        "SELECT id, username, identity_type, risk_level "
                        "FROM ir_identities WHERE org_id = ? "
                        "AND identity_type IN ('human','service_account','privileged') "
                        "LIMIT 5",
                        (org_id,),
                    ).fetchall()
                    identities = [dict(r) for r in rows]
                finally:
                    conn.close()
            except sqlite3.Error:
                identities = []

        # Pull data stores from CMDB (if present)
        data_stores: List[Dict[str, Any]] = []
        cmdb_path = Path(self._db_path).parent / "cmdb.db"
        if cmdb_path.exists():
            try:
                conn = sqlite3.connect(str(cmdb_path), timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute(
                        "SELECT ci_id, name, ci_type, criticality "
                        "FROM ci_items WHERE org_id = ? "
                        "AND ci_type IN ('database','storage') "
                        "ORDER BY CASE criticality "
                        "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                        "  WHEN 'medium' THEN 2 ELSE 3 END "
                        "LIMIT 5",
                        (org_id,),
                    ).fetchall()
                    data_stores = [dict(r) for r in rows]
                finally:
                    conn.close()
            except sqlite3.Error:
                data_stores = []

        # Build attack paths. If either side is empty, emit a partial path
        # keyed to the service alone so the frontend can still render the gap.
        paths: List[Dict[str, Any]] = []
        if identities and data_stores:
            for ident in identities:
                for ds in data_stores:
                    paths.append({
                        "path": [
                            {"type": "identity", "ref": ident["id"],
                             "label": ident.get("username") or ident["id"],
                             "risk_level": ident.get("risk_level")},
                            {"type": "ai_service", "ref": service_name,
                             "label": service_name,
                             "registered": not unregistered},
                            {"type": "data_store", "ref": ds["ci_id"],
                             "label": ds.get("name") or ds["ci_id"],
                             "criticality": ds.get("criticality")},
                        ],
                        "techniques": [
                            "prompt_injection",
                            "data_exfiltration_via_tool_use",
                            "unauthorized_model_access" if unregistered
                            else "excessive_context_exposure",
                        ],
                        "severity": "critical" if unregistered else "high",
                    })
        else:
            paths.append({
                "path": [
                    {"type": "identity", "ref": None, "label": "(unknown)"},
                    {"type": "ai_service", "ref": service_name,
                     "label": service_name,
                     "registered": not unregistered},
                    {"type": "data_store", "ref": None, "label": "(unknown)"},
                ],
                "techniques": [
                    "prompt_injection",
                    "data_exfiltration_via_tool_use",
                ],
                "severity": "critical" if unregistered else "medium",
                "note": "partial_path: identities or data_stores missing",
            })

        return {
            "service_name": service_name,
            "registered": not unregistered,
            "service": service_row,
            "identity_count": len(identities),
            "data_store_count": len(data_stores),
            "path_count": len(paths),
            "paths": paths,
        }

    # ------------------------------------------------------------------
    # GAP-043: Formula change audit history
    # ------------------------------------------------------------------

    def register_formula_change(
        self,
        org_id: str,
        formula_version: str,
        change_summary: str,
        approver: str,
        approved_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist a scoring-formula change record for governance audit.

        UNIQUE(org_id, formula_version) — re-submitting the same version is a
        no-op that returns the stored row.
        """
        if not org_id:
            raise ValueError("org_id is required.")
        formula_version = (formula_version or "").strip()
        if not formula_version:
            raise ValueError("formula_version is required.")
        change_summary = change_summary or ""
        approver = approver or ""
        now = _now_iso()
        approved_at = (approved_at or now).strip() or now
        record_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO scoring_formula_history
                       (id, org_id, formula_version, change_summary,
                        approver, approved_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record_id, org_id, formula_version, change_summary,
                        approver, approved_at, now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM scoring_formula_history "
                    "WHERE org_id = ? AND formula_version = ?",
                    (org_id, formula_version),
                ).fetchone()

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit(
                        "CONTROL_ASSESSED",
                        {
                            "entity_type": "scoring_formula_change",
                            "org_id": org_id,
                            "formula_version": formula_version,
                            "source_engine": "ai_governance",
                        },
                    )
            except Exception:
                pass

        return dict(row) if row else {}

    def list_formula_history(self, org_id: str) -> List[Dict[str, Any]]:
        """Return scoring-formula history for an org, newest first."""
        if not org_id:
            raise ValueError("org_id is required.")
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scoring_formula_history "
                "WHERE org_id = ? ORDER BY approved_at DESC, created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]
