"""Risk Register Engine — Enterprise Risk Management for ALDECI.

Provides full risk lifecycle management: CRUD, scoring, appetite thresholds,
control mapping, treatment plans, KRI tracking, heat map data, and board-level
reporting.

Usage:
    from core.risk_register import RiskRegister, get_risk_register
    register = get_risk_register()
    risk = register.create_risk(risk_in)
    report = register.get_board_report(org_id="default")
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field, model_validator

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_RISK_REGISTER_DB", ".fixops_data/risk_register.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskCategory(str, Enum):
    OPERATIONAL = "operational"
    COMPLIANCE = "compliance"
    TECHNICAL = "technical"
    STRATEGIC = "strategic"
    REPUTATIONAL = "reputational"


class RiskStatus(str, Enum):
    OPEN = "open"
    IN_TREATMENT = "in_treatment"
    ACCEPTED = "accepted"
    CLOSED = "closed"
    TRANSFERRED = "transferred"


class TreatmentAction(str, Enum):
    ACCEPT = "accept"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
    AVOID = "avoid"


class KRIStatus(str, Enum):
    NORMAL = "normal"
    WARNING = "warning"
    BREACH = "breach"


# Likelihood / Impact use a 1-5 integer scale:
#   1=Very Low, 2=Low, 3=Medium, 4=High, 5=Critical
# Inherent risk score = likelihood × impact  (range 1-25)
# Residual risk score = inherent - sum(control_effectiveness)


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class RiskControl(BaseModel):
    """A control that mitigates one or more risks."""
    id: str = Field(default_factory=lambda: f"ctrl-{uuid.uuid4().hex[:12]}")
    name: str
    description: str = ""
    control_type: str = "preventive"  # preventive | detective | corrective
    effectiveness: float = Field(default=0.0, ge=0.0, le=5.0,
                                  description="Effectiveness score 0-5 (subtracted from inherent risk)")
    owner: str = ""
    implemented: bool = False
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    org_id: str = "default"


class RiskTreatmentPlan(BaseModel):
    """Treatment plan attached to a risk."""
    id: str = Field(default_factory=lambda: f"treat-{uuid.uuid4().hex[:12]}")
    risk_id: str
    action: TreatmentAction
    description: str
    owner: str = ""
    target_date: str = ""          # ISO date string
    completion_date: str = ""      # ISO date string — set when done
    status: str = "planned"        # planned | in_progress | completed | overdue
    notes: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class KRIRecord(BaseModel):
    """Key Risk Indicator with threshold alerting."""
    id: str = Field(default_factory=lambda: f"kri-{uuid.uuid4().hex[:12]}")
    risk_id: str
    name: str
    description: str = ""
    unit: str = ""                 # e.g. "count", "percentage", "days"
    current_value: float = 0.0
    warning_threshold: float       # triggers WARNING status
    breach_threshold: float        # triggers BREACH status
    direction: str = "higher_is_worse"  # higher_is_worse | lower_is_worse
    status: KRIStatus = KRIStatus.NORMAL
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    org_id: str = "default"

    @model_validator(mode="after")
    def _compute_status(self) -> "KRIRecord":
        self.status = _evaluate_kri_status(
            self.current_value,
            self.warning_threshold,
            self.breach_threshold,
            self.direction,
        )
        return self


class RiskAppetite(BaseModel):
    """Risk appetite and tolerance thresholds per category."""
    id: str = Field(default_factory=lambda: f"rapp-{uuid.uuid4().hex[:12]}")
    org_id: str = "default"
    category: RiskCategory
    appetite_score: float = Field(..., ge=0.0, le=25.0,
                                   description="Maximum acceptable residual risk score (0-25)")
    tolerance_score: float = Field(..., ge=0.0, le=25.0,
                                    description="Breach level — above this triggers escalation")
    description: str = ""
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_by: str = ""


class Risk(BaseModel):
    """Core risk entity."""
    id: str = Field(default_factory=lambda: f"risk-{uuid.uuid4().hex[:12]}")
    title: str
    description: str = ""
    category: RiskCategory
    owner: str = ""
    org_id: str = "default"

    # Scoring
    likelihood: int = Field(default=3, ge=1, le=5,
                            description="Likelihood of occurrence 1-5")
    impact: int = Field(default=3, ge=1, le=5,
                        description="Business impact if materialised 1-5")
    inherent_risk_score: float = 0.0   # computed: likelihood × impact
    control_ids: List[str] = Field(default_factory=list)
    residual_risk_score: float = 0.0   # inherent - sum(control effectiveness)

    # Status & treatment
    status: RiskStatus = RiskStatus.OPEN
    treatment_action: Optional[TreatmentAction] = None

    # Metadata
    tags: List[str] = Field(default_factory=list)
    related_finding_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    closed_at: str = ""

    # Trend — latest 10 residual scores stored as JSON list
    score_history: List[float] = Field(default_factory=list)

    @model_validator(mode="after")
    def _compute_inherent(self) -> "Risk":
        self.inherent_risk_score = float(self.likelihood * self.impact)
        if self.residual_risk_score == 0.0:
            self.residual_risk_score = self.inherent_risk_score
        return self


class HeatMapCell(BaseModel):
    """Aggregated count of risks at a likelihood/impact grid position."""
    likelihood: int
    impact: int
    risk_count: int
    risk_ids: List[str]
    score: int   # likelihood × impact


class BoardReport(BaseModel):
    """Board-level risk summary."""
    generated_at: str
    org_id: str
    total_risks: int
    open_risks: int
    risks_above_appetite: int
    risks_above_tolerance: int
    top_10_risks: List[Dict[str, Any]]
    category_summary: Dict[str, Any]
    appetite_vs_actual: Dict[str, Any]
    trend_summary: Dict[str, Any]
    kri_alerts: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _evaluate_kri_status(
    value: float,
    warning: float,
    breach: float,
    direction: str,
) -> KRIStatus:
    if direction == "higher_is_worse":
        if value >= breach:
            return KRIStatus.BREACH
        if value >= warning:
            return KRIStatus.WARNING
        return KRIStatus.NORMAL
    else:  # lower_is_worse
        if value <= breach:
            return KRIStatus.BREACH
        if value <= warning:
            return KRIStatus.WARNING
        return KRIStatus.NORMAL


def _score_label(score: float) -> str:
    if score >= 20:
        return "critical"
    if score >= 15:
        return "high"
    if score >= 8:
        return "medium"
    if score >= 4:
        return "low"
    return "very_low"


def _trend_direction(history: List[float]) -> str:
    """Return 'increasing', 'decreasing', or 'stable' from score history."""
    if len(history) < 2:
        return "stable"
    delta = history[-1] - history[0]
    if delta > 1.0:
        return "increasing"
    if delta < -1.0:
        return "decreasing"
    return "stable"


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------

class _RiskRegisterDB:
    """SQLite persistence for all risk register entities."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        dir_part = os.path.dirname(db_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS risks (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL,
                    owner TEXT NOT NULL DEFAULT '',
                    org_id TEXT NOT NULL,
                    likelihood INTEGER NOT NULL DEFAULT 3,
                    impact INTEGER NOT NULL DEFAULT 3,
                    inherent_risk_score REAL NOT NULL DEFAULT 0.0,
                    control_ids TEXT NOT NULL DEFAULT '[]',
                    residual_risk_score REAL NOT NULL DEFAULT 0.0,
                    status TEXT NOT NULL DEFAULT 'open',
                    treatment_action TEXT,
                    tags TEXT NOT NULL DEFAULT '[]',
                    related_finding_ids TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT NOT NULL DEFAULT '',
                    score_history TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_risk_org ON risks(org_id);
                CREATE INDEX IF NOT EXISTS idx_risk_category ON risks(category);
                CREATE INDEX IF NOT EXISTS idx_risk_status ON risks(status);
                CREATE INDEX IF NOT EXISTS idx_risk_score ON risks(residual_risk_score);

                CREATE TABLE IF NOT EXISTS risk_controls (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    control_type TEXT NOT NULL DEFAULT 'preventive',
                    effectiveness REAL NOT NULL DEFAULT 0.0,
                    owner TEXT NOT NULL DEFAULT '',
                    implemented INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ctrl_org ON risk_controls(org_id);

                CREATE TABLE IF NOT EXISTS risk_treatment_plans (
                    id TEXT PRIMARY KEY,
                    risk_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    description TEXT NOT NULL,
                    owner TEXT NOT NULL DEFAULT '',
                    target_date TEXT NOT NULL DEFAULT '',
                    completion_date TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'planned',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_treat_risk ON risk_treatment_plans(risk_id);

                CREATE TABLE IF NOT EXISTS kri_records (
                    id TEXT PRIMARY KEY,
                    risk_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    unit TEXT NOT NULL DEFAULT '',
                    current_value REAL NOT NULL DEFAULT 0.0,
                    warning_threshold REAL NOT NULL,
                    breach_threshold REAL NOT NULL,
                    direction TEXT NOT NULL DEFAULT 'higher_is_worse',
                    status TEXT NOT NULL DEFAULT 'normal',
                    last_updated TEXT NOT NULL,
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_kri_risk ON kri_records(risk_id);
                CREATE INDEX IF NOT EXISTS idx_kri_org ON kri_records(org_id);
                CREATE INDEX IF NOT EXISTS idx_kri_status ON kri_records(status);

                CREATE TABLE IF NOT EXISTS risk_appetites (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    appetite_score REAL NOT NULL,
                    tolerance_score REAL NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL DEFAULT '',
                    UNIQUE(org_id, category)
                );
                CREATE INDEX IF NOT EXISTS idx_rapp_org ON risk_appetites(org_id);
            """)
            self._conn.commit()

    # ---- Risk CRUD ----

    def upsert_risk(self, risk: Risk) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO risks
                   (id, title, description, category, owner, org_id,
                    likelihood, impact, inherent_risk_score, control_ids,
                    residual_risk_score, status, treatment_action, tags,
                    related_finding_ids, created_at, updated_at, closed_at, score_history)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    risk.id, risk.title, risk.description, risk.category.value,
                    risk.owner, risk.org_id,
                    risk.likelihood, risk.impact,
                    risk.inherent_risk_score,
                    json.dumps(risk.control_ids),
                    risk.residual_risk_score,
                    risk.status.value,
                    risk.treatment_action.value if risk.treatment_action else None,
                    json.dumps(risk.tags),
                    json.dumps(risk.related_finding_ids),
                    risk.created_at, risk.updated_at, risk.closed_at,
                    json.dumps(risk.score_history),
                ),
            )
            self._conn.commit()

    def get_risk(self, risk_id: str) -> Optional[Risk]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM risks WHERE id = ?", (risk_id,)
            ).fetchone()
        return self._row_to_risk(row) if row else None

    def list_risks(
        self,
        org_id: str,
        category: Optional[str] = None,
        status: Optional[str] = None,
        min_score: Optional[float] = None,
    ) -> List[Risk]:
        query = "SELECT * FROM risks WHERE org_id = ?"
        params: List[Any] = [org_id]
        if category:
            query += " AND category = ?"
            params.append(category)
        if status:
            query += " AND status = ?"
            params.append(status)
        if min_score is not None:
            query += " AND residual_risk_score >= ?"
            params.append(min_score)
        query += " ORDER BY residual_risk_score DESC"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_risk(r) for r in rows]

    def delete_risk(self, risk_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM risks WHERE id = ?", (risk_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def _row_to_risk(self, row: Tuple) -> Risk:
        cols = [
            "id", "title", "description", "category", "owner", "org_id",
            "likelihood", "impact", "inherent_risk_score", "control_ids",
            "residual_risk_score", "status", "treatment_action", "tags",
            "related_finding_ids", "created_at", "updated_at", "closed_at",
            "score_history",
        ]
        d = dict(zip(cols, row))
        d["control_ids"] = json.loads(d["control_ids"])
        d["tags"] = json.loads(d["tags"])
        d["related_finding_ids"] = json.loads(d["related_finding_ids"])
        d["score_history"] = json.loads(d["score_history"])
        return Risk.model_validate(d)

    # ---- Controls ----

    def upsert_control(self, ctrl: RiskControl) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO risk_controls
                   (id, name, description, control_type, effectiveness, owner,
                    implemented, created_at, org_id)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    ctrl.id, ctrl.name, ctrl.description, ctrl.control_type,
                    ctrl.effectiveness, ctrl.owner,
                    1 if ctrl.implemented else 0,
                    ctrl.created_at, ctrl.org_id,
                ),
            )
            self._conn.commit()

    def get_control(self, ctrl_id: str) -> Optional[RiskControl]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM risk_controls WHERE id = ?", (ctrl_id,)
            ).fetchone()
        return self._row_to_control(row) if row else None

    def list_controls(self, org_id: str) -> List[RiskControl]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM risk_controls WHERE org_id = ?", (org_id,)
            ).fetchall()
        return [self._row_to_control(r) for r in rows]

    def delete_control(self, ctrl_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM risk_controls WHERE id = ?", (ctrl_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def _row_to_control(self, row: Tuple) -> RiskControl:
        cols = ["id", "name", "description", "control_type", "effectiveness",
                "owner", "implemented", "created_at", "org_id"]
        d = dict(zip(cols, row))
        d["implemented"] = bool(d["implemented"])
        return RiskControl.model_validate(d)

    # ---- Treatment plans ----

    def upsert_treatment(self, plan: RiskTreatmentPlan) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO risk_treatment_plans
                   (id, risk_id, action, description, owner, target_date,
                    completion_date, status, notes, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    plan.id, plan.risk_id, plan.action.value,
                    plan.description, plan.owner, plan.target_date,
                    plan.completion_date, plan.status, plan.notes,
                    plan.created_at, plan.updated_at,
                ),
            )
            self._conn.commit()

    def get_treatment(self, plan_id: str) -> Optional[RiskTreatmentPlan]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM risk_treatment_plans WHERE id = ?", (plan_id,)
            ).fetchone()
        return self._row_to_treatment(row) if row else None

    def list_treatments(self, risk_id: str) -> List[RiskTreatmentPlan]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM risk_treatment_plans WHERE risk_id = ?", (risk_id,)
            ).fetchall()
        return [self._row_to_treatment(r) for r in rows]

    def _row_to_treatment(self, row: Tuple) -> RiskTreatmentPlan:
        cols = ["id", "risk_id", "action", "description", "owner", "target_date",
                "completion_date", "status", "notes", "created_at", "updated_at"]
        return RiskTreatmentPlan.model_validate(dict(zip(cols, row)))

    # ---- KRIs ----

    def upsert_kri(self, kri: KRIRecord) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO kri_records
                   (id, risk_id, name, description, unit, current_value,
                    warning_threshold, breach_threshold, direction, status,
                    last_updated, org_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    kri.id, kri.risk_id, kri.name, kri.description,
                    kri.unit, kri.current_value,
                    kri.warning_threshold, kri.breach_threshold,
                    kri.direction, kri.status.value,
                    kri.last_updated, kri.org_id,
                ),
            )
            self._conn.commit()

    def get_kri(self, kri_id: str) -> Optional[KRIRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM kri_records WHERE id = ?", (kri_id,)
            ).fetchone()
        return self._row_to_kri(row) if row else None

    def list_kris(
        self,
        org_id: str,
        risk_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[KRIRecord]:
        query = "SELECT * FROM kri_records WHERE org_id = ?"
        params: List[Any] = [org_id]
        if risk_id:
            query += " AND risk_id = ?"
            params.append(risk_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_kri(r) for r in rows]

    def _row_to_kri(self, row: Tuple) -> KRIRecord:
        cols = ["id", "risk_id", "name", "description", "unit", "current_value",
                "warning_threshold", "breach_threshold", "direction", "status",
                "last_updated", "org_id"]
        d = dict(zip(cols, row))
        # Skip model_validator re-computation — status already stored correctly
        return KRIRecord.model_validate(d)

    # ---- Risk Appetite ----

    def upsert_appetite(self, appetite: RiskAppetite) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO risk_appetites
                   (id, org_id, category, appetite_score, tolerance_score,
                    description, updated_at, updated_by)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    appetite.id, appetite.org_id, appetite.category.value,
                    appetite.appetite_score, appetite.tolerance_score,
                    appetite.description, appetite.updated_at, appetite.updated_by,
                ),
            )
            self._conn.commit()

    def get_appetite(self, org_id: str, category: str) -> Optional[RiskAppetite]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM risk_appetites WHERE org_id = ? AND category = ?",
                (org_id, category),
            ).fetchone()
        return self._row_to_appetite(row) if row else None

    def list_appetites(self, org_id: str) -> List[RiskAppetite]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM risk_appetites WHERE org_id = ?", (org_id,)
            ).fetchall()
        return [self._row_to_appetite(r) for r in rows]

    def _row_to_appetite(self, row: Tuple) -> RiskAppetite:
        cols = ["id", "org_id", "category", "appetite_score", "tolerance_score",
                "description", "updated_at", "updated_by"]
        return RiskAppetite.model_validate(dict(zip(cols, row)))


# ---------------------------------------------------------------------------
# RiskRegister — main business logic
# ---------------------------------------------------------------------------

class RiskRegister:
    """Enterprise Risk Register engine."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _RiskRegisterDB(db_path)
        logger.info("risk_register.init", db_path=db_path)

    # ---- Risk CRUD ----

    def create_risk(self, risk: Risk) -> Risk:
        risk.inherent_risk_score = float(risk.likelihood * risk.impact)
        risk.residual_risk_score = self._compute_residual(risk)
        risk.score_history = [risk.residual_risk_score]
        self._db.upsert_risk(risk)
        logger.info("risk.created", risk_id=risk.id, title=risk.title,
                    inherent=risk.inherent_risk_score)
        return risk

    def get_risk(self, risk_id: str) -> Optional[Risk]:
        return self._db.get_risk(risk_id)

    def update_risk(self, risk_id: str, updates: Dict[str, Any]) -> Optional[Risk]:
        risk = self._db.get_risk(risk_id)
        if not risk:
            return None
        for k, v in updates.items():
            if hasattr(risk, k) and v is not None:
                setattr(risk, k, v)
        risk.inherent_risk_score = float(risk.likelihood * risk.impact)
        risk.residual_risk_score = self._compute_residual(risk)
        # Maintain score history (keep latest 10)
        history = risk.score_history[-9:] + [risk.residual_risk_score]
        risk.score_history = history
        risk.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_risk(risk)
        logger.info("risk.updated", risk_id=risk_id)
        return risk

    def delete_risk(self, risk_id: str) -> bool:
        ok = self._db.delete_risk(risk_id)
        if ok:
            logger.info("risk.deleted", risk_id=risk_id)
        return ok

    def list_risks(
        self,
        org_id: str,
        category: Optional[str] = None,
        status: Optional[str] = None,
        min_score: Optional[float] = None,
    ) -> List[Risk]:
        return self._db.list_risks(org_id, category, status, min_score)

    # ---- Controls ----

    def create_control(self, ctrl: RiskControl) -> RiskControl:
        self._db.upsert_control(ctrl)
        logger.info("control.created", ctrl_id=ctrl.id, name=ctrl.name)
        return ctrl

    def get_control(self, ctrl_id: str) -> Optional[RiskControl]:
        return self._db.get_control(ctrl_id)

    def list_controls(self, org_id: str) -> List[RiskControl]:
        return self._db.list_controls(org_id)

    def delete_control(self, ctrl_id: str) -> bool:
        return self._db.delete_control(ctrl_id)

    def map_control_to_risk(self, risk_id: str, ctrl_id: str) -> Optional[Risk]:
        """Attach a control to a risk and recompute residual score."""
        risk = self._db.get_risk(risk_id)
        ctrl = self._db.get_control(ctrl_id)
        if not risk or not ctrl:
            return None
        if ctrl_id not in risk.control_ids:
            risk.control_ids.append(ctrl_id)
        risk.residual_risk_score = self._compute_residual(risk)
        history = risk.score_history[-9:] + [risk.residual_risk_score]
        risk.score_history = history
        risk.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_risk(risk)
        logger.info("control.mapped", risk_id=risk_id, ctrl_id=ctrl_id,
                    new_residual=risk.residual_risk_score)
        return risk

    def unmap_control_from_risk(self, risk_id: str, ctrl_id: str) -> Optional[Risk]:
        """Detach a control from a risk and recompute residual score."""
        risk = self._db.get_risk(risk_id)
        if not risk:
            return None
        risk.control_ids = [c for c in risk.control_ids if c != ctrl_id]
        risk.residual_risk_score = self._compute_residual(risk)
        history = risk.score_history[-9:] + [risk.residual_risk_score]
        risk.score_history = history
        risk.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_risk(risk)
        return risk

    def _compute_residual(self, risk: Risk) -> float:
        """inherent - sum(implemented control effectiveness), floor 0."""
        inherent = float(risk.likelihood * risk.impact)
        reduction = 0.0
        for ctrl_id in risk.control_ids:
            ctrl = self._db.get_control(ctrl_id)
            if ctrl and ctrl.implemented:
                reduction += ctrl.effectiveness
        return max(0.0, inherent - reduction)

    # ---- Treatment plans ----

    def create_treatment(self, plan: RiskTreatmentPlan) -> RiskTreatmentPlan:
        self._db.upsert_treatment(plan)
        # Update risk status to in_treatment if currently open
        risk = self._db.get_risk(plan.risk_id)
        if risk and risk.status == RiskStatus.OPEN:
            risk.status = RiskStatus.IN_TREATMENT
            risk.treatment_action = plan.action
            risk.updated_at = datetime.now(timezone.utc).isoformat()
            self._db.upsert_risk(risk)
        logger.info("treatment.created", plan_id=plan.id, risk_id=plan.risk_id,
                    action=plan.action)
        return plan

    def get_treatment(self, plan_id: str) -> Optional[RiskTreatmentPlan]:
        return self._db.get_treatment(plan_id)

    def list_treatments(self, risk_id: str) -> List[RiskTreatmentPlan]:
        return self._db.list_treatments(risk_id)

    def update_treatment_status(
        self, plan_id: str, status: str, completion_date: str = ""
    ) -> Optional[RiskTreatmentPlan]:
        plan = self._db.get_treatment(plan_id)
        if not plan:
            return None
        plan.status = status
        if completion_date:
            plan.completion_date = completion_date
        elif status == "completed":
            plan.completion_date = datetime.now(timezone.utc).isoformat()
        plan.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_treatment(plan)
        return plan

    # ---- KRIs ----

    def create_kri(self, kri: KRIRecord) -> KRIRecord:
        self._db.upsert_kri(kri)
        logger.info("kri.created", kri_id=kri.id, name=kri.name,
                    status=kri.status)
        return kri

    def update_kri_value(self, kri_id: str, new_value: float) -> Optional[KRIRecord]:
        kri = self._db.get_kri(kri_id)
        if not kri:
            return None
        old_status = kri.status
        kri.current_value = new_value
        kri.status = _evaluate_kri_status(
            new_value, kri.warning_threshold, kri.breach_threshold, kri.direction
        )
        kri.last_updated = datetime.now(timezone.utc).isoformat()
        self._db.upsert_kri(kri)
        if kri.status != old_status:
            logger.warning("kri.status_change", kri_id=kri_id,
                           old=old_status, new=kri.status, value=new_value)
        return kri

    def list_kris(
        self,
        org_id: str,
        risk_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[KRIRecord]:
        return self._db.list_kris(org_id, risk_id, status)

    # ---- Risk Appetite ----

    def set_appetite(self, appetite: RiskAppetite) -> RiskAppetite:
        self._db.upsert_appetite(appetite)
        logger.info("appetite.set", org_id=appetite.org_id,
                    category=appetite.category, appetite=appetite.appetite_score)
        return appetite

    def get_appetite(self, org_id: str, category: str) -> Optional[RiskAppetite]:
        return self._db.get_appetite(org_id, category)

    def list_appetites(self, org_id: str) -> List[RiskAppetite]:
        return self._db.list_appetites(org_id)

    # ---- Heat Map ----

    def get_heat_map(self, org_id: str) -> List[HeatMapCell]:
        """Return 5×5 likelihood/impact grid populated with risk counts."""
        risks = self._db.list_risks(org_id)
        grid: Dict[Tuple[int, int], List[str]] = {}
        for risk in risks:
            key = (risk.likelihood, risk.impact)
            grid.setdefault(key, []).append(risk.id)

        cells: List[HeatMapCell] = []
        for likelihood in range(1, 6):
            for impact in range(1, 6):
                key = (likelihood, impact)
                ids = grid.get(key, [])
                cells.append(HeatMapCell(
                    likelihood=likelihood,
                    impact=impact,
                    risk_count=len(ids),
                    risk_ids=ids,
                    score=likelihood * impact,
                ))
        return cells

    # ---- Board Report ----

    def get_board_report(self, org_id: str) -> BoardReport:
        """Generate a board-level risk summary (single-pass aggregation)."""
        risks = self._db.list_risks(org_id)
        appetites = {a.category.value: a for a in self._db.list_appetites(org_id)}
        kris = self._db.list_kris(org_id)

        # --- single pass over risks: collect all aggregates at once ---
        _OPEN_STATUSES = (RiskStatus.OPEN, RiskStatus.IN_TREATMENT)
        open_count = 0
        above_appetite_count = 0
        above_tolerance_count = 0
        trend_increasing = 0
        trend_decreasing = 0

        # per-category accumulators
        from collections import defaultdict
        cat_total: Dict[str, int] = defaultdict(int)
        cat_open: Dict[str, int] = defaultdict(int)
        cat_residual_sum: Dict[str, float] = defaultdict(float)
        cat_residual_max: Dict[str, float] = defaultdict(float)

        # top-10 heap (avoid full sort until end); idx as tiebreaker prevents Risk comparison
        import heapq
        heap: list = []  # (score, idx, risk) — min-heap of size 10

        for idx, r in enumerate(risks):
            cv = r.category.value
            rs = r.residual_risk_score
            is_open = r.status in _OPEN_STATUSES

            if is_open:
                open_count += 1

            ap = appetites.get(cv)
            if ap:
                if rs > ap.tolerance_score:
                    above_tolerance_count += 1
                elif rs > ap.appetite_score:
                    above_appetite_count += 1

            td = _trend_direction(r.score_history)
            if td == "increasing":
                trend_increasing += 1
            elif td == "decreasing":
                trend_decreasing += 1

            cat_total[cv] += 1
            if is_open:
                cat_open[cv] += 1
            cat_residual_sum[cv] += rs
            if rs > cat_residual_max[cv]:
                cat_residual_max[cv] = rs

            # maintain top-10 min-heap
            if len(heap) < 10:
                heapq.heappush(heap, (rs, idx, r))
            elif rs > heap[0][0]:
                heapq.heapreplace(heap, (rs, idx, r))

        top10 = [r for _, _i, r in sorted(heap, key=lambda x: x[0], reverse=True)]

        # Category summary (O(|categories|) = O(5))
        cat_summary: Dict[str, Any] = {}
        appetite_vs_actual: Dict[str, Any] = {}
        for cat in RiskCategory:
            cv = cat.value
            total = cat_total[cv]
            avg_res = cat_residual_sum[cv] / total if total else 0.0
            ap = appetites.get(cv)
            cat_summary[cv] = {
                "total": total,
                "open": cat_open[cv],
                "avg_residual": avg_res,
                "max_residual": cat_residual_max[cv],
            }
            appetite_vs_actual[cv] = {
                "appetite_score": ap.appetite_score if ap else None,
                "tolerance_score": ap.tolerance_score if ap else None,
                "actual_avg": round(avg_res, 2),
                "within_appetite": ap is None or avg_res <= ap.appetite_score,
            }

        trend_summary = {
            "increasing": trend_increasing,
            "decreasing": trend_decreasing,
            "stable": len(risks) - trend_increasing - trend_decreasing,
        }

        # KRI alerts
        kri_alerts = [
            {
                "kri_id": k.id,
                "name": k.name,
                "risk_id": k.risk_id,
                "status": k.status.value,
                "current_value": k.current_value,
                "warning_threshold": k.warning_threshold,
                "breach_threshold": k.breach_threshold,
            }
            for k in kris
            if k.status in (KRIStatus.WARNING, KRIStatus.BREACH)
        ]

        return BoardReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            org_id=org_id,
            total_risks=len(risks),
            open_risks=open_count,
            risks_above_appetite=above_appetite_count,
            risks_above_tolerance=above_tolerance_count,
            top_10_risks=[
                {
                    "id": r.id,
                    "title": r.title,
                    "category": r.category.value,
                    "inherent_risk_score": r.inherent_risk_score,
                    "residual_risk_score": r.residual_risk_score,
                    "score_label": _score_label(r.residual_risk_score),
                    "status": r.status.value,
                    "trend": _trend_direction(r.score_history),
                    "owner": r.owner,
                }
                for r in top10
            ],
            category_summary=cat_summary,
            appetite_vs_actual=appetite_vs_actual,
            trend_summary=trend_summary,
            kri_alerts=kri_alerts,
        )


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_instance: Optional[RiskRegister] = None
_instance_lock = threading.Lock()


def get_risk_register(db_path: str = _DEFAULT_DB) -> RiskRegister:
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = RiskRegister(db_path=db_path)
    return _instance
