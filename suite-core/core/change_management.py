"""
Change Management / Change Advisory Board (CAB) Engine — ALDECI.

Provides a full ITIL-aligned change management lifecycle:
- Change request lifecycle: draft → submitted → reviewing → approved/rejected →
  implementing → completed/rolled_back
- Risk classification: Standard, Normal, Emergency
- CAB workflow: required approvers, approval/rejection, conditional approval,
  SLA auto-expiry
- Impact analysis integration: blast radius, affected services/compliance
- Rollback planning with validation criteria
- Change calendar: conflict detection, freeze periods, maintenance windows
- Metrics: success rate, review time, rollback frequency, emergency rate

Compliance: ITIL v4, SOC2 CC8.1 (Change Management)
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field, field_validator, model_validator

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus:
            bus.emit(event_type, payload)
    except Exception:
        pass

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ChangeStatus(str, Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    REVIEWING = "reviewing"
    APPROVED = "approved"
    REJECTED = "rejected"
    IMPLEMENTING = "implementing"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    EXPIRED = "expired"


class ChangeRiskLevel(str, Enum):
    """ITIL risk classification."""
    STANDARD = "standard"    # pre-approved, low risk, no CAB required
    NORMAL = "normal"        # CAB review required
    EMERGENCY = "emergency"  # expedited, post-implementation review


class ChangeCategory(str, Enum):
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    SECURITY = "security"
    DATABASE = "database"
    NETWORK = "network"
    CODE_DEPLOYMENT = "code_deployment"
    CONFIGURATION = "configuration"
    ACCESS = "access"


class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    CONDITIONAL = "conditional"


class ConflictType(str, Enum):
    WINDOW_OVERLAP = "window_overlap"
    FREEZE_PERIOD = "freeze_period"
    SAME_SERVICE = "same_service"
    RESOURCE_CONTENTION = "resource_contention"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class RollbackPlan(BaseModel):
    """Rollback plan for a change request."""
    steps: List[str] = Field(..., min_length=1, description="Ordered rollback steps")
    validation_criteria: List[str] = Field(
        default_factory=list,
        description="Criteria to confirm rollback success",
    )
    max_rollback_time_minutes: int = Field(
        default=60,
        ge=1,
        description="Maximum time allowed for rollback in minutes",
    )
    responsible_person: str = Field(..., description="Person responsible for executing rollback")
    automated: bool = Field(default=False, description="Whether rollback can be automated")
    rollback_script: Optional[str] = Field(default=None, description="Script to execute for automated rollback")


class ImpactAnalysis(BaseModel):
    """Impact analysis for a change."""
    affected_services: List[str] = Field(default_factory=list)
    affected_data_stores: List[str] = Field(default_factory=list)
    affected_compliance_frameworks: List[str] = Field(default_factory=list)
    blast_radius_score: float = Field(
        default=0.0, ge=0.0, le=10.0,
        description="0-10 score: how widely this change propagates",
    )
    security_impact: bool = Field(default=False, description="Change has security implications")
    data_migration_required: bool = Field(default=False, description="Change requires data migration")
    production_impact: bool = Field(default=True, description="Change affects production environment")
    estimated_downtime_minutes: int = Field(default=0, ge=0)
    user_impact_count: int = Field(default=0, ge=0, description="Estimated number of affected users")
    dependency_changes: List[str] = Field(default_factory=list, description="Linked code or service dependencies")
    risk_score: float = Field(
        default=0.0, ge=0.0, le=100.0,
        description="Computed composite risk score 0-100",
    )


class CABApproval(BaseModel):
    """A single CAB member approval/rejection record."""
    approver_id: str
    approver_name: str
    approver_role: str
    decision: ApprovalDecision
    comments: Optional[str] = None
    conditions: List[str] = Field(default_factory=list, description="Conditions for conditional approval")
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditEntry(BaseModel):
    """Immutable audit trail entry."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    change_id: str
    action: str
    actor_id: str
    actor_name: str
    from_status: Optional[ChangeStatus] = None
    to_status: Optional[ChangeStatus] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MaintenanceWindow(BaseModel):
    """Scheduled maintenance window."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    start_time: datetime
    end_time: datetime
    description: Optional[str] = None
    allowed_risk_levels: List[ChangeRiskLevel] = Field(
        default_factory=lambda: [ChangeRiskLevel.STANDARD, ChangeRiskLevel.NORMAL],
    )
    recurring: bool = False
    recurrence_days: Optional[int] = Field(default=None, description="Recur every N days")

    @model_validator(mode="after")
    def validate_window(self) -> "MaintenanceWindow":
        if self.end_time <= self.start_time:
            raise ValueError("end_time must be after start_time")
        return self


class FreezePeriod(BaseModel):
    """Change freeze period — no changes allowed."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    start_time: datetime
    end_time: datetime
    reason: str
    exception_allowed: bool = Field(default=False, description="Emergency changes allowed during freeze")

    @model_validator(mode="after")
    def validate_period(self) -> "FreezePeriod":
        if self.end_time <= self.start_time:
            raise ValueError("end_time must be after start_time")
        return self


class ChangeRequest(BaseModel):
    """Full change request record."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=10)
    category: ChangeCategory
    risk_level: ChangeRiskLevel = ChangeRiskLevel.NORMAL
    status: ChangeStatus = ChangeStatus.DRAFT
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")

    # Requestor
    requestor_id: str
    requestor_name: str
    requestor_team: Optional[str] = None

    # Scheduling
    scheduled_start: Optional[datetime] = None
    scheduled_end: Optional[datetime] = None
    maintenance_window_id: Optional[str] = None

    # Impact
    impact_analysis: Optional[ImpactAnalysis] = None
    rollback_plan: Optional[RollbackPlan] = None

    # CAB approvals
    required_approvers: List[str] = Field(default_factory=list, description="Role names required to approve")
    approvals: List[CABApproval] = Field(default_factory=list)
    cab_meeting_id: Optional[str] = None

    # Execution tracking
    implementation_notes: Optional[str] = None
    implementation_started_at: Optional[datetime] = None
    implementation_completed_at: Optional[datetime] = None
    rollback_executed: bool = False
    rollback_reason: Optional[str] = None
    rollback_executed_at: Optional[datetime] = None
    post_implementation_review: Optional[str] = None

    # SLA
    sla_review_deadline: Optional[datetime] = None  # auto-set on submit
    sla_implementation_deadline: Optional[datetime] = None

    # Metadata
    tags: List[str] = Field(default_factory=list)
    external_ticket_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"

    @field_validator("scheduled_end")
    @classmethod
    def validate_scheduled_end(cls, v: Optional[datetime], info: Any) -> Optional[datetime]:
        # Cannot access other fields easily in v2 field_validator; check in model_validator
        return v

    @model_validator(mode="after")
    def validate_schedule(self) -> "ChangeRequest":
        if self.scheduled_start and self.scheduled_end:
            if self.scheduled_end <= self.scheduled_start:
                raise ValueError("scheduled_end must be after scheduled_start")
        return self


class ChangeMetrics(BaseModel):
    """Aggregated change management metrics."""
    total_changes: int = 0
    by_status: Dict[str, int] = Field(default_factory=dict)
    by_risk_level: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    success_rate: float = 0.0
    rollback_rate: float = 0.0
    emergency_rate: float = 0.0
    avg_review_time_hours: float = 0.0
    avg_implementation_time_hours: float = 0.0
    change_related_incidents: int = 0
    sla_breach_count: int = 0
    period_days: int = 30


class ConflictResult(BaseModel):
    """Result of a conflict detection check."""
    has_conflict: bool
    conflicts: List[Dict[str, Any]] = Field(default_factory=list)
    change_id: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Risk Scoring Logic
# ---------------------------------------------------------------------------

# SLA hours by risk level
_SLA_REVIEW_HOURS: Dict[ChangeRiskLevel, int] = {
    ChangeRiskLevel.STANDARD: 0,    # No review needed
    ChangeRiskLevel.NORMAL: 72,     # 3 days
    ChangeRiskLevel.EMERGENCY: 4,   # 4 hours
}

_SLA_IMPLEMENTATION_HOURS: Dict[ChangeRiskLevel, int] = {
    ChangeRiskLevel.STANDARD: 168,   # 1 week
    ChangeRiskLevel.NORMAL: 720,     # 30 days
    ChangeRiskLevel.EMERGENCY: 24,   # 24 hours
}

# Required approver roles by risk level
_REQUIRED_APPROVERS: Dict[ChangeRiskLevel, List[str]] = {
    ChangeRiskLevel.STANDARD: [],                               # Pre-approved
    ChangeRiskLevel.NORMAL: ["change_manager", "tech_lead"],    # CAB
    ChangeRiskLevel.EMERGENCY: ["change_manager"],              # Expedited
}


def compute_risk_score(impact: ImpactAnalysis) -> float:
    """Compute composite risk score 0-100 from impact analysis factors."""
    score = 0.0
    # Blast radius (0-40 pts)
    score += impact.blast_radius_score * 4.0
    # Security impact (+20)
    if impact.security_impact:
        score += 20.0
    # Data migration (+15)
    if impact.data_migration_required:
        score += 15.0
    # Production impact (+10)
    if impact.production_impact:
        score += 10.0
    # Downtime (+10 if > 30 min)
    if impact.estimated_downtime_minutes > 30:
        score += min(10.0, impact.estimated_downtime_minutes / 60.0)
    # Large user impact (+5 if > 1000)
    if impact.user_impact_count > 1000:
        score += 5.0
    return round(min(score, 100.0), 2)


def classify_risk_level(impact: ImpactAnalysis) -> ChangeRiskLevel:
    """Auto-classify risk level from impact analysis."""
    score = compute_risk_score(impact)
    if score >= 60 or impact.security_impact and impact.production_impact:
        return ChangeRiskLevel.NORMAL
    if score < 20 and not impact.data_migration_required and not impact.security_impact:
        return ChangeRiskLevel.STANDARD
    return ChangeRiskLevel.NORMAL


# ---------------------------------------------------------------------------
# Database Layer
# ---------------------------------------------------------------------------


class ChangeManagementDB:
    """SQLite-backed persistence for change management records."""

    def __init__(self, db_path: str = "data/change_management.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._init_tables()
        _logger.info("change_management_db_initialized", db_path=str(self.db_path))

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_tables(self) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS change_requests (
                        id TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        status TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        category TEXT NOT NULL,
                        requestor_id TEXT NOT NULL,
                        scheduled_start TEXT,
                        scheduled_end TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_trail (
                        id TEXT PRIMARY KEY,
                        change_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        data TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (change_id) REFERENCES change_requests(id)
                    );

                    CREATE TABLE IF NOT EXISTS maintenance_windows (
                        id TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        start_time TEXT NOT NULL,
                        end_time TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS freeze_periods (
                        id TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        start_time TEXT NOT NULL,
                        end_time TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_cr_status ON change_requests(status);
                    CREATE INDEX IF NOT EXISTS idx_cr_risk ON change_requests(risk_level);
                    CREATE INDEX IF NOT EXISTS idx_cr_requestor ON change_requests(requestor_id);
                    CREATE INDEX IF NOT EXISTS idx_cr_scheduled ON change_requests(scheduled_start);
                    CREATE INDEX IF NOT EXISTS idx_audit_change ON audit_trail(change_id);
                    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_trail(timestamp);
                """)
                conn.commit()
            finally:
                conn.close()

    # --- Change Requests ---

    def create_change(self, change: ChangeRequest) -> ChangeRequest:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO change_requests
                       (id, data, status, risk_level, category, requestor_id,
                        scheduled_start, scheduled_end, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        change.id,
                        change.model_dump_json(),
                        change.status.value,
                        change.risk_level.value,
                        change.category.value,
                        change.requestor_id,
                        change.scheduled_start.isoformat() if change.scheduled_start else None,
                        change.scheduled_end.isoformat() if change.scheduled_end else None,
                        change.created_at.isoformat(),
                        change.updated_at.isoformat(),
                    ),
                )
                conn.commit()
                _tg_emit("change_management.change_created", {
                    "change_id": change.id,
                    "status": change.status.value,
                    "risk_level": change.risk_level.value,
                    "category": change.category.value,
                    "requestor_id": change.requestor_id,
                })
                return change
            finally:
                conn.close()

    def get_change(self, change_id: str) -> Optional[ChangeRequest]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT data FROM change_requests WHERE id = ?", (change_id,)
            ).fetchone()
            if row:
                return ChangeRequest.model_validate_json(row["data"])
            return None
        finally:
            conn.close()

    def update_change(self, change: ChangeRequest) -> ChangeRequest:
        change.updated_at = datetime.now(timezone.utc)
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """UPDATE change_requests
                       SET data=?, status=?, risk_level=?, scheduled_start=?,
                           scheduled_end=?, updated_at=?
                       WHERE id=?""",
                    (
                        change.model_dump_json(),
                        change.status.value,
                        change.risk_level.value,
                        change.scheduled_start.isoformat() if change.scheduled_start else None,
                        change.scheduled_end.isoformat() if change.scheduled_end else None,
                        change.updated_at.isoformat(),
                        change.id,
                    ),
                )
                conn.commit()
                return change
            finally:
                conn.close()

    def list_changes(
        self,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        requestor_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ChangeRequest]:
        conn = self._get_conn()
        try:
            clauses: List[str] = []
            params: List[Any] = []
            if status:
                clauses.append("status = ?")
                params.append(status)
            if risk_level:
                clauses.append("risk_level = ?")
                params.append(risk_level)
            if requestor_id:
                clauses.append("requestor_id = ?")
                params.append(requestor_id)
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            params.extend([limit, offset])
            rows = conn.execute(
                f"SELECT data FROM change_requests {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",  # nosec B608
                params,
            ).fetchall()
            return [ChangeRequest.model_validate_json(r["data"]) for r in rows]
        finally:
            conn.close()

    def count_changes(
        self,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> int:
        conn = self._get_conn()
        try:
            clauses: List[str] = []
            params: List[Any] = []
            if status:
                clauses.append("status = ?")
                params.append(status)
            if risk_level:
                clauses.append("risk_level = ?")
                params.append(risk_level)
            if since:
                clauses.append("created_at >= ?")
                params.append(since.isoformat())
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            row = conn.execute(
                f"SELECT COUNT(*) as c FROM change_requests {where}", params  # nosec B608
            ).fetchone()
            return row["c"] if row else 0
        finally:
            conn.close()

    # --- Audit Trail ---

    def append_audit(self, entry: AuditEntry) -> AuditEntry:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO audit_trail (id, change_id, action, actor_id, data, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        entry.id,
                        entry.change_id,
                        entry.action,
                        entry.actor_id,
                        entry.model_dump_json(),
                        entry.timestamp.isoformat(),
                    ),
                )
                conn.commit()
                return entry
            finally:
                conn.close()

    def get_audit_trail(self, change_id: str) -> List[AuditEntry]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT data FROM audit_trail WHERE change_id = ? ORDER BY timestamp ASC",
                (change_id,),
            ).fetchall()
            return [AuditEntry.model_validate_json(r["data"]) for r in rows]
        finally:
            conn.close()

    # --- Maintenance Windows ---

    def create_maintenance_window(self, window: MaintenanceWindow) -> MaintenanceWindow:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO maintenance_windows (id, data, start_time, end_time) VALUES (?, ?, ?, ?)",
                    (window.id, window.model_dump_json(), window.start_time.isoformat(), window.end_time.isoformat()),
                )
                conn.commit()
                return window
            finally:
                conn.close()

    def list_maintenance_windows(self) -> List[MaintenanceWindow]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT data FROM maintenance_windows ORDER BY start_time ASC"
            ).fetchall()
            return [MaintenanceWindow.model_validate_json(r["data"]) for r in rows]
        finally:
            conn.close()

    def get_maintenance_window(self, window_id: str) -> Optional[MaintenanceWindow]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT data FROM maintenance_windows WHERE id = ?", (window_id,)
            ).fetchone()
            return MaintenanceWindow.model_validate_json(row["data"]) if row else None
        finally:
            conn.close()

    # --- Freeze Periods ---

    def create_freeze_period(self, period: FreezePeriod) -> FreezePeriod:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO freeze_periods (id, data, start_time, end_time) VALUES (?, ?, ?, ?)",
                    (period.id, period.model_dump_json(), period.start_time.isoformat(), period.end_time.isoformat()),
                )
                conn.commit()
                return period
            finally:
                conn.close()

    def list_freeze_periods(self) -> List[FreezePeriod]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT data FROM freeze_periods ORDER BY start_time ASC"
            ).fetchall()
            return [FreezePeriod.model_validate_json(r["data"]) for r in rows]
        finally:
            conn.close()

    def list_changes_in_window(
        self, start: datetime, end: datetime
    ) -> List[ChangeRequest]:
        """Return changes scheduled to overlap with [start, end]."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT data FROM change_requests
                   WHERE scheduled_start IS NOT NULL
                     AND scheduled_end IS NOT NULL
                     AND scheduled_start < ?
                     AND scheduled_end > ?
                   ORDER BY scheduled_start ASC""",
                (end.isoformat(), start.isoformat()),
            ).fetchall()
            return [ChangeRequest.model_validate_json(r["data"]) for r in rows]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# CAB Engine
# ---------------------------------------------------------------------------


class ChangeAdvisoryBoard:
    """
    Change Advisory Board engine.

    Manages the full lifecycle of change requests from draft through
    completion, including risk assessment, CAB approval workflow,
    rollback planning, calendar management, and metrics.
    """

    def __init__(self, db: Optional[ChangeManagementDB] = None):
        self._db = db or ChangeManagementDB()
        _logger.info("cab_engine_initialized")

    # --- Lifecycle transitions ---

    def create_change_request(
        self,
        title: str,
        description: str,
        category: ChangeCategory,
        requestor_id: str,
        requestor_name: str,
        rollback_plan: RollbackPlan,
        impact_analysis: Optional[ImpactAnalysis] = None,
        scheduled_start: Optional[datetime] = None,
        scheduled_end: Optional[datetime] = None,
        priority: str = "medium",
        requestor_team: Optional[str] = None,
        tags: Optional[List[str]] = None,
        external_ticket_id: Optional[str] = None,
    ) -> ChangeRequest:
        """Create a new change request in DRAFT state."""
        # Auto-compute risk if impact provided
        risk_level = ChangeRiskLevel.NORMAL
        if impact_analysis:
            impact_analysis.risk_score = compute_risk_score(impact_analysis)
            risk_level = classify_risk_level(impact_analysis)

        change = ChangeRequest(
            title=title,
            description=description,
            category=category,
            risk_level=risk_level,
            requestor_id=requestor_id,
            requestor_name=requestor_name,
            requestor_team=requestor_team,
            impact_analysis=impact_analysis,
            rollback_plan=rollback_plan,
            scheduled_start=scheduled_start,
            scheduled_end=scheduled_end,
            priority=priority,
            required_approvers=list(_REQUIRED_APPROVERS[risk_level]),
            tags=tags or [],
            external_ticket_id=external_ticket_id,
            created_by=requestor_id,
        )
        self._db.create_change(change)
        self._audit(change.id, "created", requestor_id, requestor_name, None, ChangeStatus.DRAFT)
        _logger.info("change_request_created", change_id=change.id, risk=risk_level.value)
        return change

    def submit_change(
        self, change_id: str, actor_id: str, actor_name: str
    ) -> ChangeRequest:
        """Submit a DRAFT change for review."""
        change = self._require_change(change_id)
        self._require_status(change, ChangeStatus.DRAFT, ChangeStatus.SUBMITTED)

        now = datetime.now(timezone.utc)
        prev_status = change.status
        change.status = ChangeStatus.SUBMITTED

        # Auto-approve Standard changes, put Normal/Emergency into reviewing
        if change.risk_level == ChangeRiskLevel.STANDARD:
            change.status = ChangeStatus.APPROVED
            change.sla_implementation_deadline = now + timedelta(
                hours=_SLA_IMPLEMENTATION_HOURS[change.risk_level]
            )
        else:
            change.status = ChangeStatus.REVIEWING
            change.sla_review_deadline = now + timedelta(
                hours=_SLA_REVIEW_HOURS[change.risk_level]
            )
            change.sla_implementation_deadline = now + timedelta(
                hours=_SLA_IMPLEMENTATION_HOURS[change.risk_level]
            )

        self._db.update_change(change)
        self._audit(change.id, "submitted", actor_id, actor_name, prev_status, change.status)
        _logger.info("change_submitted", change_id=change_id, new_status=change.status.value)
        return change

    def add_approval(
        self,
        change_id: str,
        approval: CABApproval,
    ) -> Tuple[ChangeRequest, bool]:
        """Add a CAB approval/rejection. Returns (change, is_fully_resolved)."""
        change = self._require_change(change_id)
        if change.status not in (ChangeStatus.REVIEWING, ChangeStatus.SUBMITTED):
            raise ValueError(
                f"Change {change_id} is in status {change.status.value}, cannot add approval"
            )

        # Replace if same approver already voted
        change.approvals = [a for a in change.approvals if a.approver_id != approval.approver_id]
        change.approvals.append(approval)

        resolved = False
        prev_status = change.status

        if approval.decision == ApprovalDecision.REJECTED:
            change.status = ChangeStatus.REJECTED
            resolved = True
        else:
            # Check if all required approvers have approved/conditionally approved
            approved_roles = {a.approver_role for a in change.approvals
                              if a.decision in (ApprovalDecision.APPROVED, ApprovalDecision.CONDITIONAL)}
            required = set(change.required_approvers)
            if required.issubset(approved_roles) or not required:
                change.status = ChangeStatus.APPROVED
                resolved = True

        self._db.update_change(change)
        self._audit(
            change.id, f"approval_{approval.decision.value}",
            approval.approver_id, approval.approver_name,
            prev_status, change.status,
            {"comments": approval.comments, "conditions": approval.conditions},
        )
        _logger.info(
            "cab_approval_added",
            change_id=change_id,
            decision=approval.decision.value,
            resolved=resolved,
        )
        return change, resolved

    def start_implementation(
        self, change_id: str, actor_id: str, actor_name: str
    ) -> ChangeRequest:
        """Transition APPROVED change to IMPLEMENTING."""
        change = self._require_change(change_id)
        self._require_status(change, ChangeStatus.APPROVED, ChangeStatus.IMPLEMENTING)

        prev_status = change.status
        change.status = ChangeStatus.IMPLEMENTING
        change.implementation_started_at = datetime.now(timezone.utc)
        self._db.update_change(change)
        self._audit(change.id, "implementation_started", actor_id, actor_name, prev_status, change.status)
        _logger.info("change_implementation_started", change_id=change_id)
        return change

    def complete_change(
        self,
        change_id: str,
        actor_id: str,
        actor_name: str,
        implementation_notes: Optional[str] = None,
        post_implementation_review: Optional[str] = None,
    ) -> ChangeRequest:
        """Mark an IMPLEMENTING change as COMPLETED."""
        change = self._require_change(change_id)
        self._require_status(change, ChangeStatus.IMPLEMENTING, ChangeStatus.COMPLETED)

        prev_status = change.status
        change.status = ChangeStatus.COMPLETED
        change.implementation_completed_at = datetime.now(timezone.utc)
        if implementation_notes:
            change.implementation_notes = implementation_notes
        if post_implementation_review:
            change.post_implementation_review = post_implementation_review

        self._db.update_change(change)
        self._audit(
            change.id, "completed", actor_id, actor_name, prev_status, change.status,
            {"notes": implementation_notes},
        )
        _logger.info("change_completed", change_id=change_id)
        return change

    def rollback_change(
        self,
        change_id: str,
        actor_id: str,
        actor_name: str,
        reason: str,
    ) -> ChangeRequest:
        """Execute rollback for an IMPLEMENTING or COMPLETED change."""
        change = self._require_change(change_id)
        if change.status not in (ChangeStatus.IMPLEMENTING, ChangeStatus.COMPLETED):
            raise ValueError(
                f"Cannot rollback change in status {change.status.value}"
            )

        prev_status = change.status
        change.status = ChangeStatus.ROLLED_BACK
        change.rollback_executed = True
        change.rollback_reason = reason
        change.rollback_executed_at = datetime.now(timezone.utc)
        self._db.update_change(change)
        self._audit(
            change.id, "rolled_back", actor_id, actor_name, prev_status, change.status,
            {"reason": reason},
        )
        _logger.warning("change_rolled_back", change_id=change_id, reason=reason)
        return change

    def reject_change(
        self,
        change_id: str,
        actor_id: str,
        actor_name: str,
        reason: str,
    ) -> ChangeRequest:
        """Directly reject a change (by change manager)."""
        change = self._require_change(change_id)
        if change.status not in (ChangeStatus.REVIEWING, ChangeStatus.SUBMITTED, ChangeStatus.DRAFT):
            raise ValueError(f"Cannot reject change in status {change.status.value}")

        prev_status = change.status
        change.status = ChangeStatus.REJECTED
        self._db.update_change(change)
        self._audit(
            change.id, "rejected", actor_id, actor_name, prev_status, change.status,
            {"reason": reason},
        )
        _logger.info("change_rejected", change_id=change_id, reason=reason)
        return change

    def expire_stale_changes(self) -> List[str]:
        """Expire changes that have breached their SLA review deadline."""
        now = datetime.now(timezone.utc)
        changes = self._db.list_changes(status=ChangeStatus.REVIEWING.value, limit=500)
        expired_ids: List[str] = []
        for change in changes:
            if change.sla_review_deadline and change.sla_review_deadline < now:
                prev_status = change.status
                change.status = ChangeStatus.EXPIRED
                self._db.update_change(change)
                self._audit(
                    change.id, "expired", "system", "System",
                    prev_status, ChangeStatus.EXPIRED,
                    {"sla_deadline": change.sla_review_deadline.isoformat()},
                )
                expired_ids.append(change.id)
        if expired_ids:
            _logger.warning("changes_expired", count=len(expired_ids), ids=expired_ids)
        return expired_ids

    # --- Risk assessment ---

    def assess_impact(
        self,
        change_id: str,
        impact: ImpactAnalysis,
        actor_id: str,
        actor_name: str,
    ) -> ChangeRequest:
        """Attach or update impact analysis on a change request."""
        change = self._require_change(change_id)
        impact.risk_score = compute_risk_score(impact)
        change.impact_analysis = impact
        # Re-classify risk level if still in draft/submitted
        if change.status in (ChangeStatus.DRAFT, ChangeStatus.SUBMITTED, ChangeStatus.REVIEWING):
            new_risk = classify_risk_level(impact)
            if new_risk != change.risk_level:
                change.risk_level = new_risk
                change.required_approvers = list(_REQUIRED_APPROVERS[new_risk])
        self._db.update_change(change)
        self._audit(
            change.id, "impact_assessed", actor_id, actor_name, change.status, change.status,
            {"risk_score": impact.risk_score, "risk_level": change.risk_level.value},
        )
        return change

    def override_risk_level(
        self,
        change_id: str,
        new_risk: ChangeRiskLevel,
        actor_id: str,
        actor_name: str,
        justification: str,
    ) -> ChangeRequest:
        """Manually override risk classification with justification."""
        change = self._require_change(change_id)
        old_risk = change.risk_level
        change.risk_level = new_risk
        change.required_approvers = list(_REQUIRED_APPROVERS[new_risk])
        self._db.update_change(change)
        self._audit(
            change.id, "risk_overridden", actor_id, actor_name, change.status, change.status,
            {"old_risk": old_risk.value, "new_risk": new_risk.value, "justification": justification},
        )
        _logger.info("risk_overridden", change_id=change_id, old=old_risk.value, new=new_risk.value)
        return change

    # --- Calendar & conflict detection ---

    def check_conflicts(self, change: ChangeRequest) -> ConflictResult:
        """Check a change for scheduling conflicts and freeze periods."""
        conflicts: List[Dict[str, Any]] = []

        if not change.scheduled_start or not change.scheduled_end:
            return ConflictResult(has_conflict=False, change_id=change.id)

        start = change.scheduled_start
        end = change.scheduled_end

        # Check freeze periods
        for period in self._db.list_freeze_periods():
            if not (end <= period.start_time or start >= period.end_time):
                if not (period.exception_allowed and change.risk_level == ChangeRiskLevel.EMERGENCY):
                    conflicts.append({
                        "type": ConflictType.FREEZE_PERIOD.value,
                        "name": period.name,
                        "reason": period.reason,
                        "freeze_start": period.start_time.isoformat(),
                        "freeze_end": period.end_time.isoformat(),
                    })

        # Check overlapping scheduled changes
        overlapping = self._db.list_changes_in_window(start, end)
        for other in overlapping:
            if other.id == change.id:
                continue
            # Flag if same affected services overlap
            same_services: List[str] = []
            if change.impact_analysis and other.impact_analysis:
                mine = set(change.impact_analysis.affected_services)
                theirs = set(other.impact_analysis.affected_services)
                same_services = list(mine & theirs)

            if same_services or other.risk_level in (ChangeRiskLevel.NORMAL, ChangeRiskLevel.EMERGENCY):
                conflicts.append({
                    "type": ConflictType.SAME_SERVICE.value if same_services else ConflictType.WINDOW_OVERLAP.value,
                    "conflicting_change_id": other.id,
                    "conflicting_change_title": other.title,
                    "conflicting_start": other.scheduled_start.isoformat() if other.scheduled_start else None,
                    "conflicting_end": other.scheduled_end.isoformat() if other.scheduled_end else None,
                    "shared_services": same_services,
                })

        return ConflictResult(
            has_conflict=bool(conflicts),
            conflicts=conflicts,
            change_id=change.id,
        )

    def create_maintenance_window(self, window: MaintenanceWindow) -> MaintenanceWindow:
        return self._db.create_maintenance_window(window)

    def list_maintenance_windows(self) -> List[MaintenanceWindow]:
        return self._db.list_maintenance_windows()

    def create_freeze_period(self, period: FreezePeriod) -> FreezePeriod:
        return self._db.create_freeze_period(period)

    def list_freeze_periods(self) -> List[FreezePeriod]:
        return self._db.list_freeze_periods()

    # --- Queries ---

    def get_change(self, change_id: str) -> Optional[ChangeRequest]:
        return self._db.get_change(change_id)

    def list_changes(
        self,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        requestor_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ChangeRequest]:
        return self._db.list_changes(status, risk_level, requestor_id, limit, offset)

    def get_audit_trail(self, change_id: str) -> List[AuditEntry]:
        return self._db.get_audit_trail(change_id)

    # --- Metrics ---

    def get_metrics(self, period_days: int = 30) -> ChangeMetrics:
        """Compute change management metrics for the given period."""
        since = datetime.now(timezone.utc) - timedelta(days=period_days)
        all_changes = self._db.list_changes(limit=10000)
        recent = [c for c in all_changes if c.created_at >= since]

        if not recent:
            return ChangeMetrics(period_days=period_days)

        total = len(recent)
        by_status: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        completed_count = 0
        rolled_back_count = 0
        emergency_count = 0
        review_times: List[float] = []
        impl_times: List[float] = []

        for c in recent:
            by_status[c.status.value] = by_status.get(c.status.value, 0) + 1
            by_risk[c.risk_level.value] = by_risk.get(c.risk_level.value, 0) + 1
            by_category[c.category.value] = by_category.get(c.category.value, 0) + 1

            if c.status == ChangeStatus.COMPLETED:
                completed_count += 1
            if c.status == ChangeStatus.ROLLED_BACK:
                rolled_back_count += 1
            if c.risk_level == ChangeRiskLevel.EMERGENCY:
                emergency_count += 1

            # Review time: submitted → approved/rejected
            if c.approvals:
                first_decision = min(c.approvals, key=lambda a: a.decided_at)
                delta = (first_decision.decided_at - c.created_at).total_seconds() / 3600
                review_times.append(max(0.0, delta))

            # Implementation time
            if c.implementation_started_at and c.implementation_completed_at:
                delta = (
                    c.implementation_completed_at - c.implementation_started_at
                ).total_seconds() / 3600
                impl_times.append(max(0.0, delta))

        terminal = completed_count + rolled_back_count
        success_rate = round(completed_count / max(terminal, 1) * 100, 2)
        rollback_rate = round(rolled_back_count / max(total, 1) * 100, 2)
        emergency_rate = round(emergency_count / max(total, 1) * 100, 2)
        avg_review = round(sum(review_times) / max(len(review_times), 1), 2)
        avg_impl = round(sum(impl_times) / max(len(impl_times), 1), 2)

        # SLA breaches: reviewing past deadline
        now = datetime.now(timezone.utc)
        sla_breaches = sum(
            1 for c in recent
            if c.sla_review_deadline and c.sla_review_deadline < now
            and c.status in (ChangeStatus.REVIEWING, ChangeStatus.SUBMITTED)
        )

        return ChangeMetrics(
            total_changes=total,
            by_status=by_status,
            by_risk_level=by_risk,
            by_category=by_category,
            success_rate=success_rate,
            rollback_rate=rollback_rate,
            emergency_rate=emergency_rate,
            avg_review_time_hours=avg_review,
            avg_implementation_time_hours=avg_impl,
            sla_breach_count=sla_breaches,
            period_days=period_days,
        )

    # --- Internal helpers ---

    def _require_change(self, change_id: str) -> ChangeRequest:
        change = self._db.get_change(change_id)
        if not change:
            raise KeyError(f"Change request {change_id} not found")
        return change

    def _require_status(
        self, change: ChangeRequest, required: ChangeStatus, target: ChangeStatus
    ) -> None:
        if change.status != required:
            raise ValueError(
                f"Change {change.id} must be in '{required.value}' to transition to "
                f"'{target.value}', current: '{change.status.value}'"
            )

    def _audit(
        self,
        change_id: str,
        action: str,
        actor_id: str,
        actor_name: str,
        from_status: Optional[ChangeStatus],
        to_status: Optional[ChangeStatus],
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            change_id=change_id,
            action=action,
            actor_id=actor_id,
            actor_name=actor_name,
            from_status=from_status,
            to_status=to_status,
            details=details or {},
        )
        return self._db.append_audit(entry)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_cab_instance: Optional[ChangeAdvisoryBoard] = None
_cab_lock = Lock()


def get_cab() -> ChangeAdvisoryBoard:
    """Return the module-level CAB singleton."""
    global _cab_instance
    if _cab_instance is None:
        with _cab_lock:
            if _cab_instance is None:
                _cab_instance = ChangeAdvisoryBoard()
    return _cab_instance
