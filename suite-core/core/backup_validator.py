"""Backup & Disaster Recovery Validator for ALDECI.

Provides:
- Backup inventory: track jobs (source, destination, schedule, retention, encryption)
- RPO/RTO tracking: Recovery Point/Time Objectives — actual vs target per system
- Backup verification: SHA-256 checksums, restore test results, age alerts
- DR plan management: runbook steps, responsible parties, communication plan
- DR test tracking: last test date, result, gaps, remediation status
- Geographic redundancy: backup locations, distance, data residency compliance
- Business continuity scoring: readiness 0-100 based on coverage, frequency, gaps

Usage:
    from core.backup_validator import BackupValidator, get_backup_validator
    validator = get_backup_validator()
    job = validator.register_backup_job(backup_job)
    score = validator.compute_bc_score("org-1")
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_BACKUP_VALIDATOR_DB", ".fixops_data/backup_validator.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class BackupType(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"
    CONTINUOUS = "continuous"


class BackupStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    FAILED = "failed"
    UNKNOWN = "unknown"


class EncryptionType(str, Enum):
    AES256 = "aes256"
    AES128 = "aes128"
    NONE = "none"
    UNKNOWN = "unknown"


class VerificationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    PENDING = "pending"
    SKIPPED = "skipped"


class DRPlanStatus(str, Enum):
    APPROVED = "approved"
    DRAFT = "draft"
    UNDER_REVIEW = "under_review"
    ARCHIVED = "archived"


class DRTestResult(str, Enum):
    PASSED = "passed"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_TESTED = "not_tested"


class RemediationStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


class DataResidencyRegion(str, Enum):
    US = "us"
    EU = "eu"
    APAC = "apac"
    GLOBAL = "global"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class BackupJob(BaseModel):
    """Tracks a single backup job definition and its current state."""

    id: str = Field(default_factory=lambda: f"bkjob-{uuid.uuid4().hex[:12]}")
    name: str
    system_name: str                            # logical system being backed up
    backup_type: BackupType = BackupType.FULL
    source_path: str                            # filesystem path, DB name, bucket, etc.
    destination: str                            # target storage URI / path
    schedule_cron: str                          # cron expression, e.g. "0 2 * * *"
    retention_days: int = 30
    encryption: EncryptionType = EncryptionType.AES256
    status: BackupStatus = BackupStatus.ACTIVE
    last_run_at: Optional[str] = None
    last_run_size_bytes: Optional[int] = None
    last_run_duration_seconds: Optional[int] = None
    next_run_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RPOConfig(BaseModel):
    """RPO/RTO targets and actuals for a logical system."""

    id: str = Field(default_factory=lambda: f"rpo-{uuid.uuid4().hex[:12]}")
    system_name: str
    rpo_target_minutes: int = Field(240, description="Recovery Point Objective target in minutes")
    rto_target_minutes: int = Field(480, description="Recovery Time Objective target in minutes")
    rpo_actual_minutes: Optional[int] = Field(None, description="Measured RPO from last backup interval")
    rto_actual_minutes: Optional[int] = Field(None, description="Measured RTO from last restore test")
    rpo_compliant: bool = False
    rto_compliant: bool = False
    last_evaluated_at: Optional[str] = None
    notes: Optional[str] = None
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BackupVerification(BaseModel):
    """Integrity verification record for a specific backup artifact."""

    id: str = Field(default_factory=lambda: f"bkver-{uuid.uuid4().hex[:12]}")
    backup_job_id: str
    backup_artifact_path: str
    sha256_checksum: Optional[str] = None
    checksum_verified: bool = False
    restore_tested: bool = False
    restore_test_result: VerificationStatus = VerificationStatus.PENDING
    restore_test_duration_seconds: Optional[int] = None
    backup_age_hours: Optional[float] = None
    age_alert_triggered: bool = False
    age_alert_threshold_hours: float = 48.0
    verified_at: Optional[str] = None
    verified_by: Optional[str] = None
    notes: Optional[str] = None
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RunbookStep(BaseModel):
    """Single step in a DR runbook."""

    step_number: int
    title: str
    description: str
    responsible_party: str
    estimated_duration_minutes: int = 15
    dependencies: List[int] = Field(default_factory=list)  # step numbers this depends on
    validation_criteria: Optional[str] = None


class DRPlan(BaseModel):
    """Disaster Recovery plan with runbook steps and communication plan."""

    id: str = Field(default_factory=lambda: f"drplan-{uuid.uuid4().hex[:12]}")
    name: str
    system_name: str
    status: DRPlanStatus = DRPlanStatus.DRAFT
    priority_order: int = Field(1, description="Lower = higher priority for recovery")
    runbook_steps: List[RunbookStep] = Field(default_factory=list)
    responsible_parties: List[str] = Field(default_factory=list)
    communication_plan: Dict[str, Any] = Field(
        default_factory=dict,
        description="Who to notify, escalation path, channels, templates",
    )
    rto_minutes: int = 480
    rpo_minutes: int = 240
    version: str = "1.0"
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    last_reviewed_at: Optional[str] = None
    next_review_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DRTestRecord(BaseModel):
    """Record of a DR test exercise."""

    id: str = Field(default_factory=lambda: f"drtest-{uuid.uuid4().hex[:12]}")
    dr_plan_id: str
    system_name: str
    test_date: str
    result: DRTestResult = DRTestResult.NOT_TESTED
    tested_by: str
    actual_rto_minutes: Optional[int] = None
    actual_rpo_minutes: Optional[int] = None
    gaps_found: List[str] = Field(default_factory=list)
    remediation_status: RemediationStatus = RemediationStatus.OPEN
    remediation_notes: Optional[str] = None
    next_test_due: Optional[str] = None
    evidence_links: List[str] = Field(default_factory=list)
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class GeoRedundancyRecord(BaseModel):
    """Geographic backup location tracking for data residency compliance."""

    id: str = Field(default_factory=lambda: f"georec-{uuid.uuid4().hex[:12]}")
    system_name: str
    primary_location: str                       # datacenter / region / cloud region
    backup_locations: List[str] = Field(default_factory=list)
    distance_km: Optional[float] = Field(None, description="Distance from primary to nearest backup (km)")
    data_residency_region: DataResidencyRegion = DataResidencyRegion.UNKNOWN
    residency_compliant: bool = False
    required_residency: Optional[str] = None    # e.g. "EU" for GDPR
    compliance_frameworks: List[str] = Field(default_factory=list)
    last_verified_at: Optional[str] = None
    notes: Optional[str] = None
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BCScore(BaseModel):
    """Business continuity readiness score for an org."""

    org_id: str
    score: float = Field(0.0, ge=0.0, le=100.0)
    grade: str = "F"
    backup_coverage_pct: float = 0.0           # % systems with active backup jobs
    test_frequency_score: float = 0.0          # based on DR test recency
    rpo_compliance_pct: float = 0.0
    rto_compliance_pct: float = 0.0
    encryption_coverage_pct: float = 0.0
    geo_redundancy_pct: float = 0.0
    verification_pass_rate: float = 0.0
    open_gaps: int = 0
    systems_without_backup: List[str] = Field(default_factory=list)
    systems_without_dr_plan: List[str] = Field(default_factory=list)
    computed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------

class _BackupValidatorDB:
    """SQLite persistence for all backup validator entities."""

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
                CREATE TABLE IF NOT EXISTS backup_jobs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    system_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_bkjob_org ON backup_jobs(org_id);
                CREATE INDEX IF NOT EXISTS idx_bkjob_system ON backup_jobs(system_name);

                CREATE TABLE IF NOT EXISTS rpo_configs (
                    id TEXT PRIMARY KEY,
                    system_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_rpo_org ON rpo_configs(org_id);
                CREATE INDEX IF NOT EXISTS idx_rpo_system ON rpo_configs(system_name);

                CREATE TABLE IF NOT EXISTS backup_verifications (
                    id TEXT PRIMARY KEY,
                    backup_job_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_bkver_job ON backup_verifications(backup_job_id);
                CREATE INDEX IF NOT EXISTS idx_bkver_org ON backup_verifications(org_id);

                CREATE TABLE IF NOT EXISTS dr_plans (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    system_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_drplan_org ON dr_plans(org_id);
                CREATE INDEX IF NOT EXISTS idx_drplan_system ON dr_plans(system_name);

                CREATE TABLE IF NOT EXISTS dr_test_records (
                    id TEXT PRIMARY KEY,
                    dr_plan_id TEXT NOT NULL,
                    system_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_drtest_plan ON dr_test_records(dr_plan_id);
                CREATE INDEX IF NOT EXISTS idx_drtest_org ON dr_test_records(org_id);

                CREATE TABLE IF NOT EXISTS geo_redundancy (
                    id TEXT PRIMARY KEY,
                    system_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_geo_org ON geo_redundancy(org_id);
                CREATE INDEX IF NOT EXISTS idx_geo_system ON geo_redundancy(system_name);
            """)
            self._conn.commit()

    # --- Backup Jobs ---

    def upsert_backup_job(self, job: BackupJob) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO backup_jobs (id, name, system_name, data, org_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name, system_name=excluded.system_name,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (job.id, job.name, job.system_name,
                 job.model_dump_json(), job.org_id, job.created_at, job.updated_at),
            )
            self._conn.commit()

    def get_backup_job(self, job_id: str) -> Optional[BackupJob]:
        row = self._conn.execute(
            "SELECT data FROM backup_jobs WHERE id = ?", (job_id,)
        ).fetchone()
        return BackupJob.model_validate_json(row[0]) if row else None

    def list_backup_jobs(self, org_id: str, system_name: Optional[str] = None) -> List[BackupJob]:
        if system_name:
            rows = self._conn.execute(
                "SELECT data FROM backup_jobs WHERE org_id = ? AND system_name = ?",
                (org_id, system_name),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM backup_jobs WHERE org_id = ?", (org_id,)
            ).fetchall()
        return [BackupJob.model_validate_json(r[0]) for r in rows]

    def delete_backup_job(self, job_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM backup_jobs WHERE id = ?", (job_id,))
            self._conn.commit()
            return cur.rowcount > 0

    # --- RPO Configs ---

    def upsert_rpo_config(self, cfg: RPOConfig) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO rpo_configs (id, system_name, data, org_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     system_name=excluded.system_name, data=excluded.data, updated_at=excluded.updated_at""",
                (cfg.id, cfg.system_name, cfg.model_dump_json(), cfg.org_id, cfg.created_at, cfg.updated_at),
            )
            self._conn.commit()

    def get_rpo_config(self, rpo_id: str) -> Optional[RPOConfig]:
        row = self._conn.execute(
            "SELECT data FROM rpo_configs WHERE id = ?", (rpo_id,)
        ).fetchone()
        return RPOConfig.model_validate_json(row[0]) if row else None

    def get_rpo_config_by_system(self, system_name: str, org_id: str) -> Optional[RPOConfig]:
        row = self._conn.execute(
            "SELECT data FROM rpo_configs WHERE system_name = ? AND org_id = ?",
            (system_name, org_id),
        ).fetchone()
        return RPOConfig.model_validate_json(row[0]) if row else None

    def list_rpo_configs(self, org_id: str) -> List[RPOConfig]:
        rows = self._conn.execute(
            "SELECT data FROM rpo_configs WHERE org_id = ?", (org_id,)
        ).fetchall()
        return [RPOConfig.model_validate_json(r[0]) for r in rows]

    # --- Backup Verifications ---

    def insert_verification(self, ver: BackupVerification) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO backup_verifications (id, backup_job_id, data, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (ver.id, ver.backup_job_id, ver.model_dump_json(), ver.org_id, ver.created_at),
            )
            self._conn.commit()

    def get_verification(self, ver_id: str) -> Optional[BackupVerification]:
        row = self._conn.execute(
            "SELECT data FROM backup_verifications WHERE id = ?", (ver_id,)
        ).fetchone()
        return BackupVerification.model_validate_json(row[0]) if row else None

    def list_verifications(self, org_id: str, backup_job_id: Optional[str] = None) -> List[BackupVerification]:
        if backup_job_id:
            rows = self._conn.execute(
                "SELECT data FROM backup_verifications WHERE org_id = ? AND backup_job_id = ?",
                (org_id, backup_job_id),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM backup_verifications WHERE org_id = ?", (org_id,)
            ).fetchall()
        return [BackupVerification.model_validate_json(r[0]) for r in rows]

    # --- DR Plans ---

    def upsert_dr_plan(self, plan: DRPlan) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO dr_plans (id, name, system_name, data, org_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name, system_name=excluded.system_name,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (plan.id, plan.name, plan.system_name,
                 plan.model_dump_json(), plan.org_id, plan.created_at, plan.updated_at),
            )
            self._conn.commit()

    def get_dr_plan(self, plan_id: str) -> Optional[DRPlan]:
        row = self._conn.execute(
            "SELECT data FROM dr_plans WHERE id = ?", (plan_id,)
        ).fetchone()
        return DRPlan.model_validate_json(row[0]) if row else None

    def list_dr_plans(self, org_id: str, system_name: Optional[str] = None) -> List[DRPlan]:
        if system_name:
            rows = self._conn.execute(
                "SELECT data FROM dr_plans WHERE org_id = ? AND system_name = ?",
                (org_id, system_name),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM dr_plans WHERE org_id = ?", (org_id,)
            ).fetchall()
        return [DRPlan.model_validate_json(r[0]) for r in rows]

    def delete_dr_plan(self, plan_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM dr_plans WHERE id = ?", (plan_id,))
            self._conn.commit()
            return cur.rowcount > 0

    # --- DR Test Records ---

    def upsert_dr_test(self, record: DRTestRecord) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO dr_test_records
                     (id, dr_plan_id, system_name, data, org_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     data=excluded.data, updated_at=excluded.updated_at""",
                (record.id, record.dr_plan_id, record.system_name,
                 record.model_dump_json(), record.org_id, record.created_at, record.updated_at),
            )
            self._conn.commit()

    def get_dr_test(self, test_id: str) -> Optional[DRTestRecord]:
        row = self._conn.execute(
            "SELECT data FROM dr_test_records WHERE id = ?", (test_id,)
        ).fetchone()
        return DRTestRecord.model_validate_json(row[0]) if row else None

    def list_dr_tests(self, org_id: str, dr_plan_id: Optional[str] = None) -> List[DRTestRecord]:
        if dr_plan_id:
            rows = self._conn.execute(
                "SELECT data FROM dr_test_records WHERE org_id = ? AND dr_plan_id = ?",
                (org_id, dr_plan_id),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM dr_test_records WHERE org_id = ?", (org_id,)
            ).fetchall()
        return [DRTestRecord.model_validate_json(r[0]) for r in rows]

    # --- Geo Redundancy ---

    def upsert_geo_record(self, rec: GeoRedundancyRecord) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO geo_redundancy (id, system_name, data, org_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     system_name=excluded.system_name, data=excluded.data, updated_at=excluded.updated_at""",
                (rec.id, rec.system_name, rec.model_dump_json(), rec.org_id, rec.created_at, rec.updated_at),
            )
            self._conn.commit()

    def get_geo_record(self, geo_id: str) -> Optional[GeoRedundancyRecord]:
        row = self._conn.execute(
            "SELECT data FROM geo_redundancy WHERE id = ?", (geo_id,)
        ).fetchone()
        return GeoRedundancyRecord.model_validate_json(row[0]) if row else None

    def list_geo_records(self, org_id: str) -> List[GeoRedundancyRecord]:
        rows = self._conn.execute(
            "SELECT data FROM geo_redundancy WHERE org_id = ?", (org_id,)
        ).fetchall()
        return [GeoRedundancyRecord.model_validate_json(r[0]) for r in rows]


# ---------------------------------------------------------------------------
# Business logic
# ---------------------------------------------------------------------------

class BackupValidator:
    """Core engine for backup and DR validation."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _BackupValidatorDB(db_path)
        logger.info("BackupValidator initialised", db_path=db_path)

    # --- Backup Jobs ---

    def register_backup_job(self, job: BackupJob) -> BackupJob:
        """Create or update a backup job."""
        job.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_backup_job(job)
        logger.info("Backup job registered", job_id=job.id, system=job.system_name)
        return job

    def get_backup_job(self, job_id: str) -> Optional[BackupJob]:
        return self._db.get_backup_job(job_id)

    def list_backup_jobs(self, org_id: str, system_name: Optional[str] = None) -> List[BackupJob]:
        return self._db.list_backup_jobs(org_id, system_name=system_name)

    def update_backup_job(self, job_id: str, updates: Dict[str, Any]) -> Optional[BackupJob]:
        job = self._db.get_backup_job(job_id)
        if not job:
            return None
        for k, v in updates.items():
            if hasattr(job, k) and v is not None:
                setattr(job, k, v)
        job.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_backup_job(job)
        return job

    def delete_backup_job(self, job_id: str) -> bool:
        return self._db.delete_backup_job(job_id)

    # --- RPO/RTO ---

    def set_rpo_config(self, cfg: RPOConfig) -> RPOConfig:
        """Upsert RPO/RTO config for a system. Evaluates compliance."""
        cfg = self._evaluate_rpo_compliance(cfg)
        cfg.updated_at = datetime.now(timezone.utc).isoformat()
        cfg.last_evaluated_at = cfg.updated_at
        self._db.upsert_rpo_config(cfg)
        logger.info("RPO config set", system=cfg.system_name, rpo_compliant=cfg.rpo_compliant)
        return cfg

    def get_rpo_config(self, rpo_id: str) -> Optional[RPOConfig]:
        return self._db.get_rpo_config(rpo_id)

    def list_rpo_configs(self, org_id: str) -> List[RPOConfig]:
        return self._db.list_rpo_configs(org_id)

    def _evaluate_rpo_compliance(self, cfg: RPOConfig) -> RPOConfig:
        if cfg.rpo_actual_minutes is not None:
            cfg.rpo_compliant = cfg.rpo_actual_minutes <= cfg.rpo_target_minutes
        if cfg.rto_actual_minutes is not None:
            cfg.rto_compliant = cfg.rto_actual_minutes <= cfg.rto_target_minutes
        return cfg

    # --- Backup Verification ---

    def record_verification(self, ver: BackupVerification) -> BackupVerification:
        """Record a backup integrity verification result. Calculates age alert."""
        ver = self._check_age_alert(ver)
        self._db.insert_verification(ver)
        logger.info(
            "Backup verification recorded",
            ver_id=ver.id,
            job_id=ver.backup_job_id,
            age_alert=ver.age_alert_triggered,
        )
        return ver

    def get_verification(self, ver_id: str) -> Optional[BackupVerification]:
        return self._db.get_verification(ver_id)

    def list_verifications(
        self, org_id: str, backup_job_id: Optional[str] = None
    ) -> List[BackupVerification]:
        return self._db.list_verifications(org_id, backup_job_id=backup_job_id)

    def compute_checksum(self, data: bytes) -> str:
        """Compute SHA-256 checksum for backup data bytes."""
        return hashlib.sha256(data).hexdigest()

    def _check_age_alert(self, ver: BackupVerification) -> BackupVerification:
        if ver.backup_age_hours is not None:
            ver.age_alert_triggered = ver.backup_age_hours > ver.age_alert_threshold_hours
        return ver

    # --- DR Plans ---

    def register_dr_plan(self, plan: DRPlan) -> DRPlan:
        """Create or update a DR plan."""
        plan.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_dr_plan(plan)
        logger.info("DR plan registered", plan_id=plan.id, system=plan.system_name)
        return plan

    def get_dr_plan(self, plan_id: str) -> Optional[DRPlan]:
        return self._db.get_dr_plan(plan_id)

    def list_dr_plans(self, org_id: str, system_name: Optional[str] = None) -> List[DRPlan]:
        return self._db.list_dr_plans(org_id, system_name=system_name)

    def update_dr_plan(self, plan_id: str, updates: Dict[str, Any]) -> Optional[DRPlan]:
        plan = self._db.get_dr_plan(plan_id)
        if not plan:
            return None
        for k, v in updates.items():
            if hasattr(plan, k) and v is not None:
                setattr(plan, k, v)
        plan.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_dr_plan(plan)
        return plan

    def delete_dr_plan(self, plan_id: str) -> bool:
        return self._db.delete_dr_plan(plan_id)

    # --- DR Test Records ---

    def record_dr_test(self, record: DRTestRecord) -> DRTestRecord:
        """Record the result of a DR test exercise."""
        record.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_dr_test(record)
        logger.info(
            "DR test recorded",
            test_id=record.id,
            plan_id=record.dr_plan_id,
            result=record.result,
        )
        return record

    def get_dr_test(self, test_id: str) -> Optional[DRTestRecord]:
        return self._db.get_dr_test(test_id)

    def list_dr_tests(self, org_id: str, dr_plan_id: Optional[str] = None) -> List[DRTestRecord]:
        return self._db.list_dr_tests(org_id, dr_plan_id=dr_plan_id)

    def update_dr_test(self, test_id: str, updates: Dict[str, Any]) -> Optional[DRTestRecord]:
        record = self._db.get_dr_test(test_id)
        if not record:
            return None
        for k, v in updates.items():
            if hasattr(record, k) and v is not None:
                setattr(record, k, v)
        record.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_dr_test(record)
        return record

    # --- Geographic Redundancy ---

    def set_geo_redundancy(self, rec: GeoRedundancyRecord) -> GeoRedundancyRecord:
        """Register or update geographic redundancy info for a system."""
        rec.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_geo_record(rec)
        logger.info("Geo redundancy record set", geo_id=rec.id, system=rec.system_name)
        return rec

    def get_geo_record(self, geo_id: str) -> Optional[GeoRedundancyRecord]:
        return self._db.get_geo_record(geo_id)

    def list_geo_records(self, org_id: str) -> List[GeoRedundancyRecord]:
        return self._db.list_geo_records(org_id)

    # --- Business Continuity Scoring ---

    def compute_bc_score(self, org_id: str) -> BCScore:
        """Compute a 0-100 readiness score from all available data for the org."""
        jobs = self._db.list_backup_jobs(org_id)
        rpo_configs = self._db.list_rpo_configs(org_id)
        verifications = self._db.list_verifications(org_id)
        dr_plans = self._db.list_dr_plans(org_id)
        dr_tests = self._db.list_dr_tests(org_id)
        geo_records = self._db.list_geo_records(org_id)

        systems_with_backup = {j.system_name for j in jobs if j.status == BackupStatus.ACTIVE}
        systems_with_plan = {p.system_name for p in dr_plans}
        all_job_systems = {j.system_name for j in jobs}
        all_systems = all_job_systems | systems_with_plan | {r.system_name for r in rpo_configs}

        # Backup coverage: fraction of known systems with active backup
        backup_coverage = (
            len(systems_with_backup) / len(all_systems) if all_systems else 0.0
        )

        # Encryption coverage: fraction of active jobs using encryption
        active_jobs = [j for j in jobs if j.status == BackupStatus.ACTIVE]
        encrypted_jobs = [
            j for j in active_jobs if j.encryption not in (EncryptionType.NONE, EncryptionType.UNKNOWN)
        ]
        encryption_coverage = len(encrypted_jobs) / len(active_jobs) if active_jobs else 0.0

        # RPO/RTO compliance
        rpo_compliant = [r for r in rpo_configs if r.rpo_actual_minutes is not None and r.rpo_compliant]
        rto_compliant = [r for r in rpo_configs if r.rto_actual_minutes is not None and r.rto_compliant]
        evaluated = [r for r in rpo_configs if r.rpo_actual_minutes is not None]
        rpo_pct = len(rpo_compliant) / len(evaluated) if evaluated else 0.0
        rto_pct = len(rto_compliant) / len(evaluated) if evaluated else 0.0

        # Verification pass rate
        passed_vers = [
            v for v in verifications
            if v.restore_test_result == VerificationStatus.PASSED
        ]
        ver_pass_rate = len(passed_vers) / len(verifications) if verifications else 0.0

        # DR test frequency score: based on most recent test per plan
        test_score = self._compute_test_frequency_score(dr_tests, dr_plans)

        # Geo redundancy: fraction of known systems with geo record
        systems_with_geo = {r.system_name for r in geo_records if r.residency_compliant}
        geo_pct = len(systems_with_geo) / len(all_systems) if all_systems else 0.0

        # Composite score (weighted)
        score = (
            backup_coverage * 25.0
            + encryption_coverage * 10.0
            + rpo_pct * 15.0
            + rto_pct * 15.0
            + ver_pass_rate * 15.0
            + test_score * 10.0
            + geo_pct * 10.0
        )
        score = min(100.0, max(0.0, score))

        # Open gaps: DR tests with open/in-progress remediation
        open_gaps = sum(
            1 for t in dr_tests
            if t.remediation_status in (RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS)
            and t.gaps_found
        )

        grade = self._score_to_grade(score)

        result = BCScore(
            org_id=org_id,
            score=round(score, 2),
            grade=grade,
            backup_coverage_pct=round(backup_coverage * 100, 2),
            test_frequency_score=round(test_score * 100, 2),
            rpo_compliance_pct=round(rpo_pct * 100, 2),
            rto_compliance_pct=round(rto_pct * 100, 2),
            encryption_coverage_pct=round(encryption_coverage * 100, 2),
            geo_redundancy_pct=round(geo_pct * 100, 2),
            verification_pass_rate=round(ver_pass_rate * 100, 2),
            open_gaps=open_gaps,
            systems_without_backup=sorted(all_systems - systems_with_backup),
            systems_without_dr_plan=sorted(all_systems - systems_with_plan),
        )
        logger.info(
            "BC score computed", org_id=org_id, score=result.score, grade=result.grade
        )
        return result

    def _compute_test_frequency_score(
        self, tests: List[DRTestRecord], plans: List[DRPlan]
    ) -> float:
        """Score DR test frequency. Full score if all plans tested in last 90 days."""
        if not plans:
            return 0.0
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        tested_recently: set = set()
        for t in tests:
            try:
                td = datetime.fromisoformat(t.test_date.replace("Z", "+00:00"))
                if td.tzinfo is None:
                    td = td.replace(tzinfo=timezone.utc)
                if td >= cutoff and t.result in (DRTestResult.PASSED, DRTestResult.PARTIAL):
                    tested_recently.add(t.dr_plan_id)
            except (ValueError, AttributeError):
                continue
        return len(tested_recently) / len(plans)

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_validator_instance: Optional[BackupValidator] = None
_validator_lock = threading.Lock()


def get_backup_validator(db_path: str = _DEFAULT_DB) -> BackupValidator:
    """Return the process-level singleton BackupValidator."""
    global _validator_instance
    if _validator_instance is None:
        with _validator_lock:
            if _validator_instance is None:
                _validator_instance = BackupValidator(db_path=db_path)
    return _validator_instance
