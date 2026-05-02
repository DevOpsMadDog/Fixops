"""Backup & Disaster Recovery Validator API Router.

7 endpoints under /api/v1/backup-dr:
  POST   /jobs                   — register backup job
  GET    /jobs                   — list backup jobs
  POST   /rpo                    — set RPO/RTO config
  GET    /rpo                    — list RPO/RTO configs
  POST   /verifications          — record backup verification
  GET    /verifications          — list verifications
  POST   /dr-plans               — register DR plan
  GET    /dr-plans               — list DR plans
  POST   /dr-tests               — record DR test
  GET    /dr-tests               — list DR tests
  POST   /geo-redundancy         — set geo redundancy record
  GET    /geo-redundancy         — list geo redundancy records
  GET    /bc-score               — compute business continuity score

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.backup_validator import (
    BackupJob,
    BackupStatus,
    BackupType,
    BackupVerification,
    BCScore,
    DRPlan,
    DRTestRecord,
    DRTestResult,
    EncryptionType,
    GeoRedundancyRecord,
    RemediationStatus,
    RPOConfig,
    RunbookStep,
    VerificationStatus,
    get_backup_validator,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/backup-dr", tags=["backup-dr"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _val():
    return get_backup_validator()


def _require_job(job_id: str) -> BackupJob:
    job = _val().get_backup_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Backup job '{job_id}' not found")
    return job


def _require_plan(plan_id: str) -> DRPlan:
    plan = _val().get_dr_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail=f"DR plan '{plan_id}' not found")
    return plan


def _require_test(test_id: str) -> DRTestRecord:
    record = _val().get_dr_test(test_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"DR test '{test_id}' not found")
    return record


def _require_verification(ver_id: str) -> BackupVerification:
    ver = _val().get_verification(ver_id)
    if not ver:
        raise HTTPException(status_code=404, detail=f"Verification '{ver_id}' not found")
    return ver


def _require_geo(geo_id: str) -> GeoRedundancyRecord:
    rec = _val().get_geo_record(geo_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Geo redundancy record '{geo_id}' not found")
    return rec


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterBackupJobRequest(BaseModel):
    name: str = Field(..., description="Descriptive name for the backup job")
    system_name: str = Field(..., description="Logical system being backed up")
    backup_type: BackupType = Field(BackupType.FULL, description="Backup type")
    source_path: str = Field(..., description="Source path, DB name, or bucket URI")
    destination: str = Field(..., description="Destination storage URI or path")
    schedule_cron: str = Field(..., description="Cron expression (e.g. '0 2 * * *')")
    retention_days: int = Field(30, ge=1, le=3650, description="Retention period in days")
    encryption: EncryptionType = Field(EncryptionType.AES256, description="Encryption in transit/at rest")
    status: BackupStatus = Field(BackupStatus.ACTIVE, description="Current job status")
    last_run_at: Optional[str] = None
    last_run_size_bytes: Optional[int] = None
    next_run_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = Field("default", description="Organisation ID")


class UpdateBackupJobRequest(BaseModel):
    name: Optional[str] = None
    status: Optional[BackupStatus] = None
    last_run_at: Optional[str] = None
    last_run_size_bytes: Optional[int] = None
    last_run_duration_seconds: Optional[int] = None
    next_run_at: Optional[str] = None
    retention_days: Optional[int] = None
    encryption: Optional[EncryptionType] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class SetRPOConfigRequest(BaseModel):
    system_name: str = Field(..., description="System this RPO/RTO applies to")
    rpo_target_minutes: int = Field(240, ge=0, description="RPO target in minutes")
    rto_target_minutes: int = Field(480, ge=0, description="RTO target in minutes")
    rpo_actual_minutes: Optional[int] = Field(None, ge=0, description="Measured actual RPO")
    rto_actual_minutes: Optional[int] = Field(None, ge=0, description="Measured actual RTO")
    notes: Optional[str] = None
    org_id: str = Field("default", description="Organisation ID")


class RecordVerificationRequest(BaseModel):
    backup_job_id: str = Field(..., description="Backup job this verification covers")
    backup_artifact_path: str = Field(..., description="Path or URI to the backup artifact")
    sha256_checksum: Optional[str] = Field(None, description="SHA-256 hash of the artifact")
    checksum_verified: bool = Field(False, description="Was the checksum validated?")
    restore_tested: bool = Field(False, description="Was a restore test performed?")
    restore_test_result: VerificationStatus = Field(VerificationStatus.PENDING)
    restore_test_duration_seconds: Optional[int] = None
    backup_age_hours: Optional[float] = Field(None, ge=0.0, description="Age of the backup in hours")
    age_alert_threshold_hours: float = Field(48.0, ge=1.0, description="Hours before age alert fires")
    verified_by: Optional[str] = None
    notes: Optional[str] = None
    org_id: str = Field("default", description="Organisation ID")


class RegisterDRPlanRequest(BaseModel):
    name: str = Field(..., description="DR plan name")
    system_name: str = Field(..., description="System this plan covers")
    priority_order: int = Field(1, ge=1, description="Recovery priority (1 = highest)")
    runbook_steps: List[Dict[str, Any]] = Field(default_factory=list)
    responsible_parties: List[str] = Field(default_factory=list)
    communication_plan: Dict[str, Any] = Field(default_factory=dict)
    rto_minutes: int = Field(480, ge=0)
    rpo_minutes: int = Field(240, ge=0)
    version: str = Field("1.0")
    approved_by: Optional[str] = None
    next_review_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    org_id: str = Field("default", description="Organisation ID")


class UpdateDRPlanRequest(BaseModel):
    name: Optional[str] = None
    priority_order: Optional[int] = None
    runbook_steps: Optional[List[Dict[str, Any]]] = None
    responsible_parties: Optional[List[str]] = None
    communication_plan: Optional[Dict[str, Any]] = None
    rto_minutes: Optional[int] = None
    rpo_minutes: Optional[int] = None
    version: Optional[str] = None
    approved_by: Optional[str] = None
    next_review_at: Optional[str] = None
    tags: Optional[List[str]] = None


class RecordDRTestRequest(BaseModel):
    dr_plan_id: str = Field(..., description="DR plan that was tested")
    system_name: str = Field(..., description="System that was tested")
    test_date: str = Field(..., description="ISO-8601 date of the test")
    result: DRTestResult = Field(..., description="Test outcome")
    tested_by: str = Field(..., description="Person or team who ran the test")
    actual_rto_minutes: Optional[int] = Field(None, ge=0)
    actual_rpo_minutes: Optional[int] = Field(None, ge=0)
    gaps_found: List[str] = Field(default_factory=list)
    remediation_status: RemediationStatus = Field(RemediationStatus.OPEN)
    remediation_notes: Optional[str] = None
    next_test_due: Optional[str] = None
    evidence_links: List[str] = Field(default_factory=list)
    org_id: str = Field("default", description="Organisation ID")


class UpdateDRTestRequest(BaseModel):
    result: Optional[DRTestResult] = None
    actual_rto_minutes: Optional[int] = None
    actual_rpo_minutes: Optional[int] = None
    gaps_found: Optional[List[str]] = None
    remediation_status: Optional[RemediationStatus] = None
    remediation_notes: Optional[str] = None
    next_test_due: Optional[str] = None
    evidence_links: Optional[List[str]] = None


class SetGeoRedundancyRequest(BaseModel):
    system_name: str = Field(..., description="System this geo record covers")
    primary_location: str = Field(..., description="Primary datacenter / cloud region")
    backup_locations: List[str] = Field(default_factory=list)
    distance_km: Optional[float] = Field(None, ge=0.0)
    data_residency_region: str = Field("unknown")
    residency_compliant: bool = False
    required_residency: Optional[str] = None
    compliance_frameworks: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    org_id: str = Field("default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Backup Jobs endpoints
# ---------------------------------------------------------------------------

@router.post("/jobs", response_model=BackupJob, summary="Register backup job")
def register_backup_job(req: RegisterBackupJobRequest) -> BackupJob:
    """Create or update a backup job definition."""
    job = BackupJob(
        name=req.name,
        system_name=req.system_name,
        backup_type=req.backup_type,
        source_path=req.source_path,
        destination=req.destination,
        schedule_cron=req.schedule_cron,
        retention_days=req.retention_days,
        encryption=req.encryption,
        status=req.status,
        last_run_at=req.last_run_at,
        last_run_size_bytes=req.last_run_size_bytes,
        next_run_at=req.next_run_at,
        tags=req.tags,
        metadata=req.metadata,
        org_id=req.org_id,
    )
    try:
        return _val().register_backup_job(job)
    except Exception as exc:
        logger.exception("Failed to register backup job: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to register backup job: {exc}") from exc


@router.get("/jobs", response_model=List[BackupJob], summary="List backup jobs")
def list_backup_jobs(
    org_id: str = Query("default", description="Organisation ID"),
    system_name: Optional[str] = Query(None, description="Filter by system name"),
) -> List[BackupJob]:
    """List all backup jobs for an org, optionally filtered by system."""
    return _val().list_backup_jobs(org_id, system_name=system_name)


@router.get("/jobs/{job_id}", response_model=BackupJob, summary="Get backup job")
def get_backup_job(job_id: str) -> BackupJob:
    """Retrieve a single backup job by ID."""
    return _require_job(job_id)


@router.patch("/jobs/{job_id}", response_model=BackupJob, summary="Update backup job")
def update_backup_job(job_id: str, req: UpdateBackupJobRequest) -> BackupJob:
    """Partial update of a backup job (e.g. update last_run_at after execution)."""
    updated = _val().update_backup_job(job_id, req.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail=f"Backup job '{job_id}' not found")
    return updated


@router.delete("/jobs/{job_id}", summary="Delete backup job")
def delete_backup_job(job_id: str) -> Dict[str, Any]:
    """Remove a backup job from the registry."""
    deleted = _val().delete_backup_job(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Backup job '{job_id}' not found")
    return {"deleted": True, "job_id": job_id}


# ---------------------------------------------------------------------------
# RPO/RTO endpoints
# ---------------------------------------------------------------------------

@router.post("/rpo", response_model=RPOConfig, summary="Set RPO/RTO config")
def set_rpo_config(req: SetRPOConfigRequest) -> RPOConfig:
    """Create or update RPO/RTO targets and actuals for a system."""
    # Check if existing config for this system; preserve ID for upsert
    import uuid as _uuid
    existing = _val()._db.get_rpo_config_by_system(req.system_name, req.org_id)
    cfg = RPOConfig(
        id=existing.id if existing else f"rpo-{_uuid.uuid4().hex[:12]}",
        system_name=req.system_name,
        rpo_target_minutes=req.rpo_target_minutes,
        rto_target_minutes=req.rto_target_minutes,
        rpo_actual_minutes=req.rpo_actual_minutes,
        rto_actual_minutes=req.rto_actual_minutes,
        notes=req.notes,
        org_id=req.org_id,
    )
    if existing:
        cfg.created_at = existing.created_at
    try:
        return _val().set_rpo_config(cfg)
    except Exception as exc:
        logger.exception("Failed to set RPO config: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to set RPO config: {exc}") from exc


@router.get("/rpo", response_model=List[RPOConfig], summary="List RPO/RTO configs")
def list_rpo_configs(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[RPOConfig]:
    """List all RPO/RTO configurations for an org."""
    return _val().list_rpo_configs(org_id)


@router.get("/rpo/{rpo_id}", response_model=RPOConfig, summary="Get RPO/RTO config")
def get_rpo_config(rpo_id: str) -> RPOConfig:
    cfg = _val().get_rpo_config(rpo_id)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"RPO config '{rpo_id}' not found")
    return cfg


# ---------------------------------------------------------------------------
# Verification endpoints
# ---------------------------------------------------------------------------

@router.post("/verifications", response_model=BackupVerification, summary="Record backup verification")
def record_verification(req: RecordVerificationRequest) -> BackupVerification:
    """Record an integrity check / restore test result for a backup artifact."""
    _require_job(req.backup_job_id)  # validate job exists
    ver = BackupVerification(
        backup_job_id=req.backup_job_id,
        backup_artifact_path=req.backup_artifact_path,
        sha256_checksum=req.sha256_checksum,
        checksum_verified=req.checksum_verified,
        restore_tested=req.restore_tested,
        restore_test_result=req.restore_test_result,
        restore_test_duration_seconds=req.restore_test_duration_seconds,
        backup_age_hours=req.backup_age_hours,
        age_alert_threshold_hours=req.age_alert_threshold_hours,
        verified_by=req.verified_by,
        notes=req.notes,
        org_id=req.org_id,
    )
    try:
        return _val().record_verification(ver)
    except Exception as exc:
        logger.exception("Failed to record verification: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to record verification: {exc}") from exc


@router.get("/verifications", response_model=List[BackupVerification], summary="List verifications")
def list_verifications(
    org_id: str = Query("default", description="Organisation ID"),
    backup_job_id: Optional[str] = Query(None, description="Filter by backup job ID"),
) -> List[BackupVerification]:
    """List backup verification records for an org."""
    return _val().list_verifications(org_id, backup_job_id=backup_job_id)


@router.get("/verifications/{ver_id}", response_model=BackupVerification, summary="Get verification")
def get_verification(ver_id: str) -> BackupVerification:
    return _require_verification(ver_id)


# ---------------------------------------------------------------------------
# DR Plan endpoints
# ---------------------------------------------------------------------------

@router.post("/dr-plans", response_model=DRPlan, summary="Register DR plan")
def register_dr_plan(req: RegisterDRPlanRequest) -> DRPlan:
    """Create or update a Disaster Recovery plan with runbook steps."""
    steps = [RunbookStep(**s) for s in req.runbook_steps]
    plan = DRPlan(
        name=req.name,
        system_name=req.system_name,
        priority_order=req.priority_order,
        runbook_steps=steps,
        responsible_parties=req.responsible_parties,
        communication_plan=req.communication_plan,
        rto_minutes=req.rto_minutes,
        rpo_minutes=req.rpo_minutes,
        version=req.version,
        approved_by=req.approved_by,
        next_review_at=req.next_review_at,
        tags=req.tags,
        org_id=req.org_id,
    )
    try:
        return _val().register_dr_plan(plan)
    except Exception as exc:
        logger.exception("Failed to register DR plan: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to register DR plan: {exc}") from exc


@router.get("/dr-plans", response_model=List[DRPlan], summary="List DR plans")
def list_dr_plans(
    org_id: str = Query("default", description="Organisation ID"),
    system_name: Optional[str] = Query(None, description="Filter by system name"),
) -> List[DRPlan]:
    """List DR plans for an org, optionally filtered by system."""
    return _val().list_dr_plans(org_id, system_name=system_name)


@router.get("/dr-plans/{plan_id}", response_model=DRPlan, summary="Get DR plan")
def get_dr_plan(plan_id: str) -> DRPlan:
    return _require_plan(plan_id)


@router.patch("/dr-plans/{plan_id}", response_model=DRPlan, summary="Update DR plan")
def update_dr_plan(plan_id: str, req: UpdateDRPlanRequest) -> DRPlan:
    updates = req.model_dump(exclude_none=True)
    if "runbook_steps" in updates:
        updates["runbook_steps"] = [RunbookStep(**s) for s in updates["runbook_steps"]]
    updated = _val().update_dr_plan(plan_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail=f"DR plan '{plan_id}' not found")
    return updated


@router.delete("/dr-plans/{plan_id}", summary="Delete DR plan")
def delete_dr_plan(plan_id: str) -> Dict[str, Any]:
    deleted = _val().delete_dr_plan(plan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"DR plan '{plan_id}' not found")
    return {"deleted": True, "plan_id": plan_id}


# ---------------------------------------------------------------------------
# DR Test endpoints
# ---------------------------------------------------------------------------

@router.post("/dr-tests", response_model=DRTestRecord, summary="Record DR test")
def record_dr_test(req: RecordDRTestRequest) -> DRTestRecord:
    """Record the result of a DR test exercise against a DR plan."""
    _require_plan(req.dr_plan_id)  # validate plan exists
    record = DRTestRecord(
        dr_plan_id=req.dr_plan_id,
        system_name=req.system_name,
        test_date=req.test_date,
        result=req.result,
        tested_by=req.tested_by,
        actual_rto_minutes=req.actual_rto_minutes,
        actual_rpo_minutes=req.actual_rpo_minutes,
        gaps_found=req.gaps_found,
        remediation_status=req.remediation_status,
        remediation_notes=req.remediation_notes,
        next_test_due=req.next_test_due,
        evidence_links=req.evidence_links,
        org_id=req.org_id,
    )
    try:
        return _val().record_dr_test(record)
    except Exception as exc:
        logger.exception("Failed to record DR test: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to record DR test: {exc}") from exc


@router.get("/dr-tests", response_model=List[DRTestRecord], summary="List DR tests")
def list_dr_tests(
    org_id: str = Query("default", description="Organisation ID"),
    dr_plan_id: Optional[str] = Query(None, description="Filter by DR plan ID"),
) -> List[DRTestRecord]:
    """List DR test records for an org, optionally filtered by plan."""
    return _val().list_dr_tests(org_id, dr_plan_id=dr_plan_id)


@router.get("/dr-tests/{test_id}", response_model=DRTestRecord, summary="Get DR test")
def get_dr_test(test_id: str) -> DRTestRecord:
    return _require_test(test_id)


@router.patch("/dr-tests/{test_id}", response_model=DRTestRecord, summary="Update DR test")
def update_dr_test(test_id: str, req: UpdateDRTestRequest) -> DRTestRecord:
    """Update remediation status, gaps, or actual RTO/RPO on a DR test record."""
    updated = _val().update_dr_test(test_id, req.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail=f"DR test '{test_id}' not found")
    return updated


# ---------------------------------------------------------------------------
# Geo Redundancy endpoints
# ---------------------------------------------------------------------------

@router.post("/geo-redundancy", response_model=GeoRedundancyRecord, summary="Set geo redundancy")
def set_geo_redundancy(req: SetGeoRedundancyRequest) -> GeoRedundancyRecord:
    """Register or update geographic backup location for a system."""
    from core.backup_validator import DataResidencyRegion
    try:
        residency = DataResidencyRegion(req.data_residency_region)
    except ValueError:
        residency = DataResidencyRegion.UNKNOWN
    rec = GeoRedundancyRecord(
        system_name=req.system_name,
        primary_location=req.primary_location,
        backup_locations=req.backup_locations,
        distance_km=req.distance_km,
        data_residency_region=residency,
        residency_compliant=req.residency_compliant,
        required_residency=req.required_residency,
        compliance_frameworks=req.compliance_frameworks,
        notes=req.notes,
        org_id=req.org_id,
    )
    try:
        return _val().set_geo_redundancy(rec)
    except Exception as exc:
        logger.exception("Failed to set geo redundancy: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to set geo redundancy: {exc}") from exc


@router.get("/geo-redundancy", response_model=List[GeoRedundancyRecord], summary="List geo records")
def list_geo_records(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[GeoRedundancyRecord]:
    """List geographic redundancy records for an org."""
    return _val().list_geo_records(org_id)


@router.get("/geo-redundancy/{geo_id}", response_model=GeoRedundancyRecord, summary="Get geo record")
def get_geo_record(geo_id: str) -> GeoRedundancyRecord:
    return _require_geo(geo_id)


# ---------------------------------------------------------------------------
# Business Continuity Score endpoint
# ---------------------------------------------------------------------------

@router.get("/bc-score", response_model=BCScore, summary="Business continuity score")
def get_bc_score(
    org_id: str = Query("default", description="Organisation ID"),
) -> BCScore:
    """Compute a 0-100 business continuity readiness score for the org.

    Weighted across: backup coverage, encryption, RPO/RTO compliance,
    verification pass rate, DR test frequency, geographic redundancy.
    """
    try:
        return _val().compute_bc_score(org_id)
    except Exception as exc:
        logger.exception("Failed to compute BC score: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to compute BC score: {exc}") from exc
