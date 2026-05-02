"""
Backup and restore API endpoints.

Provides full backup lifecycle: create, list, get, delete, verify,
restore, schedule recurring backups, cleanup expired backups, and stats.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.backup_engine import BackupEngine, BackupRecord, BackupType, RestoreRecord
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/backups", tags=["backups"])
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = BackupEngine()
    return _engine


# ------------------------------------------------------------------
# Request / Response models
# ------------------------------------------------------------------


class CreateBackupRequest(BaseModel):
    backup_type: BackupType = BackupType.FULL
    databases: List[str] = Field(default_factory=list)
    encrypt: bool = False
    retention_days: int = 30


class RestoreRequest(BaseModel):
    target_databases: Optional[List[str]] = None


class ScheduleRequest(BaseModel):
    backup_type: BackupType = BackupType.FULL
    frequency: str = "daily"
    retention_days: int = 30


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------


@router.post("", response_model=BackupRecord, status_code=201)
def create_backup(
    body: CreateBackupRequest,
    org_id: str = Depends(get_org_id),
) -> BackupRecord:
    """Create a new backup snapshot."""
    try:
        return _get_engine().create_backup(
            org_id=org_id,
            backup_type=body.backup_type,
            databases=body.databases,
            encrypt=body.encrypt,
            retention_days=body.retention_days,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("", response_model=List[BackupRecord])
def list_backups(
    type_filter: Optional[BackupType] = Query(None),
    org_id: str = Depends(get_org_id),
) -> List[BackupRecord]:
    """List all backups for the org."""
    return _get_engine().list_backups(org_id=org_id, type_filter=type_filter)


@router.get("/schedules", response_model=List[Dict[str, Any]])
def list_schedules(org_id: str = Depends(get_org_id)) -> List[Dict[str, Any]]:
    """List all backup schedules for the org."""
    return _get_engine().get_schedules(org_id=org_id)


@router.get("/stats", response_model=Dict[str, Any])
def backup_stats(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return backup statistics for the org."""
    return _get_engine().get_backup_stats(org_id=org_id)


@router.get("/{backup_id}", response_model=BackupRecord)
def get_backup(backup_id: str, org_id: str = Depends(get_org_id)) -> BackupRecord:
    """Get a specific backup record."""
    record = _get_engine().get_backup(backup_id)
    if record is None or record.org_id != org_id:
        raise HTTPException(status_code=404, detail="Backup not found")
    return record


@router.delete("/{backup_id}", status_code=204)
def delete_backup(backup_id: str, org_id: str = Depends(get_org_id)) -> None:
    """Delete a backup file and record."""
    record = _get_engine().get_backup(backup_id)
    if record is None or record.org_id != org_id:
        raise HTTPException(status_code=404, detail="Backup not found")
    try:
        _get_engine().delete_backup(backup_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/{backup_id}/verify", response_model=Dict[str, Any])
def verify_backup(backup_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Verify backup checksum integrity."""
    record = _get_engine().get_backup(backup_id)
    if record is None or record.org_id != org_id:
        raise HTTPException(status_code=404, detail="Backup not found")
    valid = _get_engine().verify_backup(backup_id)
    return {"backup_id": backup_id, "valid": valid}


@router.post("/{backup_id}/restore", response_model=RestoreRecord)
def restore_backup(
    backup_id: str,
    body: RestoreRequest,
    org_id: str = Depends(get_org_id),
) -> RestoreRecord:
    """Restore databases from a backup."""
    record = _get_engine().get_backup(backup_id)
    if record is None or record.org_id != org_id:
        raise HTTPException(status_code=404, detail="Backup not found")
    try:
        return _get_engine().restore_backup(
            backup_id=backup_id,
            target_databases=body.target_databases,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/schedule", response_model=Dict[str, Any], status_code=201)
def schedule_backup(
    body: ScheduleRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a recurring backup schedule."""
    return _get_engine().schedule_backup(
        org_id=org_id,
        backup_type=body.backup_type,
        frequency=body.frequency,
        retention_days=body.retention_days,
    )


@router.post("/cleanup", response_model=Dict[str, Any])
def cleanup_expired(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Remove backups that have exceeded their retention period."""
    removed = _get_engine().cleanup_expired(org_id=org_id)
    return {"org_id": org_id, "removed": removed}
