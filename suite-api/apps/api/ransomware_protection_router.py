"""Ransomware Protection Router — ALDECI.

Endpoints for the Ransomware Protection engine.

Prefix: /api/v1/ransomware-protection
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/ransomware-protection/detections                  register_detection
  GET   /api/v1/ransomware-protection/detections                  list_detections
  POST  /api/v1/ransomware-protection/detections/{id}/contain     update_containment
  POST  /api/v1/ransomware-protection/backups                     register_backup
  GET   /api/v1/ransomware-protection/backups                     list_backups (via status)
  POST  /api/v1/ransomware-protection/backups/{id}/validate       validate_backup
  GET   /api/v1/ransomware-protection/unvalidated-backups         get_unvalidated_backups
  POST  /api/v1/ransomware-protection/playbooks                   create_playbook
  POST  /api/v1/ransomware-protection/playbooks/{id}/execute      execute_playbook
  GET   /api/v1/ransomware-protection/status                      get_protection_status
  GET   /api/v1/ransomware-protection/summary                     get_summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ransomware-protection",
    tags=["Ransomware Protection"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ransomware_protection_engine import RansomwareProtectionEngine
        _engine = RansomwareProtectionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DetectionCreate(BaseModel):
    org_id: str
    detection_name: str
    detection_type: str = "behavioral"
    affected_systems: List[str] = []
    file_extensions: List[str] = []
    confidence: float = 0.5
    severity: str = "high"


class ContainmentUpdate(BaseModel):
    org_id: str
    containment_status: str


class BackupCreate(BaseModel):
    org_id: str
    system_name: str
    backup_type: str = "full"
    backup_location: str = ""
    immutable: bool = False
    encrypted: bool = False
    retention_days: int = 30


class BackupValidate(BaseModel):
    org_id: str
    validation_status: str
    recovery_time_mins: int = 0


class PlaybookCreate(BaseModel):
    org_id: str
    playbook_name: str
    trigger_type: str = "manual"
    steps: List[Any] = []
    estimated_mins: int = 60


class PlaybookExecute(BaseModel):
    org_id: str


class RaaSGroupCreate(BaseModel):
    org_id: str
    group_name: str
    aliases: List[str] = []
    active_since: Optional[str] = None
    extortion_model: str = "double"
    avg_ransom_usd: int = 0
    known_sectors: List[str] = []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_ransomware_protection(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get ransomware protection summary for the org."""
    return _get_engine().get_summary(org_id=org_id)


@router.post("/detections")
def register_detection(body: DetectionCreate) -> Dict[str, Any]:
    try:
        return _get_engine().register_detection(
            org_id=body.org_id,
            detection_name=body.detection_name,
            detection_type=body.detection_type,
            affected_systems=body.affected_systems,
            file_extensions=body.file_extensions,
            confidence=body.confidence,
            severity=body.severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/detections")
def list_detections(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    return _get_engine().list_detections(org_id=org_id, status=status)


@router.post("/detections/{detection_id}/contain")
def update_containment(detection_id: str, body: ContainmentUpdate) -> Dict[str, Any]:
    try:
        return _get_engine().update_containment(
            detection_id=detection_id,
            org_id=body.org_id,
            containment_status=body.containment_status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/backups")
def register_backup(body: BackupCreate) -> Dict[str, Any]:
    try:
        return _get_engine().register_backup(
            org_id=body.org_id,
            system_name=body.system_name,
            backup_type=body.backup_type,
            backup_location=body.backup_location,
            immutable=body.immutable,
            encrypted=body.encrypted,
            retention_days=body.retention_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/backups")
def list_backups(
     org_id: str = Query(default="default"),
    system_name: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    eng = _get_engine()
    import sqlite3
    conn = sqlite3.connect(eng._db_path)
    conn.row_factory = sqlite3.Row
    if system_name:
        rows = conn.execute(
            "SELECT * FROM backup_validations WHERE org_id=? AND system_name=? ORDER BY created_at DESC",
            (org_id, system_name),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM backup_validations WHERE org_id=? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.post("/backups/{backup_id}/validate")
def validate_backup(backup_id: str, body: BackupValidate) -> Dict[str, Any]:
    try:
        return _get_engine().validate_backup(
            backup_id=backup_id,
            org_id=body.org_id,
            validation_status=body.validation_status,
            recovery_time_mins=body.recovery_time_mins,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/unvalidated-backups")
def get_unvalidated_backups(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().get_unvalidated_backups(org_id=org_id)


@router.post("/playbooks")
def create_playbook(body: PlaybookCreate) -> Dict[str, Any]:
    try:
        return _get_engine().create_playbook(
            org_id=body.org_id,
            playbook_name=body.playbook_name,
            trigger_type=body.trigger_type,
            steps=body.steps,
            estimated_mins=body.estimated_mins,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/playbooks/{playbook_id}/execute")
def execute_playbook(playbook_id: str, body: PlaybookExecute) -> Dict[str, Any]:
    try:
        return _get_engine().execute_playbook(
            playbook_id=playbook_id,
            org_id=body.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/status")
def get_protection_status(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_protection_status(org_id=org_id)


@router.get("/summary")
def get_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_summary(org_id=org_id)


@router.get("/raas-groups")
def list_raas_groups(
    org_id: str = Query(default="default"),
    active_only: bool = Query(default=True),
) -> List[Dict[str, Any]]:
    """List tracked RaaS / extortion groups for the org."""
    return _get_engine().list_raas_groups(org_id=org_id, active_only=active_only)


@router.post("/raas-groups")
def register_raas_group(body: RaaSGroupCreate) -> Dict[str, Any]:
    """Register a new RaaS threat actor group with extortion intel."""
    try:
        return _get_engine().register_raas_group(
            org_id=body.org_id,
            group_name=body.group_name,
            aliases=body.aliases,
            active_since=body.active_since,
            extortion_model=body.extortion_model,
            avg_ransom_usd=body.avg_ransom_usd,
            known_sectors=body.known_sectors,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/raas-groups/{group_id}/deactivate")
def deactivate_raas_group(
    group_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Mark a RaaS group as no longer active."""
    try:
        return _get_engine().deactivate_raas_group(group_id=group_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
