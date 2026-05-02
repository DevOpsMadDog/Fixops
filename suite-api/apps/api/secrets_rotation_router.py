"""Secrets Rotation Tracker API Router.

Tracks the lifecycle of exposed secret remediation: registration, assignment,
rotation confirmation, verification, failure, and deferral.

Prefix: /api/v1/secrets-rotation
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.secrets_rotation_tracker import (
    ROTATION_STATES,
    SECRET_TYPES,
    SecretsRotationTracker,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/secrets-rotation", tags=["Secrets Rotation"])

_tracker = SecretsRotationTracker()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ExposeRequest(BaseModel):
    secret_type: str = Field(..., description=f"One of: {SECRET_TYPES}")
    exposed_location: str = Field(..., description="File path, URL, or commit hash where secret was found")
    detection_source: str = Field(default="scanner", description="Tool that detected the secret")
    severity: str = Field(default="high", description="critical | high | medium | low")


class StartRequest(BaseModel):
    assignee: str = Field(..., description="Username/email of person assigned to rotate")


class ConfirmRequest(BaseModel):
    rotated_by: str = Field(..., description="Username/email of person who rotated")
    new_secret_hash: Optional[str] = Field(
        None, description="SHA-256 hash of the new secret (not the value itself)"
    )


class VerifyRequest(BaseModel):
    verifier: str = Field(..., description="Username/email of verifier")
    notes: str = Field(default="", description="Verification notes")


class FailRequest(BaseModel):
    reason: str = Field(..., description="Reason rotation failed")


class DeferRequest(BaseModel):
    reason: str = Field(..., description="Justification for deferral")
    defer_until: str = Field(..., description="ISO-8601 datetime until which rotation is deferred")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/expose", summary="Register an exposed secret for rotation tracking")
async def register_exposure(
    body: ExposeRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register a newly detected exposed secret. Returns rotation record with SLA deadline."""
    try:
        return _tracker.register_exposure(
            secret_type=body.secret_type,
            exposed_location=body.exposed_location,
            detection_source=body.detection_source,
            severity=body.severity,
            org_id=org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{rotation_id}/start", summary="Mark rotation as in-progress")
async def start_rotation(
    rotation_id: str,
    body: StartRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Assign and start the rotation process for a registered exposure."""
    try:
        return _tracker.start_rotation(rotation_id, assignee=body.assignee)
    except ValueError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.post("/{rotation_id}/confirm", summary="Confirm secret has been rotated")
async def confirm_rotation(
    rotation_id: str,
    body: ConfirmRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Record that the secret has been rotated. Stores hash of new secret, not its value."""
    try:
        return _tracker.confirm_rotation(
            rotation_id,
            rotated_by=body.rotated_by,
            new_secret_hash=body.new_secret_hash,
        )
    except ValueError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.post("/{rotation_id}/verify", summary="Mark rotation as verified")
async def verify_rotation(
    rotation_id: str,
    body: VerifyRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Verify the scanner no longer detects the old secret. Closes the rotation."""
    try:
        return _tracker.verify_rotation(
            rotation_id, verifier=body.verifier, notes=body.notes
        )
    except ValueError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.post("/{rotation_id}/fail", summary="Mark rotation as failed")
async def fail_rotation(
    rotation_id: str,
    body: FailRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Record a rotation failure with a reason. Can be retried by transitioning back to pending."""
    try:
        return _tracker.fail_rotation(rotation_id, reason=body.reason)
    except ValueError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.post("/{rotation_id}/defer", summary="Defer rotation with justification")
async def defer_rotation(
    rotation_id: str,
    body: DeferRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Defer rotation (e.g., awaiting maintenance window). Requires documented reason."""
    try:
        return _tracker.defer_rotation(
            rotation_id, reason=body.reason, defer_until=body.defer_until
        )
    except ValueError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.get("/overdue", summary="List overdue rotations")
async def get_overdue(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return all rotations that have passed their SLA deadline and are still pending/in_progress."""
    return _tracker.get_overdue(org_id=org_id)


@router.get("/metrics", summary="Rotation metrics for the org")
async def get_metrics(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregated rotation metrics: totals, by state, by type, overdue count, avg time."""
    return _tracker.get_metrics(org_id=org_id)


@router.get("/", summary="List rotation records")
async def list_rotations(
    state: Optional[str] = Query(None, description=f"Filter by state: {ROTATION_STATES}"),
    secret_type: Optional[str] = Query(None, description=f"Filter by type: {SECRET_TYPES}"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List all rotation records for the org, optionally filtered by state or secret type."""
    return _tracker.list_rotations(org_id=org_id, state=state, secret_type=secret_type)


@router.get("/{rotation_id}/audit", summary="Get audit trail for a rotation")
async def get_audit_trail(
    rotation_id: str,
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return the full state-transition history for a rotation record."""
    trail = _tracker.get_audit_trail(rotation_id)
    if not trail:
        # Check if rotation exists at all
        record = _tracker.get_rotation(rotation_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Rotation {rotation_id!r} not found")
    return trail


@router.get("/{rotation_id}", summary="Get a rotation record")
async def get_rotation(
    rotation_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Retrieve a single rotation record by ID."""
    record = _tracker.get_rotation(rotation_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Rotation {rotation_id!r} not found")
    return record
