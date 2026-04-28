"""
Exception Policy API — ALDECI.

Provides REST endpoints for managing org-wide vulnerability exception/suppression
policies, including rule CRUD, batch evaluation, version publishing, rollback,
and suppression statistics.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from core.exception_policy import ExceptionPolicyEngine, ExceptionRule, MatchCriteria
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/v1/exceptions",
    tags=["exception-policy"],
    dependencies=[Depends(api_key_auth)],
)

# Single shared engine instance (SQLite is file-based, thread-safe via RLock)
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = ExceptionPolicyEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class AddRuleRequest(BaseModel):
    name: str
    description: str = ""
    criteria: MatchCriteria
    action: str = Field(..., description="suppress | downgrade | defer")
    downgrade_to: Optional[str] = None
    defer_days: Optional[int] = None
    expires_at: Optional[datetime] = None
    enabled: bool = True
    created_by: str = "api"


class UpdateRuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    criteria: Optional[Dict[str, Any]] = None
    action: Optional[str] = None
    downgrade_to: Optional[str] = None
    defer_days: Optional[int] = None
    expires_at: Optional[datetime] = None
    enabled: Optional[bool] = None


class EvaluateRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., min_length=1)


class PublishVersionRequest(BaseModel):
    published_by: str = "api"
    changelog: str = ""


class RollbackRequest(BaseModel):
    version: int = Field(..., ge=1)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/rules", response_model=Dict[str, Any], status_code=201)
async def add_rule(
    body: AddRuleRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new exception rule."""
    rule = ExceptionRule(
        name=body.name,
        description=body.description,
        criteria=body.criteria,
        action=body.action,
        downgrade_to=body.downgrade_to,
        defer_days=body.defer_days,
        expires_at=body.expires_at,
        enabled=body.enabled,
        created_by=body.created_by,
    )
    try:
        created = _get_engine().add_rule(rule, org_id=org_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return created.model_dump(mode="json")


@router.get("/rules", response_model=List[Dict[str, Any]])
async def list_rules(
    org_id: str = Depends(get_org_id),
    enabled_only: bool = Query(False, description="Return only enabled rules"),
) -> List[Dict[str, Any]]:
    """List all exception rules for the org."""
    rules = _get_engine().list_rules(org_id=org_id, enabled_only=enabled_only)
    return [r.model_dump(mode="json") for r in rules]


@router.put("/rules/{rule_id}", response_model=Dict[str, Any])
async def update_rule(
    rule_id: str,
    body: UpdateRuleRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Update an existing exception rule (increments rule version)."""
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields provided for update")
    try:
        updated = _get_engine().update_rule(rule_id, updates=updates, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return updated.model_dump(mode="json")


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    org_id: str = Depends(get_org_id),
) -> None:
    """Delete an exception rule permanently."""
    try:
        _get_engine().delete_rule(rule_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/evaluate", response_model=List[Dict[str, Any]])
async def evaluate(
    body: EvaluateRequest,
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Evaluate one or more findings against current exception rules."""
    return _get_engine().evaluate_batch(body.findings, org_id=org_id)


@router.post("/publish", response_model=Dict[str, Any], status_code=201)
async def publish_version(
    body: PublishVersionRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Publish a new policy version snapshot."""
    pv = _get_engine().publish_version(
        org_id=org_id,
        published_by=body.published_by,
        changelog=body.changelog,
    )
    return pv.model_dump(mode="json")


@router.get("/versions", response_model=List[Dict[str, Any]])
async def get_versions(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return version history for the org's exception policy."""
    history = _get_engine().get_version_history(org_id=org_id)
    return [pv.model_dump(mode="json") for pv in history]


@router.post("/rollback", status_code=200)
async def rollback(
    body: RollbackRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Rollback the org's exception rules to a previously published version."""
    try:
        _get_engine().rollback_to_version(org_id=org_id, version=body.version)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "ok", "rolled_back_to": body.version, "org_id": org_id}


@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return suppression statistics for the org."""
    return _get_engine().get_suppression_stats(org_id=org_id)
