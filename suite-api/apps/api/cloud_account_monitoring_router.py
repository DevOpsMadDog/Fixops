"""Cloud Account Monitoring Router — ALDECI.

Endpoints for the Cloud Account Monitoring engine.

Prefix: /api/v1/cloud-accounts
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/cloud-accounts/accounts                              register_account
  GET  /api/v1/cloud-accounts/accounts                              list_accounts
  GET  /api/v1/cloud-accounts/accounts/{account_id}                get_account
  POST /api/v1/cloud-accounts/accounts/{account_id}/scan            update_account_scan
  POST /api/v1/cloud-accounts/accounts/{account_id}/events          record_event
  POST /api/v1/cloud-accounts/accounts/{account_id}/events/{event_id}/resolve  resolve_event
  POST /api/v1/cloud-accounts/policies                              create_policy
  POST /api/v1/cloud-accounts/policies/{policy_id}/evaluate         evaluate_policy
  GET  /api/v1/cloud-accounts/risk-summary                          get_risk_summary
  GET  /api/v1/cloud-accounts/events/unresolved                     get_unresolved_events
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-accounts",
    tags=["Cloud Account Monitoring"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_account_monitoring_engine import CloudAccountMonitoringEngine
        _engine = CloudAccountMonitoringEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AccountRegister(BaseModel):
    account_id: str
    account_name: str
    provider: str
    region: str = ""


class ScanUpdate(BaseModel):
    findings_count: int
    risk_score: float


class EventCreate(BaseModel):
    event_type: str
    severity: str
    resource: str = ""
    description: str = ""


class PolicyCreate(BaseModel):
    policy_name: str
    policy_type: str
    scope: str = ""


class PolicyEvaluate(BaseModel):
    violation_count: int


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_cloud_accounts_root(
    org_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    provider: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List registered cloud accounts (root endpoint for hub/landing pages)."""
    items = _get_engine().list_accounts(org_id, provider=provider, status=status)
    paged = items[offset : offset + limit]
    return {
        "items": paged,
        "total": len(items),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

@router.post("/accounts", dependencies=[Depends(api_key_auth)], status_code=201)
def register_account(body: AccountRegister, org_id: str = Query(default="default")):
    """Register a new cloud account."""
    try:
        return _get_engine().register_account(
            org_id,
            body.account_id,
            body.account_name,
            body.provider,
            body.region,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/accounts", dependencies=[Depends(api_key_auth)])
def list_accounts(
     org_id: str = Query(default="default"),
    provider: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List cloud accounts with optional provider/status filters."""
    return _get_engine().list_accounts(org_id, provider=provider, status=status)


@router.get("/accounts/{account_id}", dependencies=[Depends(api_key_auth)])
def get_account(account_id: str, org_id: str = Query(default="default")):
    """Get a cloud account with its recent events."""
    account = _get_engine().get_account(account_id, org_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return account


@router.post("/accounts/{account_id}/scan", dependencies=[Depends(api_key_auth)])
def update_account_scan(account_id: str, body: ScanUpdate, org_id: str = Query(default="default")):
    """Update scan results for a cloud account."""
    try:
        return _get_engine().update_account_scan(
            account_id, org_id, body.findings_count, body.risk_score
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@router.post("/accounts/{account_id}/events", dependencies=[Depends(api_key_auth)], status_code=201)
def record_event(account_id: str, body: EventCreate, org_id: str = Query(default="default")):
    """Record a security event for a cloud account."""
    try:
        return _get_engine().record_event(
            account_id,
            org_id,
            body.event_type,
            body.severity,
            body.resource,
            body.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/accounts/{account_id}/events/{event_id}/resolve",
    dependencies=[Depends(api_key_auth)],
)
def resolve_event(account_id: str, event_id: str, org_id: str = Query(default="default")):
    """Resolve a security event."""
    try:
        return _get_engine().resolve_event(account_id, event_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/events/unresolved", dependencies=[Depends(api_key_auth)])
def get_unresolved_events(
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
):
    """Get unresolved events, optionally filtered by severity."""
    return _get_engine().get_unresolved_events(org_id, severity=severity)


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@router.post("/policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_policy(body: PolicyCreate, org_id: str = Query(default="default")):
    """Create an account security policy."""
    try:
        return _get_engine().create_policy(
            org_id, body.policy_name, body.policy_type, body.scope
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/policies/{policy_id}/evaluate", dependencies=[Depends(api_key_auth)])
def evaluate_policy(policy_id: str, body: PolicyEvaluate, org_id: str = Query(default="default")):
    """Evaluate a policy and update its violation count."""
    try:
        return _get_engine().evaluate_policy(policy_id, org_id, body.violation_count)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Risk Summary
# ---------------------------------------------------------------------------

@router.get("/risk-summary", dependencies=[Depends(api_key_auth)])
def get_risk_summary(org_id: str = Query(default="default")):
    """Return per-provider risk summary."""
    return _get_engine().get_account_risk_summary(org_id)
