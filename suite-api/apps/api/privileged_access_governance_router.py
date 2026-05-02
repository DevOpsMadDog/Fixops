"""Privileged Access Governance Router — ALDECI.

Endpoints for the Privileged Access Governance engine.

Prefix: /api/v1/pag
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/pag/accounts                        register_privileged_account
  GET  /api/v1/pag/accounts                        list_privileged_accounts
  GET  /api/v1/pag/accounts/{account_id}           get_privileged_account
  POST /api/v1/pag/accounts/{account_id}/sessions  record_access_session
  GET  /api/v1/pag/sessions                        list_sessions
  POST /api/v1/pag/accounts/{account_id}/anomalies flag_anomaly
  GET  /api/v1/pag/anomalies                       list_anomalies
  GET  /api/v1/pag/stats                           get_pag_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/pag",
    tags=["Privileged Access Governance"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.privileged_access_governance_engine import (
            PrivilegedAccessGovernanceEngine,
        )
        _engine = PrivilegedAccessGovernanceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AccountCreate(BaseModel):
    username: str
    account_type: str = "service"
    system: str = ""
    owner: str = ""
    justification: str = ""


class SessionCreate(BaseModel):
    accessed_by: str = ""
    system: str = ""
    duration_minutes: int = 0
    commands_executed: int = 0
    justification: str = ""
    approved_by: str = ""
    session_at: Optional[str] = None


class AnomalyCreate(BaseModel):
    anomaly_type: str = "off_hours"
    severity: str = "medium"
    description: str = ""
    detected_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

@router.post("/accounts", dependencies=[Depends(api_key_auth)], status_code=201)
def register_privileged_account(body: AccountCreate, org_id: str = Query(default="default")):
    """Register a new privileged account."""
    try:
        return _get_engine().register_privileged_account(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/accounts", dependencies=[Depends(api_key_auth)])
def list_privileged_accounts(
     org_id: str = Query(default="default"),
    account_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List privileged accounts with optional filters.

    Falls back to live Okta sync (privileged users only) when the org has
    no registered accounts AND ``OKTA_API_KEY`` / ``OKTA_DOMAIN`` env vars
    are set. Returns ``{accounts, total, source, hint?}``.
    """
    return _get_engine().list_privileged_accounts_with_okta_fallback(
        org_id,
        account_type=account_type,
        status=status,
    )


@router.get("/accounts/{account_id}", dependencies=[Depends(api_key_auth)])
def get_privileged_account(account_id: str, org_id: str = Query(default="default")):
    """Get a single privileged account by ID."""
    result = _get_engine().get_privileged_account(org_id, account_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Privileged account not found")
    return result


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

@router.post(
    "/accounts/{account_id}/sessions",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def record_access_session(
    account_id: str, body: SessionCreate, org_id: str = Query(default="default")
):
    """Record an access session for a privileged account."""
    return _get_engine().record_access_session(org_id, account_id, body.model_dump())


@router.get("/sessions", dependencies=[Depends(api_key_auth)])
def list_sessions(
     org_id: str = Query(default="default"),
    account_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List access sessions with optional filters."""
    return _get_engine().list_sessions(
        org_id,
        account_id=account_id,
        status=status,
    )


# ---------------------------------------------------------------------------
# Anomalies
# ---------------------------------------------------------------------------

@router.post(
    "/accounts/{account_id}/anomalies",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def flag_anomaly(
    account_id: str, body: AnomalyCreate, org_id: str = Query(default="default")
):
    """Flag a behavioral anomaly on a privileged account."""
    try:
        return _get_engine().flag_anomaly(org_id, account_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/anomalies", dependencies=[Depends(api_key_auth)])
def list_anomalies(
     org_id: str = Query(default="default"),
    account_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List anomalies with optional filters."""
    return _get_engine().list_anomalies(
        org_id,
        account_id=account_id,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_pag_stats(org_id: str = Query(default="default")):
    """Return aggregated privileged access governance statistics."""
    return _get_engine().get_pag_stats(org_id)
