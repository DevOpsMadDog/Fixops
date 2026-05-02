"""SecurityExceptionWorkflow Router — ALDECI.

Exposes endpoints for managing security policy exception requests,
reviews, renewals, revocations, and expiry tracking.

Prefix: /api/v1/exception-workflow
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/exception-workflow",
    tags=["Security Exception Workflow"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_exception_workflow_engine import (
            SecurityExceptionWorkflowEngine,
        )
        _engine = SecurityExceptionWorkflowEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateRequestModel(BaseModel):
    policy_name: str
    exception_type: str = "policy-waiver"
    requestor: str = ""
    business_justification: str = ""
    risk_description: str = ""
    compensating_controls: str = ""
    priority: str = "medium"
    expires_at: Optional[str] = None
    org_id: str = "default"


class ReviewRequestModel(BaseModel):
    reviewer: str
    decision: str  # approved / rejected / needs-info
    conditions: str = ""
    risk_rating: str = "medium"
    comments: str = ""
    org_id: str = "default"


class RenewRequestModel(BaseModel):
    renewed_by: str
    new_expiry: str
    reason: str = ""
    org_id: str = "default"


class RevokeRequestModel(BaseModel):
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/requests", dependencies=[Depends(api_key_auth)], status_code=201)
def create_request(body: CreateRequestModel):
    """Create a new exception request."""
    try:
        return _get_engine().create_request(
            org_id=body.org_id,
            policy_name=body.policy_name,
            exception_type=body.exception_type,
            requestor=body.requestor,
            business_justification=body.business_justification,
            risk_description=body.risk_description,
            compensating_controls=body.compensating_controls,
            priority=body.priority,
            expires_at=body.expires_at,
        )
    except Exception as exc:
        logger.error("create_request failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/requests/{request_id}/review", dependencies=[Depends(api_key_auth)])
def review_request(request_id: str, body: ReviewRequestModel):
    """Review an exception request (approve/reject/needs-info)."""
    try:
        return _get_engine().review_request(
            request_id=request_id,
            org_id=body.org_id,
            reviewer=body.reviewer,
            decision=body.decision,
            conditions=body.conditions,
            risk_rating=body.risk_rating,
            comments=body.comments,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error("review_request failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/requests/{request_id}/renew", dependencies=[Depends(api_key_auth)])
def renew_exception(request_id: str, body: RenewRequestModel):
    """Renew an exception with a new expiry date."""
    try:
        return _get_engine().renew_exception(
            request_id=request_id,
            org_id=body.org_id,
            renewed_by=body.renewed_by,
            new_expiry=body.new_expiry,
            reason=body.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("renew_exception failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/requests/{request_id}/revoke", dependencies=[Depends(api_key_auth)])
def revoke_exception(request_id: str, body: RevokeRequestModel):
    """Revoke an approved exception."""
    try:
        return _get_engine().revoke_exception(request_id=request_id, org_id=body.org_id)
    except Exception as exc:
        logger.error("revoke_exception failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/requests/{request_id}", dependencies=[Depends(api_key_auth)])
def get_request(request_id: str, org_id: str = Query("default")):
    """Get a single exception request with reviews and renewals."""
    result = _get_engine().get_request(request_id=request_id, org_id=org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Request not found")
    return result


@router.get("/requests", dependencies=[Depends(api_key_auth)])
def list_requests(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
    exception_type: Optional[str] = Query(None),
):
    """List exception requests with optional filters."""
    return _get_engine().list_requests(org_id=org_id, status=status, exception_type=exception_type)


@router.get("/expiring", dependencies=[Depends(api_key_auth)])
def get_expiring(org_id: str = Query("default"), days_ahead: int = Query(30)):
    """Get approved exceptions expiring within days_ahead."""
    return _get_engine().get_expiring_exceptions(org_id=org_id, days_ahead=days_ahead)


@router.get("/expired", dependencies=[Depends(api_key_auth)])
def get_expired(org_id: str = Query("default")):
    """Get approved exceptions that have already expired."""
    return _get_engine().get_expired_exceptions(org_id=org_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_summary(org_id: str = Query("default")):
    """Get exception summary stats for the org."""
    return _get_engine().get_exception_summary(org_id=org_id)
