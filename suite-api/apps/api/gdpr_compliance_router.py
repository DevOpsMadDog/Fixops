"""GDPR Compliance Router — Processing activities and consent management API for ALDECI.

Prefix: /api/v1/gdpr
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/gdpr/activities                              record_processing_activity
  GET    /api/v1/gdpr/activities                              list_processing_activities
  POST   /api/v1/gdpr/consents                                record_consent
  GET    /api/v1/gdpr/consents                                list_consents
  PUT    /api/v1/gdpr/consents/{consent_id}/withdraw          withdraw_consent
  GET    /api/v1/gdpr/assessment                              run_gdpr_assessment
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/gdpr", tags=["GDPR Compliance"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.gdpr_compliance_engine import GDPRComplianceEngine
        _engine = GDPRComplianceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ProcessingActivityReq(BaseModel):
    org_id: str = Query(default="default")
    name: str
    purpose: str
    lawful_basis: str
    data_categories: List[str] = Field(default_factory=list)
    recipients: List[str] = Field(default_factory=list)
    retention_period: Optional[str] = None


class ConsentReq(BaseModel):
    org_id: str = Query(default="default")
    subject_id: str
    purpose: str
    expires_at: Optional[str] = None


class WithdrawReq(BaseModel):
    org_id: str = Query(default="default")
    reason: str = ""


# ---------------------------------------------------------------------------
# Processing activity endpoints
# ---------------------------------------------------------------------------


@router.post("/activities", status_code=201)
def record_processing_activity(body: ProcessingActivityReq, _auth=Depends(api_key_auth)) -> Dict[str, Any]:
    from core.gdpr_compliance_engine import ProcessingActivityCreate
    try:
        data = ProcessingActivityCreate(
            name=body.name,
            purpose=body.purpose,
            lawful_basis=body.lawful_basis,
            data_categories=body.data_categories,
            recipients=body.recipients,
            retention_period=body.retention_period,
        )
        return _get_engine().record_processing_activity(body.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("gdpr.record_activity error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/activities")
def list_processing_activities(
     org_id: str = Query(default="default"),
    lawful_basis: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_processing_activities(
            org_id, lawful_basis=lawful_basis, status=status
        )
    except Exception as exc:
        _logger.error("gdpr.list_activities error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Consent endpoints
# ---------------------------------------------------------------------------


@router.post("/consents", status_code=201)
def record_consent(body: ConsentReq, _auth=Depends(api_key_auth)) -> Dict[str, Any]:
    from core.gdpr_compliance_engine import ConsentCreate
    try:
        data = ConsentCreate(
            subject_id=body.subject_id,
            purpose=body.purpose,
            expires_at=body.expires_at,
        )
        return _get_engine().record_consent(body.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("gdpr.record_consent error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/consents")
def list_consents(
     org_id: str = Query(default="default"),
    subject_id: Optional[str] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_consents(org_id, subject_id=subject_id)
    except Exception as exc:
        _logger.error("gdpr.list_consents error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/consents/{consent_id}/withdraw")
def withdraw_consent(
    consent_id: str,
    body: WithdrawReq,
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().withdraw_consent(body.org_id, consent_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.error("gdpr.withdraw_consent error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Assessment endpoint
# ---------------------------------------------------------------------------


@router.get("/assessment")
def run_gdpr_assessment(
     org_id: str = Query(default="default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().run_gdpr_assessment(org_id)
    except Exception as exc:
        _logger.error("gdpr.assessment error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
