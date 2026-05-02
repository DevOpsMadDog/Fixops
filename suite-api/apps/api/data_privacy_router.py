"""Data Privacy Router — Privacy asset and DSR management API for ALDECI.

Prefix: /api/v1/data-privacy
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/data-privacy/assets                         register_data_asset
  GET    /api/v1/data-privacy/assets                         list_data_assets
  GET    /api/v1/data-privacy/assets/{asset_id}              get_data_asset
  POST   /api/v1/data-privacy/requests                       record_privacy_request
  GET    /api/v1/data-privacy/requests                       list_privacy_requests
  PUT    /api/v1/data-privacy/requests/{request_id}/status   update_request_status
  GET    /api/v1/data-privacy/stats                          get_privacy_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/data-privacy", tags=["Data Privacy"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.data_privacy_engine import DataPrivacyEngine
        _engine = DataPrivacyEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class DataAssetReq(BaseModel):
    org_id: str
    name: str
    data_category: str
    classification: str = "internal"
    description: Optional[str] = None
    location: Optional[str] = None
    data_owner: Optional[str] = None
    retention_days: Optional[int] = None


class PrivacyRequestReq(BaseModel):
    org_id: str
    request_type: str
    subject_email: str
    notes: Optional[str] = None


class RequestStatusReq(BaseModel):
    org_id: str
    status: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Asset endpoints
# ---------------------------------------------------------------------------


@router.post("/assets", status_code=201)
def register_data_asset(body: DataAssetReq, _auth=Depends(api_key_auth)) -> Dict[str, Any]:
    from core.data_privacy_engine import DataAssetCreate
    try:
        data = DataAssetCreate(
            name=body.name,
            data_category=body.data_category,
            classification=body.classification,
            description=body.description,
            location=body.location,
            data_owner=body.data_owner,
            retention_days=body.retention_days,
        )
        return _get_engine().register_data_asset(body.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("data_privacy.register_asset error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/assets")
def list_data_assets(
     org_id: str = Query(default="default"),
    data_category: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_data_assets(
            org_id, data_category=data_category, classification=classification
        )
    except Exception as exc:
        _logger.error("data_privacy.list_assets error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/assets/{asset_id}")
def get_data_asset(
    asset_id: str,
     org_id: str = Query(default="default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_data_asset(org_id, asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.error("data_privacy.get_asset error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Privacy request endpoints
# ---------------------------------------------------------------------------


@router.post("/requests", status_code=201)
def record_privacy_request(body: PrivacyRequestReq, _auth=Depends(api_key_auth)) -> Dict[str, Any]:
    from core.data_privacy_engine import PrivacyRequestCreate
    try:
        data = PrivacyRequestCreate(
            request_type=body.request_type,
            subject_email=body.subject_email,
            notes=body.notes,
        )
        return _get_engine().record_privacy_request(body.org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("data_privacy.record_request error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/requests")
def list_privacy_requests(
     org_id: str = Query(default="default"),
    request_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    _auth=Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_privacy_requests(
            org_id, request_type=request_type, status=status
        )
    except Exception as exc:
        _logger.error("data_privacy.list_requests error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/requests/{request_id}/status")
def update_request_status(
    request_id: str,
    body: RequestStatusReq,
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().update_request_status(
            body.org_id, request_id, body.status, body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.error("data_privacy.update_status error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_privacy_stats(
     org_id: str = Query(default="default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_privacy_stats(org_id)
    except Exception as exc:
        _logger.error("data_privacy.stats error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------


@router.get("/")
def get_data_privacy_summary(
    org_id: str = Query(default="default"),
    _auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """Return a 5-state summary envelope for the data-privacy domain.

    States:
      healthy   — assets registered, no overdue requests
      degraded  — pending/overdue requests exist
      empty     — fresh tenant, no assets yet (onboarding hint included)
      error     — engine raised an exception
      unknown   — stats structure unexpected
    """
    try:
        stats = _get_engine().get_privacy_stats(org_id)
    except Exception as exc:
        _logger.error("data_privacy.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "data-privacy",
        }

    total_assets = stats.get("total_assets", 0)
    overdue = stats.get("overdue_requests", 0)
    pending = stats.get("pending_requests", 0)

    if total_assets == 0:
        status = "empty"
    elif overdue > 0:
        status = "degraded"
    elif pending > 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope: Dict[str, Any] = {
        "status": status,
        "org_id": org_id,
        "domain": "data-privacy",
        "stats": stats,
    }
    if status == "empty":
        envelope["hint"] = (
            "Register data assets via POST /api/v1/data-privacy/assets "
            "to begin privacy asset tracking."
        )
    return envelope
