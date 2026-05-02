"""Cloud Access Security Broker (CASB) API Router.

Endpoints under /api/v1/casb:
  GET    /api/v1/casb/apps                        — list cloud apps
  POST   /api/v1/casb/apps                        — discover/register an app
  POST   /api/v1/casb/apps/{app_id}/sanction      — sanction an app
  POST   /api/v1/casb/apps/{app_id}/unsanction    — unsanction (shadow IT) an app
  GET    /api/v1/casb/data-activities             — list data activities
  POST   /api/v1/casb/data-activities             — record a data activity
  GET    /api/v1/casb/policies                    — list CASB policies
  POST   /api/v1/casb/policies                    — create a CASB policy
  GET    /api/v1/casb/violations                  — list policy violations
  POST   /api/v1/casb/violations                  — record a policy violation
  GET    /api/v1/casb/shadow-it-report            — shadow IT discovery report
  GET    /api/v1/casb/stats                       — aggregated CASB statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.casb_engine import CASBEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/casb",
    tags=["casb"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Singleton engine
# ---------------------------------------------------------------------------

_engine: Optional[CASBEngine] = None


def _get_engine() -> CASBEngine:
    global _engine
    if _engine is None:
        _engine = CASBEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class DiscoverAppRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    app_name: str = Field(..., description="Cloud application name (e.g. 'Dropbox')")
    app_category: str = Field(
        "other",
        description="Category: productivity/collaboration/storage/crm/devtools/social/other",
    )
    risk_level: str = Field(
        "medium", description="Risk level: critical/high/medium/low"
    )
    users_count: int = Field(0, ge=0, description="Number of users using the app")
    data_uploaded_gb: float = Field(0.0, ge=0.0, description="Data uploaded in GB")
    is_sanctioned: bool = Field(False, description="Whether the app is sanctioned")
    oauth_scopes: List[str] = Field(
        default_factory=list, description="OAuth permission scopes granted"
    )


class SanctionRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    sanctioned_by: str = Field(..., description="Identity of approver")


class UnsanctionRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    reason: str = Field(..., description="Reason for unsanctioning (blocking)")


class RecordActivityRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    app_name: str = Field(..., description="Cloud application name")
    user: str = Field(..., description="User identifier (email or username)")
    activity_type: str = Field(
        ..., description="Activity type: upload/download/share/delete"
    )
    file_type: str = Field("", description="File MIME type or extension")
    size_bytes: int = Field(0, ge=0, description="Size of data transferred in bytes")
    destination: str = Field(
        "internal", description="Destination: internal/external/public"
    )
    data_classification: str = Field(
        "internal",
        description="Data classification: public/internal/confidential/secret",
    )


class CreatePolicyRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    name: str = Field(..., description="Policy name")
    policy_type: str = Field(
        ..., description="Policy type: data_loss/app_block/oauth_restrict"
    )
    conditions: Dict[str, Any] = Field(
        default_factory=dict, description="Policy condition parameters"
    )
    action: str = Field("alert", description="Enforcement action: block/alert/encrypt")


class RecordViolationRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    policy_id: str = Field(..., description="ID of the violated policy")
    user: str = Field(..., description="User who triggered the violation")
    app_name: str = Field(..., description="App involved in the violation")
    violation_detail: str = Field("", description="Detailed description of violation")
    severity: str = Field(
        "medium", description="Severity: critical/high/medium/low/info"
    )


# ---------------------------------------------------------------------------
# Endpoints — Apps
# ---------------------------------------------------------------------------


@router.get("/apps", summary="List cloud apps")
def list_apps(
    org_id: str = Query("default", description="Organisation ID"),
    category: Optional[str] = Query(None, description="Filter by app category"),
    is_sanctioned: Optional[bool] = Query(None, description="Filter by sanction status"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
) -> List[Dict[str, Any]]:
    """List discovered cloud applications with optional filters."""
    return _get_engine().list_apps(
        org_id,
        category=category,
        is_sanctioned=is_sanctioned,
        risk_level=risk_level,
    )


@router.post("/apps", summary="Discover/register a cloud app")
def discover_app(req: DiscoverAppRequest) -> Dict[str, Any]:
    """Register or update a discovered cloud application."""
    try:
        return _get_engine().discover_app(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to discover app: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to discover app: {exc}") from exc


@router.post("/apps/{app_id}/sanction", summary="Sanction a cloud app")
def sanction_app(app_id: str, req: SanctionRequest) -> Dict[str, Any]:
    """Mark a cloud app as sanctioned (approved for use)."""
    try:
        return _get_engine().sanction_app(req.org_id, app_id, req.sanctioned_by)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to sanction app: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to sanction app: {exc}") from exc


@router.post("/apps/{app_id}/unsanction", summary="Unsanction a cloud app")
def unsanction_app(app_id: str, req: UnsanctionRequest) -> Dict[str, Any]:
    """Mark a cloud app as unsanctioned (shadow IT / blocked)."""
    try:
        return _get_engine().unsanction_app(req.org_id, app_id, req.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to unsanction app: %s", exc)
        raise HTTPException(
            status_code=500, detail=f"Failed to unsanction app: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Endpoints — Data activities
# ---------------------------------------------------------------------------


@router.get("/data-activities", summary="List data activities")
def list_data_activities(
    org_id: str = Query("default", description="Organisation ID"),
    app_name: Optional[str] = Query(None, description="Filter by app name"),
    data_classification: Optional[str] = Query(
        None, description="Filter by data classification"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Max records to return"),
) -> List[Dict[str, Any]]:
    """List cloud data activities with optional filters."""
    return _get_engine().list_data_activities(
        org_id,
        app_name=app_name,
        data_classification=data_classification,
        limit=limit,
    )


@router.post("/data-activities", summary="Record a data activity")
def record_data_activity(req: RecordActivityRequest) -> Dict[str, Any]:
    """Record a data activity event (upload/download/share/delete)."""
    try:
        return _get_engine().record_data_activity(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to record data activity: %s", exc)
        raise HTTPException(
            status_code=500, detail=f"Failed to record data activity: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Endpoints — Policies
# ---------------------------------------------------------------------------


@router.get("/policies", summary="List CASB policies")
def list_policies(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    """List all CASB policies for the organisation."""
    return _get_engine().list_policies(org_id)


@router.post("/policies", summary="Create a CASB policy")
def create_policy(req: CreatePolicyRequest) -> Dict[str, Any]:
    """Create a new CASB policy (data_loss/app_block/oauth_restrict)."""
    try:
        return _get_engine().create_policy(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create policy: %s", exc)
        raise HTTPException(
            status_code=500, detail=f"Failed to create policy: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Endpoints — Violations
# ---------------------------------------------------------------------------


@router.get("/violations", summary="List policy violations")
def list_violations(
    org_id: str = Query("default", description="Organisation ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
) -> List[Dict[str, Any]]:
    """List CASB policy violations with optional severity filter."""
    return _get_engine().list_violations(org_id, severity=severity, limit=limit)


@router.post("/violations", summary="Record a policy violation")
def record_violation(req: RecordViolationRequest) -> Dict[str, Any]:
    """Record a CASB policy violation event."""
    try:
        return _get_engine().record_policy_violation(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to record violation: %s", exc)
        raise HTTPException(
            status_code=500, detail=f"Failed to record violation: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Endpoints — Reports
# ---------------------------------------------------------------------------


@router.get("/shadow-it-report", summary="Shadow IT discovery report")
def shadow_it_report(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return shadow IT discovery report: total apps, sanctioned/unsanctioned breakdown,
    high-risk apps, and top data uploaders."""
    return _get_engine().get_shadow_it_report(org_id)


@router.get("/stats", summary="CASB statistics")
def casb_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregated CASB statistics: shadow IT %, 24h activity/violations,
    risk distribution, and policy count."""
    return _get_engine().get_casb_stats(org_id)
