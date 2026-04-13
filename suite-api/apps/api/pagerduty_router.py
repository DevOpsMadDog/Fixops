"""
ALdeci PagerDuty API Router.

Exposes PagerDuty REST API v2 integration via ALdeci REST endpoints.
Falls back to mock data when PAGERDUTY_API_TOKEN is not configured.

Endpoints:
  GET  /api/v1/pagerduty/status                    — check PagerDuty configuration
  POST /api/v1/pagerduty/incidents                 — create a new incident
  GET  /api/v1/pagerduty/incidents                 — list incidents with optional filters
  GET  /api/v1/pagerduty/incidents/{incident_id}   — get a single incident
  PATCH /api/v1/pagerduty/incidents/{incident_id}  — update/resolve an incident
  GET  /api/v1/pagerduty/schedules                 — list on-call schedules
  GET  /api/v1/pagerduty/escalation-policies       — list escalation policies
  GET  /api/v1/pagerduty/services                  — list services and health

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/pagerduty",
    tags=["pagerduty"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton client
# ---------------------------------------------------------------------------

_client = None


def _get_client():
    global _client
    if _client is None:
        from core.pagerduty_integration import PagerDutyClient
        _client = PagerDutyClient()
    return _client


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateIncidentRequest(BaseModel):
    """Request body for creating a PagerDuty incident."""

    title: str = Field(..., description="Incident summary / title")
    service_id: str = Field(..., description="PagerDuty service ID")
    urgency: str = Field("high", description="Incident urgency: 'high' or 'low'")
    body_details: Optional[str] = Field(None, description="Incident body details (plain text)")
    escalation_policy_id: Optional[str] = Field(None, description="Override escalation policy ID")
    priority_id: Optional[str] = Field(None, description="Priority object ID")


class UpdateIncidentRequest(BaseModel):
    """Request body for updating a PagerDuty incident."""

    status: Optional[str] = Field(None, description="New status: 'acknowledged' or 'resolved'")
    title: Optional[str] = Field(None, description="New incident title")
    urgency: Optional[str] = Field(None, description="New urgency: 'high' or 'low'")
    resolution: Optional[str] = Field(None, description="Resolution note")


class PagerDutyStatusResponse(BaseModel):
    configured: bool
    message: str
    from_email: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=PagerDutyStatusResponse,
    summary="Check PagerDuty API configuration",
)
def pagerduty_status():
    """
    Return whether the PagerDuty API token is configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real credentials.
    """
    import os
    client = _get_client()
    configured = client.is_configured()
    from_email = os.environ.get("PAGERDUTY_FROM_EMAIL", "") or client._from_email or None
    return {
        "configured": configured,
        "from_email": from_email if configured else None,
        "message": (
            "PagerDuty API token configured — real data active"
            if configured
            else "PAGERDUTY_API_TOKEN not set — mock data mode. "
            "Set PAGERDUTY_API_TOKEN and PAGERDUTY_FROM_EMAIL environment variables."
        ),
    }


@router.post(
    "/incidents",
    response_model=Dict[str, Any],
    summary="Create a PagerDuty incident",
    status_code=201,
)
def create_incident(body: CreateIncidentRequest):
    """
    Create a new PagerDuty incident for the given service.

    Returns mock data when PAGERDUTY_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.create_incident(
            title=body.title,
            service_id=body.service_id,
            urgency=body.urgency,
            body_details=body.body_details,
            escalation_policy_id=body.escalation_policy_id,
            priority_id=body.priority_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("create_incident failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/incidents",
    response_model=List[Dict[str, Any]],
    summary="List PagerDuty incidents",
)
def list_incidents(
    statuses: Optional[str] = Query(
        None,
        description="Comma-separated statuses to filter (triggered,acknowledged,resolved)",
    ),
    service_ids: Optional[str] = Query(
        None,
        description="Comma-separated PagerDuty service IDs to filter",
    ),
    limit: int = Query(25, ge=1, le=100, description="Max incidents to return"),
):
    """
    List PagerDuty incidents with optional status and service filters.

    Returns mock data when PAGERDUTY_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        status_list = [s.strip() for s in statuses.split(",")] if statuses else None
        service_list = [s.strip() for s in service_ids.split(",")] if service_ids else None
        return client.list_incidents(
            statuses=status_list,
            service_ids=service_list,
            limit=limit,
        )
    except Exception as exc:
        logger.error("list_incidents failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/incidents/{incident_id}",
    response_model=Dict[str, Any],
    summary="Get a single PagerDuty incident",
)
def get_incident(incident_id: str):
    """
    Retrieve a single PagerDuty incident by ID.

    Returns mock data when PAGERDUTY_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.get_incident(incident_id=incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("get_incident failed for %s: %s", incident_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.patch(
    "/incidents/{incident_id}",
    response_model=Dict[str, Any],
    summary="Update or resolve a PagerDuty incident",
)
def update_incident(incident_id: str, body: UpdateIncidentRequest):
    """
    Update a PagerDuty incident — change status, urgency, or add a resolution note.

    Returns mock data when PAGERDUTY_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.update_incident(
            incident_id=incident_id,
            status=body.status,
            title=body.title,
            urgency=body.urgency,
            resolution=body.resolution,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error(
            "update_incident failed for %s: %s", incident_id, exc, exc_info=True
        )
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/schedules",
    response_model=List[Dict[str, Any]],
    summary="List PagerDuty on-call schedules",
)
def list_schedules(
    query: Optional[str] = Query(None, description="Text filter for schedule names"),
):
    """
    List on-call schedules configured in PagerDuty.

    Returns mock data when PAGERDUTY_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.list_schedules(query=query)
    except Exception as exc:
        logger.error("list_schedules failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/escalation-policies",
    response_model=List[Dict[str, Any]],
    summary="List PagerDuty escalation policies",
)
def list_escalation_policies(
    query: Optional[str] = Query(None, description="Text filter for policy names"),
):
    """
    List escalation policies configured in PagerDuty.

    Returns mock data when PAGERDUTY_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.list_escalation_policies(query=query)
    except Exception as exc:
        logger.error("list_escalation_policies failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/services",
    response_model=List[Dict[str, Any]],
    summary="List PagerDuty services and health",
)
def list_services(
    query: Optional[str] = Query(None, description="Text filter for service names"),
):
    """
    List PagerDuty services with status information.

    Returns mock data when PAGERDUTY_API_TOKEN is not configured.
    """
    client = _get_client()
    try:
        return client.list_services(query=query)
    except Exception as exc:
        logger.error("list_services failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
