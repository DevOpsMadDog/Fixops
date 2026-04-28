"""
Insider Threat Router — ALDECI.

8 endpoints for the insider threat detection engine:
  POST   /api/v1/insider-threat/activities          record_activity
  POST   /api/v1/insider-threat/assess/{user_email} assess_user_risk
  POST   /api/v1/insider-threat/detect              detect_anomalies (full scan)
  GET    /api/v1/insider-threat/high-risk           get_high_risk_users
  GET    /api/v1/insider-threat/timeline/{user_email} get_user_timeline
  GET    /api/v1/insider-threat/distribution        get_risk_distribution
  POST   /api/v1/insider-threat/acknowledge/{user_email} acknowledge_alert
  GET    /api/v1/insider-threat/stats               get_detection_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "insider_threat_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.insider_threat import (
    ActivityRecord,
    DetectionStats,
    InsiderThreatDetector,
    RiskDistribution,
    UserRiskProfile,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/insider-threat",
    tags=["insider-threat"],
    dependencies=_AUTH_DEP,
)

# Shared detector instance (file-backed, shared across requests)
_detector: Optional[InsiderThreatDetector] = None


def _get_detector() -> InsiderThreatDetector:
    global _detector
    if _detector is None:
        _detector = InsiderThreatDetector()
    return _detector


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class RecordActivityRequest(BaseModel):
    """Body for recording a user activity event."""

    user_email: str = Field(..., description="User's email address")
    activity_type: str = Field(
        ..., description="Activity type, e.g. 'data_download', 'sudo'"
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary context (bytes_transferred, resource, etc.)",
    )
    org_id: str = Field("default", description="Organisation ID")


class RecordActivityResponse(BaseModel):
    activity_id: str
    message: str = "Activity recorded"


class AssessResponse(BaseModel):
    profile: UserRiskProfile


class DetectRequest(BaseModel):
    """Body for triggering a full anomaly scan."""

    org_id: str = Field("default", description="Organisation ID to scan")


class DetectResponse(BaseModel):
    users_flagged: int
    profiles: List[UserRiskProfile]


class AcknowledgeRequest(BaseModel):
    """Body for acknowledging a user's alerts."""

    reviewer: str = Field(..., description="Reviewer identifier (email / username)")
    org_id: str = Field("default", description="Organisation ID")


class AcknowledgeResponse(BaseModel):
    acknowledged: bool
    user_email: str
    reviewer: str


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/activities",
    response_model=RecordActivityResponse,
    summary="Record a user activity event",
)
def record_activity(body: RecordActivityRequest) -> RecordActivityResponse:
    """
    Store a single user-activity event for later risk assessment.

    Returns the UUID of the inserted record.
    """
    detector = _get_detector()
    try:
        activity_id = detector.record_activity(
            user_email=body.user_email,
            activity_type=body.activity_type,
            details=body.details,
            org_id=body.org_id,
        )
        return RecordActivityResponse(activity_id=activity_id)
    except Exception as exc:
        logger.exception("Failed to record activity for %s", body.user_email)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/assess/{user_email}",
    response_model=UserRiskProfile,
    summary="Assess risk profile for a user",
)
def assess_user_risk(
    user_email: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> UserRiskProfile:
    """
    Compute and persist the risk profile for the specified user.

    Analyses the full activity history and derives active ThreatIndicators.
    """
    detector = _get_detector()
    try:
        return detector.assess_user_risk(user_email=user_email, org_id=org_id)
    except Exception as exc:
        logger.exception("Risk assessment failed for %s", user_email)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/detect",
    response_model=DetectResponse,
    summary="Scan all users for suspicious patterns",
)
def detect_anomalies(body: DetectRequest) -> DetectResponse:
    """
    Re-assess every user in the org and return those with active ThreatIndicators.
    """
    detector = _get_detector()
    try:
        profiles = detector.detect_anomalies(org_id=body.org_id)
        return DetectResponse(users_flagged=len(profiles), profiles=profiles)
    except Exception as exc:
        logger.exception("Anomaly detection failed for org %s", body.org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/high-risk",
    response_model=List[UserRiskProfile],
    summary="List high-risk users",
)
def get_high_risk_users(
    org_id: str = Query("default", description="Organisation ID"),
    threshold: float = Query(60.0, ge=0, le=100, description="Minimum risk score"),
) -> List[UserRiskProfile]:
    """
    Return all users whose risk_score is at or above the threshold,
    sorted by risk_score descending.
    """
    detector = _get_detector()
    return detector.get_high_risk_users(org_id=org_id, threshold=threshold)


@router.get(
    "/timeline/{user_email}",
    response_model=List[ActivityRecord],
    summary="Activity timeline for a user",
)
def get_user_timeline(
    user_email: str,
    org_id: str = Query("default", description="Organisation ID"),
    limit: int = Query(200, ge=1, le=1000, description="Max records"),
) -> List[ActivityRecord]:
    """
    Return the activity history for a user, newest first.
    """
    detector = _get_detector()
    return detector.get_user_timeline(
        user_email=user_email, org_id=org_id, limit=limit
    )


@router.get(
    "/distribution",
    response_model=RiskDistribution,
    summary="Risk-level distribution across org users",
)
def get_risk_distribution(
    org_id: str = Query("default", description="Organisation ID"),
) -> RiskDistribution:
    """
    Return count of users at each alert level (low/medium/high/critical).
    """
    detector = _get_detector()
    return detector.get_risk_distribution(org_id=org_id)


@router.post(
    "/acknowledge/{user_email}",
    response_model=AcknowledgeResponse,
    summary="Acknowledge alerts for a user",
)
def acknowledge_alert(
    user_email: str,
    body: AcknowledgeRequest,
) -> AcknowledgeResponse:
    """
    Mark all unacknowledged activity records for the user as reviewed.

    Returns 404 if there are no unacknowledged records for the user.
    """
    detector = _get_detector()
    updated = detector.acknowledge_alert(
        user_email=user_email,
        reviewer=body.reviewer,
        org_id=body.org_id,
    )
    if not updated:
        raise HTTPException(
            status_code=404,
            detail=f"No unacknowledged alerts found for user '{user_email}' in org '{body.org_id}'",
        )
    return AcknowledgeResponse(
        acknowledged=True,
        user_email=user_email,
        reviewer=body.reviewer,
    )


@router.get(
    "/stats",
    response_model=DetectionStats,
    summary="Insider threat programme statistics",
)
def get_detection_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> DetectionStats:
    """
    Return aggregate statistics: total activities, alerts, reviews,
    risk distribution, and top indicators.
    """
    detector = _get_detector()
    return detector.get_detection_stats(org_id=org_id)


@router.get(
    "/context/{entity_id}",
    dependencies=_AUTH_DEP,
)
def get_trustgraph_context(
    entity_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for an insider threat entity (related assets, findings, incidents)."""
    detector = _get_detector()
    return detector.get_trustgraph_context(org_id=org_id, entity_id=entity_id)
