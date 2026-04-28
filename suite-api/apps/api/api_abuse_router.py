"""API Abuse Detection Router — ALDECI.

8 endpoints under /api/v1/api-abuse:
  POST   /record          record a request for abuse tracking
  POST   /detect          detect abuse patterns
  GET    /events          list abuse events (filtered)
  POST   /block           block an IP
  GET    /block/{ip}      check if IP is blocked
  DELETE /block/{ip}      unblock an IP
  GET    /blocklist       all currently blocked IPs
  GET    /stats           summary statistics
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "api_abuse_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.api_abuse_detector import APIAbuseDetector

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/api-abuse",
    tags=["api-abuse-detection"],
    dependencies=_AUTH_DEP,
)

_detector: Optional[APIAbuseDetector] = None


def _get_detector() -> APIAbuseDetector:
    global _detector
    if _detector is None:
        _detector = APIAbuseDetector()
    return _detector


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class RecordRequestBody(BaseModel):
    ip: str = Field(..., description="Client IP address")
    endpoint: str = Field("", description="API endpoint path")
    user_agent: str = Field("", description="User-Agent header value")
    status_code: int = Field(200, description="HTTP response status code")
    api_key: str = Field("", description="API key used in the request")
    response_time_ms: int = Field(0, description="Response time in milliseconds")
    org_id: str = Field("default", description="Organisation ID")


class RecordRequestResponse(BaseModel):
    request_id: str
    message: str = "Request recorded"


class DetectRequest(BaseModel):
    ip: Optional[str] = Field(None, description="Filter by IP address")
    api_key: Optional[str] = Field(None, description="Filter by API key")
    window_minutes: int = Field(60, description="Detection window in minutes")
    org_id: str = Field("default", description="Organisation ID")


class BlockIPRequest(BaseModel):
    ip: str = Field(..., description="IP address to block")
    reason: str = Field(..., description="Reason for blocking")
    duration_hours: int = Field(24, description="Block duration in hours")
    org_id: str = Field("default", description="Organisation ID")


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/record", response_model=RecordRequestResponse, summary="Record an API request")
def record_request(body: RecordRequestBody) -> RecordRequestResponse:
    """Log an API request for abuse monitoring."""
    det = _get_detector()
    request_id = det.record_request(
        ip=body.ip,
        endpoint=body.endpoint,
        user_agent=body.user_agent,
        status_code=body.status_code,
        api_key=body.api_key,
        response_time_ms=body.response_time_ms,
        org_id=body.org_id,
    )
    return RecordRequestResponse(request_id=request_id)


@router.post("/detect", summary="Detect abuse patterns")
def detect_abuse(body: DetectRequest) -> List[Dict[str, Any]]:
    """Run abuse detection over the specified time window.

    Returns list of detected abuse events with pattern, severity, and evidence.
    """
    det = _get_detector()
    return det.detect_abuse(
        ip=body.ip,
        api_key=body.api_key,
        window_minutes=body.window_minutes,
        org_id=body.org_id,
    )


@router.get("/events", summary="List abuse events")
def get_abuse_events(
    ip: Optional[str] = Query(None, description="Filter by IP"),
    api_key: Optional[str] = Query(None, description="Filter by API key"),
    pattern: Optional[str] = Query(None, description="Filter by abuse pattern"),
    org_id: str = Query("default", description="Organisation ID"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> List[Dict[str, Any]]:
    """List stored abuse events with optional filters."""
    det = _get_detector()
    return det.get_abuse_events(
        ip=ip,
        api_key=api_key,
        pattern=pattern,
        org_id=org_id,
        limit=limit,
    )


@router.post("/block", summary="Block an IP address")
def block_ip(body: BlockIPRequest) -> Dict[str, Any]:
    """Add an IP to the block list for the specified duration."""
    det = _get_detector()
    return det.block_ip(
        ip=body.ip,
        reason=body.reason,
        duration_hours=body.duration_hours,
        org_id=body.org_id,
    )


@router.get("/block/{ip}", summary="Check if an IP is blocked")
def is_blocked(
    ip: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Check whether an IP is currently on the block list."""
    det = _get_detector()
    return det.is_blocked(ip=ip, org_id=org_id)


@router.delete("/block/{ip}", summary="Unblock an IP address")
def unblock_ip(
    ip: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Remove an IP from the block list."""
    det = _get_detector()
    removed = det.unblock_ip(ip=ip, org_id=org_id)
    return {"success": removed, "ip": ip, "message": "Unblocked" if removed else "IP was not blocked"}


@router.get("/blocklist", summary="Get all blocked IPs")
def get_block_list(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[Dict[str, Any]]:
    """Return all currently active blocked IPs."""
    det = _get_detector()
    return det.get_block_list(org_id=org_id)


@router.get("/stats", summary="Abuse detection statistics")
def get_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return summary statistics: total requests, abuse events, blocked IPs, patterns."""
    det = _get_detector()
    return det.get_stats(org_id=org_id)
