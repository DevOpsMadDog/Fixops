"""Privileged Session Recording Router — ALDECI.

Records and audits privileged access sessions.

Prefix: /api/v1/session-recording
Auth: api_key_auth dependency

Routes:
  POST /api/v1/session-recording/sessions                    start_session
  GET  /api/v1/session-recording/sessions                    list_sessions
  GET  /api/v1/session-recording/sessions/{session_id}       get_session
  POST /api/v1/session-recording/sessions/{session_id}/end   end_session
  POST /api/v1/session-recording/sessions/{session_id}/alerts record_alert
  GET  /api/v1/session-recording/alerts                      list_alerts
  GET  /api/v1/session-recording/stats                       get_recording_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/session-recording",
    tags=["Privileged Session Recording"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.privileged_session_recording_engine import (
            PrivilegedSessionRecordingEngine,
        )
        _engine = PrivilegedSessionRecordingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class StartSessionBody(BaseModel):
    user: str = Field(..., description="User initiating the session")
    session_type: str = Field(
        default="ssh",
        description="ssh | rdp | database | api | console | winrm | telnet",
    )
    target_host: str = Field(..., description="Target host name or FQDN")
    target_ip: str = Field(default="", description="Target IP address")
    initiated_by: str = Field(default="", description="System or PAM that initiated the session")


class EndSessionBody(BaseModel):
    duration_seconds: int = Field(default=0, description="Total session duration in seconds")
    recording_url: str = Field(default="", description="URL to session recording artifact")


class RecordAlertBody(BaseModel):
    alert_type: str = Field(
        ...,
        description="suspicious_command | data_exfiltration | privilege_escalation | policy_violation | anomaly",
    )
    severity: str = Field(default="medium", description="critical | high | medium | low | info")
    description: str = Field(default="", description="Alert description")
    command_context: str = Field(default="", description="Command or context that triggered the alert")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/sessions", dependencies=[Depends(api_key_auth)])
def start_session(body: StartSessionBody, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Start a new privileged session recording."""
    try:
        return _get_engine().start_session(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/sessions", dependencies=[Depends(api_key_auth)])
def list_sessions(
    org_id: str = Query(default="default"),
    user: Optional[str] = Query(default=None),
    session_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> dict:
    """List sessions, optionally filtered.

    Type-a #14 wiring: when the org has no recorded sessions, the engine falls
    back to the CyberArk PAM connector (when CYBERARK_BASE_URL/USER/PASS env
    vars are set). Returns a 5-state envelope (org_registered / cyberark_pam /
    needs_credentials / needs_data / connector_error). NEVER mocks.
    """
    return _get_engine().list_sessions_with_pam_fallback(
        org_id, user=user, session_type=session_type, status=status,
    )


@router.get("/sessions/{session_id}", dependencies=[Depends(api_key_auth)])
def get_session(session_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Fetch a single session."""
    result = _get_engine().get_session(org_id, session_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return result


@router.post("/sessions/{session_id}/end", dependencies=[Depends(api_key_auth)])
def end_session(
    session_id: str,
    body: EndSessionBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """End a privileged session."""
    try:
        return _get_engine().end_session(org_id, session_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/sessions/{session_id}/alerts", dependencies=[Depends(api_key_auth)])
def record_alert(
    session_id: str,
    body: RecordAlertBody,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Record an alert for a session."""
    try:
        return _get_engine().record_alert(org_id, session_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/alerts", dependencies=[Depends(api_key_auth)])
def list_alerts(
    org_id: str = Query(default="default"),
    session_id: Optional[str] = Query(default=None),
    alert_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> list:
    """List alerts, optionally filtered."""
    return _get_engine().list_alerts(
        org_id, session_id=session_id, alert_type=alert_type, severity=severity
    )


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_recording_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate recording stats."""
    return _get_engine().get_recording_stats(org_id)
