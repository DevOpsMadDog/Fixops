"""
Session management API endpoints.

Provides 8 endpoints for user session lifecycle management:
- POST   /api/v1/sessions                         create_session
- GET    /api/v1/sessions/{session_id}             get_session
- POST   /api/v1/sessions/{session_id}/refresh     refresh_session
- DELETE /api/v1/sessions/{session_id}             terminate_session
- DELETE /api/v1/sessions/user/{user_email}        terminate_all_sessions
- GET    /api/v1/sessions/user/{user_email}        list_active_sessions
- POST   /api/v1/sessions/cleanup                  cleanup_expired
- GET    /api/v1/sessions/stats/{org_id}           get_session_stats
- GET    /api/v1/sessions/concurrent/{user_email}  detect_concurrent_sessions
- GET    /api/v1/sessions/suspicious/{org_id}      get_suspicious_sessions
"""

import logging
from typing import Any, Dict, List, Optional

from core.session_manager import Session, SessionManager, get_session_manager
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])

# Module-level manager — shared across requests (singleton)
_mgr: Optional[SessionManager] = None


def _get_mgr() -> SessionManager:
    global _mgr
    if _mgr is None:
        _mgr = get_session_manager()
    return _mgr


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateSessionRequest(BaseModel):
    """Request body for creating a new session."""

    user_email: str = Field(..., description="User email address")
    ip_address: str = Field(..., description="Client IP address")
    user_agent: str = Field(..., description="Client user agent string")
    org_id: str = Field(..., description="Organisation ID")
    ttl_hours: int = Field(default=24, ge=1, le=720, description="Session TTL in hours")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Optional metadata")


class RefreshSessionRequest(BaseModel):
    """Request body for refreshing a session."""

    ttl_hours: Optional[int] = Field(
        default=None, ge=1, le=720, description="New TTL from now (hours). Omit to keep existing expiry."
    )


class SessionResponse(BaseModel):
    """Session response model."""

    id: str
    user_email: str
    ip_address: str
    user_agent: str
    created_at: str
    last_active: str
    expires_at: str
    is_active: bool
    org_id: str
    metadata: Dict[str, Any]

    @classmethod
    def from_session(cls, s: Session) -> "SessionResponse":
        return cls(
            id=s.id,
            user_email=s.user_email,
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            created_at=s.created_at.isoformat(),
            last_active=s.last_active.isoformat(),
            expires_at=s.expires_at.isoformat(),
            is_active=s.is_active,
            org_id=s.org_id,
            metadata=s.metadata,
        )


class TerminateAllResponse(BaseModel):
    """Response for bulk session termination."""

    user_email: str
    sessions_terminated: int


class CleanupResponse(BaseModel):
    """Response for expired session cleanup."""

    sessions_removed: int


class SessionStatsResponse(BaseModel):
    """Session statistics for an org."""

    org_id: str
    active_count: int
    avg_duration_seconds: float
    by_user: Dict[str, int]


class ConcurrentSessionsResponse(BaseModel):
    """Concurrent session detection result."""

    user_email: str
    has_concurrent: bool
    session_count: int
    sessions: List[SessionResponse]


class SuspiciousSessionEntry(BaseModel):
    """Single suspicious session entry."""

    user_email: str
    reason: str
    distinct_ips: List[str]
    distinct_agents: List[str]
    sessions: List[SessionResponse]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=SessionResponse, status_code=201)
async def create_session(body: CreateSessionRequest) -> SessionResponse:
    """Create a new user session."""
    mgr = _get_mgr()
    session = mgr.create_session(
        user_email=body.user_email,
        ip_address=body.ip_address,
        user_agent=body.user_agent,
        org_id=body.org_id,
        ttl_hours=body.ttl_hours,
        metadata=body.metadata,
    )
    return SessionResponse.from_session(session)


@router.get("/stats/{org_id}", response_model=SessionStatsResponse)
async def get_session_stats(org_id: str) -> SessionStatsResponse:
    """Get session statistics for an organisation."""
    mgr = _get_mgr()
    stats = mgr.get_session_stats(org_id)
    return SessionStatsResponse(**stats)


@router.get("/suspicious/{org_id}", response_model=List[SuspiciousSessionEntry])
async def get_suspicious_sessions(org_id: str) -> List[SuspiciousSessionEntry]:
    """Return users with suspicious session patterns (multiple IPs or user agents)."""
    mgr = _get_mgr()
    entries = mgr.get_suspicious_sessions(org_id)
    result: List[SuspiciousSessionEntry] = []
    for entry in entries:
        result.append(
            SuspiciousSessionEntry(
                user_email=entry["user_email"],
                reason=entry["reason"],
                distinct_ips=entry["distinct_ips"],
                distinct_agents=entry["distinct_agents"],
                sessions=[SessionResponse.from_session(s) for s in entry["sessions"]],
            )
        )
    return result


@router.get("/user/{user_email}", response_model=List[SessionResponse])
async def list_active_sessions(user_email: str) -> List[SessionResponse]:
    """List all active sessions for a user."""
    mgr = _get_mgr()
    sessions = mgr.get_active_sessions(user_email)
    return [SessionResponse.from_session(s) for s in sessions]


@router.get("/concurrent/{user_email}", response_model=ConcurrentSessionsResponse)
async def detect_concurrent_sessions(user_email: str) -> ConcurrentSessionsResponse:
    """Detect concurrent (multiple simultaneous) sessions for a user."""
    mgr = _get_mgr()
    result = mgr.detect_concurrent_sessions(user_email)
    return ConcurrentSessionsResponse(
        user_email=result["user_email"],
        has_concurrent=result["has_concurrent"],
        session_count=result["session_count"],
        sessions=[SessionResponse.from_session(s) for s in result["sessions"]],
    )


@router.delete("/user/{user_email}", response_model=TerminateAllResponse)
async def terminate_all_sessions(user_email: str) -> TerminateAllResponse:
    """Terminate all active sessions for a user (force logout everywhere)."""
    mgr = _get_mgr()
    count = mgr.terminate_all_sessions(user_email)
    return TerminateAllResponse(user_email=user_email, sessions_terminated=count)


@router.post("/cleanup", response_model=CleanupResponse)
async def cleanup_expired() -> CleanupResponse:
    """Purge expired and inactive sessions from the database."""
    mgr = _get_mgr()
    count = mgr.cleanup_expired()
    return CleanupResponse(sessions_removed=count)


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str) -> SessionResponse:
    """Validate and retrieve a session by ID."""
    mgr = _get_mgr()
    session = mgr.validate_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    return SessionResponse.from_session(session)


@router.post("/{session_id}/refresh", response_model=SessionResponse)
async def refresh_session(
    session_id: str, body: RefreshSessionRequest
) -> SessionResponse:
    """Refresh a session to extend its expiry."""
    mgr = _get_mgr()
    session = mgr.refresh_session(session_id, ttl_hours=body.ttl_hours)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    return SessionResponse.from_session(session)


@router.delete("/{session_id}", status_code=204)
async def terminate_session(session_id: str) -> None:
    """Terminate (logout) a single session."""
    mgr = _get_mgr()
    found = mgr.terminate_session(session_id)
    if not found:
        raise HTTPException(status_code=404, detail="Session not found")
