"""Admin API Router — admin-prefixed user and team management.

Provides admin-namespaced endpoints expected by the Platform Admin (Hasan) persona:
    GET    /api/v1/admin/users    -- List all users (paginated)
    POST   /api/v1/admin/users    -- Create a user
    GET    /api/v1/admin/users/{id} -- Get user details
    PUT    /api/v1/admin/users/{id} -- Update user
    DELETE /api/v1/admin/users/{id} -- Delete user
    GET    /api/v1/admin/teams    -- List all teams (paginated)
    POST   /api/v1/admin/teams    -- Create a team
    GET    /api/v1/admin/teams/{id} -- Get team details
    PUT    /api/v1/admin/teams/{id} -- Update team
    DELETE /api/v1/admin/teams/{id} -- Delete team

Security:
    - All endpoints require API key + admin:all scope
    - Pydantic validation on all request bodies
    - SQLite IntegrityError → 409 (never 500)
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import require_role
from apps.api.dependencies import get_org_id
from core.audit_logger import create_audit_logger
from core.user_db import UserDB
from core.user_models import Team, User, UserRole, UserStatus
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field

logger = logging.getLogger(__name__)
_audit = create_audit_logger()

_ADMIN_ROLES = ("admin", "org_admin", "super_admin")

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["admin"],
    dependencies=[require_role(*_ADMIN_ROLES)],
)

# Shared DB instance — UserDB manages its own connection pool
_db = None  # lazy-initialised on first request


def _get_db():
    global _db
    if _db is None:
        _db = UserDB()
    return _db


# ---------------------------------------------------------------------------
# User Pydantic models
# ---------------------------------------------------------------------------


class AdminUserCreate(BaseModel):
    """Request model for creating a user via admin API."""

    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=8, max_length=128, description="User password")
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    role: UserRole = Field(default=UserRole.VIEWER)
    department: Optional[str] = Field(None, max_length=200)


class AdminUserUpdate(BaseModel):
    """Request model for updating a user via admin API."""

    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None
    department: Optional[str] = Field(None, max_length=200)


class AdminUserResponse(BaseModel):
    """Response model for a user."""

    id: str
    email: str
    first_name: str
    last_name: str
    role: str
    status: str
    department: Optional[str]
    created_at: str
    updated_at: str
    last_login_at: Optional[str]


class PaginatedAdminUserResponse(BaseModel):
    """Paginated user response."""

    items: List[AdminUserResponse]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Team Pydantic models
# ---------------------------------------------------------------------------


class AdminTeamCreate(BaseModel):
    """Request model for creating a team via admin API."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1, max_length=5000)


class AdminTeamUpdate(BaseModel):
    """Request model for updating a team via admin API."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=5000)


class AdminTeamResponse(BaseModel):
    """Response model for a team."""

    id: str
    name: str
    description: str
    created_at: str
    updated_at: str


class PaginatedAdminTeamResponse(BaseModel):
    """Paginated team response."""

    items: List[AdminTeamResponse]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# User endpoints — /api/v1/admin/users
# ---------------------------------------------------------------------------


@router.get("/users", response_model=PaginatedAdminUserResponse, summary="List all users")
async def admin_list_users(
    org_id: str = Depends(get_org_id),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """List all users with pagination. Requires admin scope."""
    users = _get_db().list_users(limit=limit, offset=offset)
    return {
        "items": [AdminUserResponse(**u.to_dict()) for u in users],
        "total": len(users),
        "limit": limit,
        "offset": offset,
    }


@router.post("/users", response_model=AdminUserResponse, status_code=201, summary="Create user")
async def admin_create_user(user_data: AdminUserCreate, request: Request) -> AdminUserResponse:
    """Create a new user. Requires admin scope."""
    existing = _get_db().get_user_by_email(user_data.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already exists")

    user = User(
        id="",
        email=user_data.email,
        password_hash=_get_db().hash_password(user_data.password),
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        role=user_data.role,
        status=UserStatus.ACTIVE,
        department=user_data.department,
    )
    try:
        created_user = _get_db().create_user(user)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email already exists")
    _audit.log_admin_action(
        action="create_user",
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        resource=f"user:{created_user.id}",
        outcome="success",
        correlation_id=getattr(request.state, "correlation_id", None),
        details={"email": user_data.email, "role": user_data.role.value if user_data.role else None},
    )
    return AdminUserResponse(**created_user.to_dict())


@router.get("/users/{user_id}", response_model=AdminUserResponse, summary="Get user")
async def admin_get_user(user_id: str) -> AdminUserResponse:
    """Get user details by ID. Requires admin scope."""
    user = _get_db().get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return AdminUserResponse(**user.to_dict())


@router.put("/users/{user_id}", response_model=AdminUserResponse, summary="Update user")
async def admin_update_user(user_id: str, user_data: AdminUserUpdate, request: Request) -> AdminUserResponse:
    """Update a user. Requires admin scope."""
    user = _get_db().get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_data.first_name is not None:
        user.first_name = user_data.first_name
    if user_data.last_name is not None:
        user.last_name = user_data.last_name
    if user_data.role is not None:
        user.role = user_data.role
    if user_data.status is not None:
        user.status = user_data.status
    if user_data.department is not None:
        user.department = user_data.department

    updated_user = _get_db().update_user(user)
    _audit.log_admin_action(
        action="update_user",
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        resource=f"user:{user_id}",
        outcome="success",
        correlation_id=getattr(request.state, "correlation_id", None),
        details={"changes": user_data.model_dump(exclude_unset=True)},
    )
    return AdminUserResponse(**updated_user.to_dict())


@router.delete("/users/{user_id}", status_code=204, summary="Delete user")
async def admin_delete_user(user_id: str, request: Request) -> None:
    """Delete a user. Requires admin scope."""
    user = _get_db().get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    _get_db().delete_user(user_id)
    _audit.log_admin_action(
        action="delete_user",
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        resource=f"user:{user_id}",
        outcome="success",
        correlation_id=getattr(request.state, "correlation_id", None),
        details={"email": user.email},
    )


# ---------------------------------------------------------------------------
# Team endpoints — /api/v1/admin/teams
# ---------------------------------------------------------------------------


@router.get("/teams", response_model=PaginatedAdminTeamResponse, summary="List all teams")
async def admin_list_teams(
    org_id: str = Depends(get_org_id),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """List all teams with pagination. Requires admin scope."""
    teams = _get_db().list_teams(limit=limit, offset=offset)
    return {
        "items": [AdminTeamResponse(**t.to_dict()) for t in teams],
        "total": len(teams),
        "limit": limit,
        "offset": offset,
    }


@router.post("/teams", response_model=AdminTeamResponse, status_code=201, summary="Create team")
async def admin_create_team(team_data: AdminTeamCreate, request: Request) -> AdminTeamResponse:
    """Create a new team. Requires admin scope."""
    team = Team(
        id="",
        name=team_data.name,
        description=team_data.description,
    )
    try:
        created_team = _get_db().create_team(team)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail=f"Team with name '{team_data.name}' already exists",
        )
    _audit.log_admin_action(
        action="create_team",
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        resource=f"team:{created_team.id}",
        outcome="success",
        correlation_id=getattr(request.state, "correlation_id", None),
        details={"name": team_data.name},
    )
    return AdminTeamResponse(**created_team.to_dict())


@router.get("/teams/{team_id}", response_model=AdminTeamResponse, summary="Get team")
async def admin_get_team(team_id: str) -> AdminTeamResponse:
    """Get team details by ID. Requires admin scope."""
    team = _get_db().get_team(team_id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    return AdminTeamResponse(**team.to_dict())


@router.put("/teams/{team_id}", response_model=AdminTeamResponse, summary="Update team")
async def admin_update_team(team_id: str, team_data: AdminTeamUpdate, request: Request) -> AdminTeamResponse:
    """Update a team. Requires admin scope."""
    team = _get_db().get_team(team_id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")

    if team_data.name is not None:
        team.name = team_data.name
    if team_data.description is not None:
        team.description = team_data.description

    try:
        updated_team = _get_db().update_team(team)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail=f"Team with name '{team_data.name}' already exists",
        )
    _audit.log_admin_action(
        action="update_team",
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        resource=f"team:{team_id}",
        outcome="success",
        correlation_id=getattr(request.state, "correlation_id", None),
        details={"changes": team_data.model_dump(exclude_unset=True)},
    )
    return AdminTeamResponse(**updated_team.to_dict())


@router.delete("/teams/{team_id}", status_code=204, summary="Delete team")
async def admin_delete_team(team_id: str, request: Request) -> None:
    """Delete a team. Requires admin scope."""
    team = _get_db().get_team(team_id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    _get_db().delete_team(team_id)
    _audit.log_admin_action(
        action="delete_team",
        user_id=getattr(request.state, "user_id", None),
        client_ip=request.client.host if request.client else None,
        resource=f"team:{team_id}",
        outcome="success",
        correlation_id=getattr(request.state, "correlation_id", None),
        details={"name": team.name},
    )


__all__ = ["router"]
