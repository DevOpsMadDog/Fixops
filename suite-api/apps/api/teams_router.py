"""
Team management API endpoints.
"""
from typing import List, Optional

from apps.api.dependencies import get_org_id
from core.user_db import UserDB
from core.user_models import Team
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/teams", tags=["teams"])
db = UserDB()


class TeamCreate(BaseModel):
    """Request model for creating a team."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str


class TeamUpdate(BaseModel):
    """Request model for updating a team."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None


class TeamResponse(BaseModel):
    """Response model for a team."""

    id: str
    name: str
    description: str
    created_at: str
    updated_at: str


class PaginatedTeamResponse(BaseModel):
    """Paginated team response."""

    items: List[TeamResponse]
    total: int
    limit: int
    offset: int


class AddMemberRequest(BaseModel):
    """Request model for adding a team member."""

    user_id: str
    role: str = "member"


@router.get("", response_model=PaginatedTeamResponse)
async def list_teams(
    org_id: str = Depends(get_org_id),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all teams with pagination."""
    teams = db.list_teams(limit=limit, offset=offset)
    return {
        "items": [TeamResponse(**t.to_dict()) for t in teams],
        "total": len(teams),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=TeamResponse, status_code=201)
async def create_team(team_data: TeamCreate):
    """Create a new team."""
    import sqlite3

    team = Team(
        id="",
        name=team_data.name,
        description=team_data.description,
    )
    try:
        created_team = db.create_team(team)
        return TeamResponse(**created_team.to_dict())
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(
                status_code=409,
                detail=f"Team with name '{team_data.name}' already exists",
            )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{id}", response_model=TeamResponse)
async def get_team(id: str):
    """Get team details by ID."""
    team = db.get_team(id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    return TeamResponse(**team.to_dict())


@router.put("/{id}", response_model=TeamResponse)
async def update_team(id: str, team_data: TeamUpdate):
    """Update a team."""
    team = db.get_team(id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")

    if team_data.name is not None:
        team.name = team_data.name
    if team_data.description is not None:
        team.description = team_data.description

    updated_team = db.update_team(team)
    return TeamResponse(**updated_team.to_dict())


@router.delete("/{id}", status_code=204)
async def delete_team(id: str):
    """Delete a team."""
    team = db.get_team(id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    db.delete_team(id)
    return None


@router.get("/{id}/members")
async def list_team_members(id: str):
    """List all members of a team."""
    team = db.get_team(id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    members = db.list_team_members(id)
    return {"team_id": id, "members": members}


@router.post("/{id}/members", status_code=201)
async def add_team_member(id: str, member_data: AddMemberRequest):
    """Add a user to a team."""
    team = db.get_team(id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")

    user = db.get_user(member_data.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    member = db.add_team_member(id, member_data.user_id, member_data.role)
    return member.to_dict()


@router.delete("/{id}/members/{user_id}", status_code=204)
async def remove_team_member(id: str, user_id: str):
    """Remove a user from a team."""
    team = db.get_team(id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")

    db.remove_team_member(id, user_id)
    return None
