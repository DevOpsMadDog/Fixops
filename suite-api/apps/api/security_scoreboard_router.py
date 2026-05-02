"""Security Scoreboard Router — ALDECI.

Endpoints for the Security Scoreboard engine.

Prefix: /api/v1/security-scoreboard
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/security-scoreboard/teams                            create_team
  GET   /api/v1/security-scoreboard/teams                            list_teams
  GET   /api/v1/security-scoreboard/teams/{team_id}                  get_team
  POST  /api/v1/security-scoreboard/challenges                       record_challenge
  POST  /api/v1/security-scoreboard/challenges/{challenge_id}/score  submit_score
  GET   /api/v1/security-scoreboard/challenges                       list_challenges
  GET   /api/v1/security-scoreboard/leaderboard                      get_leaderboard
  GET   /api/v1/security-scoreboard/stats                            get_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-scoreboard",
    tags=["Security Scoreboard"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_scoreboard_engine import SecurityScoreboardEngine
        _engine = SecurityScoreboardEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TeamCreate(BaseModel):
    name: str
    team_type: str = "blue"
    department: str = ""


class ChallengeCreate(BaseModel):
    name: str
    challenge_type: str
    max_points: int = 100
    participants: List[str] = Field(default_factory=list)


class ScoreSubmit(BaseModel):
    team_id: str
    points_earned: int
    notes: str = ""


# ---------------------------------------------------------------------------
# Teams
# ---------------------------------------------------------------------------

@router.post("/teams", dependencies=[Depends(api_key_auth)], status_code=201)
def create_team(body: TeamCreate, org_id: str = Query(default="default")):
    """Create a new security team."""
    try:
        return _get_engine().create_team(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/teams", dependencies=[Depends(api_key_auth)])
def list_teams(
     org_id: str = Query(default="default"),
    team_type: Optional[str] = Query(None),
):
    """List teams with optional type filter."""
    return _get_engine().list_teams(org_id, team_type=team_type)


@router.get("/teams/{team_id}", dependencies=[Depends(api_key_auth)])
def get_team(team_id: str, org_id: str = Query(default="default")):
    """Get a single team by ID."""
    team = _get_engine().get_team(org_id, team_id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    return team


# ---------------------------------------------------------------------------
# Challenges
# ---------------------------------------------------------------------------

@router.post("/challenges", dependencies=[Depends(api_key_auth)], status_code=201)
def record_challenge(body: ChallengeCreate, org_id: str = Query(default="default")):
    """Create a new security challenge."""
    try:
        return _get_engine().record_challenge(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/challenges/{challenge_id}/score",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def submit_score(
    challenge_id: str,
    body: ScoreSubmit,
     org_id: str = Query(default="default"),
):
    """Submit a score for a team in a challenge."""
    result = _get_engine().submit_score(
        org_id, challenge_id, body.team_id, body.points_earned, notes=body.notes
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Challenge or team not found")
    return result


@router.get("/challenges", dependencies=[Depends(api_key_auth)])
def list_challenges(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List challenges with optional status filter."""
    return _get_engine().list_challenges(org_id, status=status)


# ---------------------------------------------------------------------------
# Leaderboard & Stats
# ---------------------------------------------------------------------------

@router.get("/leaderboard", dependencies=[Depends(api_key_auth)])
def get_leaderboard(org_id: str = Query(default="default")):
    """Return teams ordered by score DESC with rank field."""
    return _get_engine().get_leaderboard(org_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_scoreboard_stats(org_id: str = Query(default="default")):
    """Return aggregated scoreboard stats for the org."""
    return _get_engine().get_scoreboard_stats(org_id)
