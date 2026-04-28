"""Security Awareness Gamification Router — ALDECI.

Prefix: /api/v1/awareness-gamification
Tags:   Security Awareness Gamification

Routes:
  POST  /challenges               create_challenge
  GET   /challenges               list_challenges
  POST  /completions              record_completion
  GET   /leaderboard              get_leaderboard
  GET   /users/{user_id}          get_user_profile
  POST  /users/{user_id}/badges   award_badge
  GET   /stats                    get_gamification_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from apps.api.auth_deps import api_key_auth

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/awareness-gamification",
    tags=["Security Awareness Gamification"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_awareness_gamification_engine import SecurityAwarenessGamificationEngine
        _engine = SecurityAwarenessGamificationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ChallengeCreate(BaseModel):
    title: str
    challenge_type: str = "quiz"
    difficulty: str = "medium"
    points: int = 10
    department: str = ""


class CompletionCreate(BaseModel):
    user_id: str
    challenge_id: str
    score: float = 0.0
    time_spent_seconds: int = 0
    passed: bool = False


class BadgeCreate(BaseModel):
    badge_name: str
    badge_type: str = "achievement"
    description: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/challenges")
async def create_challenge(
    body: ChallengeCreate,
     org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    """Create a new gamification challenge."""
    try:
        result = _get_engine().create_challenge(org_id, body.model_dump())
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/challenges")
async def list_challenges(
     org_id: str = Query(default="default"),
    challenge_type: Optional[str] = Query(None),
    difficulty: Optional[str] = Query(None),
    auth=Depends(api_key_auth),
):
    """List challenges with optional filters."""
    rows = _get_engine().list_challenges(org_id, challenge_type=challenge_type, difficulty=difficulty)
    if not rows:
        return {
            "challenges": [],
            "total": 0,
            "hint": "Create security awareness challenges via POST /api/v1/awareness-gamification/challenges (manual content authoring).",
        }
    return {"challenges": rows, "total": len(rows)}


@router.post("/completions")
async def record_completion(
    body: CompletionCreate,
     org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    """Record a challenge completion."""
    completion_data = {
        "score": body.score,
        "time_spent_seconds": body.time_spent_seconds,
        "passed": body.passed,
    }
    result = _get_engine().record_completion(
        org_id, body.user_id, body.challenge_id, completion_data
    )
    return result


@router.get("/leaderboard")
async def get_leaderboard(
     org_id: str = Query(default="default"),
    department: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    auth=Depends(api_key_auth),
):
    """Return org leaderboard ordered by total_points."""
    return _get_engine().get_leaderboard(org_id, department=department, limit=limit)


@router.get("/users/{user_id}")
async def get_user_profile(
    user_id: str,
     org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    """Return user gamification profile."""
    return _get_engine().get_user_profile(org_id, user_id)


@router.post("/users/{user_id}/badges")
async def award_badge(
    user_id: str,
    body: BadgeCreate,
     org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    """Award a badge to a user."""
    try:
        result = _get_engine().award_badge(org_id, user_id, body.model_dump())
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/stats")
async def get_gamification_stats(
     org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    """Return org-wide gamification stats."""
    return _get_engine().get_gamification_stats(org_id)
