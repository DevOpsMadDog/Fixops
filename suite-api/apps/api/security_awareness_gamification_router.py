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
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/awareness-gamification",
    tags=["Security Awareness Gamification"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_awareness_gamification_engine import (
            SecurityAwarenessGamificationEngine,
        )
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
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth=Depends(api_key_auth),
) -> Dict[str, Any]:
    """List challenges (canonical envelope, batch-7).

    Class-c contract: empty IS correct for fresh tenants — security awareness
    challenges are manually authored by L&D/security teams, not auto-derivable
    from any public source. Always returns full envelope with pagination
    context + filters echo + actionable hint when empty.
    """
    rows = _get_engine().list_challenges(
        org_id, challenge_type=challenge_type, difficulty=difficulty
    ) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope: Dict[str, Any] = {
        "items": paged,
        "challenges": paged,  # legacy key preserved
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "challenge_type": challenge_type,
            "difficulty": difficulty,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Create security awareness challenges via POST /api/v1/awareness-gamification/challenges "
            "(manual content authoring). Empty IS the correct response for a fresh "
            "tenant — no public source exists."
        )
    return envelope


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


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------


@router.get("/")
async def get_gamification_root_summary(
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    """Return a 5-state summary envelope for the Security Awareness Gamification domain.

    States:
      healthy   — active challenges with user completions and positive avg score
      degraded  — challenges exist but no completions yet
      empty     — no challenges configured for this org
      error     — engine raised an exception
      unknown   — unexpected summary structure
    """
    try:
        stats = _get_engine().get_gamification_stats(org_id)
    except Exception as exc:
        _logger.error("awareness_gamification.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "awareness-gamification",
        }

    total_challenges = stats.get("total_challenges", 0)
    total_completions = stats.get("total_completions", 0)
    active_users = stats.get("active_users", 0)

    if total_challenges == 0:
        status = "empty"
    elif total_completions == 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope = {
        "status": status,
        "org_id": org_id,
        "domain": "awareness-gamification",
        "summary": stats,
    }
    if status == "empty":
        envelope["hint"] = (
            "Create challenges via POST /api/v1/awareness-gamification/challenges "
            "to begin security awareness gamification."
        )
    elif status == "degraded":
        envelope["hint"] = (
            f"{total_challenges} challenge(s) configured but no completions recorded yet. "
            "Encourage users to participate."
        )
    return envelope
