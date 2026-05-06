"""
Developer Self-Service Security Portal — API Router.

Provides developers with a scoped view of security findings for their repos,
fix suggestions, security scores, upgrade recommendations, and learning resources.

All endpoints require API-key authentication.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.developer_portal import (
    DeveloperPortal,
    FixSuggestion,
    LearningResource,
    RepoSecurityScore,
)
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/developer",
    tags=["Developer Portal"],
    dependencies=[Depends(api_key_auth)],
)

# Singleton portal instance (SQLite-backed)
_portal = DeveloperPortal()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterRepoRequest(BaseModel):
    """Register a developer as owner of a repository."""

    repo_name: str = Field(..., description="Repository name (e.g. my-org/my-repo)")
    developer_email: str = Field(..., description="Developer e-mail address")
    org_id: str = Field(..., description="Organisation identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/findings",
    summary="My findings",
    description="Return all open security findings scoped to repos the caller owns.",
)
async def get_my_findings(
    developer_email: str = Query(..., description="Developer email"),
    org_id: str = Query(..., description="Organisation ID"),
    status: Optional[str] = Query(None, description="Filter by status (open/resolved)"),
) -> List[Dict[str, Any]]:
    """Return findings for repos owned by the developer."""
    return _portal.get_my_findings(developer_email, org_id, status=status)


@router.get(
    "/repos",
    summary="My repo scores",
    description="Return security scores for all repos owned by the developer.",
)
async def get_my_repo_scores(
    developer_email: str = Query(..., description="Developer email"),
    org_id: str = Query(..., description="Organisation ID"),
) -> List[RepoSecurityScore]:
    """Return security scores for repos the developer owns."""
    owned = _portal._get_owned_repos(developer_email, org_id)
    if not owned:
        return []
    return [_portal.get_repo_score(repo, org_id) for repo in owned]


@router.get(
    "/repos/{name}/score",
    summary="Single repo score",
    description="Return the security score for a specific repository.",
)
async def get_repo_score(
    name: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> RepoSecurityScore:
    """Return the security score for one repository."""
    return _portal.get_repo_score(name, org_id)


@router.get(
    "/findings/{id}/fix",
    summary="Fix suggestion",
    description="Return an actionable fix suggestion for the specified finding.",
)
async def get_fix_suggestion(
    id: str,
    language: Optional[str] = Query(None, description="Preferred language for code snippet"),
) -> FixSuggestion:
    """Return a fix suggestion for a finding."""
    return _portal.get_fix_suggestion(id, language=language)


@router.get(
    "/repos/{name}/upgrades",
    summary="Upgrade recommendations",
    description="Return dependency upgrade recommendations for a repository.",
)
async def get_upgrade_recommendations(
    name: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> List[Dict[str, Any]]:
    """Return dependency upgrade recommendations for a repo."""
    return _portal.get_upgrade_recommendations(name, org_id)


@router.get(
    "/learn/{finding_type}",
    summary="Learning resources",
    description="Return curated educational resources for a finding type.",
)
async def get_learning_resources(finding_type: str) -> List[LearningResource]:
    """Return learning resources for the given finding type."""
    return _portal.get_learning_resources(finding_type)


@router.post(
    "/repos/register",
    summary="Register repo ownership",
    description="Map a developer to a repository so they see its findings.",
    status_code=201,
)
async def register_repo_owner(body: RegisterRepoRequest) -> Dict[str, str]:
    """Register a developer as the owner of a repository."""
    _portal.register_repo_owner(body.repo_name, body.developer_email, body.org_id)
    return {
        "status": "registered",
        "repo_name": body.repo_name,
        "developer_email": body.developer_email,
        "org_id": body.org_id,
    }


@router.get(
    "/stats",
    summary="My developer stats",
    description="Return security statistics for the developer (fixes, avg time, repos).",
)
async def get_developer_stats(
    developer_email: str = Query(..., description="Developer email"),
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Return per-developer security statistics."""
    return _portal.get_developer_stats(developer_email, org_id)


@router.get(
    "/leaderboard",
    summary="Top fixers leaderboard",
    description="Return the top developers ranked by number of security findings fixed.",
)
async def get_leaderboard(
    org_id: str = Query(..., description="Organisation ID"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of entries"),
) -> List[Dict[str, Any]]:
    """Return a leaderboard of developers ranked by findings fixed."""
    return _portal.get_leaderboard(org_id, limit=limit)


# ---------------------------------------------------------------------------
# /api/v1/developer-portal alias router — fixes smoke #4019 (hyphenated prefix)
# ---------------------------------------------------------------------------

alias_router = APIRouter(
    prefix="/api/v1/developer-portal",
    tags=["Developer Portal"],
    dependencies=[Depends(api_key_auth)],
)


@alias_router.get("/repos", summary="Repos alias")
async def alias_repos(
    developer_email: str = Query("default"),
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    owned = _portal._get_owned_repos(developer_email, org_id)
    return [_portal.get_repo_score(r, org_id).model_dump() for r in owned]


@alias_router.get("/findings", summary="Findings alias")
async def alias_findings(
    developer_email: str = Query("default"),
    org_id: str = Query("default"),
    author: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    findings = _portal.get_my_findings(developer_email, org_id, status=status)
    if author:
        findings = [f for f in findings if f.get("author") == author]
    return findings
