"""PR Generator API — Auto-generate GitHub PRs for dependency vulnerability fixes.

Routes:
- POST   /api/v1/remediation/prs/generate  — generate PR from a single finding
- POST   /api/v1/remediation/prs/batch     — batch generate from multiple findings
- GET    /api/v1/remediation/prs           — list generated PRs
- GET    /api/v1/remediation/prs/{id}      — get PR details

Protected by api_key_auth dependency (injected via router-level Depends).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/remediation/prs",
    tags=["pr-generator"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton — avoids SQLite init at import time
# ---------------------------------------------------------------------------

_generator = None


def _get_generator():
    global _generator
    if _generator is None:
        from core.pr_generator import PRGenerator
        _generator = PRGenerator()
    return _generator


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class GeneratePRRequest(BaseModel):
    """Generate a PR from a single security finding."""

    finding: Dict[str, Any] = Field(..., description="Security finding dict (Snyk/Trivy/Grype/Dependabot shape)")
    repo: str = Field(..., description="Target repository name, e.g. 'Fixops'")
    owner: str = Field(..., description="GitHub owner or org, e.g. 'DevOpsMadDog'")
    org_id: str = Field(default="default", description="Tenant identifier")


class BatchGeneratePRRequest(BaseModel):
    """Batch-generate PRs from multiple security findings."""

    findings: List[Dict[str, Any]] = Field(..., description="List of security findings")
    repo: str
    owner: str
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/generate")
def generate_pr(request: GeneratePRRequest) -> Dict[str, Any]:
    """Generate a GitHub PR for a single dependency vulnerability finding.

    Extracts the dependency upgrade from the finding, builds a PR template,
    and (when a GitHub token is configured) creates the branch + PR via the
    GitHub API.  Without a token the record is saved with ``status='draft'``.
    """
    gen = _get_generator()

    fix = gen.analyze_finding(request.finding)
    if fix is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "Could not extract a fixable dependency upgrade from the provided finding. "
                "Ensure the finding includes package_name, current_version, and fix_version fields."
            ),
        )

    pr = gen.create_pr(fix, repo=request.repo, owner=request.owner, org_id=request.org_id)
    return pr.model_dump()


@router.post("/batch")
def batch_generate_prs(request: BatchGeneratePRRequest) -> Dict[str, Any]:
    """Batch-generate GitHub PRs from a list of security findings.

    Findings without an extractable fix are silently skipped.  Returns a
    summary plus all generated PR records.
    """
    gen = _get_generator()

    prs = gen.batch_generate(
        findings=request.findings,
        repo=request.repo,
        owner=request.owner,
        org_id=request.org_id,
    )

    return {
        "generated": len(prs),
        "skipped": len(request.findings) - len(prs),
        "prs": [pr.model_dump() for pr in prs],
    }


@router.get("")
def list_prs(
    org_id: Optional[str] = None,
    status: Optional[str] = None,
) -> Dict[str, Any]:
    """List generated PRs with optional filters.

    Query parameters:
    - **org_id**: Filter by tenant org_id
    - **status**: Filter by PR status: draft | created | merged | failed
    """
    gen = _get_generator()
    prs = gen.list_generated_prs(org_id=org_id or None, status=status or None)
    return {
        "prs": [pr.model_dump() for pr in prs],
        "count": len(prs),
    }


@router.get("/{pr_id}")
def get_pr(pr_id: str) -> Dict[str, Any]:
    """Get details for a specific generated PR by its internal ID."""
    gen = _get_generator()
    pr = gen.get_pr(pr_id)
    if pr is None:
        raise HTTPException(status_code=404, detail="PR not found")
    return pr.model_dump()
