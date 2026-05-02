"""CI/CD Pipeline Security Integration API router.

Provides endpoints for CI systems (GitHub Actions, GitLab CI, etc.) to:
- Submit scan results and evaluate them against a policy
- Manage policies
- Retrieve scan history and badge data

All endpoints require API key authentication.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.cicd_integration import (
    CICDPolicyEngine,
    PolicyRule,
    ScanResult,
)
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cicd",
    tags=["cicd"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Singleton engine (uses env-configured path or default)
# ---------------------------------------------------------------------------

_engine: Optional[CICDPolicyEngine] = None


def _get_engine() -> CICDPolicyEngine:
    global _engine
    if _engine is None:
        db_path = os.getenv("ALDECI_CICD_DB", "")
        _engine = CICDPolicyEngine(db_path=db_path or None)
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanSubmitRequest(BaseModel):
    """Payload sent by a CI job to trigger a scan evaluation."""

    repo: str = Field(..., description="Repository slug (owner/name or group/project)")
    branch: str = Field("main", description="Branch or ref name")
    commit_sha: str = Field("", description="Full commit SHA")
    policy_id: str = Field("", description="Policy UUID to evaluate against")
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of finding dicts (severity, category, title, …)",
    )
    duration_ms: int = Field(0, ge=0, description="Scan duration in milliseconds")


class EvaluateRequest(BaseModel):
    """Evaluate an existing scan result and generate a PR comment."""

    scan_result: Dict[str, Any] = Field(..., description="ScanResult dict (from /scan)")
    repo: str = Field("", description="Override repo for comment (optional)")
    pr_number: Optional[int] = Field(None, ge=1, description="PR/MR number for comment context")


class PolicyCreateRequest(BaseModel):
    """Create a new CI/CD policy."""

    org_id: str = Field("", description="Organisation ID (optional)")
    rules: List[PolicyRule] = Field(..., min_length=1, description="Policy rules")


class ScanResultResponse(BaseModel):
    """Serialisable scan result returned by the API."""

    scan_id: str
    repo: str
    branch: str
    commit_sha: str
    findings_count: int
    critical: int
    high: int
    medium: int
    low: int
    policy_action: str
    details: List[Dict[str, Any]]
    scanned_at: str
    duration_ms: int


def _result_to_response(r: ScanResult) -> ScanResultResponse:
    return ScanResultResponse(
        scan_id=r.scan_id,
        repo=r.repo,
        branch=r.branch,
        commit_sha=r.commit_sha,
        findings_count=r.findings_count,
        critical=r.critical,
        high=r.high,
        medium=r.medium,
        low=r.low,
        policy_action=r.policy_action.value,
        details=r.details,
        scanned_at=r.scanned_at.isoformat(),
        duration_ms=r.duration_ms,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", summary="Submit a CI scan and evaluate against policy")
def submit_scan(body: ScanSubmitRequest) -> Dict[str, Any]:
    """Evaluate *findings* from a CI job against the configured policy.

    Returns the scan result including ``policy_action`` (pass | warn | block).
    The result is also stored in scan history.

    If ``policy_id`` is empty, a default permissive policy is applied.
    """
    engine = _get_engine()

    # If no policy_id supplied, create a default permissive policy on the fly
    policy_id = body.policy_id
    if not policy_id:
        default_rule = PolicyRule(
            name="default",
            severity_threshold="critical",
            max_critical=0,
            max_high=10,
        )
        policy_id = engine.create_policy([default_rule])
        logger.debug("Created default policy %s for scan", policy_id)

    try:
        result = engine.evaluate_scan(
            findings=body.findings,
            policy_id=policy_id,
            repo=body.repo,
            branch=body.branch,
            commit_sha=body.commit_sha,
            duration_ms=body.duration_ms,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return _result_to_response(result).model_dump()


@router.post("/evaluate", summary="Generate PR comment and badge for a scan result")
def evaluate_result(body: EvaluateRequest) -> Dict[str, Any]:
    """Given a scan result dict, generate a PR comment (markdown) and badge data.

    The ``scan_result`` field should be the object returned by ``POST /scan``.
    """
    engine = _get_engine()

    try:
        result = ScanResult(**body.scan_result)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid scan_result: {exc}") from exc

    comment = engine.generate_pr_comment(result)
    badge = engine.generate_badge(result)

    return {
        "comment": comment,
        "badge": badge,
        "policy_action": result.policy_action.value,
    }


@router.get("/policies", summary="List all CI/CD policies")
def list_policies(
    org_id: str = Query("", description="Filter by organisation ID"),
) -> Dict[str, Any]:
    """Return all stored policies, optionally filtered by ``org_id``."""
    engine = _get_engine()
    policies = engine.list_policies(org_id=org_id)
    return {"policies": policies, "count": len(policies)}


@router.post("/policies", summary="Create a new CI/CD policy")
def create_policy(body: PolicyCreateRequest) -> Dict[str, Any]:
    """Create and store a new policy, returning its ``policy_id``."""
    engine = _get_engine()
    policy_id = engine.create_policy(rules=body.rules, org_id=body.org_id)
    return {
        "policy_id": policy_id,
        "org_id": body.org_id,
        "rules_count": len(body.rules),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/history/{repo:path}", summary="Scan history for a repository")
def scan_history(
    repo: str = Path(..., description="Repository slug (may contain slashes)"),
    branch: str = Query("", description="Filter by branch name"),
    limit: int = Query(50, ge=1, le=500, description="Maximum results"),
) -> Dict[str, Any]:
    """Return recent scan results for *repo*, newest first."""
    engine = _get_engine()
    results = engine.get_scan_history(repo=repo, branch=branch, limit=limit)
    return {
        "repo": repo,
        "branch": branch or None,
        "results": [_result_to_response(r).model_dump() for r in results],
        "count": len(results),
    }


@router.get("/badge/{repo:path}", summary="Security badge data for a repository")
def get_badge(
    repo: str = Path(..., description="Repository slug (may contain slashes)"),
    branch: str = Query("main", description="Branch name"),
) -> Dict[str, Any]:
    """Return badge SVG and metadata for the latest scan of *repo*/*branch*.

    If no scan exists, returns a neutral 'unknown' badge.
    """
    engine = _get_engine()
    history = engine.get_scan_history(repo=repo, branch=branch, limit=1)

    if not history:
        return {
            "action": "unknown",
            "label": "unknown",
            "message": "no scans",
            "color": "#9f9f9f",
            "svg": (
                '<svg xmlns="http://www.w3.org/2000/svg" width="150" height="20">'
                '<rect width="80" height="20" fill="#555"/>'
                '<rect x="80" width="70" height="20" fill="#9f9f9f"/>'
                '<text x="40" y="14" fill="#fff" font-family="Verdana" font-size="11"'
                ' text-anchor="middle">security</text>'
                '<text x="115" y="14" fill="#fff" font-family="Verdana" font-size="11"'
                ' text-anchor="middle">unknown</text>'
                '</svg>'
            ),
            "repo": repo,
            "branch": branch,
        }

    latest = history[0]
    return engine.generate_badge(latest)
