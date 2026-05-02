"""
Security Policy Document Generator API endpoints.

Provides full lifecycle management for security policy documents:
generate, list, get, update, approve, archive, review-due, export.

Compliance: SOC2 CC9.2, ISO27001 A.5.1, NIST CSF ID.GV-1.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.policy_generator import PolicyDocument, PolicyGenerator, PolicyType
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/policy-generator", tags=["policy-generator"])

# Module-level singleton (file-backed in production via env override)
_generator = PolicyGenerator()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GeneratePolicyRequest(BaseModel):
    """Request body for generating a new policy."""

    type: PolicyType
    org_id: str = Field(default="default")
    custom_title: Optional[str] = Field(None, description="Override the default policy title")
    review_days: int = Field(default=365, ge=1, description="Days until next review (default 365)")


class UpdatePolicyRequest(BaseModel):
    """Request body for updating policy content."""

    content: str = Field(..., description="New Markdown content for the policy")


class ApprovePolicyRequest(BaseModel):
    """Request body for approving a policy."""

    approver: str = Field(..., description="Name or ID of the approver")


class PolicyResponse(BaseModel):
    """API response shape for a policy document."""

    id: str
    type: str
    title: str
    version: str
    content: str
    approved_by: Optional[str]
    effective_date: Optional[str]
    review_date: Optional[str]
    status: str
    org_id: str
    created_at: str
    updated_at: str


def _to_response(policy: PolicyDocument) -> PolicyResponse:
    """Convert a PolicyDocument to the API response shape."""
    return PolicyResponse(
        id=policy.id,
        type=str(policy.type),
        title=policy.title,
        version=policy.version,
        content=policy.content,
        approved_by=policy.approved_by,
        effective_date=policy.effective_date.isoformat() if policy.effective_date else None,
        review_date=policy.review_date.isoformat() if policy.review_date else None,
        status=str(policy.status),
        org_id=policy.org_id,
        created_at=policy.created_at.isoformat(),
        updated_at=policy.updated_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/generate", response_model=PolicyResponse, status_code=201)
def generate_policy(req: GeneratePolicyRequest) -> PolicyResponse:
    """
    Auto-generate a security policy document from built-in best-practice templates.

    Returns a DRAFT policy that can be reviewed, edited, and approved.
    """
    try:
        policy = _generator.generate_policy(
            type=req.type,
            org_id=req.org_id,
            custom_title=req.custom_title,
            review_days=req.review_days,
        )
        return _to_response(policy)
    except Exception as exc:
        _logger.exception("Failed to generate policy type=%s", req.type)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies", response_model=List[PolicyResponse])
def list_policies(org_id: str = Query(default="default", description="Organisation ID")) -> List[PolicyResponse]:
    """List all policy documents for an organisation."""
    return [_to_response(p) for p in _generator.list_policies(org_id=org_id)]


@router.get("/policies/due-review", response_model=List[PolicyResponse])
def get_policies_due_review(
    org_id: str = Query(default="default", description="Organisation ID"),
) -> List[PolicyResponse]:
    """Return policies that are overdue for review (review_date is in the past)."""
    return [_to_response(p) for p in _generator.get_policies_due_review(org_id=org_id)]


@router.get("/policies/{policy_id}", response_model=PolicyResponse)
def get_policy(policy_id: str) -> PolicyResponse:
    """Retrieve a single policy document by ID."""
    policy = _generator.get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return _to_response(policy)


@router.put("/policies/{policy_id}/content", response_model=PolicyResponse)
def update_policy(policy_id: str, req: UpdatePolicyRequest) -> PolicyResponse:
    """Update the Markdown content of an existing policy document."""
    policy = _generator.update_policy(policy_id, content=req.content)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return _to_response(policy)


@router.post("/policies/{policy_id}/approve", response_model=PolicyResponse)
def approve_policy(policy_id: str, req: ApprovePolicyRequest) -> PolicyResponse:
    """
    Approve a policy document.

    Sets status to ACTIVE, records the approver, and sets effective_date to now.
    """
    policy = _generator.approve_policy(policy_id, approver=req.approver)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return _to_response(policy)


@router.post("/policies/{policy_id}/archive", response_model=PolicyResponse)
def archive_policy(policy_id: str) -> PolicyResponse:
    """Archive a policy document (marks it as ARCHIVED)."""
    policy = _generator.archive_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return _to_response(policy)


@router.get("/policies/{policy_id}/export")
def export_policy(
    policy_id: str,
    format: str = Query(default="markdown", description="Export format: 'markdown' or 'html'"),
):
    """
    Export a policy document in Markdown or HTML format.

    Returns plain text for Markdown, HTML response for HTML format.
    """
    try:
        content = _generator.export_policy(policy_id, format=format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if content is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")

    fmt = format.lower().strip()
    if fmt == "html":
        return HTMLResponse(content=content)
    return PlainTextResponse(content=content, media_type="text/markdown")
