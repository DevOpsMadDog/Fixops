"""
Security Awareness Training Tracker API router for ALDECI.

Provides endpoints for managing training modules and tracking employee
security awareness training completions across organizations.

Routes:
- POST   /api/v1/training/modules              — add training module
- GET    /api/v1/training/modules              — list training modules
- GET    /api/v1/training/modules/{module_id}  — get module detail
- POST   /api/v1/training/completions          — record training completion
- GET    /api/v1/training/users/{email}        — user training history
- GET    /api/v1/training/orgs/{org_id}/completion-rate — org completion rate
- GET    /api/v1/training/orgs/{org_id}/overdue         — overdue users
- GET    /api/v1/training/orgs/{org_id}/stats           — org training stats
- GET    /api/v1/training/orgs/{org_id}/compliance/{framework} — compliance evidence

Protected by api_key_auth dependency.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth
from core.training_tracker import TrainingCategory, TrainingCompletion, TrainingModule

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/training",
    tags=["training"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton — avoids import-time SQLite init during tests
# ---------------------------------------------------------------------------

_tracker = None


def _get_tracker():
    global _tracker
    if _tracker is None:
        from core.training_tracker import TrainingTracker
        _tracker = TrainingTracker()
    return _tracker


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AddModuleRequest(BaseModel):
    title: str = Field(..., description="Module title")
    description: str = Field(..., description="Module description")
    category: TrainingCategory = Field(..., description="Training category")
    duration_minutes: int = Field(..., ge=1, description="Estimated duration in minutes")
    passing_score: int = Field(..., ge=0, le=100, description="Minimum passing score (0-100)")
    content_url: str = Field(..., description="URL to training content")


class RecordCompletionRequest(BaseModel):
    user_email: str = Field(..., description="User's email address")
    module_id: str = Field(..., description="Training module ID")
    score: int = Field(..., ge=0, le=100, description="Score achieved (0-100)")
    org_id: str = Field(default="default", description="Organisation ID")
    completed_at: Optional[datetime] = Field(
        default=None,
        description="Completion timestamp (defaults to now)",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/modules", response_model=Dict[str, Any], status_code=201)
async def add_module(request: AddModuleRequest):
    """Create a new security awareness training module."""
    tracker = _get_tracker()
    module = TrainingModule(
        title=request.title,
        description=request.description,
        category=request.category,
        duration_minutes=request.duration_minutes,
        passing_score=request.passing_score,
        content_url=request.content_url,
    )
    try:
        created = tracker.add_module(module)
    except Exception as exc:
        logger.exception("Failed to add training module: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to create training module") from exc
    return created.model_dump()


@router.get("/modules", response_model=List[Dict[str, Any]])
async def list_modules(
    category: Optional[TrainingCategory] = Query(default=None, description="Filter by category"),
):
    """List available training modules."""
    tracker = _get_tracker()
    modules = tracker.list_modules(category=category)
    return [m.model_dump() for m in modules]


@router.get("/modules/{module_id}", response_model=Dict[str, Any])
async def get_module(module_id: str):
    """Get a single training module by ID."""
    tracker = _get_tracker()
    module = tracker.get_module(module_id)
    if not module:
        raise HTTPException(status_code=404, detail=f"Module '{module_id}' not found")
    return module.model_dump()


@router.post("/completions", response_model=Dict[str, Any], status_code=201)
async def record_completion(request: RecordCompletionRequest):
    """Log a user's training result."""
    tracker = _get_tracker()

    # Verify module exists
    module = tracker.get_module(request.module_id)
    if not module:
        raise HTTPException(status_code=404, detail=f"Module '{request.module_id}' not found")

    passed = request.score >= module.passing_score
    completed_at = request.completed_at or datetime.now(timezone.utc)

    completion = TrainingCompletion(
        user_email=request.user_email,
        module_id=request.module_id,
        score=request.score,
        passed=passed,
        completed_at=completed_at,
        org_id=request.org_id,
    )

    try:
        recorded = tracker.record_completion(completion)
    except Exception as exc:
        logger.exception("Failed to record training completion: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to record completion") from exc

    result = recorded.model_dump()
    result["module_title"] = module.title
    result["passing_score"] = module.passing_score
    return result


@router.get("/users/{email}", response_model=List[Dict[str, Any]])
async def get_user_training(
    email: str,
    org_id: Optional[str] = Query(default=None, description="Filter by organisation"),
):
    """Get a user's training history."""
    tracker = _get_tracker()
    completions = tracker.get_user_training(email, org_id=org_id)
    return [c.model_dump() for c in completions]


@router.get("/orgs/{org_id}/completion-rate", response_model=Dict[str, Any])
async def get_completion_rate(org_id: str):
    """Get the percentage of users who completed required training for an org."""
    tracker = _get_tracker()
    return tracker.get_completion_rate(org_id)


@router.get("/orgs/{org_id}/overdue", response_model=List[Dict[str, Any]])
async def get_overdue_training(
    org_id: str,
    module_ids: Optional[str] = Query(
        default=None,
        description="Comma-separated required module IDs (defaults to all built-in modules)",
    ),
):
    """Get users who haven't completed all required training modules."""
    tracker = _get_tracker()
    required = [m.strip() for m in module_ids.split(",")] if module_ids else None
    return tracker.get_overdue_training(org_id, required_module_ids=required)


@router.get("/orgs/{org_id}/stats", response_model=Dict[str, Any])
async def get_training_stats(org_id: str):
    """Get comprehensive training stats for an org: by module, by user, pass rates."""
    tracker = _get_tracker()
    return tracker.get_training_stats(org_id)


@router.get("/orgs/{org_id}/compliance/{framework}", response_model=Dict[str, Any])
async def get_compliance_training_status(org_id: str, framework: str):
    """Get training evidence for a compliance framework (SOC2, HIPAA, PCI-DSS, ISO27001, GDPR, NIST)."""
    supported = {"SOC2", "HIPAA", "PCI-DSS", "ISO27001", "GDPR", "NIST"}
    if framework.upper() not in supported:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework '{framework}'. Supported: {', '.join(sorted(supported))}",
        )
    tracker = _get_tracker()
    return tracker.get_compliance_training_status(org_id, framework)
