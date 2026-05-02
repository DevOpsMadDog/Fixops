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

from apps.api.auth_deps import api_key_auth
from core.security_training import SecurityAwarenessTracker
from core.training_tracker import TrainingCategory, TrainingCompletion, TrainingModule
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

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


# ---------------------------------------------------------------------------
# SecurityAwarenessTracker endpoints
# ---------------------------------------------------------------------------

_awareness_tracker: Optional[SecurityAwarenessTracker] = None


def _get_awareness_tracker() -> SecurityAwarenessTracker:
    global _awareness_tracker
    if _awareness_tracker is None:
        _awareness_tracker = SecurityAwarenessTracker()
    return _awareness_tracker


class AssignTrainingRequest(BaseModel):
    user_id: str = Field(..., description="User ID to assign training to")
    module: str = Field(..., description="Module ID (e.g. 'phishing-awareness')")
    due_date: Optional[datetime] = Field(default=None, description="Assignment due date (ISO 8601)")


class RecordAwarenessCompletionRequest(BaseModel):
    user_id: str = Field(..., description="User ID")
    assignment_id: str = Field(..., description="Assignment ID returned from /assign")
    score: float = Field(..., ge=0.0, le=100.0, description="Quiz score (0–100)")


class LaunchPhishingRequest(BaseModel):
    user_ids: List[str] = Field(..., description="User IDs to target")
    template: str = Field(..., description="Phishing template ID (e.g. 'tpl_cred_001')")


class PhishingClickRequest(BaseModel):
    campaign_id: str = Field(..., description="Campaign ID from /phishing/launch")
    user_id: str = Field(..., description="User ID who clicked the link")


@router.post("/assign", response_model=Dict[str, Any], status_code=201)
async def assign_training(request: AssignTrainingRequest):
    """Assign a training module to a user."""
    tracker = _get_awareness_tracker()
    assignment = tracker.assign_training(
        user_id=request.user_id,
        module=request.module,
        due_date=request.due_date,
    )
    return assignment.model_dump()


@router.post("/complete", response_model=Dict[str, Any], status_code=201)
async def record_awareness_completion(request: RecordAwarenessCompletionRequest):
    """Record training completion with a quiz score."""
    tracker = _get_awareness_tracker()
    completion = tracker.record_completion(
        user_id=request.user_id,
        assignment_id=request.assignment_id,
        score=request.score,
    )
    if completion is None:
        raise HTTPException(
            status_code=404,
            detail=f"Assignment '{request.assignment_id}' not found for user '{request.user_id}'",
        )
    return completion.model_dump()


@router.get("/compliance", response_model=Dict[str, Any])
async def get_team_compliance(
    team_id: str = Query(..., description="Team or department ID"),
):
    """Get training compliance report for a team."""
    tracker = _get_awareness_tracker()
    report = tracker.get_team_compliance(team_id=team_id)
    return report.model_dump()


@router.post("/phishing/launch", response_model=Dict[str, Any], status_code=201)
async def launch_phishing_simulation(request: LaunchPhishingRequest):
    """Launch a simulated phishing campaign against a list of users."""
    if not request.user_ids:
        raise HTTPException(status_code=400, detail="user_ids must not be empty")
    tracker = _get_awareness_tracker()
    campaign = tracker.run_phishing_simulation(
        user_ids=request.user_ids,
        template=request.template,
    )
    return campaign.model_dump()


@router.post("/phishing/click", response_model=Dict[str, Any])
async def record_phishing_click(request: PhishingClickRequest):
    """Record that a user clicked the phishing link (webhook callback)."""
    tracker = _get_awareness_tracker()
    try:
        campaign = tracker.record_phishing_click(
            campaign_id=request.campaign_id,
            user_id=request.user_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return campaign.model_dump()


@router.get("/user/{user_id}/risk", response_model=Dict[str, Any])
async def get_user_risk_score(user_id: str):
    """Calculate a user's security risk score (0.0 = no risk, 1.0 = maximum risk)."""
    tracker = _get_awareness_tracker()
    score = tracker.get_user_risk_score(user_id=user_id)
    return {"user_id": user_id, "risk_score": score}


@router.get("/suggest/{user_id}", response_model=Dict[str, Any])
async def suggest_training(
    user_id: str,
    findings: Optional[str] = Query(
        default=None,
        description="Comma-separated CWE IDs or finding labels (e.g. 'CWE-89,CWE-79')",
    ),
):
    """Suggest training modules based on recent security findings and user history."""
    tracker = _get_awareness_tracker()
    recent_findings = [f.strip() for f in findings.split(",")] if findings else []
    suggestions = tracker.suggest_training(user_id=user_id, recent_findings=recent_findings)
    return {"user_id": user_id, "suggested_modules": suggestions}
