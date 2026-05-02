"""Vulnerability Disclosure Program (VDP) / Bug Bounty Management API Router.

8 endpoints under /api/v1/bounty:
  POST   /api/v1/bounty/programs              — create program
  GET    /api/v1/bounty/programs              — list programs
  PATCH  /api/v1/bounty/programs/{id}/status  — update program status
  POST   /api/v1/bounty/submissions           — submit vulnerability
  GET    /api/v1/bounty/submissions           — list submissions
  PATCH  /api/v1/bounty/submissions/{id}/triage — triage submission
  PATCH  /api/v1/bounty/rewards/{id}          — update reward status
  GET    /api/v1/bounty/programs/{id}/metrics — program metrics

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.bug_bounty import (
    BountyProgram,
    BugBountyEngine,
    OWASPCategory,
    ProgramMetrics,
    ProgramScope,
    ProgramStatus,
    RewardRecord,
    RewardStatus,
    Severity,
    SubmissionStatus,
    VulnerabilitySubmission,
    get_bug_bounty_engine,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/bounty", tags=["bug-bounty"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateProgramRequest(BaseModel):
    name: str = Field(..., description="Program name (e.g. 'ALDECI Public VDP')")
    description: str = Field("", description="Program description and goals")
    monthly_budget: float = Field(0.0, ge=0, description="Monthly reward budget cap (USD)")
    safe_harbor: str = Field(
        "Researchers acting in good faith will not face legal action.",
        description="Safe harbor policy text",
    )
    legal_terms: str = Field("", description="Full legal terms and conditions")
    in_scope: List[str] = Field(default_factory=list, description="In-scope assets")
    out_of_scope: List[str] = Field(default_factory=list, description="Out-of-scope assets")
    org_id: str = Field("default", description="Organisation ID")


class UpdateProgramStatusRequest(BaseModel):
    status: ProgramStatus = Field(..., description="New program status")


class SubmitVulnerabilityRequest(BaseModel):
    program_id: str = Field(..., description="Target bug bounty program ID")
    reporter_email: str = Field(..., description="Reporter's email address")
    reporter_name: str = Field("", description="Reporter's display name or handle")
    affected_asset: str = Field(..., description="Affected asset (URL, domain, repo, IP)")
    vuln_type: OWASPCategory = Field(OWASPCategory.OTHER, description="OWASP Top 10 category")
    title: str = Field(..., description="Short vulnerability title")
    description: str = Field(..., description="Detailed vulnerability description")
    poc_steps: str = Field("", description="Step-by-step proof-of-concept reproduction")
    impact_assessment: str = Field("", description="Reporter's assessment of business impact")
    attachments: List[str] = Field(default_factory=list, description="Attachment filenames or URLs")
    org_id: str = Field("default", description="Organisation ID")


class TriageSubmissionRequest(BaseModel):
    decision: SubmissionStatus = Field(
        ...,
        description="Triage decision: triaging | accepted | rejected | duplicate | informational",
    )
    severity: Optional[Severity] = Field(None, description="Assigned severity")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS v3 score")
    notes: str = Field("", description="Internal triage notes")


class UpdateRewardRequest(BaseModel):
    status: RewardStatus = Field(..., description="New reward status")
    bonus_amount: float = Field(0.0, ge=0, description="Bonus amount on top of base reward (USD)")
    notes: str = Field("", description="Reward notes (payment reference, justification, etc.)")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _engine() -> BugBountyEngine:
    return get_bug_bounty_engine()


def _require_program(program_id: str) -> BountyProgram:
    prog = _engine().get_program(program_id)
    if not prog:
        raise HTTPException(status_code=404, detail=f"Program '{program_id}' not found")
    return prog


def _require_submission(submission_id: str) -> VulnerabilitySubmission:
    sub = _engine().get_submission(submission_id)
    if not sub:
        raise HTTPException(status_code=404, detail=f"Submission '{submission_id}' not found")
    return sub


def _require_reward(reward_id: str) -> RewardRecord:
    reward = _engine().get_reward(reward_id)
    if not reward:
        raise HTTPException(status_code=404, detail=f"Reward '{reward_id}' not found")
    return reward


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/programs", response_model=BountyProgram, summary="Create bug bounty program")
def create_program(req: CreateProgramRequest) -> BountyProgram:
    """Create a new Vulnerability Disclosure Program with default reward tiers."""
    scope = ProgramScope(in_scope=req.in_scope, out_of_scope=req.out_of_scope)
    try:
        return _engine().create_program(
            name=req.name,
            description=req.description,
            scope=scope,
            monthly_budget=req.monthly_budget,
            safe_harbor=req.safe_harbor,
            legal_terms=req.legal_terms,
            org_id=req.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to create program: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to create program: {exc}") from exc


@router.get("/programs", response_model=List[BountyProgram], summary="List bug bounty programs")
def list_programs(
    org_id: str = Query("default", description="Organisation ID"),
    status: Optional[ProgramStatus] = Query(None, description="Filter by program status"),
) -> List[BountyProgram]:
    """List all bug bounty programs for an org, with optional status filter."""
    return _engine().list_programs(org_id, status=status)


@router.patch(
    "/programs/{program_id}/status",
    response_model=BountyProgram,
    summary="Update program status",
)
def update_program_status(program_id: str, req: UpdateProgramStatusRequest) -> BountyProgram:
    """Activate, pause, or close a bug bounty program."""
    _require_program(program_id)
    try:
        return _engine().update_program_status(program_id, req.status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to update program status: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to update status: {exc}") from exc


@router.post(
    "/submissions",
    response_model=VulnerabilitySubmission,
    summary="Submit vulnerability report",
)
def submit_vulnerability(req: SubmitVulnerabilityRequest) -> VulnerabilitySubmission:
    """Accept a new vulnerability submission. Auto-acknowledges and deduplicates."""
    _require_program(req.program_id)
    try:
        return _engine().submit_vulnerability(
            program_id=req.program_id,
            reporter_email=req.reporter_email,
            reporter_name=req.reporter_name,
            affected_asset=req.affected_asset,
            vuln_type=req.vuln_type,
            title=req.title,
            description=req.description,
            poc_steps=req.poc_steps,
            impact_assessment=req.impact_assessment,
            attachments=req.attachments,
            org_id=req.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to accept submission: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to accept submission: {exc}") from exc


@router.get(
    "/submissions",
    response_model=List[VulnerabilitySubmission],
    summary="List vulnerability submissions",
)
def list_submissions(
    org_id: str = Query("default", description="Organisation ID"),
    program_id: Optional[str] = Query(None, description="Filter by program ID"),
    status: Optional[SubmissionStatus] = Query(None, description="Filter by submission status"),
    severity: Optional[Severity] = Query(None, description="Filter by severity"),
    reporter_id: Optional[str] = Query(None, description="Filter by reporter ID"),
) -> List[VulnerabilitySubmission]:
    """List vulnerability submissions with optional filters."""
    return _engine().list_submissions(
        org_id,
        program_id=program_id,
        status=status,
        reporter_id=reporter_id,
        severity=severity,
    )


@router.patch(
    "/submissions/{submission_id}/triage",
    response_model=VulnerabilitySubmission,
    summary="Triage a submission",
)
def triage_submission(submission_id: str, req: TriageSubmissionRequest) -> VulnerabilitySubmission:
    """Set triage decision, severity, and CVSS score. Creates pending reward on acceptance."""
    _require_submission(submission_id)
    try:
        return _engine().triage_submission(
            submission_id=submission_id,
            decision=req.decision,
            severity=req.severity,
            cvss_score=req.cvss_score,
            notes=req.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to triage submission: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to triage: {exc}") from exc


@router.patch(
    "/rewards/{reward_id}",
    response_model=RewardRecord,
    summary="Update reward status",
)
def update_reward(reward_id: str, req: UpdateRewardRequest) -> RewardRecord:
    """Approve, pay, dispute, or waive a researcher reward."""
    _require_reward(reward_id)
    try:
        return _engine().update_reward_status(
            reward_id=reward_id,
            status=req.status,
            bonus_amount=req.bonus_amount,
            notes=req.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to update reward: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to update reward: {exc}") from exc


@router.get(
    "/programs/{program_id}/metrics",
    response_model=ProgramMetrics,
    summary="Program metrics and ROI",
)
def get_program_metrics(
    program_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> ProgramMetrics:
    """Return full program metrics: submissions, acceptance rate, avg triage time, ROI."""
    _require_program(program_id)
    try:
        return _engine().get_program_metrics(program_id, org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to compute metrics: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to compute metrics: {exc}") from exc
