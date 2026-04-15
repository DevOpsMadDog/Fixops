"""
Compliance Gap Analysis & Audit Readiness API — ALDECI.

Exposes the new gap-analysis, audit-readiness, remediation-task, and
cross-framework-coverage methods added to ComplianceAutomation.

Prefix: /api/v1/compliance-automation
Frameworks: SOC2, ISO27001, PCI-DSS, HIPAA, NIST-CSF, CIS, GDPR
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.compliance_automation import ComplianceAutomation, SUPPORTED_FRAMEWORKS

router = APIRouter(prefix="/api/v1/compliance-automation", tags=["compliance"])

# Module-level singleton
_engine = ComplianceAutomation(db_path="data/compliance_automation.db")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RemediationTaskRequest(BaseModel):
    control_id: str = Field(..., description="Control ID the task addresses")
    framework: str = Field(..., description="Compliance framework")
    title: str = Field(..., description="Short title for the remediation task")
    description: str = Field(default="", description="Detailed description")
    assignee: str = Field(default="", description="Responsible person or team")
    due_date: Optional[str] = Field(None, description="ISO8601 due date")
    priority: str = Field(default="medium", description="critical/high/medium/low")
    task_status: str = Field(default="open", description="open/in_progress/closed")


class UpdateControlStatusRequest(BaseModel):
    status: str = Field(..., description="passing|failing|not_applicable|in_remediation")
    evidence_url: Optional[str] = Field(None, description="URL to supporting evidence")


# ---------------------------------------------------------------------------
# GET /gap-analysis/{framework}
# ---------------------------------------------------------------------------


@router.get("/gap-analysis/{framework}", summary="Run gap analysis for a framework")
async def get_gap_analysis(
    framework: str,
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Run gap analysis for the given framework.

    Returns score (0-100), passing/failing control counts, and a list of gaps
    with priority and remediation guidance.
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported framework '{framework}'. Choose from: {SUPPORTED_FRAMEWORKS}",
        )
    try:
        return _engine.run_gap_analysis(org_id=org_id, framework=framework)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /audit-readiness/{framework}
# ---------------------------------------------------------------------------


@router.get("/audit-readiness/{framework}", summary="Audit readiness score for a framework")
async def get_audit_readiness(
    framework: str,
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Compute audit readiness score (0-100) for a framework.

    Returns whether the org is ready for audit (score >= 80), blocker controls,
    and estimated remediation days.
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported framework '{framework}'. Choose from: {SUPPORTED_FRAMEWORKS}",
        )
    try:
        return _engine.get_audit_readiness_score(org_id=org_id, framework=framework)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /remediation-tasks
# ---------------------------------------------------------------------------


@router.post("/remediation-tasks", summary="Create a remediation task", status_code=201)
async def create_remediation_task(
    body: RemediationTaskRequest,
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Create a remediation task linked to a specific control gap.
    """
    if body.framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported framework '{body.framework}'",
        )
    try:
        task_id = _engine.create_remediation_task(
            org_id=org_id,
            control_id=body.control_id,
            framework=body.framework,
            task=body.model_dump(),
        )
        return {"task_id": task_id, "control_id": body.control_id, "framework": body.framework}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /remediation-tasks
# ---------------------------------------------------------------------------


@router.get("/remediation-tasks", summary="List remediation tasks")
async def list_remediation_tasks(
    org_id: str = Query(default="default", description="Organisation identifier"),
    framework: Optional[str] = Query(None, description="Filter by framework"),
) -> List[Dict[str, Any]]:
    """
    List all remediation tasks for an organisation, optionally filtered by framework.
    """
    try:
        return _engine.list_remediation_tasks(org_id=org_id, framework=framework)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# PUT /controls/{framework}/{control_id}
# ---------------------------------------------------------------------------


@router.put("/controls/{framework}/{control_id}", summary="Update control status")
async def update_control_status(
    framework: str,
    control_id: str,
    body: UpdateControlStatusRequest,
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Update the status of a specific control.

    status: passing | failing | not_applicable | in_remediation
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported framework '{framework}'",
        )
    try:
        success = _engine.update_control_status(
            org_id=org_id,
            framework=framework,
            control_id=control_id,
            status=body.status,
            evidence_url=body.evidence_url,
        )
        return {
            "updated": success,
            "framework": framework,
            "control_id": control_id,
            "status": body.status,
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /report/{framework}
# ---------------------------------------------------------------------------


@router.get("/report/{framework}", summary="Generate full audit report")
async def generate_audit_report(
    framework: str,
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Generate a complete audit report for a framework.

    Includes gap analysis, control details, evidence summary, and remediation tasks.
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported framework '{framework}'",
        )
    try:
        return _engine.generate_audit_report(org_id=org_id, framework=framework)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /cross-framework
# ---------------------------------------------------------------------------


@router.get("/cross-framework", summary="Cross-framework control coverage map")
async def get_cross_framework_coverage(
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Show which controls overlap across all 6 supported frameworks.

    Returns coverage groups showing how a single implementation (e.g. MFA) satisfies
    controls across SOC2 CC6.1, ISO27001 A.9.4.2, PCI-DSS REQ-8, and more simultaneously.
    """
    try:
        return _engine.get_cross_framework_coverage(org_id=org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /frameworks
# ---------------------------------------------------------------------------


@router.get("/frameworks", summary="List supported frameworks")
async def list_frameworks() -> Dict[str, Any]:
    """Return the list of supported compliance frameworks."""
    return {
        "frameworks": SUPPORTED_FRAMEWORKS,
        "count": len(SUPPORTED_FRAMEWORKS),
    }
