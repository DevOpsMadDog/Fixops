"""
Compliance Automation API endpoints — ALDECI.

Exposes task scheduling, execution, evidence collection, control checks,
report generation, dashboard, and framework recipe seeding.

Protected with API key authentication via ``_verify_api_key`` (injected via
``app.include_router`` dependencies — see app.py).
"""

from __future__ import annotations

from datetime import timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.compliance_automation import (
    ComplianceAutomation,
    ComplianceTask,
    SUPPORTED_FRAMEWORKS,
    TaskType,
)

router = APIRouter(
    prefix="/api/v1/compliance-automation",
    tags=["compliance-automation"],
)

_engine = ComplianceAutomation()


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class ScheduleTaskRequest(BaseModel):
    framework: str
    control_id: str
    task_type: TaskType
    interval_hours: float = 24.0
    org_id: str = "default"
    description: str = ""


class CollectEvidenceRequest(BaseModel):
    framework: str
    control_id: str
    org_id: str = "default"


class CheckControlsRequest(BaseModel):
    framework: str
    control_id: str
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/tasks", response_model=ComplianceTask, status_code=201)
async def schedule_task(body: ScheduleTaskRequest) -> ComplianceTask:
    """
    Create a recurring compliance automation task.

    Schedules a task for the given framework control that will be executed
    at the specified interval.
    """
    try:
        return _engine.schedule_task(
            framework=body.framework,
            control_id=body.control_id,
            task_type=body.task_type,
            interval_hours=body.interval_hours,
            org_id=body.org_id,
            description=body.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/tasks/{task_id}/run", response_model=ComplianceTask)
async def run_task(task_id: str) -> ComplianceTask:
    """
    Execute a compliance task immediately.

    Runs the task regardless of its schedule and records the result.
    """
    try:
        return _engine.run_task(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/evidence/collect")
async def collect_evidence(body: CollectEvidenceRequest) -> Dict[str, Any]:
    """
    Trigger evidence collection from connected systems for a specific control.

    Returns collected evidence artifacts and collection metadata.
    """
    try:
        return _engine.auto_collect_evidence(
            framework=body.framework,
            control_id=body.control_id,
            org_id=body.org_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/controls/check")
async def check_controls(body: CheckControlsRequest) -> Dict[str, Any]:
    """
    Verify control implementation status for a framework control.

    Returns check results, identified gaps, and implementation status score.
    """
    try:
        return _engine.auto_check_controls(
            framework=body.framework,
            control_id=body.control_id,
            org_id=body.org_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/reports/{framework}")
async def generate_report(
    framework: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Generate a framework-specific compliance report.

    Aggregates all task results for the framework and computes an overall
    compliance score with per-control breakdown.
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported framework '{framework}'. Supported: {SUPPORTED_FRAMEWORKS}",
        )
    return _engine.generate_compliance_report(framework=framework, org_id=org_id)


@router.get("/dashboard")
async def get_dashboard(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Return all compliance tasks, their statuses, and next scheduled run times.

    Provides a full operational view of the automation engine for a given org.
    """
    return _engine.get_automation_dashboard(org_id=org_id)


@router.get("/tasks/due")
async def get_due_tasks(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[ComplianceTask]:
    """
    Return compliance tasks that are ready to execute (past their next-run time).
    """
    return _engine.get_due_tasks(org_id=org_id)


@router.post("/recipes/{framework}", status_code=201)
async def seed_framework_recipes(
    framework: str,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Seed built-in automation recipes for a compliance framework.

    Creates all default scheduled tasks for the framework. Available frameworks:
    SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF, CIS, GDPR.
    """
    try:
        tasks = _engine.seed_framework_recipes(framework=framework, org_id=org_id)
        return {
            "framework": framework,
            "org_id": org_id,
            "tasks_created": len(tasks),
            "task_ids": [t.id for t in tasks],
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
