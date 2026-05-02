"""Control Testing Router — ALDECI.

Endpoints for the Control Testing engine.

Prefix: /api/v1/control-testing
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/control-testing/controls                    create_control
  GET  /api/v1/control-testing/controls                    list_controls
  GET  /api/v1/control-testing/controls/{control_id}       get_control
  POST /api/v1/control-testing/controls/{control_id}/tests run_test
  POST /api/v1/control-testing/schedules                   create_schedule
  POST /api/v1/control-testing/schedules/{id}/run          update_schedule_run
  GET  /api/v1/control-testing/due                         get_due_tests
  GET  /api/v1/control-testing/summary                     get_control_effectiveness_summary
  GET  /api/v1/control-testing/failing                     get_failing_controls
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/control-testing",
    tags=["Control Testing"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.control_testing_engine import ControlTestingEngine
        _engine = ControlTestingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ControlCreate(BaseModel):
    org_id: str
    control_name: str
    control_type: str = "preventive"
    framework: str = "NIST"
    description: str = ""
    owner: str = ""
    test_frequency_days: int = Field(default=90, ge=1)


class TestRun(BaseModel):
    org_id: str
    test_name: str
    test_method: str = "manual"
    tester: str = ""
    result: str = "fail"
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    findings: str = ""
    evidence: str = ""


class ScheduleCreate(BaseModel):
    org_id: str
    control_id: str
    schedule_name: str
    frequency_days: int = Field(default=90, ge=1)


class ScheduleRunUpdate(BaseModel):
    org_id: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_control_testing(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get control testing effectiveness summary for the org."""
    return _get_engine().get_control_effectiveness_summary(org_id=org_id)


@router.post("/controls", dependencies=[Depends(api_key_auth)])
def create_control(body: ControlCreate) -> Dict[str, Any]:
    """Create a new security control."""
    try:
        return _get_engine().create_control(
            org_id=body.org_id,
            control_name=body.control_name,
            control_type=body.control_type,
            framework=body.framework,
            description=body.description,
            owner=body.owner,
            test_frequency_days=body.test_frequency_days,
        )
    except Exception as exc:
        _logger.exception("create_control error")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/controls", dependencies=[Depends(api_key_auth)])
def list_controls(
     org_id: str = Query(default="default"),
    framework: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List controls with optional framework/status filters."""
    return _get_engine().list_controls(org_id=org_id, framework=framework, status=status)


@router.get("/controls/{control_id}", dependencies=[Depends(api_key_auth)])
def get_control(
    control_id: str,
     org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a control with its 10 most recent tests."""
    result = _get_engine().get_control(control_id=control_id, org_id=org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Control not found")
    return result


@router.post("/controls/{control_id}/tests", dependencies=[Depends(api_key_auth)])
def run_test(control_id: str, body: TestRun) -> Dict[str, Any]:
    """Run a test against a control and update its effectiveness score."""
    result = _get_engine().run_test(
        control_id=control_id,
        org_id=body.org_id,
        test_name=body.test_name,
        test_method=body.test_method,
        tester=body.tester,
        result=body.result,
        score=body.score,
        findings=body.findings,
        evidence=body.evidence,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Control not found")
    return result


@router.post("/schedules", dependencies=[Depends(api_key_auth)])
def create_schedule(body: ScheduleCreate) -> Dict[str, Any]:
    """Create a test schedule for a control."""
    try:
        return _get_engine().create_schedule(
            org_id=body.org_id,
            control_id=body.control_id,
            schedule_name=body.schedule_name,
            frequency_days=body.frequency_days,
        )
    except Exception as exc:
        _logger.exception("create_schedule error")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/schedules/{schedule_id}/run", dependencies=[Depends(api_key_auth)])
def update_schedule_run(schedule_id: str, body: ScheduleRunUpdate) -> Dict[str, Any]:
    """Mark a schedule as run and advance its next_run date."""
    result = _get_engine().update_schedule_run(
        schedule_id=schedule_id, org_id=body.org_id
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return result


@router.get("/due", dependencies=[Depends(api_key_auth)])
def get_due_tests(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """Get controls that are due for testing."""
    return _get_engine().get_due_tests(org_id=org_id)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_control_effectiveness_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get control effectiveness summary: avg score, status counts, framework breakdown."""
    return _get_engine().get_control_effectiveness_summary(org_id=org_id)


@router.get("/failing", dependencies=[Depends(api_key_auth)])
def get_failing_controls(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """Get controls with status ineffective or failing."""
    return _get_engine().get_failing_controls(org_id=org_id)
