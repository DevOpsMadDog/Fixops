"""
Continuous Control Monitoring (CCM) Router — ALDECI.

Prefix: /api/v1/ccm
Auth:   X-API-Key header (injected via Depends(_verify_api_key) in app.py)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.ccm_engine import get_engine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "ccm_engine",
    "real_integration_required": "/api/v1/connectors/ccm/configure",
    "do_not_use_in_demo": True,
}

router = APIRouter(prefix="/api/v1/ccm", tags=["ccm"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class RegisterControlRequest(BaseModel):
    control_name: str
    framework: str = "NIST"
    control_ref: str = ""
    category: str = ""
    description: str = ""
    control_type: str = "detective"
    frequency: str = "monthly"
    owner: str = ""
    enabled: bool = True


class AddTestRequest(BaseModel):
    test_name: str
    test_type: str = "automated"
    expected_result: str = ""
    evidence: str = ""


class LogFailureRequest(BaseModel):
    control_id: str
    test_id: Optional[str] = None
    failure_type: str = "gap"
    severity: str = "medium"
    description: str = ""
    detected_at: Optional[str] = None


class RemediateFailureRequest(BaseModel):
    notes: str = ""


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/controls", summary="Register a security control")
def register_control(org_id: str, req: RegisterControlRequest) -> Dict[str, Any]:
    try:
        return get_engine().register_control(org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_control failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/orgs/{org_id}/controls", summary="List security controls")
def list_controls(
    org_id: str,
    framework: Optional[str] = Query(None),
    control_type: Optional[str] = Query(None),
    enabled_only: bool = Query(True),
) -> List[Dict[str, Any]]:
    try:
        return get_engine().list_controls(org_id, framework=framework,
                                          control_type=control_type, enabled_only=enabled_only)
    except Exception as exc:
        _logger.exception("list_controls failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/controls/{control_id}/tests", summary="Add a control test")
def add_test(org_id: str, control_id: str, req: AddTestRequest) -> Dict[str, Any]:
    try:
        return get_engine().add_test(org_id, control_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("add_test failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/orgs/{org_id}/tests/{test_id}/run", summary="Run a control test")
def run_test(org_id: str, test_id: str) -> Dict[str, Any]:
    try:
        result = get_engine().run_test(org_id, test_id)
        return {"data": result, "_simulation_warning": _SIMULATION_WARNING}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("run_test failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/orgs/{org_id}/tests", summary="List control tests")
def list_tests(
    org_id: str,
    control_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return get_engine().list_tests(org_id, control_id=control_id, status=status)
    except Exception as exc:
        _logger.exception("list_tests failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/failures", summary="Log a control failure")
def log_failure(org_id: str, req: LogFailureRequest) -> Dict[str, Any]:
    try:
        data = req.model_dump()
        return get_engine().log_failure(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("log_failure failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/orgs/{org_id}/failures/{failure_id}/remediate", summary="Remediate a failure")
def remediate_failure(org_id: str, failure_id: str, req: RemediateFailureRequest) -> Dict[str, Any]:
    try:
        success = get_engine().remediate_failure(org_id, failure_id, req.notes)
        if not success:
            raise HTTPException(status_code=404, detail="Failure not found or already remediated")
        return {"failure_id": failure_id, "remediated": True}
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("remediate_failure failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/orgs/{org_id}/failures", summary="List control failures")
def list_failures(
    org_id: str,
    remediated: bool = Query(False),
    severity: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    try:
        return get_engine().list_failures(org_id, remediated=remediated, severity=severity)
    except Exception as exc:
        _logger.exception("list_failures failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Coverage & Stats
# ---------------------------------------------------------------------------

@router.get("/orgs/{org_id}/coverage", summary="Get control coverage by framework")
def get_control_coverage(org_id: str) -> Dict[str, Any]:
    try:
        return get_engine().get_control_coverage(org_id)
    except Exception as exc:
        _logger.exception("get_control_coverage failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/orgs/{org_id}/stats", summary="Get CCM statistics")
def get_ccm_stats(org_id: str) -> Dict[str, Any]:
    try:
        return get_engine().get_ccm_stats(org_id)
    except Exception as exc:
        _logger.exception("get_ccm_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
