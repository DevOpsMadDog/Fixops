"""Security Configuration Benchmark REST API — ALDECI.

Endpoints:
  POST   /api/v1/config-benchmark/profiles                         -- Create profile
  GET    /api/v1/config-benchmark/profiles                         -- List profiles
  POST   /api/v1/config-benchmark/profiles/{profile_id}/checks     -- Add check
  GET    /api/v1/config-benchmark/profiles/{profile_id}/checks     -- List checks
  POST   /api/v1/config-benchmark/profiles/{profile_id}/assess     -- Run assessment
  GET    /api/v1/config-benchmark/assessments                      -- List assessments
  GET    /api/v1/config-benchmark/assessments/{result_id}          -- Get assessment detail
  GET    /api/v1/config-benchmark/assessments/{result_id}/failures -- Failed checks
  GET    /api/v1/config-benchmark/stats                            -- Aggregate stats

Security: Bearer token / API key required on all endpoints.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.config_benchmark_engine import ConfigBenchmarkEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_SIMULATION_WARNING = {
    "is_simulated": True,
    "engine": "config_benchmark_engine",
    "real_integration_required": "/api/v1/connectors/config-benchmark/configure",
    "do_not_use_in_demo": True,
}

router = APIRouter(prefix="/api/v1/config-benchmark", tags=["config-benchmark"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = ConfigBenchmarkEngine()
    return _engine


# ============================================================================
# REQUEST MODELS
# ============================================================================


class ProfileRequest(BaseModel):
    name: str = Field(..., min_length=1)
    standard: str = Field("CIS", pattern="^(CIS|DISA_STIG|NIST_800_53|PCI_DSS_HW|custom)$")
    target_type: str = Field(
        "linux_server",
        pattern="^(linux_server|windows_server|network_device|kubernetes|docker|aws|azure)$",
    )
    version: str = Field("1.0")


class CheckRequest(BaseModel):
    check_ref: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    description: str = Field("")
    category: str = Field("")
    severity: str = Field("medium", pattern="^(critical|high|medium|low|info)$")
    expected_value: str = Field("")
    remediation: str = Field("")


class AssessRequest(BaseModel):
    target_name: str = Field(..., min_length=1)


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/profiles", summary="Create a benchmark profile")
async def create_profile(
    body: ProfileRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    try:
        return _get_engine().create_profile(org_id, body.model_dump())
    except Exception as exc:
        logger.error("create_profile failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/profiles", summary="List benchmark profiles")
async def list_profiles(
    standard: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    return _get_engine().list_profiles(org_id, standard=standard)


@router.post("/profiles/{profile_id}/checks", summary="Add a check to a profile")
async def add_check(
    profile_id: str,
    body: CheckRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    try:
        return _get_engine().add_check(org_id, profile_id, body.model_dump())
    except Exception as exc:
        logger.error("add_check failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/profiles/{profile_id}/checks", summary="List checks for a profile")
async def list_checks(
    profile_id: str,
    severity: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    return _get_engine().list_checks(org_id, profile_id, severity=severity)


@router.post("/profiles/{profile_id}/assess", summary="Run assessment against a profile")
async def run_assessment(
    profile_id: str,
    body: AssessRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    result = _get_engine().run_assessment(org_id, profile_id, body.target_name)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"data": result, "_simulation_warning": _SIMULATION_WARNING}


@router.get("/assessments", summary="List assessments")
async def list_assessments(
    profile_id: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    return _get_engine().list_assessments(org_id, profile_id=profile_id)


@router.get("/assessments/{result_id}", summary="Get assessment detail with check results")
async def get_assessment(
    result_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    result = _get_engine().get_assessment(org_id, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.get("/assessments/{result_id}/failures", summary="List failed checks for an assessment")
async def get_failed_checks(
    result_id: str,
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    return _get_engine().get_failed_checks(org_id, result_id)


@router.get("/stats", summary="Aggregate benchmark statistics")
async def get_benchmark_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    return _get_engine().get_benchmark_stats(org_id)
