"""DevSecOps Pipeline Security Router — ALDECI.

Exposes pipeline management, run triggering, findings, gate policies, and stats.
Prefix: /api/v1/devsecops
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/devsecops",
    tags=["DevSecOps Pipeline Security"],
)

_SIMULATION_WARNING: Dict[str, Any] = {
    "is_simulated": False,
    "engine": "devsecops_engine",
    "scanners": {
        "sast": "core.semgrep_integration.SemgrepScanner",
        "sca": "core.trivy_integration.TrivyScanner",
        "secret_scan": "core.secret_scanner_engine.SecretScannerEngine",
        "container": "core.trivy_integration.TrivyScanner",
    },
    "note": (
        "Real scanners — empty findings are returned when a scanner binary "
        "is unavailable; nothing is fabricated."
    ),
}


def _wrap(data: Any) -> Dict[str, Any]:
    """Wrap engine output with engine envelope (post-real-scanner cutover)."""
    return {"data": data, "_simulation_warning": _SIMULATION_WARNING}


# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.devsecops_engine import get_devsecops_engine
        _engine = get_devsecops_engine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PipelineCreate(BaseModel):
    name: str
    repo_url: str = ""
    branch: str = "main"
    ci_platform: str = "github_actions"
    security_gates_enabled: int = Field(default=1, ge=0, le=1)
    sast_enabled: int = Field(default=1, ge=0, le=1)
    dast_enabled: int = Field(default=0, ge=0, le=1)
    sca_enabled: int = Field(default=1, ge=0, le=1)
    secret_scan_enabled: int = Field(default=1, ge=0, le=1)
    container_scan_enabled: int = Field(default=0, ge=0, le=1)


class RunTrigger(BaseModel):
    triggered_by: str = "manual"
    commit_sha: str = ""
    branch: str = "main"


class GatePolicyCreate(BaseModel):
    name: str
    pipeline_id: str = ""
    block_on_critical: int = Field(default=1, ge=0, le=1)
    block_on_high: int = Field(default=0, ge=0, le=1)
    max_critical: int = Field(default=0, ge=0)
    max_high: int = Field(default=5, ge=0)
    max_medium: int = Field(default=20, ge=0)
    enabled: int = Field(default=1, ge=0, le=1)


# ---------------------------------------------------------------------------
# Pipeline endpoints
# ---------------------------------------------------------------------------

@router.post("/pipelines", dependencies=[Depends(api_key_auth)], status_code=201)
def register_pipeline(body: PipelineCreate, org_id: str = Query(default="default")):
    """Register a new CI/CD pipeline."""
    try:
        return _wrap(_get_engine().register_pipeline(org_id, body.model_dump()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/pipelines", dependencies=[Depends(api_key_auth)])
def list_pipelines(
     org_id: str = Query(default="default"),
    ci_platform: Optional[str] = Query(None),
):
    """List pipelines for an org, optionally filtered by ci_platform."""
    return _wrap(_get_engine().list_pipelines(org_id, ci_platform=ci_platform))


# ---------------------------------------------------------------------------
# Run endpoints
# ---------------------------------------------------------------------------

@router.post("/pipelines/{pipeline_id}/runs", dependencies=[Depends(api_key_auth)], status_code=201)
def trigger_run(pipeline_id: str, body: RunTrigger, org_id: str = Query(default="default")):
    """Trigger a new security-gated pipeline run."""
    try:
        return _wrap(_get_engine().trigger_run(org_id, pipeline_id, body.model_dump()))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/runs", dependencies=[Depends(api_key_auth)])
def list_runs(
     org_id: str = Query(default="default"),
    pipeline_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(default=20, ge=1, le=100),
):
    """List pipeline runs with optional filters."""
    return _wrap(_get_engine().list_runs(org_id, pipeline_id=pipeline_id, status=status, limit=limit))


@router.get("/runs/{run_id}", dependencies=[Depends(api_key_auth)])
def get_run(run_id: str, org_id: str = Query(default="default")):
    """Fetch a single pipeline run by run_id."""
    result = _get_engine().get_run(org_id, run_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found.")
    return _wrap(result)


# ---------------------------------------------------------------------------
# Findings endpoints
# ---------------------------------------------------------------------------

@router.get("/findings", dependencies=[Depends(api_key_auth)])
def list_findings(
     org_id: str = Query(default="default"),
    run_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    suppressed: bool = Query(default=False),
):
    """List security findings with optional filters."""
    return _wrap(_get_engine().list_findings(
        org_id, run_id=run_id, severity=severity, suppressed=suppressed
    ))


@router.post("/findings/{finding_id}/suppress", dependencies=[Depends(api_key_auth)])
def suppress_finding(finding_id: str, org_id: str = Query(default="default")):
    """Suppress a security finding by finding_id."""
    success = _get_engine().suppress_finding(org_id, finding_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")
    return _wrap({"suppressed": True, "finding_id": finding_id})


# ---------------------------------------------------------------------------
# Gate policy endpoints
# ---------------------------------------------------------------------------

@router.post("/gate-policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_gate_policy(body: GatePolicyCreate, org_id: str = Query(default="default")):
    """Create a security gate policy."""
    try:
        return _wrap(_get_engine().create_gate_policy(org_id, body.model_dump()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/gate-policies", dependencies=[Depends(api_key_auth)])
def list_gate_policies(
     org_id: str = Query(default="default"),
    pipeline_id: Optional[str] = Query(None),
):
    """List gate policies, optionally filtered by pipeline_id."""
    return _wrap(_get_engine().list_gate_policies(org_id, pipeline_id=pipeline_id))


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_devsecops_stats(org_id: str = Query(default="default")):
    """Return DevSecOps aggregate statistics for an org."""
    return _wrap(_get_engine().get_devsecops_stats(org_id))
