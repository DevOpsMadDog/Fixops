"""Pipeline BOM (PBOM) Router — ALDECI GAP-017.

Prefix: /api/v1/pbom
Auth:   ``Depends(api_key_auth)`` on all endpoints.

Endpoints
---------
POST /api/v1/pbom/run/start                         - start a run, returns run_id
POST /api/v1/pbom/run/{run_id}/step                 - record a step
POST /api/v1/pbom/run/{run_id}/artifact             - record an artifact
POST /api/v1/pbom/run/{run_id}/deploy               - record a deployment
POST /api/v1/pbom/run/{run_id}/complete             - complete the run
GET  /api/v1/pbom/run/{run_id}/export               - nested PBOM JSON
GET  /api/v1/pbom/artifact/{sha256}/provenance      - runs that produced this artifact
GET  /api/v1/pbom/stats?org_id=...                  - aggregate stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/pbom",
    tags=["Pipeline BOM (PBOM)"],
)


_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.pipeline_bom_engine import PipelineBOMEngine
        _engine = PipelineBOMEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class StartRunRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    repo_ref: str = Field(..., description="Repository reference (org/repo)")
    run_id_external: str = Field(
        default="", description="CI provider's native run ID"
    )
    ci_provider: str = Field(
        ..., description="github-actions|gitlab-ci|jenkins|circleci|azure-devops|argo|tekton|other"
    )
    trigger: str = Field(default="", description="push|pull_request|schedule|manual|tag")
    branch: str = Field(default="")
    commit_sha: str = Field(default="", description="Git commit SHA")


class StepRequest(BaseModel):
    step_order: int = Field(..., ge=0, description="Ordinal of this step in the run")
    step_name: str = Field(..., description="Human-readable step name")
    step_type: str = Field(
        ..., description="build|test|lint|scan|sign|publish|deploy"
    )
    image: str = Field(default="", description="Container image used to run the step")
    command: str = Field(default="", description="Command executed by the step")
    config_hash: str = Field(default="", description="Hash of step config (YAML/JSON)")
    duration_ms: int = Field(default=0, ge=0)
    outcome: str = Field(
        default="neutral", description="success|failed|skipped|cancelled|neutral"
    )


class ArtifactRequest(BaseModel):
    step_id: Optional[str] = Field(
        default=None, description="Producing step_id (optional)"
    )
    artifact_ref: str = Field(..., description="Registry path / file path / package ref")
    artifact_type: str = Field(
        ..., description="container-image|binary|package|sbom|attestation"
    )
    sha256: str = Field(..., description="SHA-256 of artifact")
    size_bytes: int = Field(default=0, ge=0)
    signed_by: str = Field(default="", description="Signer identity (cosign sub, KMS key)")
    signature_algo: str = Field(default="", description="e.g. sigstore, rsa-sha256, ed25519")


class DeployRequest(BaseModel):
    artifact_id: str = Field(..., description="Artifact being deployed")
    environment: str = Field(..., description="dev|staging|prod|...")
    target: str = Field(default="", description="k8s cluster, cloud account, host")
    deployed_by: str = Field(default="")


class CompleteRequest(BaseModel):
    status: str = Field(
        ..., description="queued|running|success|failed|cancelled|partial"
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/run/start", dependencies=[Depends(api_key_auth)], status_code=201)
def start_run(req: StartRunRequest) -> Dict[str, Any]:
    try:
        run_id = _get_engine().record_run(
            org_id=req.org_id,
            repo_ref=req.repo_ref,
            run_id_external=req.run_id_external,
            ci_provider=req.ci_provider,
            trigger=req.trigger,
            branch=req.branch,
            commit_sha=req.commit_sha,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"run_id": run_id, "status": "running"}


@router.post(
    "/run/{run_id}/step", dependencies=[Depends(api_key_auth)], status_code=201
)
def add_step(run_id: str, req: StepRequest) -> Dict[str, Any]:
    try:
        step_id = _get_engine().record_step(
            run_db_id=run_id,
            step_order=req.step_order,
            step_name=req.step_name,
            step_type=req.step_type,
            image=req.image,
            command=req.command,
            config_hash=req.config_hash,
            duration_ms=req.duration_ms,
            outcome=req.outcome,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"step_id": step_id, "run_id": run_id}


@router.post(
    "/run/{run_id}/artifact", dependencies=[Depends(api_key_auth)], status_code=201
)
def add_artifact(run_id: str, req: ArtifactRequest) -> Dict[str, Any]:
    try:
        art_id = _get_engine().record_artifact(
            run_db_id=run_id,
            step_id=req.step_id,
            artifact_ref=req.artifact_ref,
            artifact_type=req.artifact_type,
            sha256=req.sha256,
            size_bytes=req.size_bytes,
            signed_by=req.signed_by,
            signature_algo=req.signature_algo,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"artifact_id": art_id, "run_id": run_id, "sha256": req.sha256}


@router.post(
    "/run/{run_id}/deploy", dependencies=[Depends(api_key_auth)], status_code=201
)
def add_deploy(run_id: str, req: DeployRequest) -> Dict[str, Any]:
    try:
        dep_id = _get_engine().record_deploy(
            run_db_id=run_id,
            artifact_id=req.artifact_id,
            environment=req.environment,
            target=req.target,
            deployed_by=req.deployed_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "deploy_id": dep_id,
        "run_id": run_id,
        "artifact_id": req.artifact_id,
        "environment": req.environment,
    }


@router.post(
    "/run/{run_id}/complete", dependencies=[Depends(api_key_auth)]
)
def complete_run(run_id: str, req: CompleteRequest) -> Dict[str, Any]:
    try:
        run = _get_engine().complete_run(run_db_id=run_id, status=req.status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return run


@router.get("/run/{run_id}/export", dependencies=[Depends(api_key_auth)])
def export_pbom(run_id: str) -> Dict[str, Any]:
    try:
        return _get_engine().export_pbom(run_db_id=run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/artifact/{sha256}/provenance", dependencies=[Depends(api_key_auth)]
)
def artifact_provenance(
    sha256: str, org_id: str = Query(..., description="Organisation ID")
) -> Dict[str, Any]:
    try:
        runs = _get_engine().find_runs_producing_artifact(
            org_id=org_id, artifact_sha256=sha256
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "sha256": sha256,
        "org_id": org_id,
        "runs": runs,
        "total": len(runs),
    }


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def stats(org_id: str = Query(..., description="Organisation ID")) -> Dict[str, Any]:
    return _get_engine().stats(org_id=org_id)
