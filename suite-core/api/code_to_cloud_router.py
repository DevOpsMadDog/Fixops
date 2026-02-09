"""Code-to-Cloud Tracer Router — Vulnerability tracing endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/code-to-cloud", tags=["Code-to-Cloud"])


class TraceRequest(BaseModel):
    vulnerability_id: str
    source_file: str = ""
    source_line: int = 0
    git_commit: str = ""
    container_image: str = ""
    k8s_namespace: str = ""
    k8s_deployment: str = ""
    cloud_service: str = ""
    cloud_region: str = ""
    internet_facing: bool = False


@router.post("/trace")
async def trace_vulnerability(req: TraceRequest) -> Dict[str, Any]:
    """Trace a vulnerability from code to cloud deployment."""
    from core.code_to_cloud_tracer import get_code_to_cloud_tracer

    tracer = get_code_to_cloud_tracer()
    result = tracer.trace(
        vulnerability_id=req.vulnerability_id,
        source_file=req.source_file,
        source_line=req.source_line,
        git_commit=req.git_commit,
        container_image=req.container_image,
        k8s_namespace=req.k8s_namespace,
        k8s_deployment=req.k8s_deployment,
        cloud_service=req.cloud_service,
        cloud_region=req.cloud_region,
        internet_facing=req.internet_facing,
    )
    return result.to_dict()


@router.get("/status")
async def tracer_status() -> Dict[str, Any]:
    return {"engine": "code_to_cloud_tracer", "status": "ready", "version": "1.0.0"}

