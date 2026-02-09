"""CSPM Router — Cloud Security Posture Management endpoints."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/cspm", tags=["CSPM"])


class TerraformScanRequest(BaseModel):
    content: str
    filename: str = "main.tf"


class CloudFormationScanRequest(BaseModel):
    content: str


@router.post("/scan/terraform")
async def scan_terraform(req: TerraformScanRequest) -> Dict[str, Any]:
    """Scan Terraform HCL for cloud misconfigurations."""
    from core.cspm_engine import get_cspm_engine

    engine = get_cspm_engine()
    result = engine.scan_terraform(req.content, req.filename)
    return result.to_dict()


@router.post("/scan/cloudformation")
async def scan_cloudformation(req: CloudFormationScanRequest) -> Dict[str, Any]:
    """Scan CloudFormation JSON/YAML for AWS misconfigurations."""
    from core.cspm_engine import get_cspm_engine

    engine = get_cspm_engine()
    result = engine.scan_cloudformation(req.content)
    return result.to_dict()


@router.get("/rules")
async def list_rules() -> Dict[str, Any]:
    """List all CSPM rules by provider."""
    from core.cspm_engine import AWS_RULES, AZURE_RULES, GCP_RULES

    def fmt(rules):
        return [{"id": r[0], "title": r[1], "severity": r[2], "cwe": r[3]} for r in rules]

    return {
        "aws": fmt(AWS_RULES),
        "azure": fmt(AZURE_RULES),
        "gcp": fmt(GCP_RULES),
        "total": len(AWS_RULES) + len(AZURE_RULES) + len(GCP_RULES),
    }


@router.get("/status")
async def cspm_status() -> Dict[str, Any]:
    from core.cspm_engine import get_cspm_engine

    engine = get_cspm_engine()
    return {
        "engine": "cspm", "status": "ready", "version": "1.0.0",
        "boto3_available": engine._boto3_available,
        "azure_available": engine._azure_available,
        "gcp_available": engine._gcp_available,
    }

