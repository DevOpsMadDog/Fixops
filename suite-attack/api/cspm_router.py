"""CSPM Router — Cloud Security Posture Management endpoints.

Endpoints:
  POST /api/v1/cspm/scan/terraform       — scan Terraform HCL
  POST /api/v1/cspm/scan/cloudformation   — scan CloudFormation
  GET  /api/v1/cspm/rules                 — list all CSPM rules
  GET  /api/v1/cspm/status                — engine status
  GET  /api/v1/cspm/health                — health check
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cspm", tags=["CSPM"])

_MAX_CONTENT_LENGTH = 1_000_000  # 1MB max IaC content
_MAX_FILENAME_LENGTH = 255


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    if ".." in filename or "/" in filename or "\\" in filename:
        safe = os.path.basename(filename)
    else:
        safe = filename
    safe = "".join(c for c in safe if c.isprintable() and c != "\x00")
    if len(safe) > _MAX_FILENAME_LENGTH:
        safe = safe[:_MAX_FILENAME_LENGTH]
    return safe or "main.tf"


class TerraformScanRequest(BaseModel):
    content: str = Field(
        ...,
        description="Terraform HCL content to scan",
        max_length=_MAX_CONTENT_LENGTH,
    )
    filename: str = Field(
        "main.tf",
        description="Filename for reporting",
        max_length=_MAX_FILENAME_LENGTH,
    )


class CloudFormationScanRequest(BaseModel):
    content: str = Field(
        ...,
        description="CloudFormation JSON/YAML content to scan",
        max_length=_MAX_CONTENT_LENGTH,
    )


@router.post("/scan/terraform")
async def scan_terraform(req: TerraformScanRequest) -> Dict[str, Any]:
    """Scan Terraform HCL for cloud misconfigurations."""
    if not req.content.strip():
        raise HTTPException(400, "Empty Terraform content provided")
    safe_filename = _sanitize_filename(req.filename)
    try:
        from core.cspm_engine import get_cspm_engine

        engine = get_cspm_engine()
        result = engine.scan_terraform(req.content, safe_filename)
        return result.to_dict()
    except Exception as e:
        logger.exception("Terraform scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Terraform scan failed: {type(e).__name__}")


@router.post("/scan/cloudformation")
async def scan_cloudformation(req: CloudFormationScanRequest) -> Dict[str, Any]:
    """Scan CloudFormation JSON/YAML for AWS misconfigurations."""
    if not req.content.strip():
        raise HTTPException(400, "Empty CloudFormation content provided")
    try:
        from core.cspm_engine import get_cspm_engine

        engine = get_cspm_engine()
        result = engine.scan_cloudformation(req.content)
        return result.to_dict()
    except Exception as e:
        logger.exception("CloudFormation scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"CloudFormation scan failed: {type(e).__name__}")


@router.get("/rules")
async def list_rules() -> Dict[str, Any]:
    """List all CSPM rules by provider."""
    from core.cspm_engine import AWS_RULES, AZURE_RULES, GCP_RULES

    def fmt(rules):
        return [
            {"id": r[0], "title": r[1], "severity": r[2], "cwe": r[3]} for r in rules
        ]

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
        "engine": "cspm",
        "status": "ready",
        "version": "1.0.0",
        "boto3_available": engine._boto3_available,
        "azure_available": engine._azure_available,
        "gcp_available": engine._gcp_available,
    }


@router.get("/health")
async def cspm_health() -> Dict[str, Any]:
    """CSPM engine health check (alias for /status)."""
    return await cspm_status()
