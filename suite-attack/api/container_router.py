"""ALdeci Container Scanner Router — Container Image & Dockerfile scanning API.

Endpoints:
  POST /api/v1/container/scan/dockerfile  — scan Dockerfile content
  POST /api/v1/container/scan/image       — scan container image (Trivy)
  GET  /api/v1/container/status           — check tool availability
"""

from __future__ import annotations

from typing import Any, Dict

from core.container_scanner import get_container_scanner
from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/container", tags=["Container Scanner"])


class ScanDockerfileRequest(BaseModel):
    content: str = Field(..., description="Dockerfile content")
    filename: str = Field("Dockerfile", description="Filename for reporting")


class ScanImageRequest(BaseModel):
    image_ref: str = Field(..., description="Image reference e.g. python:3.11-slim")


@router.post("/scan/dockerfile")
async def scan_dockerfile(req: ScanDockerfileRequest) -> Dict[str, Any]:
    """Scan Dockerfile content for misconfigurations."""
    scanner = get_container_scanner()
    result = scanner.scan_dockerfile(req.content, req.filename)
    return result.to_dict()


@router.post("/scan/image")
async def scan_image(req: ScanImageRequest) -> Dict[str, Any]:
    """Scan a container image using Trivy/Grype."""
    scanner = get_container_scanner()
    result = await scanner.scan_image(req.image_ref)
    return result.to_dict()


@router.get("/status")
async def container_status() -> Dict[str, Any]:
    """Container scanner status."""
    scanner = get_container_scanner()
    return {
        "status": "healthy",
        "engine": "ALdeci Container Scanner",
        "trivy_available": scanner.trivy_available,
        "grype_available": scanner.grype_available,
        "dockerfile_rules": 10,
        "known_vulnerable_images": 15,
        "capabilities": [
            "dockerfile_analysis",
            "base_image_check",
            "trivy_integration",
            "grype_integration",
        ],
    }
