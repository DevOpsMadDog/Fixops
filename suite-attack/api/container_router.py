"""ALdeci Container Scanner Router — Container Image & Dockerfile scanning API.

Endpoints:
  POST /api/v1/container/scan/dockerfile  — scan Dockerfile content
  POST /api/v1/container/scan/image       — scan container image (Trivy)
  GET  /api/v1/container/status           — check tool availability
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict

from core.container_scanner import get_container_scanner
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/container", tags=["Container Scanner"])

_MAX_DOCKERFILE_LENGTH = 500_000  # 500KB max Dockerfile content
_MAX_FILENAME_LENGTH = 255
_MAX_IMAGE_REF_LENGTH = 512
# Allowed image ref pattern: registry/repo:tag@sha256:hash
_IMAGE_REF_PATTERN = re.compile(
    r"^[a-zA-Z0-9]"  # Must start with alphanumeric
    r"[a-zA-Z0-9._\-/:@]+"  # Allowed characters
    r"$"
)


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and injection."""
    # Check raw input for traversal BEFORE using os.path.basename
    if ".." in filename or "/" in filename or "\\" in filename:
        safe = os.path.basename(filename)
    else:
        safe = filename
    # Remove null bytes and control characters
    safe = "".join(c for c in safe if c.isprintable() and c != "\x00")
    if len(safe) > _MAX_FILENAME_LENGTH:
        safe = safe[:_MAX_FILENAME_LENGTH]
    return safe or "Dockerfile"


class ScanDockerfileRequest(BaseModel):
    content: str = Field(
        ...,
        description="Dockerfile content",
        max_length=_MAX_DOCKERFILE_LENGTH,
    )
    filename: str = Field(
        "Dockerfile",
        description="Filename for reporting",
        max_length=_MAX_FILENAME_LENGTH,
    )


class ScanImageRequest(BaseModel):
    image_ref: str = Field(
        ...,
        description="Image reference e.g. python:3.11-slim",
        max_length=_MAX_IMAGE_REF_LENGTH,
    )

    @field_validator("image_ref")
    @classmethod
    def validate_image_ref(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("image_ref must not be empty")
        if not _IMAGE_REF_PATTERN.match(v):
            raise ValueError(
                "image_ref contains invalid characters. "
                "Expected format: registry/repo:tag or repo:tag"
            )
        # Block shell injection via image refs
        dangerous_chars = set(";|&$`(){}!><\n\r")
        if dangerous_chars & set(v):
            raise ValueError("image_ref contains forbidden shell characters")
        return v


@router.post("/scan/dockerfile")
async def scan_dockerfile(req: ScanDockerfileRequest) -> Dict[str, Any]:
    """Scan Dockerfile content for misconfigurations."""
    if not req.content.strip():
        raise HTTPException(400, "Empty Dockerfile content provided")
    safe_filename = _sanitize_filename(req.filename)
    try:
        scanner = get_container_scanner()
        result = scanner.scan_dockerfile(req.content, safe_filename)
        return result.to_dict()
    except Exception as e:
        logger.exception("Container Dockerfile scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Scan failed: {type(e).__name__}")


@router.post("/scan/image")
async def scan_image(req: ScanImageRequest) -> Dict[str, Any]:
    """Scan a container image using Trivy/Grype."""
    try:
        scanner = get_container_scanner()
        result = await scanner.scan_image(req.image_ref)
        return result.to_dict()
    except Exception as e:
        logger.exception("Container image scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Image scan failed: {type(e).__name__}")


@router.get("/images")
async def list_container_images(
    limit: int = 50,
) -> Dict[str, Any]:
    """List scanned container images and their vulnerability status.

    Returns images from the container scanner's scan history.
    Empty list indicates no scans have been performed yet.
    """
    scanner = get_container_scanner()
    scan_history = getattr(scanner, "scan_history", None) or []
    images = []
    for entry in scan_history[:limit]:
        if isinstance(entry, dict):
            images.append(entry)
    return {"images": images, "total": len(images)}


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


@router.get("/health")
async def container_health() -> Dict[str, Any]:
    """Container scanner health check (alias for /status)."""
    return await container_status()
