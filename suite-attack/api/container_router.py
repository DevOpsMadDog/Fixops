"""ALdeci Container Scanner Router — Container Image & Dockerfile scanning API.

Endpoints:
  POST /api/v1/container/scan/dockerfile  — scan Dockerfile content
  POST /api/v1/container/scan/image       — scan container image (Trivy/Grype)
  POST /api/v1/container/scan/helm        — scan Helm chart for misconfigurations
  POST /api/v1/container/scan/secrets     — scan Dockerfile/layers for hardcoded secrets
  GET  /api/v1/container/rules            — list all container scanning rules
  GET  /api/v1/container/status           — check tool availability
  GET  /api/v1/container/health           — health check
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict

from core.container_scanner import (
    get_container_scanner,
    get_security_scanner,
    DOCKERFILE_RULES,
    HELM_CHART_RULES,
    LAYER_SECRET_PATTERNS,
    KNOWN_VULNERABLE_IMAGES,
)
from fastapi import APIRouter, HTTPException, Depends
from apps.api.dependencies import get_org_id
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
        scanner = get_security_scanner()
        analysis = scanner.scan_dockerfile(req.content, safe_filename)
        result_dict = analysis.model_dump(mode="json")
        # Normalise output for backward compat
        result_dict["total_findings"] = len(result_dict.get("findings", []))
        result_dict["findings_count"] = result_dict["total_findings"]
        # TrustGraph explicit indexing (fire-and-forget)
        try:
            from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus as _get_eb
            _bus = _get_eb()
            if _bus and _bus.enabled:
                import asyncio as _asyncio
                _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                    "finding_id": f"container-dockerfile-{safe_filename}",
                    "type": "container_finding", "severity": "medium",
                    "source": "container_router", "data": result_dict,
                }))
        except Exception:
            pass
        return result_dict
    except Exception as e:
        logger.exception("Container Dockerfile scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Scan failed: {type(e).__name__}")


@router.post("/scan/image")
async def scan_image(req: ScanImageRequest) -> Dict[str, Any]:
    """Scan a container image using Trivy/Grype."""
    try:
        scanner = get_container_scanner()
        result = await scanner.scan_image(req.image_ref)
        result_dict = result.to_dict()
        # TrustGraph explicit indexing (fire-and-forget)
        try:
            from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus as _get_eb
            _bus = _get_eb()
            if _bus and _bus.enabled:
                import asyncio as _asyncio
                _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                    "finding_id": f"container-image-{req.image_ref}",
                    "type": "container_vuln", "severity": "high",
                    "source": "container_router", "data": result_dict,
                }))
        except Exception:
            pass
        return result_dict
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.exception("Container image scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Image scan failed: {type(e).__name__}")


class ScanHelmRequest(BaseModel):
    content: str = Field(
        ...,
        description="Helm chart content (values.yaml, templates, or Chart.yaml)",
        max_length=_MAX_DOCKERFILE_LENGTH,
    )
    filename: str = Field(
        "Chart.yaml",
        description="Filename for reporting",
        max_length=_MAX_FILENAME_LENGTH,
    )


class ScanSecretsRequest(BaseModel):
    content: str = Field(
        ...,
        description="Dockerfile or image layer content to scan for secrets",
        max_length=_MAX_DOCKERFILE_LENGTH,
    )
    filename: str = Field(
        "Dockerfile",
        description="Filename for reporting",
        max_length=_MAX_FILENAME_LENGTH,
    )


@router.post("/scan/helm")
async def scan_helm_chart(req: ScanHelmRequest) -> Dict[str, Any]:
    """Scan Helm chart content for security misconfigurations.

    Analyzes values.yaml, templates, and Chart.yaml for:
    - Privileged containers, root users, host networking
    - Missing resource limits, security contexts, probes
    - Hardcoded secrets in values
    - Dangerous Linux capabilities
    - Missing NetworkPolicy
    """
    if not req.content.strip():
        raise HTTPException(400, "Empty Helm chart content provided")
    safe_filename = _sanitize_filename(req.filename)
    try:
        scanner = get_container_scanner()
        result = scanner.scan_helm_chart(req.content, safe_filename)
        return result.to_dict()
    except (OSError, ValueError, KeyError, RuntimeError) as e:
        logger.exception("Helm chart scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Helm scan failed: {type(e).__name__}")


@router.post("/scan/secrets")
async def scan_layer_secrets(req: ScanSecretsRequest) -> Dict[str, Any]:
    """Scan Dockerfile/image layers for hardcoded secrets.

    Detects 20+ secret patterns including:
    - AWS access keys and secret keys
    - GitHub/GitLab/NPM tokens
    - Private keys (RSA, EC, DSA, OPENSSH)
    - Database connection strings
    - Cloud provider credentials (Azure, GCP)
    - Sensitive file copies (.env, .pfx, service account JSON)
    """
    if not req.content.strip():
        raise HTTPException(400, "Empty content provided")
    safe_filename = _sanitize_filename(req.filename)
    try:
        scanner = get_container_scanner()
        result = scanner.scan_layer_secrets(req.content, safe_filename)
        return result.to_dict()
    except (OSError, ValueError, KeyError, RuntimeError) as e:
        logger.exception("Layer secret scan failed: %s", type(e).__name__)
        raise HTTPException(500, f"Secret scan failed: {type(e).__name__}")


@router.get("/images")
async def list_container_images(
    limit: int = 50,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List scanned container images and their vulnerability status."""
    scanner = get_container_scanner()
    scan_history = getattr(scanner, "scan_history", None) or []
    images = []
    for entry in scan_history[:limit]:
        if isinstance(entry, dict):
            images.append(entry)
    return {"images": images, "total": len(images)}


@router.get("/rules")
async def list_container_rules() -> Dict[str, Any]:
    """List all container scanning rules across Dockerfile, Helm, and secret detection."""
    dockerfile_rules = [
        {"id": r[0], "title": r[1], "severity": r[2], "cwe": r[3], "category": "dockerfile"}
        for r in DOCKERFILE_RULES
    ]
    helm_rules = [
        {"id": r["id"], "title": r["title"], "severity": r["severity"], "cwe": r["cwe"], "category": "helm"}
        for r in HELM_CHART_RULES
    ]
    secret_rules = [
        {"id": r["id"], "name": r["name"], "severity": r["severity"], "category": "secrets"}
        for r in LAYER_SECRET_PATTERNS
    ]
    vuln_images = [
        {"image": img, "severity": sev, "reason": desc}
        for img, (sev, desc) in KNOWN_VULNERABLE_IMAGES.items()
    ]
    return {
        "dockerfile_rules": dockerfile_rules,
        "helm_rules": helm_rules,
        "secret_patterns": secret_rules,
        "known_vulnerable_images": vuln_images,
        "total_rules": len(dockerfile_rules) + len(helm_rules) + len(secret_rules) + len(vuln_images),
    }


@router.get("/status")
async def container_status() -> Dict[str, Any]:
    """Container scanner status."""
    scanner = get_container_scanner()
    return {
        "status": "healthy",
        "engine": "ALdeci Container Scanner",
        "trivy_available": scanner.trivy_available,
        "grype_available": scanner.grype_available,
        "dockerfile_rules": len(DOCKERFILE_RULES),
        "helm_rules": len(HELM_CHART_RULES),
        "secret_patterns": len(LAYER_SECRET_PATTERNS),
        "known_vulnerable_images": len(KNOWN_VULNERABLE_IMAGES),
        "capabilities": [
            "dockerfile_analysis",
            "base_image_check",
            "trivy_integration",
            "grype_integration",
            "helm_chart_scanning",
            "layer_secret_detection",
        ],
    }


@router.get("/health")
async def container_health() -> Dict[str, Any]:
    """Container scanner health check (alias for /status)."""
    return await container_status()
