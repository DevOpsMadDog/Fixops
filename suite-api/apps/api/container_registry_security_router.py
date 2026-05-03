"""Container Registry Security Router — ALDECI.

Image vulnerability scanning, registry management, and admission policy enforcement.

Prefix: /api/v1/container-registry-security
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/container-registry-security/registries              register_registry
  GET    /api/v1/container-registry-security/registries              list_registries
  GET    /api/v1/container-registry-security/registries/{id}         get_registry
  POST   /api/v1/container-registry-security/scans                   scan_image
  GET    /api/v1/container-registry-security/scans                   list_image_scans
  GET    /api/v1/container-registry-security/scans/{id}              get_scan
  POST   /api/v1/container-registry-security/policies                create_policy
  GET    /api/v1/container-registry-security/policies                list_policies
  POST   /api/v1/container-registry-security/scans/{id}/evaluate     evaluate_image
  GET    /api/v1/container-registry-security/stats                   get_registry_stats
  POST   /api/v1/container-registry-security/allowlist               add_allowlist_entry
  GET    /api/v1/container-registry-security/allowlist               list_allowlist
  DELETE /api/v1/container-registry-security/allowlist/{id}          remove_allowlist_entry
  GET    /api/v1/container-registry-security/allowlist/check         check_image_allowed
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/container-registry-security",
    tags=["Container Registry Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.container_registry_security_engine import (
            ContainerRegistrySecurityEngine,
        )
        _engine = ContainerRegistrySecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterRegistryRequest(BaseModel):
    name: str = Field(..., description="Registry display name")
    url: str = Field("", description="Registry URL (e.g. registry.example.com)")
    registry_type: str = Field("docker", description="One of: docker, ecr, gcr, acr, harbor")
    auth_configured: bool = Field(False, description="Whether auth credentials are configured")


class ScanImageRequest(BaseModel):
    registry_id: str = Field(..., description="ID of the registry containing this image")
    image_name: str = Field(..., description="Image name (e.g. myapp/backend)")
    tag: str = Field("latest", description="Image tag")
    vulnerabilities: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of {cve_id, severity, package} vulnerability objects",
    )
    scan_score: Optional[int] = Field(
        None, ge=0, le=100, description="Override scan score (0-100); computed if omitted"
    )


class CreatePolicyRequest(BaseModel):
    name: str = Field(..., description="Policy name")
    block_critical: bool = Field(True, description="Block images with any critical CVEs")
    max_high_vulns: int = Field(5, ge=0, description="Maximum allowed high-severity CVEs")
    require_signed: bool = Field(False, description="Require image signature verification")


class AllowlistEntryRequest(BaseModel):
    image: str = Field(..., description="Base image name (e.g. python, ubuntu, gcr.io/distroless/base)")
    tag_pattern: str = Field("*", description="Exact tag or '*' to match any tag")
    reason: str = Field("", description="Why this image is trusted")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/registries", dependencies=[Depends(api_key_auth)], status_code=201)
def register_registry(
    body: RegisterRegistryRequest,
    org_id: str = Query(default="default"),
):
    """Register a new container registry (Docker Hub, ECR, GCR, ACR, Harbor)."""
    try:
        return _get_engine().register_registry(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering registry")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/registries", dependencies=[Depends(api_key_auth)])
def list_registries(org_id: str = Query(default="default")):
    """List all registered container registries for an org."""
    return _get_engine().list_registries(org_id)


@router.get("/registries/{registry_id}", dependencies=[Depends(api_key_auth)])
def get_registry(registry_id: str, org_id: str = Query(default="default")):
    """Retrieve a single container registry by ID."""
    result = _get_engine().get_registry(org_id, registry_id)
    if not result:
        raise HTTPException(status_code=404, detail="Registry not found")
    return result


@router.post("/scans", dependencies=[Depends(api_key_auth)], status_code=201)
def scan_image(
    body: ScanImageRequest,
    org_id: str = Query(default="default"),
):
    """Record a container image vulnerability scan."""
    try:
        return _get_engine().scan_image(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording image scan")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/scans", dependencies=[Depends(api_key_auth)])
def list_image_scans(
    org_id: str = Query(default="default"),
    registry_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None, description="Filter: critical|high|medium|low"),
):
    """List image scans, optionally filtered by registry or minimum severity."""
    return _get_engine().list_image_scans(org_id, registry_id=registry_id, severity=severity)


@router.get("/scans/{scan_id}", dependencies=[Depends(api_key_auth)])
def get_scan(scan_id: str, org_id: str = Query(default="default")):
    """Retrieve a single image scan by ID."""
    result = _get_engine().get_scan(org_id, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.post("/policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_policy(
    body: CreatePolicyRequest,
    org_id: str = Query(default="default"),
):
    """Create an image admission policy for the org."""
    try:
        return _get_engine().create_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating policy")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies", dependencies=[Depends(api_key_auth)])
def list_policies(org_id: str = Query(default="default")):
    """List all image admission policies for an org."""
    return _get_engine().list_policies(org_id)


@router.post("/scans/{scan_id}/evaluate", dependencies=[Depends(api_key_auth)])
def evaluate_image(scan_id: str, org_id: str = Query(default="default")):
    """Evaluate an image scan against all org policies. Returns allow/warn/block."""
    try:
        return _get_engine().evaluate_image(org_id, scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error evaluating image")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_registry_stats(org_id: str = Query(default="default")):
    """Return aggregated registry security statistics for the org."""
    return _get_engine().get_registry_stats(org_id)


# ---------------------------------------------------------------------------
# Base Image Allowlist
# ---------------------------------------------------------------------------

@router.post("/allowlist", dependencies=[Depends(api_key_auth)], status_code=201)
def add_allowlist_entry(
    body: AllowlistEntryRequest,
    org_id: str = Query(default="default"),
):
    """Add a trusted base image to the org allowlist.

    Use tag_pattern='*' to trust all tags for an image, or specify an exact tag
    (e.g. '3.12-slim') to restrict trust to that tag only.
    """
    try:
        return _get_engine().add_allowlist_entry(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error adding allowlist entry")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/allowlist", dependencies=[Depends(api_key_auth)])
def list_allowlist(org_id: str = Query(default="default")):
    """List all trusted base images in the org allowlist."""
    return _get_engine().list_allowlist(org_id)


@router.get("/allowlist/check", dependencies=[Depends(api_key_auth)])
def check_image_allowed(
    image: str = Query(..., description="Image name to check"),
    tag: str = Query(default="latest", description="Image tag to check"),
    org_id: str = Query(default="default"),
):
    """Check whether image:tag is on the org allowlist.

    Returns {allowed: bool, matched_entry: object|null}.
    """
    return _get_engine().check_image_allowed(org_id, image, tag)


@router.delete("/allowlist/{entry_id}", dependencies=[Depends(api_key_auth)])
def remove_allowlist_entry(
    entry_id: str,
    org_id: str = Query(default="default"),
):
    """Remove a trusted base image from the org allowlist by entry ID."""
    deleted = _get_engine().remove_allowlist_entry(org_id, entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Allowlist entry not found")
    return {"deleted": True, "id": entry_id}
