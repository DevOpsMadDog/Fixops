"""Security Registry Router — ALDECI.

Endpoints for the Security Registry engine.

Prefix: /api/v1/security-registry
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/security-registry/artifacts                     register_artifact
  GET    /api/v1/security-registry/artifacts                     list_artifacts
  GET    /api/v1/security-registry/artifacts/{id}                get_artifact
  PATCH  /api/v1/security-registry/artifacts/{id}/status         update_artifact_status
  POST   /api/v1/security-registry/artifacts/{id}/reviews        record_review
  GET    /api/v1/security-registry/reviews                       list_reviews
  POST   /api/v1/security-registry/artifacts/{id}/references     add_reference
  GET    /api/v1/security-registry/artifacts/{id}/references     list_references
  GET    /api/v1/security-registry/stats                         get_registry_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-registry",
    tags=["Security Registry"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_registry_engine import SecurityRegistryEngine
        _engine = SecurityRegistryEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ArtifactRegister(BaseModel):
    artifact_name: str = Field(..., description="Name of the security artifact")
    artifact_type: str = Field(
        default="policy",
        description=(
            "policy | standard | procedure | guideline | "
            "control | framework | tool | runbook"
        ),
    )
    version: str = Field(default="1.0")
    artifact_status: str = Field(
        default="draft",
        description="draft | active | deprecated | under_review | archived",
    )
    description: str = Field(default="")
    owner: str = Field(default="")
    review_date: Optional[str] = Field(default=None)
    next_review_date: Optional[str] = Field(default=None)
    reviewer: str = Field(default="")
    download_url: str = Field(default="")
    tag_list: List[str] = Field(default_factory=list)


class ArtifactStatusUpdate(BaseModel):
    new_status: str = Field(
        ...,
        description="draft | active | deprecated | under_review | archived",
    )


class ReviewCreate(BaseModel):
    reviewer: str = Field(..., description="Name of the reviewer")
    review_outcome: str = Field(
        ...,
        description="approved | rejected | approved_with_changes | deferred",
    )
    comments: str = Field(default="")
    review_date: Optional[str] = Field(default=None)
    next_review_date: Optional[str] = Field(default=None)


class ReferenceCreate(BaseModel):
    referenced_artifact_id: str = Field(..., description="ID of the artifact being referenced")
    reference_type: str = Field(default="related", description="related | supersedes | implements | required_by")
    notes: str = Field(default="")


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

@router.post("/artifacts", dependencies=[Depends(api_key_auth)], status_code=201)
def register_artifact(
    body: ArtifactRegister,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Register a new security artifact."""
    try:
        return _get_engine().register_artifact(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/artifacts", dependencies=[Depends(api_key_auth)])
def list_artifacts(
    org_id: str = Query(..., description="Organization ID"),
    artifact_type: Optional[str] = Query(default=None),
    artifact_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List artifacts with optional type/status filters."""
    return _get_engine().list_artifacts(
        org_id,
        artifact_type=artifact_type,
        artifact_status=artifact_status,
    )


@router.get("/artifacts/{artifact_id}", dependencies=[Depends(api_key_auth)])
def get_artifact(
    artifact_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single artifact by ID."""
    artifact = _get_engine().get_artifact(org_id, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail=f"Artifact '{artifact_id}' not found")
    return artifact


@router.patch("/artifacts/{artifact_id}/status", dependencies=[Depends(api_key_auth)])
def update_artifact_status(
    artifact_id: str,
    body: ArtifactStatusUpdate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update the status of an artifact."""
    try:
        return _get_engine().update_artifact_status(org_id, artifact_id, body.new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Reviews
# ---------------------------------------------------------------------------

@router.post("/artifacts/{artifact_id}/reviews", dependencies=[Depends(api_key_auth)], status_code=201)
def record_review(
    artifact_id: str,
    body: ReviewCreate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Record a review for an artifact."""
    try:
        return _get_engine().record_review(org_id, artifact_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/reviews", dependencies=[Depends(api_key_auth)])
def list_reviews(
    org_id: str = Query(..., description="Organization ID"),
    artifact_id: Optional[str] = Query(default=None),
    review_outcome: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List reviews with optional filters."""
    return _get_engine().list_reviews(
        org_id,
        artifact_id=artifact_id,
        review_outcome=review_outcome,
    )


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------

@router.post("/artifacts/{artifact_id}/references", dependencies=[Depends(api_key_auth)], status_code=201)
def add_reference(
    artifact_id: str,
    body: ReferenceCreate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add a cross-reference between two artifacts."""
    try:
        return _get_engine().add_reference(org_id, artifact_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/artifacts/{artifact_id}/references", dependencies=[Depends(api_key_auth)])
def list_references(
    artifact_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """List all references for an artifact."""
    return _get_engine().list_references(org_id, artifact_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_registry_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregated security registry statistics."""
    return _get_engine().get_registry_stats(org_id)


@router.get("", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns artifacts list for dashboard health-checks."""
    return _get_engine().list_artifacts(org_id)
