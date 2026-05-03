"""SLSA Provenance Router — ALDECI GAP-018.

SLSA v1.0 in-toto attestation generation + DSSE envelope endpoints.

Prefix: /api/v1/slsa
Auth:   api_key_auth dependency on ALL endpoints.

Routes:
  POST /api/v1/slsa/attest                 generate_attestation
  POST /api/v1/slsa/verify/{id}            verify_attestation
  GET  /api/v1/slsa/attestations           list_attestations
  GET  /api/v1/slsa/attestations/{id}      get_attestation
  GET  /api/v1/slsa/stats                  stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/slsa",
    tags=["SLSA Provenance"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.slsa_provenance_engine import SLSAProvenanceEngine
        _engine = SLSAProvenanceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AttestRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID (multi-tenant isolation)")
    subject_name: str = Field(
        ...,
        description="Name of the subject — typically a container image reference "
                    "or artifact URL",
    )
    subject_sha256: str = Field(
        ..., description="SHA-256 digest of the subject artifact"
    )
    builder_id: str = Field(
        ...,
        description="URI identifying the build platform (e.g. "
                    "https://github.com/actions/runner)",
    )
    build_type: str = Field(
        ...,
        description="URI identifying the build process schema (e.g. "
                    "https://slsa.dev/container-based-build/v0.1?draft)",
    )
    invocation: Dict[str, Any] = Field(
        default_factory=dict,
        description="Build invocation metadata (configSource, parameters, environment)",
    )
    materials: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of build-input materials (source repos, base images, etc.)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional invocation metadata (buildStartedOn, reproducible, etc.)",
    )
    slsa_level: int = Field(
        default=3, ge=1, le=4,
        description="Target SLSA level 1-4 per SLSA v1.0 spec",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(api_key_auth)])
def slsa_health() -> Dict[str, Any]:
    """Health/status endpoint for the SLSA Provenance service."""
    return {
        "service": "slsa-provenance",
        "status": "ok",
        "version": "v0.2",
        "spec": "https://slsa.dev/provenance/v0.2",
    }


@router.post("/attest", dependencies=[Depends(api_key_auth)], status_code=201)
def generate_attestation(req: AttestRequest) -> Dict[str, Any]:
    """Generate an in-toto SLSA v0.2 provenance attestation wrapped in DSSE."""
    try:
        return _get_engine().generate_attestation(
            org_id=req.org_id,
            subject_name=req.subject_name,
            subject_sha256=req.subject_sha256,
            builder_id=req.builder_id,
            build_type=req.build_type,
            invocation=req.invocation,
            materials=req.materials,
            metadata=req.metadata,
            slsa_level=req.slsa_level,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/verify/{attestation_id}", dependencies=[Depends(api_key_auth)])
def verify_attestation(
    attestation_id: str,
    verifier: str = Query(default="internal", description="Verifier identifier"),
) -> Dict[str, Any]:
    """Perform v0 structural verification of a stored attestation.

    Real cryptographic verification (cosign/sigstore) is a TODO.
    """
    try:
        return _get_engine().verify_attestation(
            attestation_id=attestation_id,
            verifier=verifier,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/attestations", dependencies=[Depends(api_key_auth)])
def list_attestations(
    org_id: str = Query(..., description="Organisation ID"),
    subject_name: Optional[str] = Query(default=None, description="Filter by subject name"),
    builder_id: Optional[str] = Query(default=None, description="Filter by builder id"),
) -> List[Dict[str, Any]]:
    """List attestations for an org with optional filters."""
    try:
        return _get_engine().list_attestations(
            org_id=org_id,
            subject_name=subject_name,
            builder_id=builder_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/attestations/{attestation_id}", dependencies=[Depends(api_key_auth)])
def get_attestation(attestation_id: str) -> Dict[str, Any]:
    """Return a single attestation by id."""
    att = _get_engine().get_attestation(attestation_id)
    if att is None:
        raise HTTPException(status_code=404, detail="attestation not found")
    return att


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def stats(org_id: str = Query(..., description="Organisation ID")) -> Dict[str, Any]:
    """Return aggregate stats: counts by SLSA level + verification pass/fail rate."""
    try:
        return _get_engine().stats(org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
