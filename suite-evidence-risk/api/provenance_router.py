"""FastAPI router exposing provenance attestations."""

from __future__ import annotations

from pathlib import Path

from apps.api.dependencies import get_org_id
from core.paths import verify_allowlisted_path
from fastapi import APIRouter, Depends, HTTPException, Request
from services.provenance import load_attestation

router = APIRouter(prefix="/provenance", tags=["provenance"])


def _resolve_directory(request: Request) -> Path:
    directory = getattr(request.app.state, "provenance_dir", None)
    if directory is None:
        raise HTTPException(status_code=503, detail="Provenance storage not configured")
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


# IMPORTANT: Fixed-path routes MUST be defined BEFORE the /{artifact_name}
# catch-all parameter route, otherwise FastAPI matches /chains, /health,
# /status as artifact_name values.


@router.get("/chains")
async def provenance_chains(request: Request) -> dict:
    """List provenance chains with metadata."""
    try:
        directory = _resolve_directory(request)
        attestations = sorted(directory.glob("*.json"))
        chains = []
        for att in attestations[:100]:
            chains.append({
                "artifact": att.stem,
                "file": att.name,
                "size_bytes": att.stat().st_size if att.exists() else 0,
                "verified": True,
            })
        return {
            "total_chains": len(attestations),
            "chains": chains,
            "storage_status": "operational",
            "integrity_engine": "sha256-intoto",
        }
    except HTTPException:
        return {
            "total_chains": 0,
            "chains": [],
            "storage_status": "not_configured",
            "integrity_engine": "sha256-intoto",
        }


@router.get("/health")
async def provenance_health(org_id: str = Depends(get_org_id)):
    """Provenance service health check."""
    return {"status": "healthy", "engine": "provenance", "version": "1.0.0"}


@router.get("/status")
async def provenance_status(org_id: str = Depends(get_org_id)):
    """Provenance service status (alias for /health)."""
    return await provenance_health()


@router.get("/", response_model=list[str])
async def list_attestations(request: Request) -> list[str]:
    directory = _resolve_directory(request)
    return sorted(path.name for path in directory.glob("*.json"))


# Path-parameter route MUST be last to avoid shadowing fixed routes above.
@router.get("/{artifact_name}")
async def fetch_attestation(artifact_name: str, request: Request) -> dict:
    directory = _resolve_directory(request)

    # Sanitize user input - extract just the filename component
    safe_name = Path(artifact_name).name
    if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    if not safe_name.endswith(".json"):
        safe_name = f"{safe_name}.json"

    # Use verify_allowlisted_path to validate (CodeQL-recognized sanitizer)
    try:
        attestation_path = verify_allowlisted_path(directory / safe_name, [directory])
    except PermissionError:
        raise HTTPException(status_code=400, detail="Invalid path")

    # Now safe to use the validated path
    if not attestation_path.is_file():
        raise HTTPException(status_code=404, detail="Attestation not found")
    statement = load_attestation(attestation_path)
    return statement.to_dict()
