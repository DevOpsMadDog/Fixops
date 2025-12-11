"""FastAPI router exposing provenance attestations."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from services.provenance import load_attestation

router = APIRouter(prefix="/provenance", tags=["provenance"])


def _resolve_directory(request: Request) -> Path:
    directory = getattr(request.app.state, "provenance_dir", None)
    if directory is None:
        raise HTTPException(status_code=503, detail="Provenance storage not configured")
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


@router.get("/", response_model=list[str])
async def list_attestations(request: Request) -> list[str]:
    directory = _resolve_directory(request)
    return sorted(path.name for path in directory.glob("*.json"))


def _validate_path_within_base(path: Path, base: Path) -> Path:
    """Validate that a resolved path is within the expected base directory."""
    resolved_path = path.resolve()
    resolved_base = base.resolve()
    if not resolved_path.is_relative_to(resolved_base):
        raise HTTPException(status_code=400, detail="Invalid path")
    return resolved_path


@router.get("/{artifact_name}")
async def fetch_attestation(artifact_name: str, request: Request) -> dict:
    directory = _resolve_directory(request)
    resolved_directory = directory.resolve()
    # Sanitize artifact name to prevent path traversal
    safe_name = Path(artifact_name).name
    # Additional validation: reject any path traversal attempts
    if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    if not safe_name.endswith(".json"):
        safe_name = f"{safe_name}.json"
    # Construct and validate attestation path
    attestation_path = _validate_path_within_base(
        directory / safe_name, resolved_directory
    )
    if not attestation_path.is_file():
        raise HTTPException(status_code=404, detail="Attestation not found")
    statement = load_attestation(attestation_path)
    return statement.to_dict()
