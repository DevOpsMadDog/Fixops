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


@router.get("/{artifact_name}")
async def fetch_attestation(artifact_name: str, request: Request) -> dict:
    directory = _resolve_directory(request)

    # Inline path validation pattern (CodeQL-friendly)
    # Step 1: Resolve base directory first (before any user input)
    base = directory.resolve()

    # Step 2: Sanitize user input - extract just the filename component
    safe_name = Path(artifact_name).name
    if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    if not safe_name.endswith(".json"):
        safe_name = f"{safe_name}.json"

    # Step 3: Construct candidate path from base + sanitized component
    candidate = (base / safe_name).resolve()

    # Step 4: Validate candidate is within base directory
    if not candidate.is_relative_to(base):
        raise HTTPException(status_code=400, detail="Invalid attestation path")

    # Step 5: Now safe to use the validated path
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="Attestation not found")
    statement = load_attestation(candidate)
    return statement.to_dict()
