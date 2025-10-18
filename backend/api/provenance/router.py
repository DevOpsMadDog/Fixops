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
    safe_name = Path(artifact_name).name
    if not safe_name.endswith(".json"):
        safe_name = f"{safe_name}.json"
    attestation_path = directory / safe_name
    if not attestation_path.is_file():
        raise HTTPException(status_code=404, detail="Attestation not found")
    statement = load_attestation(attestation_path)
    return statement.to_dict()
