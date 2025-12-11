from pathlib import Path
from typing import Any

import yaml  # type: ignore[import]
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

router = APIRouter(prefix="/evidence", tags=["evidence"])


def _resolve_directories(request: Request) -> tuple[Path, Path]:
    manifest_dir = getattr(request.app.state, "evidence_manifest_dir", None)
    bundle_dir = getattr(request.app.state, "evidence_bundle_dir", None)
    if manifest_dir is None or bundle_dir is None:
        raise HTTPException(status_code=503, detail="Evidence storage not configured")
    return Path(manifest_dir), Path(bundle_dir)


@router.get("/")
async def list_evidence(request: Request) -> dict[str, Any]:
    manifest_dir, bundle_dir = _resolve_directories(request)
    releases: list[dict[str, Any]] = []
    for manifest_path in sorted(manifest_dir.glob("*.yaml")):
        tag = manifest_path.stem
        bundle_path = bundle_dir / f"{tag}.zip"
        releases.append(
            {
                "tag": tag,
                "manifest_path": str(manifest_path),
                "bundle_available": bundle_path.is_file(),
                "bundle_path": str(bundle_path) if bundle_path.is_file() else None,
                "updated_at": manifest_path.stat().st_mtime,
            }
        )
    return {"count": len(releases), "releases": releases}


def _sanitize_path_component(name: str) -> str:
    """Sanitize a path component to prevent directory traversal attacks.

    Removes any path separators and parent directory references.
    """
    # Get just the filename, stripping any directory components
    safe_name = Path(name).name
    # Reject if it contains path traversal attempts
    if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
        raise HTTPException(status_code=400, detail="Invalid path component")
    return safe_name


def _validate_path_within_base(path: Path, base: Path) -> Path:
    """Validate that a resolved path is within the expected base directory."""
    resolved_path = path.resolve()
    resolved_base = base.resolve()
    if not resolved_path.is_relative_to(resolved_base):
        raise HTTPException(status_code=400, detail="Invalid path")
    return resolved_path


@router.get("/{release}")
async def evidence_manifest(release: str, request: Request) -> dict[str, Any]:
    manifest_dir, bundle_dir = _resolve_directories(request)
    resolved_manifest_dir = manifest_dir.resolve()
    resolved_bundle_dir = bundle_dir.resolve()
    # Sanitize release name to prevent path traversal
    safe_release = _sanitize_path_component(release)
    # Construct and validate manifest path
    manifest_path = _validate_path_within_base(
        manifest_dir / f"{safe_release}.yaml", resolved_manifest_dir
    )
    if not manifest_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence manifest not found")
    with manifest_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="Malformed evidence manifest")
    # Construct and validate bundle path
    bundle_path = _validate_path_within_base(
        bundle_dir / f"{safe_release}.zip", resolved_bundle_dir
    )
    return {
        "tag": safe_release,
        "manifest": payload,
        "bundle_available": bundle_path.is_file(),
        "bundle_path": str(bundle_path) if bundle_path.is_file() else None,
    }


@router.get("/bundles/{bundle_id}/download")
async def download_evidence_bundle(bundle_id: str, request: Request):
    """Download evidence bundle by ID."""
    # Sanitize bundle_id to prevent path traversal
    safe_bundle_id = _sanitize_path_component(bundle_id)
    evidence_base = Path("data/data/evidence").resolve()

    bundle_path = None
    for run_dir in evidence_base.glob("*"):
        if run_dir.is_dir():
            potential_bundle = run_dir / "fixops-demo-run-bundle.json.gz"
            if potential_bundle.exists():
                # Verify the bundle path is within the evidence base directory
                if potential_bundle.resolve().is_relative_to(evidence_base):
                    bundle_path = potential_bundle
                    break

    if not bundle_path or not bundle_path.exists():
        raise HTTPException(status_code=404, detail="Evidence bundle not found")

    return FileResponse(
        path=str(bundle_path),
        media_type="application/gzip",
        filename=f"fixops-evidence-{safe_bundle_id}.json.gz",
        headers={
            "Content-Disposition": f'attachment; filename="fixops-evidence-{safe_bundle_id}.json.gz"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


__all__ = ["router"]
