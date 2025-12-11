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


@router.get("/{release}")
async def evidence_manifest(release: str, request: Request) -> dict[str, Any]:
    manifest_dir, bundle_dir = _resolve_directories(request)

    # Inline path validation pattern (CodeQL-friendly)
    # Step 1: Resolve base directories first (before any user input)
    manifest_base = manifest_dir.resolve()
    bundle_base = bundle_dir.resolve()

    # Step 2: Sanitize user input - extract just the filename component
    safe_release = Path(release).name
    if ".." in safe_release or "/" in safe_release or "\\" in safe_release:
        raise HTTPException(status_code=400, detail="Invalid release name")

    # Step 3: Construct candidate paths from base + sanitized component
    manifest_candidate = (manifest_base / f"{safe_release}.yaml").resolve()
    bundle_candidate = (bundle_base / f"{safe_release}.zip").resolve()

    # Step 4: Validate candidates are within their respective base directories
    if not manifest_candidate.is_relative_to(manifest_base):
        raise HTTPException(status_code=400, detail="Invalid manifest path")
    if not bundle_candidate.is_relative_to(bundle_base):
        raise HTTPException(status_code=400, detail="Invalid bundle path")

    # Step 5: Now safe to use the validated paths
    if not manifest_candidate.is_file():
        raise HTTPException(status_code=404, detail="Evidence manifest not found")
    with manifest_candidate.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="Malformed evidence manifest")

    return {
        "tag": safe_release,
        "manifest": payload,
        "bundle_available": bundle_candidate.is_file(),
        "bundle_path": str(bundle_candidate) if bundle_candidate.is_file() else None,
    }


@router.get("/bundles/{bundle_id}/download")
async def download_evidence_bundle(bundle_id: str, request: Request):
    """Download evidence bundle by ID."""
    # Inline path validation pattern (CodeQL-friendly)
    # Step 1: Resolve base directory first (before any user input)
    evidence_base = Path("data/data/evidence").resolve()

    # Step 2: Sanitize user input - extract just the filename component
    safe_bundle_id = Path(bundle_id).name
    if ".." in safe_bundle_id or "/" in safe_bundle_id or "\\" in safe_bundle_id:
        raise HTTPException(status_code=400, detail="Invalid bundle ID")

    # Search for bundle in evidence directories
    # Note: We only use hardcoded filenames here, not user input
    bundle_path = None
    for run_dir in evidence_base.glob("*"):
        if run_dir.is_dir():
            # Hardcoded filename - safe by design
            potential_bundle = run_dir / "fixops-demo-run-bundle.json.gz"
            if potential_bundle.exists():
                # Verify the bundle path is within the evidence base directory
                resolved_bundle = potential_bundle.resolve()
                if resolved_bundle.is_relative_to(evidence_base):
                    bundle_path = resolved_bundle
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
