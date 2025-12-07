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
    manifest_path = manifest_dir / f"{release}.yaml"
    if not manifest_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence manifest not found")
    with manifest_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="Malformed evidence manifest")
    bundle_path = bundle_dir / f"{release}.zip"
    return {
        "tag": release,
        "manifest": payload,
        "bundle_available": bundle_path.is_file(),
        "bundle_path": str(bundle_path) if bundle_path.is_file() else None,
    }


@router.get("/bundles/{bundle_id}/download")
async def download_evidence_bundle(bundle_id: str, request: Request):
    """Download evidence bundle by ID."""
    evidence_base = Path("data/data/evidence")

    bundle_path = None
    for run_dir in evidence_base.glob("*"):
        if run_dir.is_dir():
            potential_bundle = run_dir / "fixops-demo-run-bundle.json.gz"
            if potential_bundle.exists():
                bundle_path = potential_bundle
                break

    if not bundle_path or not bundle_path.exists():
        raise HTTPException(status_code=404, detail="Evidence bundle not found")

    return FileResponse(
        path=str(bundle_path),
        media_type="application/gzip",
        filename=f"fixops-evidence-{bundle_id}.json.gz",
        headers={
            "Content-Disposition": f'attachment; filename="fixops-evidence-{bundle_id}.json.gz"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


__all__ = ["router"]
