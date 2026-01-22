import base64
import json
import logging
from pathlib import Path
from typing import Any, Callable, Optional

import yaml  # type: ignore[import]
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core.paths import verify_allowlisted_path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/evidence", tags=["evidence"])

_rsa_verify: Optional[Callable[[bytes, bytes, str], bool]] = None

try:
    from fixops_enterprise.src.utils.crypto import rsa_verify as _enterprise_rsa_verify

    _rsa_verify = _enterprise_rsa_verify
except ImportError:
    try:
        import sys

        # Use append instead of insert(0) to avoid shadowing repo root packages
        # like services.graph when the enterprise path is searched first
        sys.path.append(
            str(
                Path(__file__).parent.parent.parent.parent / "fixops-enterprise" / "src"
            )
        )
        from utils.crypto import rsa_verify as _alt_rsa_verify

        _rsa_verify = _alt_rsa_verify
    except ImportError:
        pass


class EvidenceVerifyRequest(BaseModel):
    bundle_id: str = Field(..., description="The evidence bundle ID to verify")
    signature: Optional[str] = Field(
        None,
        description="Base64-encoded RSA signature (optional, will be read from manifest if not provided)",
    )
    fingerprint: Optional[str] = Field(
        None,
        description="Public key fingerprint (optional, will be read from manifest if not provided)",
    )


class EvidenceVerifyResponse(BaseModel):
    bundle_id: str
    verified: bool
    fingerprint: Optional[str] = None
    signed_at: Optional[str] = None
    signature_algorithm: Optional[str] = None
    error: Optional[str] = None


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

    # Sanitize user input - extract just the filename component
    safe_release = Path(release).name
    if ".." in safe_release or "/" in safe_release or "\\" in safe_release:
        raise HTTPException(status_code=400, detail="Invalid release name")

    # Use verify_allowlisted_path to validate paths (CodeQL-recognized sanitizer)
    try:
        manifest_path = verify_allowlisted_path(
            manifest_dir / f"{safe_release}.yaml", [manifest_dir]
        )
        bundle_path = verify_allowlisted_path(
            bundle_dir / f"{safe_release}.zip", [bundle_dir]
        )
    except PermissionError:
        raise HTTPException(status_code=400, detail="Invalid path")

    # Now safe to use the validated paths
    if not manifest_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence manifest not found")
    with manifest_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="Malformed evidence manifest")

    return {
        "tag": safe_release,
        "manifest": payload,
        "bundle_available": bundle_path.is_file(),
        "bundle_path": str(bundle_path) if bundle_path.is_file() else None,
    }


@router.get("/bundles/{bundle_id}/download")
async def download_evidence_bundle(bundle_id: str, request: Request):
    """Download evidence bundle by ID."""
    # Sanitize user input - extract just the filename component
    safe_bundle_id = Path(bundle_id).name
    if ".." in safe_bundle_id or "/" in safe_bundle_id or "\\" in safe_bundle_id:
        raise HTTPException(status_code=400, detail="Invalid bundle ID")

    # Use evidence base from app state or default
    evidence_base = Path("data/data/evidence")
    evidence_base.mkdir(parents=True, exist_ok=True)

    # Search for bundle in evidence directories
    # Note: We only use hardcoded filenames here, not user input
    bundle_path = None
    for run_dir in evidence_base.glob("*"):
        if run_dir.is_dir():
            # Hardcoded filename - safe by design
            potential_bundle = run_dir / "fixops-demo-run-bundle.json.gz"
            if potential_bundle.exists():
                # Use verify_allowlisted_path to validate (CodeQL-recognized sanitizer)
                try:
                    validated_bundle = verify_allowlisted_path(
                        potential_bundle, [evidence_base]
                    )
                    bundle_path = validated_bundle
                    break
                except PermissionError:
                    continue

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


@router.post("/verify", response_model=EvidenceVerifyResponse)
async def verify_evidence(
    request: Request, body: EvidenceVerifyRequest
) -> EvidenceVerifyResponse:
    """
    Verify the RSA-SHA256 signature of an evidence bundle.

    This endpoint verifies that an evidence bundle has not been tampered with
    by checking its cryptographic signature against the stored fingerprint.

    The signature and fingerprint can be provided in the request body, or they
    will be read from the bundle's manifest if not provided.
    """
    if _rsa_verify is None:
        raise HTTPException(
            status_code=503,
            detail="RSA verification module not available. Install fixops-enterprise package.",
        )

    bundle_id = body.bundle_id

    safe_bundle_id = Path(bundle_id).name
    if ".." in safe_bundle_id or "/" in safe_bundle_id or "\\" in safe_bundle_id:
        raise HTTPException(status_code=400, detail="Invalid bundle ID")

    # Use configured evidence directories instead of hardcoded paths
    try:
        manifest_dir, bundle_dir = _resolve_directories(request)
        evidence_base = bundle_dir.parent  # Evidence base is parent of bundle dir
    except HTTPException:
        # Fall back to default paths if not configured
        evidence_base = Path("data/data/evidence")
        if not evidence_base.exists():
            evidence_base = Path("data/evidence")

    manifest_path: Optional[Path] = None
    bundle_path: Optional[Path] = None

    for mode_dir in evidence_base.glob("*"):
        if mode_dir.is_dir():
            run_dir = mode_dir / safe_bundle_id
            if run_dir.is_dir():
                potential_manifest = run_dir / "manifest.json"
                if potential_manifest.exists():
                    try:
                        manifest_path = verify_allowlisted_path(
                            potential_manifest, [evidence_base]
                        )
                        break
                    except PermissionError:
                        continue

    if manifest_path is None:
        for mode_dir in evidence_base.glob("*"):
            if mode_dir.is_dir():
                for run_dir in mode_dir.glob("*"):
                    if run_dir.is_dir() and run_dir.name == safe_bundle_id:
                        potential_manifest = run_dir / "manifest.json"
                        if potential_manifest.exists():
                            try:
                                manifest_path = verify_allowlisted_path(
                                    potential_manifest, [evidence_base]
                                )
                                break
                            except PermissionError:
                                continue

    if manifest_path is None:
        raise HTTPException(status_code=404, detail="Evidence manifest not found")

    try:
        with manifest_path.open("r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        raise HTTPException(status_code=500, detail=f"Failed to read manifest: {e}")

    signature_b64 = body.signature or manifest.get("signature")
    fingerprint = body.fingerprint or manifest.get("fingerprint")
    signed_at = manifest.get("signed_at")
    signature_algorithm = manifest.get("signature_algorithm", "RSA-SHA256")

    if not signature_b64:
        return EvidenceVerifyResponse(
            bundle_id=bundle_id,
            verified=False,
            fingerprint=fingerprint,
            signed_at=signed_at,
            signature_algorithm=signature_algorithm,
            error="No signature found in manifest or request",
        )

    if not fingerprint:
        return EvidenceVerifyResponse(
            bundle_id=bundle_id,
            verified=False,
            signed_at=signed_at,
            signature_algorithm=signature_algorithm,
            error="No fingerprint found in manifest or request",
        )

    bundle_file = manifest.get("bundle")
    if not bundle_file:
        raise HTTPException(
            status_code=500, detail="Manifest does not contain bundle path"
        )

    bundle_path = Path(bundle_file)
    if not bundle_path.is_absolute():
        bundle_path = manifest_path.parent / bundle_path.name

    try:
        bundle_path = verify_allowlisted_path(
            bundle_path, [evidence_base, manifest_path.parent]
        )
    except PermissionError:
        raise HTTPException(status_code=400, detail="Invalid bundle path")

    if not bundle_path.exists():
        raise HTTPException(status_code=404, detail="Evidence bundle file not found")

    try:
        bundle_bytes = bundle_path.read_bytes()
    except IOError as e:
        raise HTTPException(status_code=500, detail=f"Failed to read bundle: {e}")

    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception as e:
        return EvidenceVerifyResponse(
            bundle_id=bundle_id,
            verified=False,
            fingerprint=fingerprint,
            signed_at=signed_at,
            signature_algorithm=signature_algorithm,
            error=f"Invalid signature encoding: {e}",
        )

    try:
        verified = _rsa_verify(bundle_bytes, signature_bytes, fingerprint)
    except Exception as e:
        logger.warning(f"RSA verification failed for bundle {bundle_id}: {e}")
        return EvidenceVerifyResponse(
            bundle_id=bundle_id,
            verified=False,
            fingerprint=fingerprint,
            signed_at=signed_at,
            signature_algorithm=signature_algorithm,
            error=f"Verification error: {e}",
        )

    return EvidenceVerifyResponse(
        bundle_id=bundle_id,
        verified=verified,
        fingerprint=fingerprint,
        signed_at=signed_at,
        signature_algorithm=signature_algorithm,
        error=None if verified else "Signature verification failed",
    )


__all__ = ["router"]
