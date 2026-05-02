"""Binary Fingerprint Router — ALDECI (GAP-008).

Sonatype ABF-style fingerprinting API. Endpoints accept a binary blob via
multipart upload OR base64 in the request body.

Prefix: /api/v1/binary-fp
Auth: api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/binary-fp/fingerprint     compute-only (no persistence)
  POST /api/v1/binary-fp/register        compute + persist to registry
  POST /api/v1/binary-fp/query-similar   find similar prior artefacts
  POST /api/v1/binary-fp/check-bad       known-bad verdict (optionally logs)
  GET  /api/v1/binary-fp/stats           counters per org
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/binary-fp",
    tags=["Binary Fingerprint"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.binary_fingerprint_engine import BinaryFingerprintEngine
        _engine = BinaryFingerprintEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class BlobBody(BaseModel):
    blob_base64: str = Field(..., description="Base64-encoded binary blob")


class RegisterBody(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    artifact_ref: str = Field(default="", description="Artefact URI/path/tag")
    blob_base64: str = Field(..., description="Base64-encoded binary blob")


class QuerySimilarBody(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    blob_base64: str = Field(..., description="Base64-encoded binary blob")
    min_similarity: float = Field(default=0.85, ge=0.0, le=1.0)


class CheckBadBody(BaseModel):
    blob_base64: str = Field(..., description="Base64-encoded binary blob")
    org_id: Optional[str] = Field(default=None)
    candidate_id: str = Field(default="")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_b64(blob_b64: str) -> bytes:
    try:
        return base64.b64decode(blob_b64.encode("ascii"), validate=False)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid base64: {exc}")


async def _read_blob_from_upload_or_body(
    file: Optional[UploadFile],
    blob_base64: Optional[str],
) -> bytes:
    """Accept either a multipart file OR a base64 body string."""
    if file is not None:
        return await file.read()
    if blob_base64:
        return _decode_b64(blob_base64)
    raise HTTPException(
        status_code=422,
        detail="Provide either a multipart 'file' upload or 'blob_base64' body.",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/fingerprint", dependencies=[Depends(api_key_auth)])
async def fingerprint_blob(
    file: Optional[UploadFile] = File(default=None),
    blob_base64: Optional[str] = Form(default=None),
) -> Dict[str, Any]:
    """Compute-only fingerprint (no persistence). Accepts multipart OR form field."""
    blob = await _read_blob_from_upload_or_body(file, blob_base64)
    fp = _get_engine().compute_fingerprint(blob)
    return {"fingerprint": fp}


@router.post("/fingerprint/json", dependencies=[Depends(api_key_auth)])
def fingerprint_blob_json(body: BlobBody) -> Dict[str, Any]:
    """JSON-body variant for clients that can't do multipart."""
    blob = _decode_b64(body.blob_base64)
    fp = _get_engine().compute_fingerprint(blob)
    return {"fingerprint": fp}


@router.post("/register", dependencies=[Depends(api_key_auth)], status_code=201)
async def register_artifact_multipart(
    org_id: str = Form(...),
    artifact_ref: str = Form(default=""),
    file: Optional[UploadFile] = File(default=None),
    blob_base64: Optional[str] = Form(default=None),
) -> Dict[str, Any]:
    """Compute + persist a fingerprint for an org-owned artefact."""
    blob = await _read_blob_from_upload_or_body(file, blob_base64)
    try:
        return _get_engine().register_artifact(
            org_id=org_id, artifact_ref=artifact_ref, blob=blob
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/register/json", dependencies=[Depends(api_key_auth)], status_code=201)
def register_artifact_json(body: RegisterBody) -> Dict[str, Any]:
    """JSON-body variant of /register."""
    blob = _decode_b64(body.blob_base64)
    try:
        return _get_engine().register_artifact(
            org_id=body.org_id, artifact_ref=body.artifact_ref, blob=blob
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/query-similar", dependencies=[Depends(api_key_auth)])
def query_similar(body: QuerySimilarBody) -> Dict[str, Any]:
    """Find previously registered artefacts similar to the supplied blob."""
    blob = _decode_b64(body.blob_base64)
    try:
        return _get_engine().query_similar(
            org_id=body.org_id,
            blob=blob,
            min_similarity=body.min_similarity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/check-bad", dependencies=[Depends(api_key_auth)])
def check_known_bad(body: CheckBadBody) -> Dict[str, Any]:
    """Check a blob against the known-bad fingerprint registry."""
    blob = _decode_b64(body.blob_base64)
    verdict = _get_engine().check_known_bad(
        blob=blob,
        org_id=body.org_id,
        candidate_id=body.candidate_id,
    )
    if verdict is None:
        fp = _get_engine().compute_fingerprint(blob)
        return {
            "verdict": "unknown",
            "match_type": None,
            "similarity": 0.0,
            "query_fingerprint": fp,
        }
    return verdict


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def stats(
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Return fingerprint counters for an org."""
    try:
        return _get_engine().stats(org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
