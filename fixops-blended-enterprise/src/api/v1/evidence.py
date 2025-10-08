"""Evidence verification endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from src.api.dependencies import authenticate
from src.services import signing
from src.services.runtime import EVIDENCE_STORE

router = APIRouter(tags=["evidence"])


@router.get("/{evidence_id}/verify")
async def verify_evidence(evidence_id: str, _: None = Depends(authenticate)) -> dict:
    record = EVIDENCE_STORE.get(evidence_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    signature = record.signature
    verified = False
    if signature:
        verified = signing.verify_manifest(record.manifest, signature)
    return {
        "evidence_id": record.evidence_id,
        "verified": verified,
        "kid": record.kid,
        "algorithm": record.algorithm or signing.ALGORITHM,
    }

