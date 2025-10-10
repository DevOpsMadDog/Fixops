"""Evidence export endpoints aligned with DecisionFactory Part 3."""

from __future__ import annotations

import io
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse

from src.core.security import TenantPersona, get_current_user, require_tenant_role
from src.services.evidence_export import EvidenceExportService

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("/{evidence_id}/download", response_class=StreamingResponse)
async def download_evidence_bundle(
    evidence_id: str,
    _: Dict[str, str] = Depends(require_tenant_role(TenantPersona.AUDITOR)),
    current_user: Dict = Depends(get_current_user),
) -> StreamingResponse:
    """Stream a signed JSON + PDF evidence bundle."""

    service = EvidenceExportService()
    try:
        archive_bytes, metadata = await service.build_bundle(evidence_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    headers = {
        "X-Evidence-Fingerprint": metadata["fingerprint"],
        "X-Evidence-Signature": metadata["signature"],
        "X-Served-By": "FixOps Evidence Exporter",
    }

    return StreamingResponse(
        io.BytesIO(archive_bytes),
        media_type="application/zip",
        headers=headers,
        background=None,
    )

