"""
Evidence Chain API — tamper-proof cryptographic audit trail endpoints.

Provides 6 REST endpoints for appending, verifying, querying,
and exporting the SHA-256 hash-chained audit log.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.evidence_chain import EvidenceChain

router = APIRouter(prefix="/api/v1/evidence-chain", tags=["evidence-chain"])

_chain = EvidenceChain()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class AppendRequest(BaseModel):
    """Request body for appending a new evidence entry."""

    event_type: str = Field(..., min_length=1, description="Type of security event")
    data: Dict[str, Any] = Field(default_factory=dict, description="Event payload")


class ChainEntryResponse(BaseModel):
    """Single chain entry serialisation."""

    id: str
    sequence_number: int
    event_type: str
    data_hash: str
    previous_hash: str
    timestamp: str
    signature: str
    org_id: str


class VerifyResponse(BaseModel):
    org_id: str
    chain_length: int
    is_valid: bool
    broken_links: List[int]
    invalid_signatures: List[int]
    verified_at: str


class StatsResponse(BaseModel):
    org_id: str
    length: int
    first_timestamp: Optional[str]
    last_timestamp: Optional[str]
    integrity_status: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/append", response_model=ChainEntryResponse, status_code=201)
async def append_entry(
    body: AppendRequest,
    org_id: str = Depends(get_org_id),
):
    """Append a new event to the tamper-proof evidence chain.

    Each entry is linked to the previous via SHA-256 (blockchain-style)
    and signed with HMAC-SHA-256.
    """
    entry = _chain.append(event_type=body.event_type, data=body.data, org_id=org_id)
    return ChainEntryResponse(
        id=entry.id,
        sequence_number=entry.sequence_number,
        event_type=entry.event_type,
        data_hash=entry.data_hash,
        previous_hash=entry.previous_hash,
        timestamp=entry.timestamp.isoformat(),
        signature=entry.signature,
        org_id=entry.org_id,
    )


@router.get("/verify", response_model=VerifyResponse)
async def verify_chain(org_id: str = Depends(get_org_id)):
    """Verify the integrity of the entire evidence chain for this org.

    Re-derives all hash links and validates HMAC signatures.
    Returns broken link positions and invalid signature positions.
    """
    result = _chain.verify_chain(org_id)
    return VerifyResponse(**result)


@router.get("/entries", response_model=List[ChainEntryResponse])
async def get_chain(
    org_id: str = Depends(get_org_id),
    start: int = Query(0, ge=0, description="Start sequence number (inclusive)"),
    end: Optional[int] = Query(None, ge=0, description="End sequence number (inclusive)"),
):
    """Retrieve a segment of the evidence chain by sequence number range."""
    entries = _chain.get_chain(org_id=org_id, start=start, end=end)
    return [
        ChainEntryResponse(
            id=e.id,
            sequence_number=e.sequence_number,
            event_type=e.event_type,
            data_hash=e.data_hash,
            previous_hash=e.previous_hash,
            timestamp=e.timestamp.isoformat(),
            signature=e.signature,
            org_id=e.org_id,
        )
        for e in entries
    ]


@router.get("/latest", response_model=ChainEntryResponse)
async def get_latest(org_id: str = Depends(get_org_id)):
    """Return the most recent entry in the evidence chain."""
    entry = _chain.get_latest(org_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="No entries in chain for this org")
    return ChainEntryResponse(
        id=entry.id,
        sequence_number=entry.sequence_number,
        event_type=entry.event_type,
        data_hash=entry.data_hash,
        previous_hash=entry.previous_hash,
        timestamp=entry.timestamp.isoformat(),
        signature=entry.signature,
        org_id=entry.org_id,
    )


@router.get("/export")
async def export_chain(org_id: str = Depends(get_org_id)):
    """Export the full evidence chain as JSON for external audit."""
    from fastapi.responses import Response

    chain_data = _chain.export_chain(org_id)
    payload = json.dumps(
        {
            "org_id": org_id,
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "entry_count": len(chain_data),
            "chain": chain_data,
        },
        indent=2,
    )
    return Response(
        content=payload,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=evidence_chain_{org_id}.json"
        },
    )


@router.get("/stats", response_model=StatsResponse)
async def get_stats(org_id: str = Depends(get_org_id)):
    """Return summary statistics for the evidence chain: length, timestamps, integrity."""
    stats = _chain.get_chain_stats(org_id)
    return StatsResponse(**stats)
