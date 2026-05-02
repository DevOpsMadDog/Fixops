"""Network Forensics API Router — ALDECI."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/network-forensics", tags=["Network Forensics"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.network_forensics_engine import NetworkForensicsEngine
        _engine = NetworkForensicsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CaptureCreate(BaseModel):
    interface: str
    filter_bpf: str = ""
    duration_sec: int = 60


class ArtifactCreate(BaseModel):
    artifact_type: str = "pcap"
    size_bytes: int = 0
    findings_count: int = 0
    analysis_json: str = ""


class AnalyzeRequest(BaseModel):
    suspicious_ips: List[str] = []
    protocols_seen: List[str] = []
    anomalies: List[str] = []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_network_forensics(org_id: str = Query("default")):
    """List network forensics captures for the org."""
    captures = _get_engine().list_captures(org_id=org_id)
    return {"org_id": org_id, "captures": captures, "total": len(captures)}


@router.post("/captures")
async def create_capture(
    body: CaptureCreate,
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().create_capture(org_id=org_id, data=body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/captures")
async def list_captures(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth=Depends(api_key_auth),
):
    """List network forensics captures (canonical envelope, batch-7).

    Class-c contract: empty IS correct for fresh tenants — packet captures are
    manually started or triggered by detection events, not auto-derivable from
    any public source. Always returns full envelope with pagination context +
    filters echo + actionable hint when empty.
    """
    try:
        rows = _get_engine().list_captures(org_id=org_id, status=status) or []
        paged = rows[offset : offset + limit] if offset else rows[:limit]
        envelope: Dict[str, Any] = {
            "items": paged,
            "captures": paged,  # legacy key preserved
            "total": len(rows),
            "org_id": org_id,
            "limit": limit,
            "offset": offset,
            "filters_applied": {
                "status": status,
            },
        }
        if not rows:
            envelope["hint"] = (
                "Packet captures are manual/triggered. Start one via POST "
                "/api/v1/network-forensics/captures. Empty IS the correct response "
                "for a fresh tenant — no public source exists."
            )
        return envelope
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/captures/{capture_id}")
async def get_capture(
    capture_id: str,
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    result = _get_engine().get_capture(org_id=org_id, capture_id=capture_id)
    if not result:
        raise HTTPException(status_code=404, detail="Capture not found")
    return result


@router.post("/captures/{capture_id}/artifacts")
async def add_artifact(
    capture_id: str,
    body: ArtifactCreate,
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().add_artifact(org_id=org_id, capture_id=capture_id, data=body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/captures/{capture_id}/analyze")
async def analyze_capture(
    capture_id: str,
    body: AnalyzeRequest,
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().analyze_capture(
            org_id=org_id,
            capture_id=capture_id,
            analysis_data=body.model_dump(),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/artifacts")
async def list_artifacts(
    org_id: str = Query(default="default"),
    capture_id: Optional[str] = Query(default=None),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().list_artifacts(org_id=org_id, capture_id=capture_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats")
async def get_stats(
    org_id: str = Query(default="default"),
    auth=Depends(api_key_auth),
):
    try:
        return _get_engine().get_forensics_stats(org_id=org_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
