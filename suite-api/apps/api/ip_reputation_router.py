"""IP Reputation API router.

Endpoints at /api/v1/reputation/* for tracking, scoring, and managing
IP reputation records.
"""

from __future__ import annotations

from typing import List, Optional

from apps.api.dependencies import get_org_id
from core.ip_reputation import IPRecord, IPReputationEngine, ReputationLevel
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/reputation", tags=["ip-reputation"])
_engine = IPReputationEngine()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RecordIPRequest(BaseModel):
    ip_address: str = Field(..., description="IPv4 or IPv6 address to record")
    source: str = Field(..., min_length=1, description="Source of the sighting (e.g. 'scanner', 'threat_intel')")


class BulkCheckRequest(BaseModel):
    ips: List[str] = Field(..., min_items=1, max_items=500, description="List of IPs to score")


class BlocklistAddRequest(BaseModel):
    ip_address: str = Field(..., description="IP to block")
    reason: str = Field(..., min_length=1, description="Reason for blocking")


class EnrichResponse(BaseModel):
    ip: str
    country_code: Optional[str]
    asn: Optional[str]
    isp: Optional[str]
    is_tor: bool
    is_vpn: bool
    is_datacenter: bool
    enriched_at: str


class StatsResponse(BaseModel):
    total_tracked: int
    by_level: dict
    average_score: float
    manual_blocklist_count: int
    top_malicious: list


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/record", response_model=IPRecord, summary="Record an IP sighting")
def record_ip(
    body: RecordIPRequest,
    org_id: str = Depends(get_org_id),
) -> IPRecord:
    """Record an IP sighting from any source and return its updated reputation."""
    return _engine.record_ip(ip=body.ip_address, source=body.source, org_id=org_id)


@router.get("/score/{ip}", response_model=IPRecord, summary="Score an IP address")
def score_ip(
    ip: str,
    org_id: str = Depends(get_org_id),
) -> IPRecord:
    """Calculate (or recalculate) the reputation score for an IP address."""
    return _engine.score_ip(ip=ip, org_id=org_id)


@router.get("/ip/{ip}", response_model=IPRecord, summary="Get stored IP record")
def get_ip(
    ip: str,
    org_id: str = Depends(get_org_id),
) -> IPRecord:
    """Retrieve the stored reputation record for an IP without rescoring."""
    record = _engine.get_ip(ip=ip, org_id=org_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"IP {ip!r} not found for this org")
    return record


@router.get("/list", response_model=List[IPRecord], summary="List tracked IPs")
def list_ips(
    level: Optional[ReputationLevel] = Query(None, description="Filter by reputation level"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    org_id: str = Depends(get_org_id),
) -> List[IPRecord]:
    """List all tracked IPs for the org, optionally filtered by reputation level."""
    return _engine.list_ips(org_id=org_id, level_filter=level, limit=limit)


@router.get("/malicious", response_model=List[IPRecord], summary="List malicious IPs")
def get_malicious(
    org_id: str = Depends(get_org_id),
) -> List[IPRecord]:
    """Return all MALICIOUS and BLOCKLISTED IPs for the org."""
    return _engine.get_malicious(org_id=org_id)


@router.get("/check-blocklist/{ip}", summary="Check if IP is in built-in blocklist")
def check_blocklist(ip: str) -> dict:
    """Check whether an IP matches any built-in known-malicious CIDR range."""
    is_blocked = _engine.check_blocklist(ip=ip)
    return {"ip": ip, "in_blocklist": is_blocked}


@router.get("/enrich/{ip}", response_model=EnrichResponse, summary="Enrich IP with geo/ASN/ISP data")
def enrich_ip(ip: str) -> EnrichResponse:
    """Return geo, ASN, and ISP enrichment data for an IP address."""
    data = _engine.enrich_ip(ip=ip)
    return EnrichResponse(**data)


@router.get("/history/{ip}", summary="Get IP activity history")
def get_ip_history(
    ip: str,
    org_id: str = Depends(get_org_id),
) -> list:
    """Return the full event history for an IP within the org."""
    return _engine.get_ip_history(ip=ip, org_id=org_id)


@router.post("/bulk-check", response_model=List[IPRecord], summary="Batch score multiple IPs")
def bulk_check(
    body: BulkCheckRequest,
    org_id: str = Depends(get_org_id),
) -> List[IPRecord]:
    """Score multiple IP addresses in a single request."""
    return _engine.bulk_check(ips=body.ips, org_id=org_id)


@router.post("/blocklist/add", summary="Manually add IP to blocklist")
def add_to_blocklist(
    body: BlocklistAddRequest,
    org_id: str = Depends(get_org_id),
) -> dict:
    """Add an IP to the manual org blocklist (forces BLOCKLISTED level)."""
    _engine.add_to_blocklist(ip=body.ip_address, reason=body.reason, org_id=org_id)
    return {"status": "blocked", "ip": body.ip_address, "reason": body.reason}


@router.delete("/blocklist/remove/{ip}", summary="Remove IP from blocklist")
def remove_from_blocklist(
    ip: str,
    org_id: str = Depends(get_org_id),
) -> dict:
    """Remove an IP from the manual org blocklist and rescore it."""
    _engine.remove_from_blocklist(ip=ip, org_id=org_id)
    return {"status": "unblocked", "ip": ip}


@router.get("/stats", response_model=StatsResponse, summary="Get reputation statistics")
def get_reputation_stats(
    org_id: str = Depends(get_org_id),
) -> StatsResponse:
    """Return aggregate IP reputation statistics for the org."""
    stats = _engine.get_reputation_stats(org_id=org_id)
    return StatsResponse(**stats)
