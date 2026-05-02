"""IP Reputation Router — ALDECI.

IP reputation submission, bulk checking, and per-org blocklist management.

Prefix: /api/v1/ip-reputation
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/ip-reputation/submit          submit_reputation
  GET    /api/v1/ip-reputation/{ip}            get_reputation
  POST   /api/v1/ip-reputation/bulk-check      bulk_check
  POST   /api/v1/ip-reputation/blocklist       add_to_blocklist
  DELETE /api/v1/ip-reputation/blocklist/{ip}  remove_from_blocklist
  GET    /api/v1/ip-reputation/blocklist        get_blocklist
  GET    /api/v1/ip-reputation/blocked/{ip}    is_blocked
  GET    /api/v1/ip-reputation/stats           get_reputation_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ip-reputation",
    tags=["IP Reputation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ip_reputation_engine import IPReputationEngine
        _engine = IPReputationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SubmitReputationRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    ip: str = Field(..., description="IP address")
    reputation_score: int = Field(
        default=50, ge=0, le=100,
        description="Reputation score 0-100 (lower = worse reputation)"
    )
    categories: List[str] = Field(
        default_factory=list,
        description="Threat categories: spam, botnet, proxy, tor, scanner, malware"
    )
    source: str = Field(default="", description="Data source / feed name")


class BulkCheckRequest(BaseModel):
    org_id: str = Field(default="default")
    ips: List[str] = Field(..., description="List of IP addresses to check")


class BlocklistRequest(BaseModel):
    org_id: str = Field(default="default")
    ip: str = Field(..., description="IP address to block")
    reason: str = Field(default="", description="Reason for blocking")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/submit", dependencies=[Depends(api_key_auth)])
def submit_reputation(req: SubmitReputationRequest) -> Dict[str, Any]:
    """Submit or update IP reputation data."""
    try:
        return _get_engine().submit_reputation(req.org_id, req.model_dump(exclude={"org_id"}))
    except Exception as exc:
        _logger.exception("submit_reputation failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_reputation_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate IP reputation statistics for the org."""
    try:
        return _get_engine().get_reputation_stats(org_id)
    except Exception as exc:
        _logger.exception("get_reputation_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/blocklist", dependencies=[Depends(api_key_auth)])
def get_blocklist(
    org_id: str = Query(default="default"),
    limit: int = Query(default=100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """Return the org IP blocklist."""
    try:
        return _get_engine().get_blocklist(org_id, limit)
    except Exception as exc:
        _logger.exception("get_blocklist failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/bulk-check", dependencies=[Depends(api_key_auth)])
def bulk_check(req: BulkCheckRequest) -> List[Dict[str, Any]]:
    """Bulk check reputation scores for a list of IPs."""
    try:
        return _get_engine().bulk_check(req.org_id, req.ips)
    except Exception as exc:
        _logger.exception("bulk_check failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/blocklist", dependencies=[Depends(api_key_auth)])
def add_to_blocklist(req: BlocklistRequest) -> Dict[str, Any]:
    """Add an IP to the org blocklist."""
    try:
        return _get_engine().add_to_blocklist(req.org_id, req.ip, req.reason)
    except Exception as exc:
        _logger.exception("add_to_blocklist failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/blocklist/{ip}", dependencies=[Depends(api_key_auth)])
def remove_from_blocklist(
    ip: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Remove an IP from the org blocklist."""
    try:
        return _get_engine().remove_from_blocklist(org_id, ip)
    except Exception as exc:
        _logger.exception("remove_from_blocklist failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/blocked/{ip}", dependencies=[Depends(api_key_auth)])
def is_blocked(ip: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Check if a specific IP is on the blocklist."""
    try:
        blocked = _get_engine().is_blocked(org_id, ip)
        return {"ip": ip, "blocked": blocked}
    except Exception as exc:
        _logger.exception("is_blocked failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{ip}", dependencies=[Depends(api_key_auth)])
def get_reputation(ip: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get reputation data for a single IP."""
    try:
        result = _get_engine().get_reputation(org_id, ip)
        if not result:
            raise HTTPException(status_code=404, detail=f"No reputation data for IP: {ip}")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("get_reputation failed")
        raise HTTPException(status_code=500, detail=str(exc))
