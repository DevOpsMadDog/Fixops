"""Cloudflare API v4 Live REST Router — ALDECI (NEW — 2026-05-04).

Wraps ``core.cloudflare_engine.CloudflareEngine`` with REST endpoints
for Zones / DNS Records / Firewall Rules / WAF Packages / Security
Events / Access Groups against the live Cloudflare control plane.

Prefix: /api/v1/cloudflare
Auth:   api_key_auth dependency (mount layer adds read:scans scope)

Routes:
  GET  /api/v1/cloudflare/                                                 capability summary
  GET  /api/v1/cloudflare/client/v4/zones                                  list zones
  GET  /api/v1/cloudflare/client/v4/zones/{zone_id}                        single zone
  GET  /api/v1/cloudflare/client/v4/zones/{zone_id}/dns_records            DNS records
  GET  /api/v1/cloudflare/client/v4/zones/{zone_id}/firewall/rules         firewall rules
  GET  /api/v1/cloudflare/client/v4/zones/{zone_id}/waf/packages           WAF packages
  GET  /api/v1/cloudflare/client/v4/zones/{zone_id}/security_events        security events
  GET  /api/v1/cloudflare/client/v4/accounts/{account_id}/access/groups    access groups

NO MOCKS rule: when CLOUDFLARE_API_TOKEN is missing the capability summary
reports ``status="unavailable"`` and every live endpoint returns HTTP 503.
We do not fabricate zones / records / rules / events ever.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloudflare",
    tags=["Cloudflare API v4"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_cloudflare_engine().
    from core.cloudflare_engine import get_cloudflare_engine
    return get_cloudflare_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    cloudflare_api_token_present: bool
    status: str  # ok | empty | unavailable


class CloudflareEnvelope(BaseModel):
    """Cloudflare standard envelope: {success, errors, messages, result, result_info?}."""
    model_config = {"extra": "allow"}

    success: bool = True
    errors: List[Any] = Field(default_factory=list)
    messages: List[Any] = Field(default_factory=list)
    result: Any = None
    result_info: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a Cloudflare call, translating engine errors to HTTP responses.

    CloudflareUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError                 -> 422 (input validation)
    """
    from core.cloudflare_engine import CloudflareUnavailableError
    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CloudflareUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service summary — safe to call without Cloudflare credentials."""
    eng = _engine()
    tok = eng.token_present()
    status = "ok" if tok else "unavailable"
    return CapabilityResponse(
        service="Cloudflare API v4",
        endpoints=[
            "/client/v4/zones",
            "/client/v4/zones/{zone_id}/dns_records",
            "/client/v4/zones/{zone_id}/firewall/rules",
            "/client/v4/zones/{zone_id}/waf/packages",
            "/client/v4/zones/{zone_id}/security_events",
            "/client/v4/accounts/{account_id}/access/groups",
        ],
        cloudflare_api_token_present=tok,
        status=status,
    )


@router.get("/client/v4/zones", response_model=CloudflareEnvelope)
async def list_zones(
    name: Optional[str] = Query(None, description="Zone FQDN filter"),
    status: Optional[str] = Query(
        None, description="initializing|pending|active|moved|deleted|deactivated"
    ),
    account_id: Optional[str] = Query(
        None, alias="account.id", description="Account UUID filter"
    ),
    page: Optional[int] = Query(None, ge=1),
    per_page: Optional[int] = Query(None, ge=1, le=1000),
    order: Optional[str] = Query(None, description="Sort field e.g. status|name"),
    direction: Optional[str] = Query(None, description="asc|desc"),
    match: Optional[str] = Query(None, description="any|all"),
) -> CloudflareEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.list_zones(
            name=name,
            status=status,
            account_id=account_id,
            page=page,
            per_page=per_page,
            order=order,
            direction=direction,
            match=match,
        )
    )
    return CloudflareEnvelope(**data)


@router.get("/client/v4/zones/{zone_id}", response_model=CloudflareEnvelope)
async def get_zone(
    zone_id: str = Path(..., min_length=1, max_length=128),
) -> CloudflareEnvelope:
    eng = _engine()
    data = _serve(lambda: eng.get_zone(zone_id))
    return CloudflareEnvelope(**data)


@router.get(
    "/client/v4/zones/{zone_id}/dns_records",
    response_model=CloudflareEnvelope,
)
async def list_dns_records(
    zone_id: str = Path(..., min_length=1, max_length=128),
    type: Optional[str] = Query(
        None, description="A|AAAA|CNAME|MX|TXT|NS|SRV|CAA|PTR|..."
    ),
    name: Optional[str] = Query(None, description="Record name FQDN filter"),
    content: Optional[str] = Query(None, description="Record content filter"),
    page: Optional[int] = Query(None, ge=1),
    per_page: Optional[int] = Query(None, ge=1, le=1000),
    order: Optional[str] = Query(None, description="Sort field"),
    direction: Optional[str] = Query(None, description="asc|desc"),
    match: Optional[str] = Query(None, description="any|all"),
) -> CloudflareEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.list_dns_records(
            zone_id,
            type=type,
            name=name,
            content=content,
            page=page,
            per_page=per_page,
            order=order,
            direction=direction,
            match=match,
        )
    )
    return CloudflareEnvelope(**data)


@router.get(
    "/client/v4/zones/{zone_id}/firewall/rules",
    response_model=CloudflareEnvelope,
)
async def list_firewall_rules(
    zone_id: str = Path(..., min_length=1, max_length=128),
    page: Optional[int] = Query(None, ge=1),
    per_page: Optional[int] = Query(None, ge=1, le=1000),
) -> CloudflareEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.list_firewall_rules(zone_id, page=page, per_page=per_page)
    )
    return CloudflareEnvelope(**data)


@router.get(
    "/client/v4/zones/{zone_id}/waf/packages",
    response_model=CloudflareEnvelope,
)
async def list_waf_packages(
    zone_id: str = Path(..., min_length=1, max_length=128),
) -> CloudflareEnvelope:
    eng = _engine()
    data = _serve(lambda: eng.list_waf_packages(zone_id))
    return CloudflareEnvelope(**data)


@router.get(
    "/client/v4/zones/{zone_id}/security_events",
    response_model=CloudflareEnvelope,
)
async def list_security_events(
    zone_id: str = Path(..., min_length=1, max_length=128),
    since: Optional[str] = Query(None, description="ISO-8601 lower bound"),
    until: Optional[str] = Query(None, description="ISO-8601 upper bound"),
    action: Optional[str] = Query(
        None, description="block|challenge|js_challenge|allow|log|bypass"
    ),
    kind: Optional[str] = Query(
        None, description="firewall|managed_challenge"
    ),
    limit: Optional[int] = Query(None, ge=1, le=10000),
) -> CloudflareEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.list_security_events(
            zone_id,
            since=since,
            until=until,
            action=action,
            kind=kind,
            limit=limit,
        )
    )
    return CloudflareEnvelope(**data)


@router.get(
    "/client/v4/accounts/{account_id}/access/groups",
    response_model=CloudflareEnvelope,
)
async def list_access_groups(
    account_id: str = Path(..., min_length=1, max_length=128),
    name: Optional[str] = Query(None, description="Group name search"),
    page: Optional[int] = Query(None, ge=1),
    per_page: Optional[int] = Query(None, ge=1, le=1000),
) -> CloudflareEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.list_access_groups(
            account_id, name=name, page=page, per_page=per_page
        )
    )
    return CloudflareEnvelope(**data)


__all__ = ["router"]
