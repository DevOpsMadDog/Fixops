"""SecurityTrails Passive DNS Router — ALDECI.

Endpoints for subdomain enumeration, DNS history, and reverse DNS via
the SecurityTrails API (https://api.securitytrails.com/v1/).

Requires SECURITYTRAILS_API_KEY env var (free tier: 50 calls/month).
Without a key, POST /enumerate returns status="needs_credentials".

Prefix: /api/v1/securitytrails
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/securitytrails/enumerate          enumerate_domain_endpoint
  GET  /api/v1/securitytrails/domain/{domain}    get_domain_report_endpoint
  GET  /api/v1/securitytrails/ip/{ip}            get_ip_report_endpoint
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/securitytrails",
    tags=["SecurityTrails"],
)


def _get_importer():
    from feeds.securitytrails.importer import (
        enumerate_domain,
        get_domain_report,
        get_ip_report,
        lookup_ip,
    )
    return enumerate_domain, get_domain_report, get_ip_report, lookup_ip


@router.post("/enumerate", dependencies=[Depends(api_key_auth)])
def enumerate_domain_endpoint(
    domain: str = Body(..., embed=True, description="Apex domain to enumerate (e.g. 'example.com')"),
) -> Dict[str, Any]:
    """Fetch subdomains + passive DNS A-record history for *domain*.

    Results are cached for 7 days. Returns status='needs_credentials' if
    SECURITYTRAILS_API_KEY is not set.
    """
    if not domain or not domain.strip():
        raise HTTPException(status_code=422, detail="domain must be a non-empty string")
    try:
        enumerate_domain_fn, _, _, _ = _get_importer()
        result = enumerate_domain_fn(domain.strip().lower())
        return result
    except Exception as exc:
        logger.exception("SecurityTrails enumerate failed for %s", domain)
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/domain/{domain}", dependencies=[Depends(api_key_auth)])
def get_domain_report_endpoint(
    domain: str = Path(..., description="Apex domain (e.g. 'example.com')"),
) -> Dict[str, Any]:
    """Return the full cached passive DNS report for *domain*.

    Returns 404 if the domain has not been enumerated yet.
    Trigger enumeration first via POST /enumerate.
    """
    try:
        _, get_domain_report_fn, _, _ = _get_importer()
        report = get_domain_report_fn(domain.strip().lower())
        if report is None:
            raise HTTPException(
                status_code=404,
                detail=f"No cached report for domain '{domain}'. "
                       "Call POST /api/v1/securitytrails/enumerate first.",
            )
        return report
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("SecurityTrails domain report failed for %s", domain)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/ip/{ip}", dependencies=[Depends(api_key_auth)])
def get_ip_report_endpoint(
    ip: str = Path(..., description="IPv4 address for reverse DNS lookup"),
) -> Dict[str, Any]:
    """Perform (or return cached) reverse DNS lookup for *ip*.

    Calls SecurityTrails GET /v1/ips/{ip} and caches the result for 7 days.
    Returns status='needs_credentials' if SECURITYTRAILS_API_KEY is not set.
    """
    if not ip or not ip.strip():
        raise HTTPException(status_code=422, detail="ip must be a non-empty string")
    try:
        _, _, get_ip_report_fn, lookup_ip_fn = _get_importer()
        # Try cache first
        cached = get_ip_report_fn(ip.strip())
        if cached is not None:
            return cached
        # Not cached — perform live lookup
        result = lookup_ip_fn(ip.strip())
        return result
    except Exception as exc:
        logger.exception("SecurityTrails reverse DNS failed for %s", ip)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
