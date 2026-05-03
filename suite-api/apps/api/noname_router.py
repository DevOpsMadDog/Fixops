"""Noname Security API Router — ALDECI.

Prefix: /api/v1/noname
Scope:  read:scans (mounted via platform_app)

Routes:
  GET   /                                       capability summary
  GET   /api/v3/apis                            list APIs (filter, paginate)
  GET   /api/v3/apis/{api_id}                   single API + classifications
  GET   /api/v3/apis/{api_id}/endpoints         list endpoints for an API
  GET   /api/v3/issues                          list issues (severity/status/type/apiId)
  GET   /api/v3/inventory/endpoints             list endpoint inventory
  GET   /api/v3/sources                         list traffic sources (gateway/firewall/...)
  GET   /api/v3/posture-policies                list posture-management policies

Returns 503 on lookup endpoints when NONAME_BASE_URL/NONAME_CLIENT_ID/
NONAME_CLIENT_SECRET unset. NO MOCKS — engine raises RuntimeError → 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/noname", tags=["Noname Security"])


def _engine():
    from core.noname_engine import get_noname_engine
    return get_noname_engine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke an engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — when env not set
        raise HTTPException(status_code=503, detail=f"noname unavailable: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(status_code=status, detail=f"noname error: {exc}") from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"noname transport error: {exc}") from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Noname Security integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# APIs
# ---------------------------------------------------------------------------


@router.get("/api/v3/apis")
def list_apis(
    limit: int = Query(default=50, ge=1, le=500),
    page: int = Query(default=1, ge=1, le=10000),
    filter: Optional[str] = Query(  # noqa: A002
        default=None,
        max_length=4096,
        description="CEL filter expression (Noname filter DSL)",
    ),
) -> Dict[str, Any]:
    """List APIs discovered by Noname (paginated, filterable)."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_apis(limit=limit, page=page, filter_=filter)
    )


@router.get("/api/v3/apis/{api_id}")
def get_api(api_id: str) -> Dict[str, Any]:
    """Return a single API + endpoints + classifications."""
    if not api_id or len(api_id) > 256:
        raise HTTPException(status_code=400, detail="invalid api_id")
    eng = _engine()
    return _handle_engine_call(lambda: eng.get_api(api_id))


@router.get("/api/v3/apis/{api_id}/endpoints")
def list_api_endpoints(
    api_id: str,
    limit: int = Query(default=50, ge=1, le=500),
    page: int = Query(default=1, ge=1, le=10000),
) -> Dict[str, Any]:
    """List endpoints belonging to a specific API."""
    if not api_id or len(api_id) > 256:
        raise HTTPException(status_code=400, detail="invalid api_id")
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_api_endpoints(api_id, limit=limit, page=page)
    )


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------


@router.get("/api/v3/issues")
def list_issues(
    severity: Optional[str] = Query(
        default=None,
        description="critical|high|medium|low",
        max_length=32,
    ),
    status: Optional[str] = Query(
        default=None,
        description="open|in_progress|resolved|wontfix",
        max_length=32,
    ),
    type: Optional[str] = Query(  # noqa: A002
        default=None,
        max_length=64,
        description="authentication|authorization|input-validation|sensitive-data|misconfiguration|business-logic|owasp-top-10",
    ),
    apiId: Optional[str] = Query(default=None, max_length=256),  # noqa: N803
    limit: int = Query(default=50, ge=1, le=500),
    page: int = Query(default=1, ge=1, le=10000),
) -> Dict[str, Any]:
    """List Noname posture/security issues, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_issues(
            severity=severity,
            status=status,
            type_=type,
            api_id=apiId,
            limit=limit,
            page=page,
        )
    )


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


@router.get("/api/v3/inventory/endpoints")
def list_inventory_endpoints(
    limit: int = Query(default=50, ge=1, le=500),
    page: int = Query(default=1, ge=1, le=10000),
    filter: Optional[str] = Query(  # noqa: A002
        default=None, max_length=4096, description="CEL filter expression"
    ),
) -> Dict[str, Any]:
    """List endpoint-level inventory across all observed APIs."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_inventory_endpoints(limit=limit, page=page, filter_=filter)
    )


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


@router.get("/api/v3/sources")
def list_sources(
    type: Optional[str] = Query(  # noqa: A002
        default=None,
        description="GATEWAY|FIREWALL|SIDECAR|SCANNER|TAP|MIRROR",
        max_length=32,
    ),
) -> Dict[str, Any]:
    """List configured traffic sources (gateways, firewalls, sidecars, ...)."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.list_sources(type_=type))


# ---------------------------------------------------------------------------
# Posture policies
# ---------------------------------------------------------------------------


@router.get("/api/v3/posture-policies")
def list_posture_policies() -> Dict[str, Any]:
    """List posture-management policies (rules, scopes, conditions)."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.list_posture_policies())
