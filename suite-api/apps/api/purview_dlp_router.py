"""Microsoft Purview DLP Router — ALDECI.

Prefix: /api/v1/microsoft-purview
Scope:  read:scans (mounted via platform_app)

Routes:
  GET  /                                          capability summary
  GET  /v1.0/security/dataLossPreventionPolicies  list DLP policies
  GET  /v1.0/security/labels/sensitivityLabels    list sensitivity labels
  GET  /v1.0/security/incidents                   list Defender XDR incidents (DLP-flagged)
  GET  /v1.0/security/cases/ediscoveryCases       list eDiscovery cases
  GET  /v1.0/dataClassification/sensitiveTypes    list sensitive info types

NO MOCKS — engine raises RuntimeError when env unset → mapped to HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/microsoft-purview", tags=["Microsoft Purview DLP"])


def _engine():
    from core.purview_dlp_engine import get_purview_dlp_engine
    return get_purview_dlp_engine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    try:
        return callable_()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503, detail=f"microsoft purview unavailable: {exc}"
        ) from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(
            status_code=status, detail=f"microsoft purview error: {exc}"
        ) from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(
            status_code=502, detail=f"microsoft purview transport error: {exc}"
        ) from exc


def _require_configured(eng) -> None:
    if not eng.configured:
        raise HTTPException(
            status_code=503,
            detail="microsoft purview unavailable: AZURE_TENANT_ID, AZURE_CLIENT_ID, "
            "AZURE_CLIENT_SECRET must be set",
        )


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Microsoft Purview DLP integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# DLP Policies
# ---------------------------------------------------------------------------


@router.get("/v1.0/security/dataLossPreventionPolicies")
def list_dlp_policies(
    top: Optional[int] = Query(default=None, alias="$top", ge=1, le=999),
    skip: Optional[int] = Query(default=None, alias="$skip", ge=0, le=100000),
    filter_: Optional[str] = Query(default=None, alias="$filter", max_length=2048),
) -> Dict[str, Any]:
    """List Microsoft Purview Data Loss Prevention policies."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_dlp_policies(top=top, skip=skip, odata_filter=filter_)
    )


# ---------------------------------------------------------------------------
# Sensitivity Labels
# ---------------------------------------------------------------------------


@router.get("/v1.0/security/labels/sensitivityLabels")
def list_sensitivity_labels(
    top: Optional[int] = Query(default=None, alias="$top", ge=1, le=999),
    filter_: Optional[str] = Query(default=None, alias="$filter", max_length=2048),
) -> Dict[str, Any]:
    """List Microsoft Information Protection sensitivity labels."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_sensitivity_labels(top=top, odata_filter=filter_)
    )


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@router.get("/v1.0/security/incidents")
def list_incidents(
    top: Optional[int] = Query(default=None, alias="$top", ge=1, le=999),
    filter_: Optional[str] = Query(default=None, alias="$filter", max_length=2048),
    orderby: Optional[str] = Query(default=None, alias="$orderby", max_length=512),
) -> Dict[str, Any]:
    """List Defender XDR incidents (DLP-flagged via $filter)."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_incidents(top=top, odata_filter=filter_, orderby=orderby)
    )


# ---------------------------------------------------------------------------
# eDiscovery cases
# ---------------------------------------------------------------------------


@router.get("/v1.0/security/cases/ediscoveryCases")
def list_ediscovery_cases(
    top: Optional[int] = Query(default=None, alias="$top", ge=1, le=999),
    filter_: Optional[str] = Query(default=None, alias="$filter", max_length=2048),
    orderby: Optional[str] = Query(default=None, alias="$orderby", max_length=512),
    expand: Optional[str] = Query(default=None, alias="$expand", max_length=512),
) -> Dict[str, Any]:
    """List Microsoft Purview eDiscovery (Premium) cases."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_ediscovery_cases(
            top=top,
            odata_filter=filter_,
            orderby=orderby,
            expand=expand,
        )
    )


# ---------------------------------------------------------------------------
# Sensitive types
# ---------------------------------------------------------------------------


@router.get("/v1.0/dataClassification/sensitiveTypes")
def list_sensitive_types(
    top: Optional[int] = Query(default=None, alias="$top", ge=1, le=999),
    filter_: Optional[str] = Query(default=None, alias="$filter", max_length=2048),
) -> Dict[str, Any]:
    """List Microsoft Purview sensitive information types (built-in + custom)."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_sensitive_types(top=top, odata_filter=filter_)
    )


__all__ = ["router"]
