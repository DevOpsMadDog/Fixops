"""Zscaler ZIA Router — ALDECI.

Wraps Zscaler Internet Access REST surfaces under prefix ``/api/v1/zscaler-zia``:

  - GET    /                                                    — capability summary
  - POST   /api/v1/authenticatedSession                         — login (cookie session)
  - DELETE /api/v1/authenticatedSession                         — logout
  - GET    /api/v1/sandbox/report/{md5_hash}?details=summary|full
  - GET    /api/v1/urlCategories?customOnly=&includeOnlyUrlKeywordCounts=&includeIcap=
  - GET    /api/v1/firewallFilteringRules
  - GET    /api/v1/users?name=&dept=&group=&page=&pageSize=
  - GET    /api/v1/locations?search=&page=&pageSize=

NO MOCKS rule
-------------
* When any of ZSCALER_ZIA_BASE_URL / ZSCALER_ZIA_USERNAME /
  ZSCALER_ZIA_PASSWORD / ZSCALER_ZIA_API_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/zscaler-zia",
    tags=["Zscaler ZIA"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.zscaler_zia_engine import get_zscaler_zia_engine

    return get_zscaler_zia_engine()


def _serve(callable_):
    """Run a ZIA call, translating engine errors to HTTP responses.

    ZscalerZIAUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError                 -> 422 (input validation)
    """
    from core.zscaler_zia_engine import ZscalerZIAUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ZscalerZIAUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class AuthenticatedSessionRequest(BaseModel):
    """POST /api/v1/authenticatedSession body — entirely optional.

    The router obfuscates the configured ``ZSCALER_ZIA_API_KEY`` against the
    current timestamp internally, so callers don't need to send anything.
    Fields are accepted for documentation parity with the Zscaler ZIA spec
    but are ignored when present (we never trust client-supplied creds).
    """

    apiKey: Optional[str] = Field(default=None, description="Ignored — derived server-side")
    username: Optional[str] = Field(default=None, description="Ignored — read from env")
    password: Optional[str] = Field(default=None, description="Ignored — read from env")
    timestamp: Optional[str] = Field(default=None, description="Ignored — generated server-side")

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Zscaler ZIA capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    base_ok = eng.base_url_present()
    user_ok = eng.username_present()
    pwd_ok = eng.password_present()
    api_ok = eng.api_key_present()
    creds = base_ok and user_ok and pwd_ok and api_ok
    return {
        "service": "Zscaler ZIA",
        "endpoints": [
            "/api/v1/sandbox/report",
            "/api/v1/urlCategories",
            "/api/v1/firewallFilteringRules",
            "/api/v1/users",
            "/api/v1/locations",
            "/api/v1/security/advanced",
        ],
        "zscaler_zia_base_url_present": base_ok,
        "zscaler_zia_username_present": user_ok,
        "zscaler_zia_password_present": pwd_ok,
        "zscaler_zia_api_key_present": api_ok,
        "status": "ok" if creds else "unavailable",
    }


# ---------------------------------------------------------------------------
# Auth — session lifecycle
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/authenticatedSession",
    summary="Open a ZIA cookie-based session (server-derived obfuscated apiKey)",
)
def authenticated_session_login(
    body: AuthenticatedSessionRequest = Body(default_factory=AuthenticatedSessionRequest),
) -> Dict[str, Any]:
    # Body fields are intentionally ignored — we never trust client-supplied
    # creds. The engine derives apiKey + timestamp from env-side config.
    _ = body
    result = _serve(lambda: _engine().login())
    return {
        "authType": result.get("authType") or "ADMIN_LOGIN",
        "obfuscateApiKey": True,
    }


@router.delete(
    "/api/v1/authenticatedSession",
    summary="Close the active ZIA session",
)
def authenticated_session_logout() -> Dict[str, Any]:
    return _serve(lambda: _engine().logout())


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/sandbox/report/{md5_hash}",
    summary="Fetch Zscaler ZIA sandbox detonation report by MD5",
)
def sandbox_report(
    md5_hash: str = Path(
        ...,
        min_length=32,
        max_length=32,
        description="32-character md5 hex digest",
    ),
    details: str = Query(
        default="summary",
        pattern="^(summary|full)$",
        description="Report depth: 'summary' or 'full'",
    ),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().sandbox_report(md5_hash, details))


# ---------------------------------------------------------------------------
# URL Categories
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/urlCategories",
    summary="List ZIA URL categories",
)
def url_categories(
    customOnly: Optional[bool] = Query(default=None),
    includeOnlyUrlKeywordCounts: Optional[bool] = Query(default=None),
    includeIcap: Optional[bool] = Query(default=None),
) -> List[Dict[str, Any]]:
    return _serve(
        lambda: _engine().url_categories(
            custom_only=customOnly,
            include_only_url_keyword_counts=includeOnlyUrlKeywordCounts,
            include_icap=includeIcap,
        )
    )


# ---------------------------------------------------------------------------
# Firewall filtering rules
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/firewallFilteringRules",
    summary="List ZIA firewall filtering rules",
)
def firewall_filtering_rules() -> List[Dict[str, Any]]:
    return _serve(lambda: _engine().firewall_filtering_rules())


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/users",
    summary="List ZIA users",
)
def users(
    name: Optional[str] = Query(default=None),
    dept: Optional[str] = Query(default=None),
    group: Optional[str] = Query(default=None),
    page: Optional[int] = Query(default=None, ge=1),
    pageSize: Optional[int] = Query(default=None, ge=1, le=10000),
) -> List[Dict[str, Any]]:
    return _serve(
        lambda: _engine().users(
            name=name,
            dept=dept,
            group=group,
            page=page,
            page_size=pageSize,
        )
    )


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/locations",
    summary="List ZIA locations",
)
def locations(
    search: Optional[str] = Query(default=None),
    page: Optional[int] = Query(default=None, ge=1),
    pageSize: Optional[int] = Query(default=None, ge=1, le=10000),
) -> List[Dict[str, Any]]:
    return _serve(
        lambda: _engine().locations(
            search=search,
            page=page,
            page_size=pageSize,
        )
    )


__all__ = ["router"]
