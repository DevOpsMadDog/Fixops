"""Salt Security Router — ALDECI.

Wraps Salt Security's API protection telemetry under prefix
``/api/v1/salt-security``:

  - GET  /                                                 — capability summary
  - POST /api/oauth/token                                  — OAuth2 client_credentials
  - GET  /api/v1/incidents                                 — incidents (paged, filterable)
  - GET  /api/v1/api-catalog                               — API catalog (paged, filterable)
  - GET  /api/v1/api-catalog/{api_id}                      — single API entry
  - GET  /api/v1/api-catalog/{api_id}/endpoints            — endpoints w/ sensitive-data overlay
  - GET  /api/v1/attackers                                 — attacker IPs (page-token paged)
  - GET  /api/v1/policies                                  — detection/protection/notification policies

NO MOCKS rule
-------------
* When any of SALT_API_BASE / SALT_CLIENT_ID / SALT_CLIENT_SECRET is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/salt-security",
    tags=["Salt Security"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.salt_security_engine import get_salt_security_engine

    return get_salt_security_engine()


def _serve(callable_):
    """Run a Salt call, translating engine errors to HTTP responses.

    SaltUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError           -> 422 (input validation)
    """
    from core.salt_security_engine import SaltUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SaltUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class TokenRequest(BaseModel):
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    grant_type: str = Field(default="client_credentials")


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Salt Security capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    base_ok = eng.api_base_present()
    cid_ok = eng.client_id_present()
    cs_ok = eng.client_secret_present()
    creds = base_ok and cid_ok and cs_ok
    return {
        "service": "Salt Security",
        "endpoints": [
            "/api/v1/incidents",
            "/api/v1/api-catalog",
            "/api/v1/attackers",
            "/api/v1/policies",
            "/api/v1/sources",
        ],
        "salt_api_base_present": base_ok,
        "salt_client_id_present": cid_ok,
        "salt_client_secret_present": cs_ok,
        "status": "ok" if creds else "unavailable",
    }


# ---------------------------------------------------------------------------
# OAuth2 token
# ---------------------------------------------------------------------------


@router.post("/api/oauth/token", summary="Salt OAuth2 client_credentials token")
def oauth_token(body: TokenRequest = Body(...)) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().fetch_token(
            client_id=body.client_id,
            client_secret=body.client_secret,
            grant_type=body.grant_type,
        )
    )


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@router.get("/api/v1/incidents", summary="List Salt-detected API incidents")
def incidents(
    severity: Optional[str] = Query(default=None, description="high|medium|low"),
    status: Optional[str] = Query(
        default=None, description="open|closed|investigating|mitigated|false_positive"
    ),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    fromDate: Optional[str] = Query(default=None),
    toDate: Optional[str] = Query(default=None),
    apiId: Optional[str] = Query(default=None),
    attackerId: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_incidents(
            severity=severity,
            status=status,
            limit=limit,
            offset=offset,
            from_date=fromDate,
            to_date=toDate,
            api_id=apiId,
            attacker_id=attackerId,
        )
    )


# ---------------------------------------------------------------------------
# API catalog
# ---------------------------------------------------------------------------


@router.get("/api/v1/api-catalog", summary="List discovered APIs")
def api_catalog(
    limit: int = Query(default=50, ge=1, le=1000),
    page: int = Query(default=1, ge=1),
    search: Optional[str] = Query(default=None),
    riskScoreGte: Optional[int] = Query(default=None, ge=0, le=100),
    hasSensitiveData: Optional[bool] = Query(default=None),
    environment: Optional[str] = Query(
        default=None, description="production|staging|development"
    ),
    classification: Optional[str] = Query(
        default=None, description="internal|external|partner"
    ),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_api_catalog(
            limit=limit,
            page=page,
            search=search,
            risk_score_gte=riskScoreGte,
            has_sensitive_data=hasSensitiveData,
            environment=environment,
            classification=classification,
        )
    )


@router.get("/api/v1/api-catalog/{api_id}", summary="Get single API entry")
def api_catalog_entry(
    api_id: str = Path(..., min_length=1),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().get_api(api_id))


@router.get(
    "/api/v1/api-catalog/{api_id}/endpoints",
    summary="List endpoints for an API w/ sensitive-data overlay",
)
def api_catalog_endpoints(
    api_id: str = Path(..., min_length=1),
    limit: int = Query(default=50, ge=1, le=1000),
    page: int = Query(default=1, ge=1),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_api_endpoints(api_id, limit=limit, page=page)
    )


# ---------------------------------------------------------------------------
# Attackers
# ---------------------------------------------------------------------------


@router.get("/api/v1/attackers", summary="List attacker IPs")
def attackers(
    status: Optional[str] = Query(
        default=None, description="active|blocked|cleared"
    ),
    riskScoreGte: Optional[int] = Query(default=None, ge=0, le=100),
    firstSeenGte: Optional[str] = Query(default=None),
    pageSize: int = Query(default=50, ge=1, le=1000),
    pageToken: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_attackers(
            status=status,
            risk_score_gte=riskScoreGte,
            first_seen_gte=firstSeenGte,
            page_size=pageSize,
            page_token=pageToken,
        )
    )


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/policies", summary="List detection/protection/notification policies"
)
def policies(
    type: Optional[str] = Query(
        default=None, description="detection|protection|notification"
    ),
    enabled: Optional[bool] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_policies(type_=type, enabled=enabled)
    )


__all__ = ["router"]
