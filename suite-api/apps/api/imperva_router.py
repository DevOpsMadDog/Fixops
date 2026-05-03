"""Imperva Cloud WAF Router — ALDECI.

Combines two Imperva surfaces under prefix ``/api/v1/imperva``:

  Legacy v1 (https://my.imperva.com)
    * POST /api/prov/v1/sites/list                     list managed sites
    * POST /api/prov/v1/sites/status                   one site's full status
    * POST /api/prov/v1/sites/configure/security       change a WAF rule action

  Modern v3 (https://api.imperva.com)
    * GET  /api/v3/policies?accountId=...              list policies for account
    * GET  /api/v3/sites/{site_id}                     modern site detail

  Incidents v1 (https://my.imperva.com)
    * GET  /api/incidents/v1/incidents                 customer incidents

NO MOCKS rule
-------------
* When IMPERVA_API_ID / IMPERVA_API_KEY env are unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints → HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Form, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/imperva",
    tags=["Imperva Cloud WAF"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.imperva_waf_engine import get_imperva_waf_engine

    return get_imperva_waf_engine()


def _serve(callable_):
    """Run an Imperva call, translating engine errors to HTTP responses."""
    from core.imperva_waf_engine import ImpervaUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ImpervaUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    imperva_api_id_present: bool
    imperva_api_key_present: bool
    status: str  # ok | empty | unavailable


class SimpleRes(BaseModel):
    res: int
    res_message: str = ""


# Legacy v1 — sites/list response shape
class WafRule(BaseModel):
    action: str = ""
    action_text: str = ""
    id: str = ""
    name: str = ""


class GeneratedCertificate(BaseModel):
    ca: str = ""
    validation_method: str = ""
    validation_data: str = ""
    san: List[Any] = Field(default_factory=list)
    generation_time: str = ""


class SiteSecurity(BaseModel):
    waf: Dict[str, Any] = Field(default_factory=dict)
    owasp_v2: Dict[str, Any] = Field(default_factory=dict)
    hackerProtect: Dict[str, Any] = Field(default_factory=dict)


class SiteSslShape(BaseModel):
    custom_certificate: Dict[str, Any] = Field(default_factory=dict)
    generated_certificate: Dict[str, Any] = Field(default_factory=dict)


class SealLocation(BaseModel):
    id: str = ""
    name: str = ""


class LoginProtect(BaseModel):
    enabled: bool = False
    specific_users_list: List[Any] = Field(default_factory=list)
    send_lp_notifications: bool = False
    allow_all_users: bool = False
    sms_enabled: bool = False
    allowed_users: List[Any] = Field(default_factory=list)


class SiteEntry(BaseModel):
    site_id: str = ""
    status: str = ""
    domain: str = ""
    account_id: Any = ""
    acceleration_level: str = ""
    site_creation_date: Any = ""
    ips: List[str] = Field(default_factory=list)
    dns: List[Any] = Field(default_factory=list)
    ssl: Dict[str, Any] = Field(default_factory=dict)
    original_dns_records: List[Any] = Field(default_factory=list)
    warnings: List[Any] = Field(default_factory=list)
    log_level: str = ""
    security: Dict[str, Any] = Field(default_factory=dict)
    sealLocation: Dict[str, Any] = Field(default_factory=dict)
    ssl_safe_browsing_id: str = ""
    login_protect: Dict[str, Any] = Field(default_factory=dict)
    performance_configuration: Dict[str, Any] = Field(default_factory=dict)
    extended_ddos: Dict[str, Any] = Field(default_factory=dict)


class SitesListResponse(BaseModel):
    res: int
    res_message: str = ""
    sites: List[SiteEntry] = Field(default_factory=list)
    total_count: int = 0
    total_pages: int = 0


class SiteStatusResponse(SiteEntry):
    res: int = 0
    res_message: str = ""


# Modern v3 — policies
class PolicySetting(BaseModel):
    settingsAction: str = ""
    policySettingType: str = ""
    data: List[Any] = Field(default_factory=list)


class PolicyEntry(BaseModel):
    id: str = ""
    type: str = ""
    name: str = ""
    description: str = ""
    enabled: bool = False
    default: bool = False
    source: str = ""
    accountId: Any = ""
    lastModified: Any = ""
    lastModifiedBy: str = ""
    ratePolicyDefinition: Dict[str, Any] = Field(default_factory=dict)
    aclPolicyDefinition: Dict[str, Any] = Field(default_factory=dict)
    exceptions: List[Any] = Field(default_factory=list)
    policySettings: List[PolicySetting] = Field(default_factory=list)


class PoliciesResponse(BaseModel):
    data: List[PolicyEntry] = Field(default_factory=list)


# Modern v3 — site detail
class AccountInheritance(BaseModel):
    accountInheritedFromTier1: bool = False
    accountInheritedFromTier2: bool = False
    accountInheritedFromTier3: bool = False


class SiteV3(BaseModel):
    id: str = ""
    name: str = ""
    type: str = ""
    accountId: Any = ""
    refId: str = ""
    accountInheritance: AccountInheritance = Field(default_factory=AccountInheritance)


class SiteV3Response(BaseModel):
    data: SiteV3


# Incidents
class IncidentSiteRef(BaseModel):
    siteId: str = ""
    siteName: str = ""


class IncidentEntry(BaseModel):
    id: str = ""
    accountId: Any = ""
    accountName: str = ""
    severity: str = ""
    status: str = ""
    type: str = ""
    openedAt: Any = ""
    closedAt: Any = ""
    lastUpdatedAt: Any = ""
    sites: List[IncidentSiteRef] = Field(default_factory=list)
    assetId: str = ""
    ddosVolume: Any = 0
    ddosTotalRequests: Any = 0
    mitigationActions: List[Any] = Field(default_factory=list)
    description: str = ""
    recommendation: str = ""
    attackVector: str = ""


class IncidentsResponse(BaseModel):
    incidents: List[IncidentEntry] = Field(default_factory=list)
    totalIncidents: int = 0


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse, summary="Imperva capability summary")
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without credentials."""
    eng = _engine()
    api_id_present = eng.api_id_present()
    api_key_present = eng.api_key_present()
    if not (api_id_present and api_key_present):
        status = "unavailable"
    else:
        status = "ok"
    return CapabilityResponse(
        service="Imperva Cloud WAF",
        endpoints=[
            "/api/prov/v1/sites/list",
            "/api/prov/v1/sites/status",
            "/api/incidents/v1/incidents",
        ],
        imperva_api_id_present=api_id_present,
        imperva_api_key_present=api_key_present,
        status=status,
    )


# ---------------------------------------------------------------------------
# Legacy v1 — provisioning (form-encoded)
# ---------------------------------------------------------------------------


@router.post("/api/prov/v1/sites/list", response_model=SitesListResponse)
async def sites_list_endpoint(
    api_id: str = Form(..., description="Imperva API ID"),
    api_key: str = Form(..., description="Imperva API Key"),
    account_id: Optional[str] = Form(default=None),
    page_size: Optional[int] = Form(default=None, ge=1, le=500),
    page_num: Optional[int] = Form(default=None, ge=0),
) -> SitesListResponse:
    """List managed sites (Imperva v1 prov)."""
    eng = _engine()
    data = _serve(
        lambda: eng.sites_list(
            api_id=api_id,
            api_key=api_key,
            account_id=account_id,
            page_size=page_size,
            page_num=page_num,
        )
    )
    return SitesListResponse(**data)


@router.post("/api/prov/v1/sites/status", response_model=SiteStatusResponse)
async def sites_status_endpoint(
    api_id: str = Form(...),
    api_key: str = Form(...),
    site_id: str = Form(...),
    tests: Optional[str] = Form(
        default=None,
        description="Comma-separated tests list (optional)",
    ),
) -> SiteStatusResponse:
    """Fetch one site's full status (Imperva v1 prov)."""
    eng = _engine()
    tests_list = (
        [t.strip() for t in tests.split(",") if t.strip()] if tests else None
    )
    data = _serve(
        lambda: eng.sites_status(
            site_id=site_id,
            api_id=api_id,
            api_key=api_key,
            tests=tests_list,
        )
    )
    return SiteStatusResponse(**data)


@router.post("/api/prov/v1/sites/configure/security", response_model=SimpleRes)
async def sites_configure_security_endpoint(
    api_id: str = Form(...),
    api_key: str = Form(...),
    site_id: str = Form(...),
    rule_id: str = Form(...),
    security_rule_action: str = Form(...),
) -> SimpleRes:
    """Set a WAF rule's action for a site (Imperva v1 prov)."""
    eng = _engine()
    data = _serve(
        lambda: eng.sites_configure_security(
            site_id=site_id,
            rule_id=rule_id,
            security_rule_action=security_rule_action,
            api_id=api_id,
            api_key=api_key,
        )
    )
    return SimpleRes(**data)


# ---------------------------------------------------------------------------
# Modern v3 (header auth)
# ---------------------------------------------------------------------------


@router.get("/api/v3/policies", response_model=PoliciesResponse)
async def list_policies_endpoint(
    accountId: str = Query(..., description="Imperva account ID"),
) -> PoliciesResponse:
    """List policies for an Imperva account (modern v3)."""
    eng = _engine()
    data = _serve(lambda: eng.list_policies(accountId))
    return PoliciesResponse(**data)


@router.get("/api/v3/sites/{site_id}", response_model=SiteV3Response)
async def get_site_v3_endpoint(
    site_id: str = Path(..., description="Modern site identifier"),
) -> SiteV3Response:
    """Fetch modern site detail (Imperva v3)."""
    eng = _engine()
    data = _serve(lambda: eng.get_site(site_id))
    return SiteV3Response(**data)


# ---------------------------------------------------------------------------
# Incidents v1
# ---------------------------------------------------------------------------


@router.get("/api/incidents/v1/incidents", response_model=IncidentsResponse)
async def list_incidents_endpoint(
    from_time: Optional[str] = Query(
        default=None,
        description="ISO-8601 lower bound — only incidents after this time",
    ),
    to_time: Optional[str] = Query(
        default=None,
        description="ISO-8601 upper bound — only incidents before this time",
    ),
    accountId: Optional[str] = Query(
        default=None,
        description="Restrict to one Imperva account",
    ),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    offset: Optional[int] = Query(default=None, ge=0),
) -> IncidentsResponse:
    """List Imperva customer incidents (DDoS, MitigationFailure, etc.)."""
    eng = _engine()
    data = _serve(
        lambda: eng.list_incidents(
            from_time=from_time,
            to_time=to_time,
            account_id=accountId,
            page_size=pageSize,
            offset=offset,
        )
    )
    return IncidentsResponse(**data)


__all__ = ["router"]
