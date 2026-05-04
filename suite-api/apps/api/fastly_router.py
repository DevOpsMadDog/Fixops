"""Fastly Edge Router — ALDECI.

Surface under prefix ``/api/v1/fastly`` wrapping ``core.fastly_edge_engine``.

NO MOCKS rule
-------------
* When FASTLY_API_TOKEN is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/fastly",
    tags=["Fastly"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.fastly_edge_engine import get_fastly_edge_engine

    return get_fastly_edge_engine()


def _serve(callable_):
    """Run a Fastly call, translating engine errors to HTTP responses."""
    from core.fastly_edge_engine import FastlyUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FastlyUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    fastly_api_token_present: bool
    status: str  # ok | empty | unavailable


class FastlyVersion(BaseModel):
    number: int
    active: bool = False
    locked: bool = False
    staging: bool = False
    deployed: bool = False
    comment: str = ""
    deployed_at: str = ""
    created_at: str = ""
    updated_at: str = ""


class FastlyService(BaseModel):
    id: str
    name: str = ""
    comment: str = ""
    customer_id: str = ""
    type: str = "vcl"
    deleted_at: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    versions: List[FastlyVersion] = Field(default_factory=list)
    publish_key: str = ""


class FastlyServiceDetails(FastlyService):
    active_version: Optional[FastlyVersion] = None
    environments: Optional[List[Dict[str, Any]]] = None


class FastlyDictionary(BaseModel):
    id: str
    service_id: str
    version: int
    name: str
    write_only: bool = False
    created_at: str = ""
    updated_at: str = ""


class FastlyDictionaryItem(BaseModel):
    dictionary_id: str
    item_key: str
    item_value: str = ""
    created_at: str = ""
    updated_at: str = ""


class FastlyACL(BaseModel):
    id: str
    service_id: str
    version: int
    name: str
    created_at: str = ""
    updated_at: str = ""


class FastlyACLEntry(BaseModel):
    id: str
    acl_id: str
    ip: str
    subnet: Optional[int] = None
    negated: bool = False
    comment: str = ""
    created_at: str = ""
    updated_at: str = ""


class PurgeBody(BaseModel):
    surrogate_key: Optional[str] = Field(
        default=None,
        description="Comma-separated surrogate-key list (overrides header)",
    )


class PurgeResponse(BaseModel):
    status: str = "ok"
    id: str = ""


class PurgeAllResponse(BaseModel):
    status: str = "ok"


class StatsRow(BaseModel):
    service_id: str
    hits: int = 0
    miss: int = 0
    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0
    bandwidth: int = 0
    requests: int = 0
    status_200: int = 0
    status_204: int = 0
    status_206: int = 0
    status_301: int = 0
    status_302: int = 0
    status_304: int = 0
    status_400: int = 0
    status_401: int = 0
    status_403: int = 0
    status_404: int = 0
    status_416: int = 0
    status_500: int = 0
    status_501: int = 0
    status_502: int = 0
    status_503: int = 0
    status_504: int = 0
    status_505: int = 0
    ipv6_bandwidth: int = 0


class StatsMeta(BaseModel):
    from_: str = Field(default="", alias="from")
    to: str = ""
    by: str = "hour"
    region: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class StatsResponse(BaseModel):
    data: List[StatsRow]
    meta: StatsMeta


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


_CAPABILITY_ENDPOINTS = [
    "/service",
    "/service/{id}",
    "/service/{id}/version",
    "/purge",
    "/service/{id}/details",
]


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Fastly capability summary",
)
async def capability_summary() -> CapabilityResponse:
    eng = _engine()
    token_present = eng.api_token_present()
    if not token_present:
        status = "unavailable"
    else:
        # Without a cache there's no notion of "empty" — once the token is
        # present we report status="ok"; the upstream may still be empty
        # for this customer, surfaced via individual list endpoints.
        status = "ok"
    return CapabilityResponse(
        service="Fastly",
        endpoints=list(_CAPABILITY_ENDPOINTS),
        fastly_api_token_present=token_present,
        status=status,
    )


# ---------------------------------------------------------------------------
# Service inventory
# ---------------------------------------------------------------------------


@router.get("/service", response_model=List[FastlyService])
async def list_services_endpoint(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    per_page: int = Query(
        20, ge=1, le=100, description="Items per page (1-100)"
    ),
    direction: str = Query(
        "ascend",
        pattern="^(ascend|descend)$",
        description="Sort direction",
    ),
    sort: str = Query("created", description="Sort field"),
) -> List[FastlyService]:
    eng = _engine()
    rows = _serve(
        lambda: eng.list_services(
            page=page, per_page=per_page, direction=direction, sort=sort
        )
    )
    return [FastlyService(**row) for row in rows]


@router.get("/service/{service_id}", response_model=FastlyService)
async def get_service_endpoint(
    service_id: str = Path(..., description="Fastly service ID"),
) -> FastlyService:
    eng = _engine()
    data = _serve(lambda: eng.get_service(service_id))
    return FastlyService(**data)


@router.get(
    "/service/{service_id}/details", response_model=FastlyServiceDetails
)
async def get_service_details_endpoint(
    service_id: str = Path(..., description="Fastly service ID"),
) -> FastlyServiceDetails:
    eng = _engine()
    data = _serve(lambda: eng.get_service_details(service_id))
    return FastlyServiceDetails(**data)


@router.get(
    "/service/{service_id}/version", response_model=List[FastlyVersion]
)
async def list_versions_endpoint(
    service_id: str = Path(..., description="Fastly service ID"),
) -> List[FastlyVersion]:
    eng = _engine()
    rows = _serve(lambda: eng.list_versions(service_id))
    return [FastlyVersion(**row) for row in rows]


# ---------------------------------------------------------------------------
# Dictionaries
# ---------------------------------------------------------------------------


@router.get(
    "/service/{service_id}/version/{version}/dictionary",
    response_model=List[FastlyDictionary],
)
async def list_dictionaries_endpoint(
    service_id: str = Path(...),
    version: int = Path(..., ge=1),
) -> List[FastlyDictionary]:
    eng = _engine()
    rows = _serve(lambda: eng.list_dictionaries(service_id, version))
    return [FastlyDictionary(**row) for row in rows]


@router.get(
    "/service/{service_id}/version/{version}/dictionary/{name}/items",
    response_model=List[FastlyDictionaryItem],
)
async def list_dictionary_items_endpoint(
    service_id: str = Path(...),
    version: int = Path(..., ge=1),
    name: str = Path(...),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=1000),
) -> List[FastlyDictionaryItem]:
    eng = _engine()
    rows = _serve(
        lambda: eng.list_dictionary_items(
            service_id, version, name, page=page, per_page=per_page
        )
    )
    return [FastlyDictionaryItem(**row) for row in rows]


# ---------------------------------------------------------------------------
# ACLs
# ---------------------------------------------------------------------------


@router.get(
    "/service/{service_id}/version/{version}/acl",
    response_model=List[FastlyACL],
)
async def list_acls_endpoint(
    service_id: str = Path(...),
    version: int = Path(..., ge=1),
) -> List[FastlyACL]:
    eng = _engine()
    rows = _serve(lambda: eng.list_acls(service_id, version))
    return [FastlyACL(**row) for row in rows]


@router.get(
    "/service/{service_id}/version/{version}/acl/{name}/entries",
    response_model=List[FastlyACLEntry],
)
async def list_acl_entries_endpoint(
    service_id: str = Path(...),
    version: int = Path(..., ge=1),
    name: str = Path(...),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=1000),
) -> List[FastlyACLEntry]:
    eng = _engine()
    rows = _serve(
        lambda: eng.list_acl_entries(
            service_id, version, name, page=page, per_page=per_page
        )
    )
    return [FastlyACLEntry(**row) for row in rows]


# ---------------------------------------------------------------------------
# Backends + Snippets (passthrough lists)
# ---------------------------------------------------------------------------


@router.get(
    "/service/{service_id}/version/{version}/backend",
    response_model=List[Dict[str, Any]],
)
async def list_backends_endpoint(
    service_id: str = Path(...),
    version: int = Path(..., ge=1),
) -> List[Dict[str, Any]]:
    eng = _engine()
    return _serve(lambda: eng.list_backends(service_id, version))


@router.get(
    "/service/{service_id}/version/{version}/snippet",
    response_model=List[Dict[str, Any]],
)
async def list_snippets_endpoint(
    service_id: str = Path(...),
    version: int = Path(..., ge=1),
) -> List[Dict[str, Any]]:
    eng = _engine()
    return _serve(lambda: eng.list_snippets(service_id, version))


# ---------------------------------------------------------------------------
# Purge
# ---------------------------------------------------------------------------


@router.post(
    "/purge/{key_or_url:path}",
    response_model=PurgeResponse,
)
async def purge_key_or_url_endpoint(
    key_or_url: str = Path(
        ..., description="Surrogate key or URL to purge (path-encoded)"
    ),
    body: Optional[PurgeBody] = Body(default=None),
    fastly_soft_purge: Optional[str] = Header(
        default=None, alias="fastly-soft-purge"
    ),
    surrogate_key_hdr: Optional[str] = Header(
        default=None, alias="surrogate-key"
    ),
) -> PurgeResponse:
    eng = _engine()
    soft = bool(fastly_soft_purge and fastly_soft_purge.strip() == "1")
    surrogate_keys = (body.surrogate_key if body else None) or surrogate_key_hdr
    data = _serve(
        lambda: eng.purge_key_or_url(
            key_or_url, soft=soft, surrogate_keys=surrogate_keys
        )
    )
    return PurgeResponse(**data)


@router.post(
    "/service/{service_id}/purge_all", response_model=PurgeAllResponse
)
async def purge_all_endpoint(
    service_id: str = Path(..., description="Fastly service ID"),
) -> PurgeAllResponse:
    eng = _engine()
    data = _serve(lambda: eng.purge_all(service_id))
    return PurgeAllResponse(**data)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=StatsResponse)
async def stats_endpoint(
    from_: str = Query(..., alias="from", description="ISO start timestamp"),
    to: str = Query(..., description="ISO end timestamp"),
    by: str = Query(
        "hour",
        pattern="^(hour|minute|day)$",
        description="Aggregation granularity",
    ),
    region: Optional[str] = Query(
        default=None,
        pattern="^(usa|europe|asia|africa|sa|au)$",
        description="Optional region filter",
    ),
) -> StatsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.stats(from_ts=from_, to_ts=to, by=by, region=region)
    )
    rows = [StatsRow(**r) for r in data.get("data", [])]
    meta = data.get("meta", {})
    meta_payload: Dict[str, Any] = {
        "from": meta.get("from", from_),
        "to": meta.get("to", to),
        "by": meta.get("by", by),
    }
    if meta.get("region") is not None:
        meta_payload["region"] = meta.get("region")
    elif region is not None:
        meta_payload["region"] = region
    return StatsResponse(data=rows, meta=StatsMeta(**meta_payload))




__all__ = ["router"]
