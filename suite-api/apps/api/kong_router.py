"""ALDECI Kong Admin API Router.

Direct pass-through to the **Kong Admin API** — services, routes, plugins,
consumers, key-auth credentials, upstreams, targets, certificates, SNIs,
and node status.

Endpoints (mounted at ``/api/v1/kong``)
---------------------------------------
GET    /                                                   capability summary
GET    /services                                           list services
GET    /services/{service_id_or_name}                      single service
GET    /routes                                             list routes (filter: service.id)
GET    /plugins                                            list plugins (filter: service.id, route.id, consumer.id)
GET    /consumers                                          list consumers
GET    /consumers/{consumer_id_or_username}/key-auth       list a consumer's key-auth credentials
GET    /upstreams                                          list upstreams
GET    /upstreams/{upstream_id_or_name}/targets            list upstream targets
GET    /certificates                                       list TLS certificates
GET    /snis                                               list SNIs
GET    /status                                             Kong node status (db, server, memory)

When ``KONG_ADMIN_URL`` is unset the capability summary reports
``status="unavailable"`` and lookup endpoints respond with HTTP 503.
``KONG_ADMIN_TOKEN`` is **optional** — Kong Admin API on private networks
typically runs unauthenticated.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Path, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/kong",
    tags=["kong"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.kong_admin_engine import get_kong_admin_engine

    return get_kong_admin_engine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "kong_admin_unavailable",
            "message": "KONG_ADMIN_URL environment variable is not configured",
        },
    )


def _map_kong_error(exc: Exception) -> HTTPException:
    from core.kong_admin_engine import (
        KongAdminHTTPError,
        KongAdminUnavailable,
    )

    if isinstance(exc, KongAdminUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "kong_admin_unavailable", "message": str(exc)},
        )
    if isinstance(exc, KongAdminHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        st = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=st,
            detail={
                "error": "kong_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", summary="Kong Admin capability summary")
def capability_summary() -> dict:
    engine = _get_engine()
    return engine.capability_summary()


@router.get("/services", summary="List Kong services")
def list_services(
    size: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[str] = Query(None, description="Opaque next-page cursor"),
    tags: Optional[str] = Query(None, description="Comma-separated tag filter"),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_services(size=size, offset=offset, tags=tags)
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get(
    "/services/{service_id_or_name}",
    summary="Get a single Kong service",
)
def get_service(
    service_id_or_name: str = Path(..., description="Service UUID or name"),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_service(service_id_or_name)
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get("/routes", summary="List Kong routes")
def list_routes(
    size: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    service_id: Optional[str] = Query(
        None,
        alias="service.id",
        description="Filter routes by parent service UUID",
    ),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_routes(
            size=size,
            offset=offset,
            tags=tags,
            service_id=service_id,
        )
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get("/plugins", summary="List Kong plugins")
def list_plugins(
    size: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    service_id: Optional[str] = Query(None, alias="service.id"),
    route_id: Optional[str] = Query(None, alias="route.id"),
    consumer_id: Optional[str] = Query(None, alias="consumer.id"),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_plugins(
            size=size,
            offset=offset,
            tags=tags,
            service_id=service_id,
            route_id=route_id,
            consumer_id=consumer_id,
        )
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get("/consumers", summary="List Kong consumers")
def list_consumers(
    size: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    custom_id: Optional[str] = Query(None),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_consumers(
            size=size, offset=offset, tags=tags, custom_id=custom_id
        )
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get(
    "/consumers/{consumer_id_or_username}/key-auth",
    summary="List a consumer's key-auth credentials",
)
def consumer_key_auth(
    consumer_id_or_username: str = Path(...),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.consumer_key_auth(consumer_id_or_username)
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get("/upstreams", summary="List Kong upstreams")
def list_upstreams(
    size: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_upstreams(size=size, offset=offset, tags=tags)
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get(
    "/upstreams/{upstream_id_or_name}/targets",
    summary="List targets of an upstream",
)
def upstream_targets(
    upstream_id_or_name: str = Path(...),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.upstream_targets(upstream_id_or_name)
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get("/certificates", summary="List TLS certificates")
def list_certificates(
    size: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_certificates(size=size, offset=offset, tags=tags)
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get("/snis", summary="List SNIs")
def list_snis(
    size: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
) -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_snis(size=size, offset=offset, tags=tags)
    except Exception as exc:
        raise _map_kong_error(exc) from exc


@router.get("/status", summary="Kong node status (db / server / memory)")
def node_status() -> dict:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.status_report()
    except Exception as exc:
        raise _map_kong_error(exc) from exc


__all__ = ["router"]
