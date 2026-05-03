"""ALDECI Crossplane (k8s API proxy) router — REAL API only, NO MOCKS.

Mounted at ``/api/v1/crossplane`` under the ``read:scans`` scope.

Endpoints
---------
GET  /                                                                   — capability summary
GET  /apis/pkg.crossplane.io/v1/providers                                — list providers
GET  /apis/apiextensions.crossplane.io/v1/compositions                   — list compositions
GET  /apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions   — list XRDs
GET  /apis/pkg.crossplane.io/v1/configurations                           — list configurations
GET  /apis/pkg.crossplane.io/v1/functions                                — list composition functions
GET  /apis/pkg.crossplane.io/v1beta1/lock                                — get package Lock CR
GET  /apis/{group}/{version}/{plural}                                    — generic managed listing
GET  /apis/{group}/{version}/namespaces/{ns}/{plural}                    — namespace-scoped listing
GET  /apis/{group}/{version}/{plural}/{name}                             — single managed resource
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

from core.crossplane_engine import (
    CrossplaneUnavailableError,
    get_crossplane_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/crossplane",
    tags=["crossplane"],
    dependencies=[Depends(api_key_auth)],
)


# ----------------------------------------------------------------- helpers


def _to_503(exc: CrossplaneUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("", summary="Crossplane capability summary")
@router.get("/", summary="Crossplane capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_crossplane_engine()
    return eng.capability_summary()


# --------- providers ---------


@router.get(
    "/apis/pkg.crossplane.io/v1/providers",
    summary="List Crossplane providers",
)
def list_providers(
    limit: Optional[int] = Query(None, ge=0),
    continue_: Optional[str] = Query(None, alias="continue"),
    labelSelector: Optional[str] = Query(None),
    fieldSelector: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.list_providers(
            limit=limit,
            cont=continue_,
            label_selector=labelSelector,
            field_selector=fieldSelector,
        )
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# --------- compositions ---------


@router.get(
    "/apis/apiextensions.crossplane.io/v1/compositions",
    summary="List Crossplane compositions",
)
def list_compositions(
    limit: Optional[int] = Query(None, ge=0),
    continue_: Optional[str] = Query(None, alias="continue"),
    labelSelector: Optional[str] = Query(None),
    fieldSelector: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.list_compositions(
            limit=limit,
            cont=continue_,
            label_selector=labelSelector,
            field_selector=fieldSelector,
        )
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# --------- XRDs ---------


@router.get(
    "/apis/apiextensions.crossplane.io/v1/compositeresourcedefinitions",
    summary="List CompositeResourceDefinitions (XRDs)",
)
def list_xrds(
    limit: Optional[int] = Query(None, ge=0),
    continue_: Optional[str] = Query(None, alias="continue"),
    labelSelector: Optional[str] = Query(None),
    fieldSelector: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.list_xrds(
            limit=limit,
            cont=continue_,
            label_selector=labelSelector,
            field_selector=fieldSelector,
        )
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# --------- configurations ---------


@router.get(
    "/apis/pkg.crossplane.io/v1/configurations",
    summary="List Crossplane configurations",
)
def list_configurations(
    limit: Optional[int] = Query(None, ge=0),
    continue_: Optional[str] = Query(None, alias="continue"),
    labelSelector: Optional[str] = Query(None),
    fieldSelector: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.list_configurations(
            limit=limit,
            cont=continue_,
            label_selector=labelSelector,
            field_selector=fieldSelector,
        )
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# --------- functions ---------


@router.get(
    "/apis/pkg.crossplane.io/v1/functions",
    summary="List Crossplane composition functions",
)
def list_functions(
    limit: Optional[int] = Query(None, ge=0),
    continue_: Optional[str] = Query(None, alias="continue"),
    labelSelector: Optional[str] = Query(None),
    fieldSelector: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.list_functions(
            limit=limit,
            cont=continue_,
            label_selector=labelSelector,
            field_selector=fieldSelector,
        )
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# --------- lock ---------


@router.get(
    "/apis/pkg.crossplane.io/v1beta1/lock",
    summary="Get Crossplane package Lock",
)
def get_lock() -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.get_lock()
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)


# --------- generic managed (namespaced) — MUST come BEFORE the cluster-scoped
# --------- match because both share the {group}/{version} prefix. FastAPI
# --------- registers in declaration order; the more specific path wins when
# --------- declared first.


@router.get(
    "/apis/{group}/{version}/namespaces/{namespace}/{plural}",
    summary="List namespace-scoped managed resources",
)
def list_managed_namespaced(
    group: str,
    version: str,
    namespace: str,
    plural: str,
    limit: Optional[int] = Query(None, ge=0),
    continue_: Optional[str] = Query(None, alias="continue"),
    labelSelector: Optional[str] = Query(None),
    fieldSelector: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.list_managed(
            group=group,
            version=version,
            plural=plural,
            namespace=namespace,
            limit=limit,
            cont=continue_,
            label_selector=labelSelector,
            field_selector=fieldSelector,
        )
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get(
    "/apis/{group}/{version}/{plural}/{name}",
    summary="Get a single managed resource",
)
def get_managed(
    group: str,
    version: str,
    plural: str,
    name: str,
) -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.get_managed(
            group=group, version=version, plural=plural, name=name
        )
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get(
    "/apis/{group}/{version}/{plural}",
    summary="List cluster-scoped managed resources",
)
def list_managed_cluster(
    group: str,
    version: str,
    plural: str,
    limit: Optional[int] = Query(None, ge=0),
    continue_: Optional[str] = Query(None, alias="continue"),
    labelSelector: Optional[str] = Query(None),
    fieldSelector: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_crossplane_engine()
    try:
        return eng.list_managed(
            group=group,
            version=version,
            plural=plural,
            namespace=None,
            limit=limit,
            cont=continue_,
            label_selector=labelSelector,
            field_selector=fieldSelector,
        )
    except CrossplaneUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


__all__ = ["router"]
