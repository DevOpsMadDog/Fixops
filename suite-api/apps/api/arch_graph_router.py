"""Architecture-Aware Graph Router — ALDECI (GAP-065).

Exposes layer classification + architecture flow tracing API.

Prefix: /api/v1/arch-graph
Auth:   api_key_auth dependency on all routes.

Routes:
  POST /api/v1/arch-graph/classify            classify a node (heuristic)
  GET  /api/v1/arch-graph/classifications     list classifications
  POST /api/v1/arch-graph/link-api            link an API endpoint to a layer
  POST /api/v1/arch-graph/link-datastore      link a datastore to a layer
  POST /api/v1/arch-graph/trace-flow          walk the graph, annotate hops, flag boundary crossings
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/arch-graph",
    tags=["Architecture-Aware Graph"],
    dependencies=[Depends(api_key_auth)],
)

_dep_engine = None
_api_engine = None
_data_engine = None


def _get_dep_engine():
    global _dep_engine
    if _dep_engine is None:
        from core.security_dependency_mapping_engine import (
            SecurityDependencyMappingEngine,
        )
        _dep_engine = SecurityDependencyMappingEngine()
    return _dep_engine


def _get_api_engine():
    global _api_engine
    if _api_engine is None:
        from core.api_discovery_engine import APIDiscoveryEngine
        _api_engine = APIDiscoveryEngine()
    return _api_engine


def _get_data_engine():
    global _data_engine
    if _data_engine is None:
        from core.data_discovery_engine import DataDiscoveryEngine
        _data_engine = DataDiscoveryEngine()
    return _data_engine


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class ClassifyBody(BaseModel):
    node_ref: str = Field(..., description="Node reference (path / FQN)", min_length=1, max_length=2048)
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional context: {imports: [...], importers: [...]}",
    )


class LinkApiBody(BaseModel):
    endpoint_path: str = Field(..., description="API endpoint path", min_length=1, max_length=2048)
    layer: str = Field(default="api", description="data | api | ui | service | standalone")


class LinkDatastoreBody(BaseModel):
    datastore_ref: str = Field(..., description="Datastore reference", min_length=1, max_length=2048)
    layer: str = Field(default="data", description="data | api | ui | service | standalone")


class TraceFlowBody(BaseModel):
    start_ref: str = Field(..., description="Starting node ref (service id or name)", min_length=1, max_length=2048)
    max_hops: int = Field(default=5, ge=1, le=25)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/classify")
def classify_node(
    body: ClassifyBody,
    org_id: str = Query(default="default", max_length=256),
) -> Dict[str, Any]:
    """Classify a node into one of data|api|ui|service|standalone."""
    try:
        return _get_dep_engine().classify_layer(
            node_ref=body.node_ref,
            context=body.context,
            org_id=org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/classifications")
def list_classifications(
    org_id: str = Query(default="default", max_length=256),
    layer: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List layer classifications for an org, optionally filtered."""
    if layer is not None and layer not in {"data", "api", "ui", "service", "standalone"}:
        raise HTTPException(
            status_code=422,
            detail="layer must be one of data|api|ui|service|standalone",
        )
    return _get_dep_engine().list_classifications(org_id=org_id, layer=layer)


@router.post("/link-api")
def link_api(
    body: LinkApiBody,
    org_id: str = Query(default="default", max_length=256),
) -> Dict[str, Any]:
    """Link an API endpoint path to an architecture layer."""
    try:
        return _get_api_engine().link_to_layer(
            org_id=org_id,
            endpoint_path=body.endpoint_path,
            layer=body.layer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/link-datastore")
def link_datastore(
    body: LinkDatastoreBody,
    org_id: str = Query(default="default", max_length=256),
) -> Dict[str, Any]:
    """Link a datastore reference to an architecture layer."""
    try:
        return _get_data_engine().link_to_layer(
            org_id=org_id,
            datastore_ref=body.datastore_ref,
            layer=body.layer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/trace-flow")
def trace_flow(
    body: TraceFlowBody,
    org_id: str = Query(default="default", max_length=256),
) -> Dict[str, Any]:
    """Walk the dep-mapping graph annotating each hop with its layer.

    Boundary crossings (hops where source.layer != target.layer) are
    surfaced explicitly so trust-boundary alerting can key on them.
    """
    from core.arch_flow_tracer import trace_flow as _trace_flow
    try:
        return _trace_flow(
            org_id=org_id,
            start_ref=body.start_ref,
            max_hops=body.max_hops,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
