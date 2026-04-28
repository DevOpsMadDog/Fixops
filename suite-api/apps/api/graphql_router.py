"""GraphQL Router for ALDECI/FixOps.

Exposes a single HTTP endpoint for GraphQL queries and mutations, plus a
schema introspection endpoint.

Endpoints:
  POST /api/v1/graphql        — Execute a GraphQL query or mutation
  GET  /api/v1/graphql/schema — Return the SDL schema for introspection
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/graphql", tags=["graphql"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class GraphQLRequest(BaseModel):
    """Standard GraphQL over HTTP request body."""

    query: str = Field(..., min_length=1, description="GraphQL query or mutation document")
    variables: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional variable map merged with inline arguments",
    )
    operation_name: Optional[str] = Field(
        default=None,
        description="Optional operation name (informational only)",
    )


class GraphQLErrorLocation(BaseModel):
    line: int
    column: int


class GraphQLError(BaseModel):
    message: str
    locations: Optional[List[GraphQLErrorLocation]] = None
    path: Optional[List[str]] = None


class GraphQLResponse(BaseModel):
    data: Optional[Dict[str, Any]] = None
    errors: Optional[List[Dict[str, Any]]] = None
    extensions: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Lazy import helper — avoids circular import at module load time
# ---------------------------------------------------------------------------

_graphql_schema_module = None


def _get_schema_module():
    global _graphql_schema_module
    if _graphql_schema_module is None:
        try:
            from core import graphql_schema
            _graphql_schema_module = graphql_schema
        except ImportError as exc:
            logger.error("Failed to import graphql_schema: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="GraphQL schema module not available",
            )
    return _graphql_schema_module


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=GraphQLResponse,
    summary="Execute GraphQL query or mutation",
    description=(
        "Standard GraphQL over HTTP endpoint. Send a JSON body with `query` "
        "(required), `variables` (optional), and `operation_name` (optional). "
        "Returns `{data: {...}}` on success or `{errors: [...]}` on failure."
    ),
)
async def graphql_endpoint(
    body: GraphQLRequest,
    request: Request,
) -> GraphQLResponse:
    """Execute a GraphQL query or mutation.

    Supports:
    - All Query fields: findings, assets, incidents, compliance_status,
      posture_score, attack_surface, vendors, threat_landscape
    - All Mutation fields: acknowledge_finding, create_incident,
      update_compliance, accept_risk
    - Subscription type definitions (returns null data + extension hint)

    Args:
        body:    GraphQL request with query document and optional variables.
        request: FastAPI request (used for logging).

    Returns:
        GraphQLResponse with data or errors.
    """
    schema = _get_schema_module()

    logger.debug(
        "GraphQL request",
        operation_name=body.operation_name,
        query_preview=body.query[:120].replace("\n", " "),
    )

    try:
        result = schema.execute_graphql(
            query=body.query,
            variables=body.variables,
        )
    except Exception as exc:
        logger.exception("Unhandled error in GraphQL execution")
        return GraphQLResponse(
            errors=[{"message": f"Internal server error: {exc}"}]
        )

    return GraphQLResponse(
        data=result.get("data"),
        errors=result.get("errors"),
        extensions=result.get("extensions"),
    )


@router.get(
    "/schema",
    response_class=PlainTextResponse,
    summary="Introspect GraphQL SDL schema",
    description="Returns the full GraphQL Schema Definition Language (SDL) document.",
)
async def graphql_schema_endpoint() -> str:
    """Return the GraphQL SDL for introspection tools (GraphiQL, Apollo Studio, etc.).

    Returns:
        Plain-text SDL schema string.
    """
    schema = _get_schema_module()
    return schema.get_schema_sdl()
