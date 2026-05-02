"""API Documentation & Developer Portal Router.

Provides interactive documentation, spec exports, and endpoint exploration
for the ALDECI Security Platform API.

Routes:
  GET /api/v1/docs/openapi.json   — Full OpenAPI 3.1 spec as JSON
  GET /api/v1/docs/openapi.yaml   — OpenAPI 3.1 spec as YAML
  GET /api/v1/docs/postman.json   — Postman Collection v2.1 export
  GET /api/v1/docs/summary        — Markdown API reference
  GET /api/v1/docs/stats          — Endpoint counts by domain/tag
  GET /api/v1/docs/endpoints      — Searchable endpoint list with filters
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import yaml
from apps.api.auth_deps import api_key_auth
from core.api_doc_generator import APIDocGenerator
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, PlainTextResponse, Response

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/docs",
    tags=["api-docs"],
    dependencies=[Depends(api_key_auth)],
)

# Singleton generator — scanned once at first request, then cached
_generator: Optional[APIDocGenerator] = None


def _get_generator() -> APIDocGenerator:
    global _generator
    if _generator is None:
        _generator = APIDocGenerator()
    return _generator


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/openapi.json",
    summary="OpenAPI spec (JSON)",
    description="Full OpenAPI 3.1 specification for the ALDECI platform in JSON format.",
    response_class=JSONResponse,
)
async def get_openapi_json(
    include_examples: bool = Query(True, description="Include request/response examples"),
) -> JSONResponse:
    """Return the full OpenAPI 3.1 spec as JSON."""
    spec = _get_generator().generate_openapi_spec(include_examples=include_examples)
    return JSONResponse(content=spec)


@router.get(
    "/openapi.yaml",
    summary="OpenAPI spec (YAML)",
    description="Full OpenAPI 3.1 specification for the ALDECI platform in YAML format.",
    response_class=Response,
)
async def get_openapi_yaml(
    include_examples: bool = Query(True, description="Include request/response examples"),
) -> Response:
    """Return the full OpenAPI 3.1 spec as YAML."""
    spec = _get_generator().generate_openapi_spec(include_examples=include_examples)
    yaml_content = yaml.dump(spec, default_flow_style=False, allow_unicode=True, sort_keys=False)
    return Response(content=yaml_content, media_type="application/yaml")


@router.get(
    "/postman.json",
    summary="Postman Collection export",
    description="Postman Collection v2.1 for all ALDECI endpoints, ready to import into Postman.",
    response_class=JSONResponse,
)
async def get_postman_collection() -> JSONResponse:
    """Return a Postman Collection v2.1 dict."""
    collection = _get_generator().generate_postman_collection()
    return JSONResponse(content=collection)


@router.get(
    "/summary",
    summary="Markdown API reference",
    description="Human-readable Markdown summary of all API endpoints, grouped by security domain.",
    response_class=PlainTextResponse,
)
async def get_summary() -> PlainTextResponse:
    """Return a Markdown-formatted API reference."""
    markdown = _get_generator().export_markdown_summary()
    return PlainTextResponse(content=markdown, media_type="text/markdown")


@router.get(
    "/stats",
    summary="Endpoint statistics",
    description="Endpoint counts by security domain and tag, plus totals.",
)
async def get_stats() -> Dict[str, Any]:
    """Return endpoint statistics grouped by domain and tag."""
    gen = _get_generator()
    tag_counts = gen.count_endpoints_by_tag()
    domain_map = gen.get_endpoints_by_security_domain()
    endpoints = gen.scan_routers()

    domain_counts = {domain: len(eps) for domain, eps in domain_map.items()}

    return {
        "total_endpoints": len(endpoints),
        "total_tags": len(tag_counts),
        "total_domains": len(domain_counts),
        "by_tag": tag_counts,
        "by_domain": domain_counts,
        "api_version": APIDocGenerator.API_VERSION,
    }


@router.get(
    "/endpoints",
    summary="Searchable endpoint list",
    description=(
        "List all API endpoints with optional filters by method, tag, domain, "
        "or path substring. Returns paginated results."
    ),
)
async def list_endpoints(
    method: Optional[str] = Query(None, description="Filter by HTTP method (GET, POST, …)"),
    tag: Optional[str] = Query(None, description="Filter by tag (case-insensitive substring)"),
    domain: Optional[str] = Query(None, description="Filter by security domain"),
    search: Optional[str] = Query(None, description="Search in path or summary (case-insensitive)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> Dict[str, Any]:
    """Return a filtered, paginated list of endpoints."""
    gen = _get_generator()
    all_eps = gen.scan_routers()

    # Apply filters
    filtered = all_eps

    if method:
        method_upper = method.upper()
        filtered = [ep for ep in filtered if ep.method.upper() == method_upper]

    if tag:
        tag_lower = tag.lower()
        filtered = [ep for ep in filtered if any(tag_lower in t.lower() for t in ep.tags)]

    if domain:
        domain_map = gen.get_endpoints_by_security_domain()
        domain_eps = {ep.path + ep.method for ep in domain_map.get(domain, [])}
        filtered = [ep for ep in filtered if (ep.path + ep.method) in domain_eps]

    if search:
        search_lower = search.lower()
        filtered = [
            ep for ep in filtered
            if search_lower in ep.path.lower() or search_lower in ep.summary.lower()
        ]

    total = len(filtered)
    page = filtered[offset : offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "endpoints": [ep.to_dict() for ep in page],
    }
