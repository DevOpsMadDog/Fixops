"""Elasticsearch Data-Plane Connector Router — ALDECI (2026-05-31).

Wraps the Elasticsearch REST API with live httpx calls for cluster health,
index inspection, node statistics, running task enumeration, and ad-hoc
search across any index. Supports two auth modes:

  • Basic auth  — ELASTICSEARCH_USER + ELASTICSEARCH_PASSWORD
  • API key     — ELASTICSEARCH_API_KEY (``Authorization: ApiKey <key>``)

Basic auth takes precedence when both env sets are present.

Prefix: /api/v1/elasticsearch
Auth:   api_key_auth dependency (read:scans scope at registration)

Routes:
  GET  /api/v1/elasticsearch/                      connector info / configured-status
  GET  /api/v1/elasticsearch/cluster/health        GET /_cluster/health
  GET  /api/v1/elasticsearch/indices               GET /_cat/indices?format=json&h=...
  POST /api/v1/elasticsearch/search/{index}        POST /{index}/_search (query DSL forwarded)
  GET  /api/v1/elasticsearch/nodes                 GET /_nodes/stats?metric=fs,jvm,os
  GET  /api/v1/elasticsearch/tasks                 GET /_tasks?detailed=true

NO MOCKS rule: when ELASTICSEARCH_URL is missing, or when neither Basic-auth
credentials nor an API key are set, every live endpoint returns HTTP 503 with
``{"error":"elasticsearch_not_configured","needed":[...]}``. Upstream
401/403/500 responses are passed through as-is — we never fabricate cluster
health, index lists, or search results.

Credentials
-----------
  ELASTICSEARCH_URL            — base URL, e.g. ``https://my-cluster.es.io:9243``
  ELASTICSEARCH_USER           — username for Basic auth (pair with PASSWORD)
  ELASTICSEARCH_PASSWORD       — password for Basic auth
  ELASTICSEARCH_API_KEY        — encoded API key for ``Authorization: ApiKey`` header
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx
from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_TIMEOUT = 10.0
_NOT_CONFIGURED_ERROR = "elasticsearch_not_configured"

router = APIRouter(
    prefix="/api/v1/elasticsearch",
    tags=["Elasticsearch"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_config() -> tuple[str, Optional[httpx.BasicAuth], Optional[str]]:
    """Return (base_url, basic_auth_or_None, api_key_or_None).

    Returns (None, None, None) when ELASTICSEARCH_URL is missing.
    Returns (url, None, None) when URL is present but no auth method is set.
    """
    url = os.environ.get("ELASTICSEARCH_URL", "").strip().rstrip("/")
    if not url:
        return None, None, None  # type: ignore[return-value]

    user = os.environ.get("ELASTICSEARCH_USER", "").strip()
    password = os.environ.get("ELASTICSEARCH_PASSWORD", "").strip()
    api_key = os.environ.get("ELASTICSEARCH_API_KEY", "").strip()

    if user and password:
        return url, httpx.BasicAuth(user, password), None
    if api_key:
        return url, None, api_key
    # URL present but no auth configured
    return url, None, None


def _require_config() -> tuple[str, Optional[httpx.BasicAuth], Optional[str]]:
    """Return (base_url, basic_auth_or_None, api_key_or_None) or raise 503."""
    url, basic_auth, api_key = _get_config()
    if not url:
        raise HTTPException(
            status_code=503,
            detail={
                "error": _NOT_CONFIGURED_ERROR,
                "needed": ["ELASTICSEARCH_URL"],
                "hint": "Also set ELASTICSEARCH_USER+ELASTICSEARCH_PASSWORD or ELASTICSEARCH_API_KEY",
            },
        )
    if basic_auth is None and not api_key:
        raise HTTPException(
            status_code=503,
            detail={
                "error": _NOT_CONFIGURED_ERROR,
                "needed": [
                    "ELASTICSEARCH_USER+ELASTICSEARCH_PASSWORD",
                    "or ELASTICSEARCH_API_KEY",
                ],
                "hint": "ELASTICSEARCH_URL is set but no auth credentials are configured",
            },
        )
    return url, basic_auth, api_key


def _build_headers(api_key: Optional[str]) -> Dict[str, str]:
    """Build extra headers — adds ApiKey authorization when key-based auth."""
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    return headers


async def _get(
    base_url: str,
    basic_auth: Optional[httpx.BasicAuth],
    api_key: Optional[str],
    path: str,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Issue an authenticated GET against Elasticsearch.

    Raises HTTPException on upstream HTTP errors or timeouts.
    Returns the parsed JSON body on success.
    """
    url = f"{base_url}{path}"
    headers = _build_headers(api_key)
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            auth=basic_auth,
        ) as client:
            resp = await client.get(url, headers=headers, params=params or {})
    except httpx.TimeoutException as exc:
        _logger.warning("elasticsearch_timeout path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "elasticsearch_timeout", "path": path},
        ) from exc
    except httpx.HTTPError as exc:
        _logger.warning("elasticsearch_http_error path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "elasticsearch_upstream_error", "path": path},
        ) from exc

    if resp.status_code >= 400:
        _logger.warning(
            "elasticsearch_upstream_error path=%s status=%d body=%.200s",
            path, resp.status_code, resp.text,
        )
        try:
            detail = resp.json()
        except Exception:
            detail = {"error": "elasticsearch_upstream_error", "status": resp.status_code}
        raise HTTPException(status_code=resp.status_code, detail=detail)

    return resp.json()


async def _post(
    base_url: str,
    basic_auth: Optional[httpx.BasicAuth],
    api_key: Optional[str],
    path: str,
    body: Any,
) -> Any:
    """Issue an authenticated POST against Elasticsearch.

    Raises HTTPException on upstream HTTP errors or timeouts.
    Returns the parsed JSON body on success.
    """
    url = f"{base_url}{path}"
    headers = _build_headers(api_key)
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            auth=basic_auth,
        ) as client:
            resp = await client.post(url, headers=headers, json=body)
    except httpx.TimeoutException as exc:
        _logger.warning("elasticsearch_timeout path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "elasticsearch_timeout", "path": path},
        ) from exc
    except httpx.HTTPError as exc:
        _logger.warning("elasticsearch_http_error path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "elasticsearch_upstream_error", "path": path},
        ) from exc

    if resp.status_code >= 400:
        _logger.warning(
            "elasticsearch_upstream_error path=%s status=%d body=%.200s",
            path, resp.status_code, resp.text,
        )
        try:
            detail = resp.json()
        except Exception:
            detail = {"error": "elasticsearch_upstream_error", "status": resp.status_code}
        raise HTTPException(status_code=resp.status_code, detail=detail)

    return resp.json()


# ---------------------------------------------------------------------------
# Pydantic response schemas
# ---------------------------------------------------------------------------


class ConnectorInfoResponse(BaseModel):
    service: str = "Elasticsearch REST API"
    version: str = "8.x/7.x"
    endpoints: List[str]
    url_present: bool
    auth_mode: str  # basic | api_key | none
    status: str  # ok | partial | unavailable


class ClusterHealthResponse(BaseModel):
    model_config = {"extra": "allow"}


class IndicesResponse(BaseModel):
    indices: List[Dict[str, Any]] = Field(default_factory=list)


class SearchResponse(BaseModel):
    model_config = {"extra": "allow"}


class NodesResponse(BaseModel):
    model_config = {"extra": "allow"}


class TasksResponse(BaseModel):
    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# GET / — connector info (always returns 200, no creds required)
# ---------------------------------------------------------------------------


@router.get("/", response_model=ConnectorInfoResponse)
async def connector_info() -> ConnectorInfoResponse:
    """Connector capability summary — safe to call without credentials.

    Returns configured-status so the UI can surface actionable setup guidance
    without requiring a live Elasticsearch cluster.
    """
    url = os.environ.get("ELASTICSEARCH_URL", "").strip()
    user = os.environ.get("ELASTICSEARCH_USER", "").strip()
    password = os.environ.get("ELASTICSEARCH_PASSWORD", "").strip()
    api_key = os.environ.get("ELASTICSEARCH_API_KEY", "").strip()

    url_present = bool(url)

    if user and password:
        auth_mode = "basic"
    elif api_key:
        auth_mode = "api_key"
    else:
        auth_mode = "none"

    if url_present and auth_mode != "none":
        status = "ok"
    elif url_present:
        status = "partial"
    else:
        status = "unavailable"

    _logger.info(
        "elasticsearch_connector_info url_present=%s auth_mode=%s status=%s",
        url_present, auth_mode, status,
    )
    return ConnectorInfoResponse(
        endpoints=[
            "/cluster/health",
            "/indices",
            "/search/{index}",
            "/nodes",
            "/tasks",
        ],
        url_present=url_present,
        auth_mode=auth_mode,
        status=status,
    )


# ---------------------------------------------------------------------------
# GET /cluster/health — /_cluster/health
# ---------------------------------------------------------------------------


@router.get("/cluster/health", response_model=ClusterHealthResponse)
async def cluster_health() -> ClusterHealthResponse:
    """Return the cluster health report.

    Upstream: GET /_cluster/health
    Returns 503 when ELASTICSEARCH_URL or auth credentials are unset.
    """
    base_url, basic_auth, api_key = _require_config()
    data = await _get(base_url, basic_auth, api_key, "/_cluster/health")
    _logger.info(
        "elasticsearch_cluster_health status=%s",
        data.get("status", "unknown"),
    )
    return ClusterHealthResponse(**data)


# ---------------------------------------------------------------------------
# GET /indices — /_cat/indices
# ---------------------------------------------------------------------------


@router.get("/indices", response_model=IndicesResponse)
async def list_indices() -> IndicesResponse:
    """List all indices with key health and size metrics.

    Upstream: GET /_cat/indices?format=json&h=index,health,docs.count,store.size
    Returns 503 when ELASTICSEARCH_URL or auth credentials are unset.
    """
    base_url, basic_auth, api_key = _require_config()
    params = {
        "format": "json",
        "h": "index,health,docs.count,store.size",
    }
    data = await _get(base_url, basic_auth, api_key, "/_cat/indices", params=params)
    # _cat returns a list directly
    indices = data if isinstance(data, list) else data.get("indices", [])
    _logger.info("elasticsearch_list_indices count=%d", len(indices))
    return IndicesResponse(indices=indices)


# ---------------------------------------------------------------------------
# POST /search/{index} — /{index}/_search (query DSL forwarded)
# ---------------------------------------------------------------------------


@router.post("/search/{index}", response_model=SearchResponse)
async def search_index(
    index: str = Path(..., min_length=1, max_length=512, description="Index name or pattern"),
    query: Dict[str, Any] = Body(default_factory=dict, description="Elasticsearch query DSL"),
) -> SearchResponse:
    """Execute an Elasticsearch Query DSL search against the named index.

    The request body is forwarded verbatim to ``POST /{index}/_search``.
    Returns 503 when ELASTICSEARCH_URL or auth credentials are unset.
    """
    base_url, basic_auth, api_key = _require_config()
    data = await _post(base_url, basic_auth, api_key, f"/{index}/_search", query)
    hits = data.get("hits", {})
    _logger.info(
        "elasticsearch_search index=%s total=%s",
        index, hits.get("total", {}).get("value", "?"),
    )
    return SearchResponse(**data)


# ---------------------------------------------------------------------------
# GET /nodes — /_nodes/stats (security-relevant node info)
# ---------------------------------------------------------------------------


@router.get("/nodes", response_model=NodesResponse)
async def node_stats() -> NodesResponse:
    """Return per-node statistics for filesystem, JVM, and OS metrics.

    Upstream: GET /_nodes/stats?metric=fs,jvm,os
    Returns 503 when ELASTICSEARCH_URL or auth credentials are unset.
    """
    base_url, basic_auth, api_key = _require_config()
    data = await _get(
        base_url, basic_auth, api_key,
        "/_nodes/stats",
        params={"metric": "fs,jvm,os"},
    )
    node_count = len(data.get("nodes", {}))
    _logger.info("elasticsearch_node_stats node_count=%d", node_count)
    return NodesResponse(**data)


# ---------------------------------------------------------------------------
# GET /tasks — /_tasks (running tasks)
# ---------------------------------------------------------------------------


@router.get("/tasks", response_model=TasksResponse)
async def list_tasks() -> TasksResponse:
    """List all currently running tasks in the cluster.

    Upstream: GET /_tasks?detailed=true
    Returns 503 when ELASTICSEARCH_URL or auth credentials are unset.
    """
    base_url, basic_auth, api_key = _require_config()
    data = await _get(
        base_url, basic_auth, api_key,
        "/_tasks",
        params={"detailed": "true"},
    )
    _logger.info("elasticsearch_list_tasks")
    return TasksResponse(**data)


__all__ = ["router"]
