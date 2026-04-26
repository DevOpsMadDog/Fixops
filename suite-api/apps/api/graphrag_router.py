"""GraphRAG Router — exposes GraphRAGEngine and TrustGraphQueryBuilder.

Endpoints
---------
POST /api/v1/graphrag/query                 Run a natural-language query over cores.
POST /api/v1/graphrag/builder               Execute a structured TrustGraph query.
POST /api/v1/graphrag/query-with-trace      NL query returning a hop-level trace.
GET  /api/v1/graphrag/traced-history        List cached NL queries for an org.
GET  /api/v1/graphrag/traced-stats          Aggregate stats for traced NL queries.
POST /api/v1/graphrag/cache/clear           Clear in-memory query cache.
GET  /api/v1/graphrag/health                Liveness probe.
GET  /api/v1/graphrag/status                Status alias.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth
except Exception:  # pragma: no cover
    def api_key_auth() -> None:  # type: ignore
        return None

logger = structlog.get_logger(__name__)
_stdlib_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/graphrag",
    tags=["GraphRAG"],
    dependencies=[Depends(api_key_auth)],
)

_engine_singleton = None


def _engine():
    global _engine_singleton
    if _engine_singleton is None:
        from core.graphrag_engine import GraphRAGEngine

        _engine_singleton = GraphRAGEngine()
    return _engine_singleton


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class GraphQueryRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    query_text: str = Field(..., min_length=1, max_length=2048)
    target_cores: List[int] = Field(default_factory=lambda: [1, 2, 3])
    max_results: int = Field(default=20, ge=1, le=200)
    include_relationships: bool = True
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)


class BuilderFilter(BaseModel):
    field: str = Field(..., min_length=1, max_length=128)
    operator: str = Field(..., min_length=1, max_length=32)
    value: Any


class BuilderRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    core_id: int = Field(..., ge=1, le=5)
    filters: List[BuilderFilter] = Field(default_factory=list, max_length=16)
    related_to: Optional[str] = Field(default=None, max_length=128)
    limit: int = Field(default=20, ge=1, le=200)


class TracedQueryRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    question: str = Field(..., min_length=1, max_length=2048)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/query")
def query(body: GraphQueryRequest) -> Dict[str, Any]:
    from core.graphrag_engine import GraphQuery

    try:
        result = _engine().query(
            GraphQuery(
                query_text=body.query_text,
                target_cores=body.target_cores,
                max_results=body.max_results,
                include_relationships=body.include_relationships,
                confidence_threshold=body.confidence_threshold,
            )
        )
        return {"org_id": body.org_id, **result.to_dict()}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("graphrag.query_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"query_failure: {exc}")


@router.post("/builder")
def builder(body: BuilderRequest) -> Dict[str, Any]:
    from core.graphrag_engine import TrustGraphQueryBuilder

    try:
        b = TrustGraphQueryBuilder().from_core(body.core_id).limit(body.limit)
        for f in body.filters:
            b.where(f.field, f.operator, f.value)
        if body.related_to:
            b.related_to(body.related_to)
        results = b.execute()
        return {
            "org_id": body.org_id,
            "query": b.build_query_dict(),
            "result_count": len(results),
            "results": results,
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("graphrag.builder_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"builder_failure: {exc}")


@router.post("/query-with-trace")
def query_with_trace(body: TracedQueryRequest) -> Dict[str, Any]:
    try:
        return _engine().query_with_trace(org_id=body.org_id, nl_question=body.question)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("graphrag.traced_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"traced_failure: {exc}")


@router.get("/traced-history")
def traced_history(
    org_id: str = Query(..., min_length=1, max_length=128),
    limit: int = Query(default=50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    try:
        return _engine().list_traced_history(org_id=org_id, limit=limit)
    except Exception as exc:  # pragma: no cover
        logger.exception("graphrag.history_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"history_failure: {exc}")


@router.get("/traced-stats")
def traced_stats(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    try:
        return _engine().traced_stats(org_id=org_id)
    except Exception as exc:  # pragma: no cover
        logger.exception("graphrag.stats_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"stats_failure: {exc}")


@router.post("/cache/clear")
def cache_clear() -> Dict[str, Any]:
    try:
        _engine().clear_cache()
        return {"status": "ok", "cleared": True}
    except Exception as exc:  # pragma: no cover
        logger.exception("graphrag.cache_clear_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"cache_clear_failure: {exc}")


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "engine": "graphrag"}


@router.get("/status")
def status() -> Dict[str, Any]:
    try:
        engine = _engine()
        return {
            "status": "ok",
            "engine": "graphrag",
            "ready": True,
            "cache_ttl_seconds": engine.cache_ttl,
            "cached_queries": len(engine._query_cache),
        }
    except Exception as exc:  # pragma: no cover
        return {"status": "degraded", "engine": "graphrag", "error": str(exc)}


__all__ = ["router"]
