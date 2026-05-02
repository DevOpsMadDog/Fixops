"""NL Graph Router — GAP-029.

Natural-language graph assistant with traversal-trace explanation.
Wraps `intelligent_security_engine.nl_graph_assistant` /
`ai_security_advisor_engine.answer_graph_question` /
`graphrag_engine.query_with_trace`.

Prefix: /api/v1/nl-graph
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/nl-graph/query     -- NL question -> answer + trace + explanation
  POST   /api/v1/nl-graph/trace     -- NL question -> traversal trace only
  GET    /api/v1/nl-graph/history   -- cached queries
  GET    /api/v1/nl-graph/stats     -- aggregate stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/nl-graph",
    tags=["NL Graph Assistant (GAP-029)"],
)


# ---------------------------------------------------------------------------
# Lazy engine getters
# ---------------------------------------------------------------------------

_advisor = None
_graphrag = None


def _get_advisor():
    global _advisor
    if _advisor is None:
        from core.ai_security_advisor_engine import AISecurityAdvisorEngine
        _advisor = AISecurityAdvisorEngine()
    return _advisor


def _get_graphrag():
    global _graphrag
    if _graphrag is None:
        from core.graphrag_engine import GraphRAGEngine
        _graphrag = GraphRAGEngine()
    return _graphrag


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class NLQuestionRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Natural-language graph question.",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/query", dependencies=[Depends(api_key_auth)])
def nl_graph_query(
    body: NLQuestionRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Answer a natural-language graph question with trace + explanation."""
    try:
        return _get_advisor().answer_graph_question(org_id, body.question)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("nl_graph_query failed")
        raise HTTPException(status_code=500, detail=f"nl_graph_query error: {exc}") from exc


@router.post("/trace", dependencies=[Depends(api_key_auth)])
def nl_graph_trace(
    body: NLQuestionRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return only the traversal trace for a NL graph question."""
    try:
        return _get_graphrag().query_with_trace(org_id, body.question)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("nl_graph_trace failed")
        raise HTTPException(status_code=500, detail=f"nl_graph_trace error: {exc}") from exc


@router.get("/history", dependencies=[Depends(api_key_auth)])
def nl_graph_history(
    org_id: str = Query(default="default"),
    limit: int = Query(default=50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List cached NL graph queries for an org, newest first."""
    try:
        return _get_graphrag().list_traced_history(org_id, limit=limit)
    except Exception as exc:
        _logger.exception("nl_graph_history failed")
        raise HTTPException(status_code=500, detail=f"nl_graph_history error: {exc}") from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def nl_graph_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregate stats for NL traced queries."""
    try:
        return _get_graphrag().traced_stats(org_id)
    except Exception as exc:
        _logger.exception("nl_graph_stats failed")
        raise HTTPException(status_code=500, detail=f"nl_graph_stats error: {exc}") from exc
