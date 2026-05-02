"""Function Reachability Router — ALDECI (GAP-010).

Endpoints for function-level reachability analysis (Endor Labs moat).

Prefix: /api/v1/reachability
Auth:   api_key_auth dependency on every route

Routes:
  POST /api/v1/reachability/parse                          parse_repo
  POST /api/v1/reachability/query                          is_reachable
  POST /api/v1/reachability/vulnerable                     vulnerable_reachability
  GET  /api/v1/reachability/callgraph/{repo_ref}           list_callgraph
  GET  /api/v1/reachability/stats                          stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/reachability",
    tags=["Function Reachability"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.function_reachability_engine import FunctionReachabilityEngine
        _engine = FunctionReachabilityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ParseRequest(BaseModel):
    org_id: str = "default"
    repo_ref: str = Field(..., description="Customer-chosen ref, e.g. 'myapp@main'")
    language: str = Field(..., description="python | typescript | java")
    root_path: str = Field(..., description="Absolute path to repo root")


class QueryRequest(BaseModel):
    org_id: str = "default"
    start_fqn: str
    target_fqn: str
    max_depth: int = 10


class VulnerableRequest(BaseModel):
    org_id: str = "default"
    cve_id: str
    dependency_fqn_pattern: str = Field(
        ..., description="SQL LIKE pattern, e.g. 'requests.Session.mount' or 'requests.%'"
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/parse")
async def parse_repo(body: ParseRequest) -> Dict[str, Any]:
    """Parse a repo into the call graph (Python only in v0)."""
    eng = _get_engine()
    lang = body.language.lower().strip()
    try:
        if lang == "python":
            nodes_added = eng.parse_python_repo(
                body.org_id, body.repo_ref, body.root_path
            )
        elif lang in ("typescript", "javascript"):
            eng.parse_typescript_repo(body.org_id, body.repo_ref, body.root_path)
            raise RuntimeError("unreachable")  # pragma: no cover
        elif lang == "java":
            eng.parse_java_repo(body.org_id, body.repo_ref, body.root_path)
            raise RuntimeError("unreachable")  # pragma: no cover
        else:
            raise HTTPException(
                status_code=422,
                detail=f"Unsupported language '{body.language}'",
            )
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "org_id": body.org_id,
        "repo_ref": body.repo_ref,
        "language": lang,
        "nodes_added": nodes_added,
    }


@router.post("/query")
async def query_reachability(body: QueryRequest) -> Dict[str, Any]:
    """Run BFS from ``start_fqn`` to ``target_fqn`` and return path if any."""
    try:
        reachable, path = _get_engine().is_reachable(
            body.org_id,
            body.start_fqn,
            body.target_fqn,
            max_depth=body.max_depth,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "org_id": body.org_id,
        "start_fqn": body.start_fqn,
        "target_fqn": body.target_fqn,
        "reachable": reachable,
        "path": path,
        "max_depth": body.max_depth,
    }


@router.post("/vulnerable")
async def vulnerable(body: VulnerableRequest) -> Dict[str, Any]:
    """Return all customer callers that reach a vulnerable dep function."""
    try:
        callers = _get_engine().vulnerable_reachability(
            body.org_id, body.cve_id, body.dependency_fqn_pattern
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "org_id": body.org_id,
        "cve_id": body.cve_id,
        "dependency_fqn_pattern": body.dependency_fqn_pattern,
        "caller_count": len(callers),
        "callers": callers,
    }


@router.get("/callgraph/{repo_ref}")
async def get_callgraph(
    repo_ref: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return nodes + edges for a repo (for graph visualisation)."""
    return _get_engine().list_callgraph(org_id, repo_ref)


@router.get("/stats")
async def get_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Aggregate counts: nodes, edges, queries, verdicts."""
    return _get_engine().stats(org_id)
