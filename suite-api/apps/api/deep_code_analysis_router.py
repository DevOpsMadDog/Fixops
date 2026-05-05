"""Deep Code Analysis Router — REST endpoints for GAP-012 (Apiiro DCA parity).

Endpoints under /api/v1/dca:
  POST   /analyze                                  — Walk a repo and extract symbols
  GET    /analyses?org_id=&repo_ref=               — List analyses
  GET    /analyses/{id}/summary                    — Summary counts
  POST   /analyses/{id}/feed-api-discovery         — Push endpoints to API Discovery
  POST   /analyses/{id}/feed-data-classification   — Push sensitive models to DataClass
  GET    /stats?org_id=                            — Aggregate per-org stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dca",
    tags=["Deep Code Analysis"],
    dependencies=[Depends(api_key_auth)],
)


def _get_engine():
    try:
        from core.deep_code_analysis_engine import get_engine
        return get_engine()
    except Exception as exc:
        _logger.error("DeepCodeAnalysisEngine unavailable: %s", exc)
        raise HTTPException(
            status_code=503,
            detail=f"Deep code analysis engine unavailable: {exc}",
        )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AnalyzeRepoRequest(BaseModel):
    repo_ref: str = Field(..., min_length=1, max_length=512)
    commit_sha: str = Field(default="", max_length=128)
    root_path: str = Field(..., min_length=1, max_length=4096)
    org_id: str = Field(default="default", min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/analyze")
async def analyze_repo(req: AnalyzeRepoRequest) -> Dict[str, Any]:
    """Walk a repo at `root_path` and extract symbols/endpoints/models."""
    engine = _get_engine()
    try:
        return engine.analyze_repo(
            org_id=req.org_id,
            repo_ref=req.repo_ref,
            commit_sha=req.commit_sha,
            root_path=req.root_path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        _logger.exception("dca analyze failed")
        raise HTTPException(status_code=500, detail=f"analyze failed: {exc}")


@router.get("/analyses")
async def list_analyses(
    org_id: str = Query(..., min_length=1, max_length=128),
    repo_ref: Optional[str] = Query(default=None, max_length=512),
) -> List[Dict[str, Any]]:
    """List analyses for an org, optionally filtered by repo_ref."""
    engine = _get_engine()
    return engine.list_analyses(org_id=org_id, repo_ref=repo_ref)


@router.get("/analyses/{analysis_id}/summary")
async def get_summary(analysis_id: str) -> Dict[str, Any]:
    """Summary counts for a single analysis."""
    engine = _get_engine()
    try:
        return engine.get_analysis_summary(analysis_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/analyses/{analysis_id}/feed-api-discovery")
async def feed_api_discovery(analysis_id: str) -> Dict[str, Any]:
    """Push discovered endpoints into api_discovery.db."""
    engine = _get_engine()
    try:
        return engine.feed_api_discovery(analysis_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        _logger.exception("dca feed_api_discovery failed")
        raise HTTPException(status_code=500, detail=f"feed failed: {exc}")


@router.post("/analyses/{analysis_id}/feed-data-classification")
async def feed_data_classification(analysis_id: str) -> Dict[str, Any]:
    """Push sensitive data models into data_classification data_assets."""
    engine = _get_engine()
    try:
        return engine.feed_data_classification(analysis_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        _logger.exception("dca feed_data_classification failed")
        raise HTTPException(status_code=500, detail=f"feed failed: {exc}")


@router.get("/stats")
async def get_stats(
    org_id: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    """Aggregate per-org stats across all analyses."""
    engine = _get_engine()
    return engine.stats(org_id=org_id)


@router.get("/", summary="Deep code analysis index", tags=["dca"])
async def dca_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return deep code analysis summary and recent analyses for the org."""
    try:
        engine = _get_engine()
        stats = engine.stats(org_id=org_id)
        items = engine.list_analyses(org_id=org_id)
    except Exception:
        stats = {}
        items = []
    return {"router": "dca", "org_id": org_id, "stats": stats, "items": items, "count": len(items)}
