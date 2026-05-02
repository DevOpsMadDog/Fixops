"""GAP-043 Formula Transparency REST API.

3 endpoints exposing the vulnerability scoring formula:

- GET  /api/v1/formula/breakdown?org_id=&finding_id=
- POST /api/v1/formula/history body: {formula_version, change_summary, approver, approved_at}
- GET  /api/v1/formula/history?org_id=

All endpoints require api_key_auth via FastAPI dependency.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

try:
    from apps.api.auth_deps import api_key_auth
except ImportError:  # pragma: no cover
    async def api_key_auth() -> None:  # type: ignore
        return None


router = APIRouter(
    prefix="/api/v1/formula",
    tags=["formula-transparency"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------

_SCORING_SINGLETON: Optional[Any] = None
_GOV_SINGLETON: Optional[Any] = None


def _get_scoring() -> Any:
    global _SCORING_SINGLETON
    if _SCORING_SINGLETON is not None:
        return _SCORING_SINGLETON
    try:
        from core.vulnerability_scoring_engine import VulnerabilityScoringEngine
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"VulnerabilityScoringEngine not available: {exc}",
        )
    _SCORING_SINGLETON = VulnerabilityScoringEngine()
    return _SCORING_SINGLETON


def _get_gov() -> Any:
    global _GOV_SINGLETON
    if _GOV_SINGLETON is not None:
        return _GOV_SINGLETON
    try:
        from core.ai_governance_engine import AIGovernanceEngine
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"AIGovernanceEngine not available: {exc}",
        )
    _GOV_SINGLETON = AIGovernanceEngine()
    return _GOV_SINGLETON


def _resolve_org(org_id: Optional[str], dep_org_id: Optional[str]) -> str:
    value = (
        (org_id or dep_org_id or "").strip()
        if isinstance(org_id, str) or isinstance(dep_org_id, str)
        else ""
    )
    if not value:
        raise HTTPException(status_code=400, detail="org_id is required")
    return value


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FormulaHistoryBody(BaseModel):
    formula_version: str = Field(..., min_length=1, max_length=64)
    change_summary: str = Field(default="", max_length=4_000)
    approver: str = Field(default="", max_length=256)
    approved_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 approval timestamp; defaults to now().",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/breakdown",
    summary="GAP-043: Return full scoring formula transparency",
)
def formula_breakdown(
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    finding_id: Optional[str] = Query(
        default=None, description="Optional finding id for contributor values"
    ),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    engine = _get_scoring()
    effective_org = _resolve_org(org_id, dep_org_id)
    try:
        return engine.get_formula_transparency(effective_org, finding_id=finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/history",
    summary="GAP-043: Register a scoring-formula change for audit",
)
def formula_history_create(
    body: FormulaHistoryBody,
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    engine = _get_gov()
    effective_org = _resolve_org(org_id, dep_org_id)
    try:
        return engine.register_formula_change(
            effective_org,
            body.formula_version,
            body.change_summary,
            body.approver,
            body.approved_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get(
    "/history",
    summary="GAP-043: List scoring-formula change history",
)
def formula_history_list(
    org_id: Optional[str] = Query(default=None, description="Tenant org_id"),
    dep_org_id: Optional[str] = Depends(get_org_id),
) -> Dict[str, Any]:
    engine = _get_gov()
    effective_org = _resolve_org(org_id, dep_org_id)
    try:
        history: List[Dict[str, Any]] = engine.list_formula_history(effective_org)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "org_id": effective_org,
        "total": len(history),
        "items": history,
    }
