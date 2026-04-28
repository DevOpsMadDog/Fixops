"""Context Engine Router — exposes ContextEngine business-aware signal derivation.

Endpoints
---------
POST /api/v1/context-engine/evaluate            Evaluate components + crosswalk.
GET  /api/v1/context-engine/health              Liveness probe.
GET  /api/v1/context-engine/status              Status alias.

The ContextEngine is configured per-call via the `settings` payload (overlay
config) so multiple tenants can use distinct weights/playbooks without the
router holding tenant state.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth
except Exception:  # pragma: no cover
    def api_key_auth() -> None:  # type: ignore
        return None

logger = structlog.get_logger(__name__)
_stdlib_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/context-engine",
    tags=["Context Engine"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ContextEvaluateRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    settings: Dict[str, Any] = Field(default_factory=dict)
    design_rows: List[Dict[str, Any]] = Field(..., min_length=1, max_length=4096)
    crosswalk: List[Dict[str, Any]] = Field(default_factory=list, max_length=4096)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/evaluate")
def evaluate(body: ContextEvaluateRequest) -> Dict[str, Any]:
    from core.context_engine import ContextEngine

    try:
        engine = ContextEngine(body.settings)
        result = engine.evaluate(design_rows=body.design_rows, crosswalk=body.crosswalk)
        return {"org_id": body.org_id, **result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("context_engine.evaluate_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"evaluate_failure: {exc}")


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "engine": "context_engine"}


@router.get("/status")
def status() -> Dict[str, Any]:
    return {"status": "ok", "engine": "context_engine", "ready": True}


__all__ = ["router"]
