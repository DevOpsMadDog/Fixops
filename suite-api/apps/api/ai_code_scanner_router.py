"""AI-Generated Code Scanner Router — GAP-019.

AI-generated code scanning = SAST applied at keystroke time. This router exposes
snippet-level SAST plus AI-specific risk heuristics (hardcoded secrets, eval,
os.system, shell=True, etc.).

Prefix: /api/v1/ai-scan
Auth:   api_key_auth (X-API-Key or Authorization: Bearer <token>)

Routes:
  POST   /api/v1/ai-scan/snippet    Scan a single snippet (SAST only).
  POST   /api/v1/ai-scan/analyze    Full analysis = SAST + AI-specific risks.
  GET    /api/v1/ai-scan/history    Snippet scan history for an org.
  GET    /api/v1/ai-scan/stats      Aggregated snippet-scan statistics.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ai-scan",
    tags=["AI Code Scanner"],
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScanSnippetRequest(BaseModel):
    code: str = Field(..., description="Source code snippet to scan.", min_length=1)
    language: str = Field(
        ...,
        description="Language name (python/javascript/typescript/go/java/ruby/php/c/cpp/rust/csharp).",
        min_length=1,
    )
    source_hint: str = Field(
        default="ai_generated",
        description="Provenance tag: ai_generated|copilot|claude|cursor|manual|unknown.",
    )


class AnalyzeRequest(BaseModel):
    code: str = Field(..., description="Source code snippet to analyse.", min_length=1)
    language: str = Field(
        ...,
        description="Language name (python/javascript/typescript/go/java/ruby/php/c/cpp/rust/csharp).",
        min_length=1,
    )


# ---------------------------------------------------------------------------
# Lazy engine accessors
# ---------------------------------------------------------------------------


_ai_advisor_engine = None


def _get_advisor():
    global _ai_advisor_engine
    if _ai_advisor_engine is None:
        from core.ai_security_advisor_engine import AISecurityAdvisorEngine

        _ai_advisor_engine = AISecurityAdvisorEngine()
    return _ai_advisor_engine


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/snippet", dependencies=[Depends(api_key_auth)], status_code=200)
def scan_snippet_endpoint(
    body: ScanSnippetRequest,
    org_id: str = Query(default="default", description="Organisation identifier."),
) -> Dict[str, Any]:
    """Scan a single snippet with the SAST ruleset. Idempotent by snippet SHA-256."""
    try:
        from core.sast_engine import scan_snippet
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"SAST engine unavailable: {exc}") from exc

    try:
        return scan_snippet(
            org_id=org_id,
            code=body.code,
            language=body.language,
            source_hint=body.source_hint,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("scan_snippet failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/analyze", dependencies=[Depends(api_key_auth)], status_code=200)
def analyze_ai_generated_endpoint(
    body: AnalyzeRequest,
    org_id: str = Query(default="default", description="Organisation identifier."),
) -> Dict[str, Any]:
    """Full analysis: SAST findings + AI-specific risk signals + combined score."""
    try:
        return _get_advisor().analyze_ai_generated(
            org_id=org_id,
            code=body.code,
            language=body.language,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("analyze_ai_generated failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/history", dependencies=[Depends(api_key_auth)])
def snippet_history(
    org_id: str = Query(default="default"),
    language: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Return snippet scan history for the given org (optionally filtered by language)."""
    try:
        from core.sast_engine import list_snippet_scans
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"SAST engine unavailable: {exc}") from exc

    try:
        items = list_snippet_scans(org_id=org_id, language=language, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "org_id": org_id,
        "language": language,
        "count": len(items),
        "items": items,
    }


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def snippet_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return aggregated snippet scan statistics for the given org."""
    try:
        from core.sast_engine import snippet_scan_stats
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"SAST engine unavailable: {exc}") from exc

    try:
        return snippet_scan_stats(org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
