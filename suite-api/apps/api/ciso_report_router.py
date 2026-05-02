"""CISO Report Router — ALDECI.

REST endpoints for the CISO weekly briefing package.

Prefix: /api/v1/ciso-report
Auth: api_key_auth dependency

Routes:
  GET /api/v1/ciso-report/weekly-brief        Full weekly CISO brief (JSON)
  GET /api/v1/ciso-report/executive-summary   3-bullet executive summary
  GET /api/v1/ciso-report/risk-delta          Risk posture delta over N days
  GET /api/v1/ciso-report/top-risks           Top N risks requiring CISO attention
  GET /api/v1/ciso-report/export/markdown     Full brief as Markdown text
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ciso-report",
    tags=["CISO Report"],
)

_generator = None


def _get_generator():
    global _generator
    if _generator is None:
        from core.ciso_report_generator import CISOReportGenerator
        _generator = CISOReportGenerator()
    return _generator


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/weekly-brief", dependencies=[Depends(api_key_auth)])
def get_weekly_brief(
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Generate full CISO weekly brief aggregating data from all engines."""
    gen = _get_generator()
    return gen.generate_weekly_brief(org_id=org_id)


@router.get("/executive-summary", dependencies=[Depends(api_key_auth)])
def get_executive_summary(
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return 3-bullet executive summary suitable for board presentation."""
    gen = _get_generator()
    return gen.generate_executive_summary(org_id=org_id)


@router.get("/risk-delta", dependencies=[Depends(api_key_auth)])
def get_risk_delta(
    org_id: str = Query(default="default", description="Organisation identifier"),
    days: int = Query(default=7, ge=1, le=90, description="Look-back period in days"),
) -> Dict[str, Any]:
    """Return risk posture delta (score change) over the last N days."""
    gen = _get_generator()
    return gen.get_risk_posture_delta(org_id=org_id, days=days)


@router.get("/top-risks", dependencies=[Depends(api_key_auth)])
def get_top_risks(
    org_id: str = Query(default="default", description="Organisation identifier"),
    limit: int = Query(default=5, ge=1, le=20, description="Max number of risks to return"),
) -> List[Dict[str, Any]]:
    """Return top N risks requiring CISO attention this week."""
    gen = _get_generator()
    return gen.get_top_risks(org_id=org_id, limit=limit)


@router.get("/export/markdown", dependencies=[Depends(api_key_auth)])
def export_markdown(
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> PlainTextResponse:
    """Export full CISO brief as Markdown text (suitable for Slack/email)."""
    gen = _get_generator()
    md = gen.export_markdown(org_id=org_id)
    return PlainTextResponse(content=md, media_type="text/markdown")


@router.get("/context/{entity_id}", dependencies=[Depends(api_key_auth)])
def get_trustgraph_context(
    entity_id: str,
    org_id: str = Query(default="default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for a CISO report entity (related assets, findings, incidents)."""
    gen = _get_generator()
    return gen.get_trustgraph_context(org_id=org_id, entity_id=entity_id)
