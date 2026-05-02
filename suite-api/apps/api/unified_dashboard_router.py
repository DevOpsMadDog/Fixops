"""
Unified Security Metrics Dashboard API Router — ALDECI.

Single endpoint per persona that returns ALL dashboard data in one call.
Eliminates the N+1 query problem for frontend dashboard loads.

Endpoints:
    GET /api/v1/unified-dashboard/ciso          CISO executive view
    GET /api/v1/unified-dashboard/soc           SOC analyst view
    GET /api/v1/unified-dashboard/compliance    Compliance officer view
    GET /api/v1/unified-dashboard/developer     Developer view
    GET /api/v1/unified-dashboard/executive     Board-level summary
    GET /api/v1/unified-dashboard/real-time     Live event feed (no cache)

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging

from core.unified_dashboard import DashboardLayout, get_unified_dashboard
from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/unified-dashboard",
    tags=["unified-dashboard"],
)


def _dashboard():
    return get_unified_dashboard()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/ciso",
    response_model=DashboardLayout,
    summary="CISO Executive Dashboard",
    description=(
        "Returns all CISO KPIs in a single call: posture score, SLA compliance, "
        "critical findings, compliance coverage, incidents, and threat intelligence. "
        "Results cached for 60 seconds."
    ),
)
def get_ciso_dashboard(
    org_id: str = Query("default", description="Organisation identifier"),
) -> DashboardLayout:
    try:
        return _dashboard().get_ciso_dashboard(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to build CISO dashboard: %s", exc)
        raise HTTPException(status_code=500, detail=f"Dashboard error: {exc}") from exc


@router.get(
    "/soc",
    response_model=DashboardLayout,
    summary="SOC Analyst Dashboard",
    description=(
        "Returns SOC analyst view: active incidents, open findings, threats, "
        "SLA queue, attack surface, and recent events timeline. "
        "Results cached for 60 seconds."
    ),
)
def get_soc_dashboard(
    org_id: str = Query("default", description="Organisation identifier"),
) -> DashboardLayout:
    try:
        return _dashboard().get_soc_dashboard(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to build SOC dashboard: %s", exc)
        raise HTTPException(status_code=500, detail=f"Dashboard error: {exc}") from exc


@router.get(
    "/compliance",
    response_model=DashboardLayout,
    summary="Compliance Officer Dashboard",
    description=(
        "Returns compliance view: framework coverage (SOC2/PCI/ISO27001), "
        "evidence gaps, audit readiness, SLA compliance, and posture components. "
        "Results cached for 60 seconds."
    ),
)
def get_compliance_dashboard(
    org_id: str = Query("default", description="Organisation identifier"),
) -> DashboardLayout:
    try:
        return _dashboard().get_compliance_dashboard(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to build compliance dashboard: %s", exc)
        raise HTTPException(status_code=500, detail=f"Dashboard error: {exc}") from exc


@router.get(
    "/developer",
    response_model=DashboardLayout,
    summary="Developer Dashboard",
    description=(
        "Returns developer view: findings assigned to the requesting user, "
        "autofix opportunities, sprint metrics, and team fix rate. "
        "Results cached for 60 seconds per (org_id, user_email)."
    ),
)
def get_developer_dashboard(
    org_id: str = Query("default", description="Organisation identifier"),
    user_email: str = Query("developer@org", description="User email for per-user filtering"),
) -> DashboardLayout:
    try:
        return _dashboard().get_developer_dashboard(org_id=org_id, user_email=user_email)
    except Exception as exc:
        logger.exception("Failed to build developer dashboard: %s", exc)
        raise HTTPException(status_code=500, detail=f"Dashboard error: {exc}") from exc


@router.get(
    "/executive",
    response_model=DashboardLayout,
    summary="Executive / Board Dashboard",
    description=(
        "Returns board-level summary: top-line risk posture, compliance posture, "
        "estimated risk exposure, cost avoidance estimate, and SLA performance. "
        "Results cached for 60 seconds."
    ),
)
def get_executive_dashboard(
    org_id: str = Query("default", description="Organisation identifier"),
) -> DashboardLayout:
    try:
        return _dashboard().get_executive_dashboard(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to build executive dashboard: %s", exc)
        raise HTTPException(status_code=500, detail=f"Dashboard error: {exc}") from exc


@router.get(
    "/real-time",
    response_model=DashboardLayout,
    summary="Real-Time Security Feed",
    description=(
        "Returns latest events across all ALDECI modules with no caching — "
        "always fetches fresh data. Includes live event stream, active alerts, "
        "and current posture score."
    ),
)
def get_real_time_feed(
    org_id: str = Query("default", description="Organisation identifier"),
) -> DashboardLayout:
    try:
        return _dashboard().get_real_time_feed(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to build real-time feed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Dashboard error: {exc}") from exc
