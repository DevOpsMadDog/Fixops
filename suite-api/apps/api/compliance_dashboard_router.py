"""Compliance Dashboard Router — ALDECI.

Aggregated dashboard view over the ComplianceAutomationEngine.
Distinct from compliance_router.py (which owns CRUD/evidence/POAM).

Prefix: /api/v1/compliance-dashboard
Auth:   api_key_auth dependency

Routes:
  GET /api/v1/compliance-dashboard/summary      — cross-framework score card
  GET /api/v1/compliance-dashboard/gaps         — priority-ranked gaps (all frameworks)
  GET /api/v1/compliance-dashboard/frameworks   — per-framework status list
  GET /api/v1/compliance-dashboard/health       — liveness probe
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance-dashboard",
    tags=["Compliance Dashboard"],
)

# ---------------------------------------------------------------------------
# Lazy engine accessor — imports _get_engine from the authoritative router
# so there is exactly one engine singleton shared across both routers.
# The real function name in compliance_router.py is _get_engine() — NOT
# get_compliance_engine (which does not exist there).
# ---------------------------------------------------------------------------

def _engine():
    from apps.api.compliance_router import _get_engine  # noqa: PLC0415
    return _get_engine()


_FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "FedRAMP", "ISO27001", "NIST-800-53", "CMMC"]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
def dashboard_health():
    """Liveness probe — does not require auth."""
    return {"status": "healthy", "router": "compliance-dashboard", "version": "1.0.0"}


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_dashboard_summary():
    """
    Cross-framework compliance score card.

    Returns overall status + per-framework pass/fail/score, aggregated
    from ComplianceAutomationEngine.get_overall_status().
    """
    try:
        status = _engine().get_overall_status()
        return {
            "overall": status,
            "frameworks_tracked": _FRAMEWORKS,
            "endpoint": "compliance-dashboard/summary",
        }
    except Exception as exc:  # pragma: no cover
        _logger.error("compliance_dashboard.summary error: %s", exc)
        raise HTTPException(status_code=503, detail=f"Compliance engine unavailable: {exc}") from exc


@router.get("/gaps", dependencies=[Depends(api_key_auth)])
def get_dashboard_gaps(framework: Optional[str] = Query(default=None, description="Filter by framework")):
    """Priority-ranked gap analysis across all frameworks (or a single one)."""
    try:
        gaps = _engine().get_gaps(framework=framework)
        return {"gaps": gaps, "framework_filter": framework}
    except Exception as exc:  # pragma: no cover
        _logger.error("compliance_dashboard.gaps error: %s", exc)
        raise HTTPException(status_code=503, detail=f"Compliance engine unavailable: {exc}") from exc


@router.get("/frameworks", dependencies=[Depends(api_key_auth)])
def get_framework_statuses():
    """Per-framework status list — iterates all 7 supported frameworks."""
    results: List[Dict[str, Any]] = []
    engine = _engine()
    for fw in _FRAMEWORKS:
        try:
            status = engine.get_framework_status(fw)
            results.append({"framework": fw, "status": status})
        except Exception as exc:  # pragma: no cover
            results.append({"framework": fw, "error": str(exc)})
    return {"frameworks": results, "count": len(results)}
