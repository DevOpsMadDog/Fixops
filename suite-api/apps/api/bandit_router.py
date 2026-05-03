"""
ALdeci Bandit SAST Capability Router.

Exposes the Bandit (Python SAST) capability and rule catalog over REST.

Endpoints:
  GET  /api/v1/bandit/                — capability summary
  GET  /api/v1/bandit/rules           — full Bandit rule catalog
  GET  /api/v1/bandit/rules/{rule_id} — single rule detail
  POST /api/v1/bandit/scan            — queue a scan job

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/bandit",
    tags=["bandit-sast"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (allows test override via monkeypatch)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.bandit_scan_engine import get_bandit_scan_engine

    return get_bandit_scan_engine()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    rule_ids: List[str]
    confidence_levels: List[str]
    severity_levels: List[str]
    status: str
    rule_count: int
    scan_count: int


class RuleDetail(BaseModel):
    rule_id: str
    name: str
    severity: str
    confidence: str
    description: str


class RulesListResponse(BaseModel):
    rules: List[RuleDetail]
    count: int


class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Filesystem path to scan")
    rule_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional subset of Bandit rule IDs to apply (default: all).",
    )
    severity_threshold: Optional[str] = Field(
        default=None,
        description="Optional severity floor: LOW | MEDIUM | HIGH",
    )


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    started_at: str
    rule_ids: List[str]
    severity_threshold: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Bandit SAST capability summary",
)
def capability_summary() -> Dict[str, Any]:
    """
    Return the Bandit SAST capability descriptor — rule IDs, severity and
    confidence vocabulary, and overall status (``ok`` if rules are loaded
    and at least one scan has been recorded, otherwise ``empty``).
    """
    from core.bandit_scan_engine import (
        ALL_RULE_IDS,
        CONFIDENCE_LEVELS,
        SEVERITY_LEVELS,
    )

    engine = _get_engine()
    scan_count = engine.count_scans()
    status = "ok" if scan_count > 0 else "empty"
    return {
        "service": "Bandit",
        "rule_ids": ALL_RULE_IDS,
        "confidence_levels": CONFIDENCE_LEVELS,
        "severity_levels": SEVERITY_LEVELS,
        "status": status,
        "rule_count": len(ALL_RULE_IDS),
        "scan_count": scan_count,
    }


@router.get(
    "/rules",
    response_model=RulesListResponse,
    summary="List all Bandit rules",
)
def list_rules() -> Dict[str, Any]:
    """Return the complete Bandit rule catalog."""
    engine = _get_engine()
    rules = engine.list_rules()
    return {"rules": rules, "count": len(rules)}


@router.get(
    "/rules/{rule_id}",
    response_model=RuleDetail,
    summary="Get a single Bandit rule",
)
def get_rule(rule_id: str) -> Dict[str, str]:
    """Return one Bandit rule by canonical B-code (e.g. ``B101``)."""
    engine = _get_engine()
    rule = engine.get_rule(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=404,
            detail=f"Bandit rule '{rule_id}' not found",
        )
    return rule


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=202,
    summary="Queue a Bandit scan",
)
def queue_scan(body: ScanRequest) -> Dict[str, Any]:
    """
    Queue a Bandit scan job. Returns the scan id and ``status=queued`` —
    the actual binary execution is performed by a downstream worker.
    """
    engine = _get_engine()
    if body.severity_threshold is not None:
        from core.bandit_scan_engine import SEVERITY_LEVELS

        if body.severity_threshold.upper() not in SEVERITY_LEVELS:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid severity_threshold '{body.severity_threshold}'."
                    f" Allowed: {SEVERITY_LEVELS}"
                ),
            )
    try:
        scan = engine.queue_scan(
            target_path=body.target_path,
            rule_ids=body.rule_ids,
            severity_threshold=(
                body.severity_threshold.upper()
                if body.severity_threshold
                else None
            ),
        )
    except Exception as exc:
        logger.error("queue_scan failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    return scan
