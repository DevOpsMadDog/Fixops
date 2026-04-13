"""Enhanced LLM Council API Router.

Provides endpoints for council calibration, feedback, and recent verdicts:

    GET  /api/v1/council/calibration     — model accuracy report (last 30 days)
    POST /api/v1/council/feedback        — submit actual outcome for a verdict
    GET  /api/v1/council/recent-verdicts — last 50 decisions with accuracy

Security: no auth required (internal-facing); add Depends(_verify_api_key) if exposed externally.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/council", tags=["council"])

# Lazy singleton — avoid importing heavy council at module load
_council: Optional[Any] = None


def _get_council() -> Any:
    """Lazy-init EnhancedLLMCouncil singleton."""
    global _council
    if _council is None:
        from core.council_enhanced import EnhancedLLMCouncil
        _council = EnhancedLLMCouncil()
    return _council


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class FeedbackRequest(BaseModel):
    """Submit actual outcome for a council verdict to drive calibration."""

    verdict_id: str = Field(..., description="verdict_id from CouncilVerdict")
    actual_outcome: str = Field(
        ...,
        description="Ground-truth label: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW",
        pattern="^(TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW)$",
    )


class FeedbackResponse(BaseModel):
    status: str
    verdict_id: str
    actual_outcome: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/calibration", summary="Model accuracy report (last 30 days)")
def get_calibration(
    window_days: int = Query(default=30, ge=1, le=365, description="Rolling window in days"),
) -> Dict[str, Any]:
    """Return accuracy metrics per model over the last N days.

    Shows each model's prediction accuracy and current voting weight.
    Weights are adjusted automatically as outcomes are fed back via /feedback.
    """
    try:
        council = _get_council()
        report = council.get_calibration_report(window_days=window_days)
        return report.to_dict()
    except Exception as exc:
        logger.error("get_calibration failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Calibration report failed: {exc}") from exc


@router.post("/feedback", summary="Submit actual outcome for a verdict")
def post_feedback(body: FeedbackRequest) -> FeedbackResponse:
    """Feed the actual outcome of a finding back to calibrate model weights.

    Call this after a human analyst (or automated verification) confirms whether
    the council's verdict was correct. Correct predictions increase a model's weight;
    incorrect predictions decrease it.
    """
    try:
        council = _get_council()
        council.track_accuracy(body.verdict_id, body.actual_outcome)
        return FeedbackResponse(
            status="ok",
            verdict_id=body.verdict_id,
            actual_outcome=body.actual_outcome,
        )
    except Exception as exc:
        logger.error("post_feedback failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Feedback recording failed: {exc}") from exc


@router.get("/recent-verdicts", summary="Last 50 council decisions with accuracy")
def get_recent_verdicts(
    limit: int = Query(default=50, ge=1, le=200, description="Max verdicts to return"),
) -> List[Dict[str, Any]]:
    """Return the most recent council verdicts, including accuracy where known.

    Each entry includes:
    - verdict_id, verdict, confidence, agreement_pct
    - escalated flag, processing_ms, created_at
    - actual_outcome (if feedback has been submitted)
    - accurate (True/False/None — None if no outcome yet)
    """
    try:
        council = _get_council()
        return council.get_recent_verdicts(limit=limit)
    except Exception as exc:
        logger.error("get_recent_verdicts failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Recent verdicts failed: {exc}") from exc
