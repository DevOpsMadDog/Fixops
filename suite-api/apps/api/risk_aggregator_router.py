"""Risk Aggregator Router — ALDECI.

Unified risk scoring across all entity types (asset, user, network,
application, vendor) with heatmaps, composite org score, and threshold rules.

Prefix: /api/v1/risk-aggregator
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/risk-aggregator/scores                     record_risk_score
  GET    /api/v1/risk-aggregator/scores                     list_risk_scores
  GET    /api/v1/risk-aggregator/scores/entity/{entity_id}  get_entity_risk
  GET    /api/v1/risk-aggregator/heatmap                    get_risk_heatmap
  GET    /api/v1/risk-aggregator/top-risks                  get_top_risks
  GET    /api/v1/risk-aggregator/org-score                  calculate_org_risk_score
  POST   /api/v1/risk-aggregator/thresholds                 create_risk_threshold
  GET    /api/v1/risk-aggregator/thresholds                 list_risk_thresholds
  GET    /api/v1/risk-aggregator/stats                      get_aggregator_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/risk-aggregator",
    tags=["Risk Aggregator"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.risk_aggregator_engine import RiskAggregatorEngine
        _engine = RiskAggregatorEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RecordRiskScoreRequest(BaseModel):
    entity_id: str = Field(..., description="Unique identifier for the entity")
    entity_name: Optional[str] = Field(default="", description="Human-readable entity name")
    entity_type: str = Field(
        default="asset",
        description="asset | user | network | application | vendor",
    )
    source_engine: Optional[str] = Field(default="", description="Engine producing the score")
    risk_score: float = Field(..., ge=0, le=100, description="Risk score 0-100")
    risk_factors: Optional[List[str]] = Field(
        default_factory=list, description="Contributing risk factors"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Override severity: critical | high | medium | low (auto-derived if omitted)",
    )


class CreateRiskThresholdRequest(BaseModel):
    entity_type: str = Field(
        default="asset",
        description="asset | user | network | application | vendor",
    )
    threshold: float = Field(default=70, ge=0, le=100, description="Score threshold 0-100")
    action: str = Field(default="alert", description="alert | escalate | block")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/scores", dependencies=[Depends(api_key_auth)], status_code=201)
def record_risk_score(
    body: RecordRiskScoreRequest,
    org_id: str = Query(default="default"),
):
    """Record a risk score for an entity from any source engine."""
    try:
        data = body.model_dump()
        if data.get("risk_factors") is None:
            data["risk_factors"] = []
        return _get_engine().record_risk_score(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording risk score")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/scores", dependencies=[Depends(api_key_auth)])
def list_risk_scores(
    org_id: str = Query(default="default"),
    entity_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """List risk scores with optional entity_type and severity filters."""
    return _get_engine().list_risk_scores(
        org_id, entity_type=entity_type, severity=severity, limit=limit
    )


@router.get("/scores/entity/{entity_id}", dependencies=[Depends(api_key_auth)])
def get_entity_risk(
    entity_id: str,
    org_id: str = Query(default="default"),
):
    """Return the latest risk score and full history for a specific entity."""
    return _get_engine().get_entity_risk(org_id, entity_id)


@router.get("/heatmap", dependencies=[Depends(api_key_auth)])
def get_risk_heatmap(org_id: str = Query(default="default")):
    """Return a risk heatmap: entity_types x severity counts."""
    return _get_engine().get_risk_heatmap(org_id)


@router.get("/top-risks", dependencies=[Depends(api_key_auth)])
def get_top_risks(
    org_id: str = Query(default="default"),
    limit: int = Query(default=10, ge=1, le=100),
):
    """Return the highest-risk entities across all types."""
    return _get_engine().get_top_risks(org_id, limit=limit)


@router.get("/org-score", dependencies=[Depends(api_key_auth)])
def calculate_org_risk_score(org_id: str = Query(default="default")):
    """Calculate composite organisational risk score with grade and trend."""
    return _get_engine().calculate_org_risk_score(org_id)


@router.post("/thresholds", dependencies=[Depends(api_key_auth)], status_code=201)
def create_risk_threshold(
    body: CreateRiskThresholdRequest,
    org_id: str = Query(default="default"),
):
    """Create a risk threshold rule that triggers an action when exceeded."""
    try:
        return _get_engine().create_risk_threshold(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating risk threshold")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/thresholds", dependencies=[Depends(api_key_auth)])
def list_risk_thresholds(org_id: str = Query(default="default")):
    """List all risk threshold rules for an org."""
    return _get_engine().list_risk_thresholds(org_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_aggregator_stats(org_id: str = Query(default="default")):
    """Return aggregated risk statistics: entity count, high-risk count, org score."""
    return _get_engine().get_aggregator_stats(org_id)


@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync_from_brain(
    org_id: str = Query(default="default"),
    brain_db_path: Optional[str] = Query(
        default=None,
        description="Override path to fixops_brain.db (defaults to FIXOPS_BRAIN_DB_PATH env or data/fixops_brain.db)",
    ),
):
    """Trigger a manual sync of risk scores from the Knowledge Brain graph.

    Reads all finding nodes for the org from the brain graph, computes
    risk scores from CVSS / severity / exposure properties, and stores
    them in the risk_scores table so that /stats and /org-score reflect
    real ASPM data.
    """
    try:
        result = _get_engine().sync_from_brain_graph(
            org_id=org_id,
            brain_db_path=brain_db_path,
        )
        return result
    except Exception as exc:
        _logger.exception("Error syncing risk scores from brain graph")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
