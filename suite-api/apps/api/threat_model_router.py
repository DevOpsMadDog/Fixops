"""
Threat Modeling Router — ALDECI STRIDE/DREAD API.

10 endpoints for structured threat modeling:

  POST   /api/v1/threat-models                      create_model
  GET    /api/v1/threat-models                      list_models
  GET    /api/v1/threat-models/{model_id}           get_model
  GET    /api/v1/threat-models/{model_id}/summary   get_model_summary
  GET    /api/v1/threat-models/{model_id}/matrix    get_threat_matrix
  POST   /api/v1/threat-models/{model_id}/threats   add_threat
  POST   /api/v1/threat-models/{model_id}/auto-identify   auto_identify_threats
  GET    /api/v1/threat-models/threats/{threat_id}  get_threat
  POST   /api/v1/threat-models/threats/{threat_id}/score      score_threat
  POST   /api/v1/threat-models/threats/{threat_id}/mitigations add_mitigation
  GET    /api/v1/threat-models/unmitigated           get_unmitigated_threats

All endpoints require API key authentication.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "threat_model_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.threat_model import (
    DREADScore,
    STRIDECategory,
    ThreatEntry,
    ThreatModel,
    ThreatModelEngine,
    ThreatStatus,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-models",
    tags=["threat-modeling"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (file-backed, shared across requests)
_engine: Optional[ThreatModelEngine] = None


def _get_engine() -> ThreatModelEngine:
    global _engine
    if _engine is None:
        _engine = ThreatModelEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class CreateModelRequest(BaseModel):
    name: str = Field(..., description="Threat model name")
    system_description: str = Field(..., description="Description of system being modeled")
    data_flow_description: str = Field("", description="Data flow narrative (DFD summary)")
    trust_boundaries: List[str] = Field(default_factory=list, description="Trust boundary labels")
    org_id: str = Field("default", description="Organisation identifier")


class CreateModelResponse(BaseModel):
    model_id: str
    message: str = "Threat model created"


class AddThreatRequest(BaseModel):
    title: str = Field(..., description="Short threat title")
    description: str = Field(..., description="Detailed threat description")
    stride_category: STRIDECategory = Field(..., description="STRIDE category")
    affected_component: str = Field(..., description="Component at risk")
    org_id: str = Field("default", description="Organisation identifier")
    status: ThreatStatus = Field(ThreatStatus.IDENTIFIED, description="Initial status")


class AddThreatResponse(BaseModel):
    threat_id: str
    message: str = "Threat added"


class ScoreThreatRequest(BaseModel):
    damage: int = Field(..., ge=1, le=10)
    reproducibility: int = Field(..., ge=1, le=10)
    exploitability: int = Field(..., ge=1, le=10)
    affected_users: int = Field(..., ge=1, le=10)
    discoverability: int = Field(..., ge=1, le=10)


class AddMitigationRequest(BaseModel):
    mitigation: str = Field(..., description="Mitigation control description")


class AddMitigationResponse(BaseModel):
    threat_id: str
    mitigations: List[str]
    message: str = "Mitigation added"


class AutoIdentifyResponse(BaseModel):
    model_id: str
    new_threat_ids: List[str]
    count: int
    message: str = "Auto-identification complete"


class ThreatModelExportResponse(BaseModel):
    """Full STRIDE/DREAD export for a threat model — summary + matrix + all threats."""

    export_version: str = "1.0"
    model_id: str
    name: str
    org_id: str
    created_at: str
    summary: Dict[str, Any]
    threat_matrix: Dict[str, Any]
    threats: List[Dict[str, Any]]
    total_threats: int
    average_dread_score: float


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("", response_model=CreateModelResponse, status_code=201)
async def create_model(
    body: CreateModelRequest,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> CreateModelResponse:
    """Define a new system for threat modeling."""
    model_id = engine.create_model(
        name=body.name,
        system_description=body.system_description,
        data_flow_description=body.data_flow_description,
        trust_boundaries=body.trust_boundaries,
        org_id=body.org_id,
    )
    return CreateModelResponse(model_id=model_id)


@router.get("", response_model=List[ThreatModel])
async def list_models(
    org_id: str = Query("default", description="Organisation identifier"),
    engine: ThreatModelEngine = Depends(_get_engine),
) -> List[ThreatModel]:
    """List all threat models for an organisation."""
    return engine.list_models(org_id=org_id)


@router.get("/unmitigated", response_model=List[ThreatEntry])
async def get_unmitigated_threats(
    org_id: str = Query("default", description="Organisation identifier"),
    engine: ThreatModelEngine = Depends(_get_engine),
) -> List[ThreatEntry]:
    """Return all open (unmitigated) threats for an organisation."""
    return engine.get_unmitigated_threats(org_id=org_id)


@router.get("/threats/{threat_id}", response_model=ThreatEntry)
async def get_threat(
    threat_id: str,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> ThreatEntry:
    """Retrieve a single threat entry by ID."""
    entry = engine.get_threat(threat_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Threat not found: {threat_id}")
    return entry


@router.post("/threats/{threat_id}/score", response_model=DREADScore)
async def score_threat(
    threat_id: str,
    body: ScoreThreatRequest,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> DREADScore:
    """Calculate and store DREAD score for a threat."""
    dread = DREADScore(
        damage=body.damage,
        reproducibility=body.reproducibility,
        exploitability=body.exploitability,
        affected_users=body.affected_users,
        discoverability=body.discoverability,
    )
    try:
        return engine.score_threat(threat_id, dread)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/threats/{threat_id}/mitigations", response_model=AddMitigationResponse)
async def add_mitigation(
    threat_id: str,
    body: AddMitigationRequest,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> AddMitigationResponse:
    """Append a mitigation control to a threat entry."""
    try:
        mitigations = engine.add_mitigation(threat_id, body.mitigation)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return AddMitigationResponse(threat_id=threat_id, mitigations=mitigations)


@router.get("/{model_id}", response_model=ThreatModel)
async def get_model(
    model_id: str,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> ThreatModel:
    """Retrieve a threat model by ID."""
    model = engine.get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail=f"Threat model not found: {model_id}")
    return model


@router.get("/{model_id}/summary")
async def get_model_summary(
    model_id: str,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return risk overview — STRIDE breakdown, DREAD averages, top risks."""
    try:
        return engine.get_model_summary(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/{model_id}/matrix")
async def get_threat_matrix(
    model_id: str,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return STRIDE-category × component threat matrix."""
    try:
        return engine.get_threat_matrix(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/{model_id}/threats", response_model=AddThreatResponse, status_code=201)
async def add_threat(
    model_id: str,
    body: AddThreatRequest,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> AddThreatResponse:
    """Add a threat entry to an existing threat model."""
    try:
        threat_id = engine.add_threat(
            model_id=model_id,
            title=body.title,
            description=body.description,
            stride_category=body.stride_category,
            affected_component=body.affected_component,
            org_id=body.org_id,
            status=body.status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return AddThreatResponse(threat_id=threat_id)


@router.get("/{model_id}/export", response_model=ThreatModelExportResponse)
async def export_threat_model(
    model_id: str,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> ThreatModelExportResponse:
    """Export a full STRIDE/DREAD threat model report (summary + matrix + all threats)."""
    model = engine.get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail=f"Threat model not found: {model_id}")

    try:
        summary = engine.get_model_summary(model_id)
        matrix = engine.get_threat_matrix(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    # ThreatModel.threats holds all threat IDs belonging to this model
    threats_out: List[Dict[str, Any]] = []
    for tid in model.threats:
        entry = engine.get_threat(tid)
        if entry is None:
            continue
        d: Dict[str, Any] = {
            "id": entry.id,
            "title": entry.title,
            "description": entry.description,
            "stride_category": entry.stride_category.value,
            "affected_component": entry.affected_component,
            "mitigations": entry.mitigations,
            "status": entry.status.value,
            "org_id": entry.org_id,
            "created_at": entry.created_at.isoformat(),
        }
        if entry.dread_score:
            d["dread_score"] = entry.dread_score.model_dump()
            d["dread_total"] = entry.dread_score.total
        threats_out.append(d)

    return ThreatModelExportResponse(
        model_id=model_id,
        name=model.name,
        org_id=model.org_id,
        created_at=model.created_at.isoformat(),
        summary=summary,
        threat_matrix=matrix,
        threats=threats_out,
        total_threats=summary.get("total_threats", len(threats_out)),
        average_dread_score=summary.get("average_dread_score", 0.0),
    )


@router.post("/{model_id}/auto-identify", response_model=AutoIdentifyResponse)
async def auto_identify_threats(
    model_id: str,
    engine: ThreatModelEngine = Depends(_get_engine),
) -> AutoIdentifyResponse:
    """Auto-generate STRIDE threats from the model's system description."""
    try:
        new_ids = engine.auto_identify_threats(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return AutoIdentifyResponse(
        model_id=model_id,
        new_threat_ids=new_ids,
        count=len(new_ids),
    )
