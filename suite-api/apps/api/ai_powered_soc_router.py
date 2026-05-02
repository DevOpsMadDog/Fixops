"""AI-Powered SOC Router — ALDECI.

ML-driven detection management, model registry, automation rules, and SOC stats.

Prefix: /api/v1/ai-soc
Auth: api_key_auth dependency

Routes:
  POST  /api/v1/ai-soc/detections                    record_detection
  GET   /api/v1/ai-soc/detections                    list_detections
  PUT   /api/v1/ai-soc/detections/{id}/triage        triage_detection
  POST  /api/v1/ai-soc/models                        register_model
  GET   /api/v1/ai-soc/models                        list_models
  PUT   /api/v1/ai-soc/models/{id}/status            update_model_status
  POST  /api/v1/ai-soc/automation                    create_automation_rule
  GET   /api/v1/ai-soc/automation                    list_automation_rules
  PUT   /api/v1/ai-soc/automation/{id}/execute       execute_automation
  GET   /api/v1/ai-soc/stats                         get_soc_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ai-soc",
    tags=["AI-Powered SOC"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ai_powered_soc_engine import AIPoweredSOCEngine
        _engine = AIPoweredSOCEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RecordDetectionRequest(BaseModel):
    detection_name: str = Field(..., description="Name of the detection")
    model_type: str = Field(
        default="rule_based",
        description="anomaly_detection | classification | nlp | graph_ml | time_series | rule_based | ensemble",
    )
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)
    severity: str = Field(default="medium", description="critical | high | medium | low")
    source_data_type: str = Field(
        default="logs",
        description="logs | network | endpoint | identity | cloud | email | file",
    )


class TriageDetectionRequest(BaseModel):
    new_status: str = Field(
        ...,
        description="new | triaged | investigating | escalated | resolved | false_positive",
    )
    auto_triaged: bool = Field(default=False)
    triage_time_seconds: int = Field(default=0, ge=0)


class RegisterModelRequest(BaseModel):
    model_name: str = Field(..., description="Human-readable model name")
    model_type: str = Field(
        default="anomaly_detection",
        description="anomaly_detection | classification | nlp | graph_ml | time_series | ensemble",
    )
    accuracy_score: float = Field(default=0.0, ge=0.0, le=100.0)
    false_positive_rate: float = Field(default=0.0, ge=0.0, le=100.0)
    version: str = Field(default="1.0")
    training_data_size: int = Field(default=0, ge=0)
    deployed_at: Optional[str] = Field(default=None)
    last_retrained: Optional[str] = Field(default=None)


class UpdateModelStatusRequest(BaseModel):
    status: str = Field(
        ..., description="training | active | deprecated | failed"
    )
    last_retrained: Optional[str] = Field(default=None)


class CreateAutomationRuleRequest(BaseModel):
    rule_name: str = Field(..., description="Human-readable rule name")
    trigger_condition: str = Field(default="", description="Trigger condition expression")
    action_type: str = Field(
        default="notify",
        description="auto_close | escalate | enrich | notify | block | isolate",
    )
    confidence_threshold: float = Field(default=80.0, ge=0.0, le=100.0)
    enabled: bool = Field(default=True)


class ExecuteAutomationRequest(BaseModel):
    success: bool = Field(default=True, description="Whether the execution succeeded")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/detections", dependencies=[Depends(api_key_auth)], status_code=201)
def record_detection(
    body: RecordDetectionRequest,
    org_id: str = Query(default="default"),
):
    """Record a new AI-driven SOC detection."""
    try:
        return _get_engine().record_detection(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording detection")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/detections", dependencies=[Depends(api_key_auth)])
def list_detections(
    org_id: str = Query(default="default"),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    source_data_type: Optional[str] = Query(default=None),
):
    """List detections with optional severity/status/source filters.

    Type-a #27 wiring: when the org has no registered detections, the engine
    will fall back to Microsoft Defender XDR live alerts (when
    DEFENDER_TENANT_ID/CLIENT_ID/CLIENT_SECRET env vars are set). NEVER mocks;
    returns a 5-state envelope (org_registered / defender_xdr /
    needs_credentials / needs_data / connector_error).
    """
    return _get_engine().list_detections_with_xdr_fallback(
        org_id,
        severity=severity,
        status=status,
        source_data_type=source_data_type,
    )


@router.put("/detections/{detection_id}/triage", dependencies=[Depends(api_key_auth)])
def triage_detection(
    detection_id: str,
    body: TriageDetectionRequest,
    org_id: str = Query(default="default"),
):
    """Triage a detection — update status, auto_triaged flag, and triage time."""
    try:
        return _get_engine().triage_detection(
            org_id,
            detection_id,
            body.new_status,
            auto_triaged=body.auto_triaged,
            triage_time_seconds=body.triage_time_seconds,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error triaging detection")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/models", dependencies=[Depends(api_key_auth)], status_code=201)
def register_model(
    body: RegisterModelRequest,
    org_id: str = Query(default="default"),
):
    """Register a new AI/ML model."""
    try:
        return _get_engine().register_model(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering model")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/models", dependencies=[Depends(api_key_auth)])
def list_models(
    org_id: str = Query(default="default"),
    model_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List models with optional type/status filters."""
    return _get_engine().list_models(org_id, model_type=model_type, status=status)


@router.put("/models/{model_id}/status", dependencies=[Depends(api_key_auth)])
def update_model_status(
    model_id: str,
    body: UpdateModelStatusRequest,
    org_id: str = Query(default="default"),
):
    """Update a model's lifecycle status."""
    try:
        return _get_engine().update_model_status(
            org_id, model_id, body.status, last_retrained=body.last_retrained
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating model status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/automation", dependencies=[Depends(api_key_auth)], status_code=201)
def create_automation_rule(
    body: CreateAutomationRuleRequest,
    org_id: str = Query(default="default"),
):
    """Create a SOC automation rule."""
    try:
        return _get_engine().create_automation_rule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating automation rule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/automation", dependencies=[Depends(api_key_auth)])
def list_automation_rules(
    org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(default=None),
):
    """List automation rules with optional enabled filter."""
    return _get_engine().list_automation_rules(org_id, enabled=enabled)


@router.put("/automation/{rule_id}/execute", dependencies=[Depends(api_key_auth)])
def execute_automation(
    rule_id: str,
    body: ExecuteAutomationRequest,
    org_id: str = Query(default="default"),
):
    """Record execution of an automation rule."""
    try:
        return _get_engine().execute_automation(org_id, rule_id, success=body.success)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error executing automation rule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_soc_stats(org_id: str = Query(default="default")):
    """Return aggregated AI SOC statistics: detections, models, automation, breakdowns."""
    return _get_engine().get_soc_stats(org_id)
