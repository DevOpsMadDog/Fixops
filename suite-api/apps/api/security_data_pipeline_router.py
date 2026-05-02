"""Security Data Pipeline Router — ALDECI.

Register and manage security data ingestion pipelines, record execution runs,
and view throughput/error statistics.

Prefix: /api/v1/data-pipeline
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/data-pipeline/pipelines                      register_pipeline
  GET    /api/v1/data-pipeline/pipelines                      list_pipelines
  GET    /api/v1/data-pipeline/pipelines/{id}                 get_pipeline
  POST   /api/v1/data-pipeline/pipelines/{id}/runs            record_pipeline_run
  GET    /api/v1/data-pipeline/runs                           list_runs
  PATCH  /api/v1/data-pipeline/pipelines/{id}/status          update_pipeline_status
  GET    /api/v1/data-pipeline/stats                          get_pipeline_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/data-pipeline",
    tags=["Security Data Pipeline"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_data_pipeline_engine import SecurityDataPipelineEngine
        _engine = SecurityDataPipelineEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterPipelineRequest(BaseModel):
    name: str = Field(..., description="Human-readable pipeline name")
    source_type: str = Field(
        default="siem",
        description="siem | edr | ndr | cloud | api | database | file | streaming",
    )
    source_endpoint: Optional[str] = Field(default=None, description="Source URL or connection string")
    data_format: str = Field(
        default="json",
        description="json | cef | leef | syslog | csv | parquet | avro",
    )
    transformation_rules_json: Optional[str] = Field(
        default=None, description="JSON string of field mapping / transformation rules"
    )
    destination: Optional[str] = Field(default=None, description="Destination system or topic")


class RecordRunRequest(BaseModel):
    run_status: str = Field(
        ...,
        description="queued | running | completed | failed | partial",
    )
    records_in: int = Field(default=0, ge=0, description="Records read from source")
    records_out: int = Field(default=0, ge=0, description="Records successfully processed")
    records_failed: int = Field(default=0, ge=0, description="Records that failed processing")
    duration_seconds: int = Field(default=0, ge=0, description="Wall-clock duration of the run")
    error_message: Optional[str] = Field(default=None, description="Error detail if run failed")
    started_at: Optional[str] = Field(default=None, description="ISO-8601 run start time")
    completed_at: Optional[str] = Field(default=None, description="ISO-8601 run completion time")


class UpdatePipelineStatusRequest(BaseModel):
    status: str = Field(
        ...,
        description="active | paused | error | stopped | testing",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/pipelines", dependencies=[Depends(api_key_auth)], status_code=201)
def register_pipeline(
    body: RegisterPipelineRequest,
    org_id: str = Query(default="default"),
):
    """Register a new security data ingestion pipeline."""
    try:
        data = body.model_dump(exclude_none=False)
        for key in ("source_endpoint", "transformation_rules_json", "destination"):
            if data.get(key) is None:
                data[key] = "" if key != "transformation_rules_json" else "{}"
        return _get_engine().register_pipeline(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering pipeline")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/pipelines", dependencies=[Depends(api_key_auth)])
def list_pipelines(
    org_id: str = Query(default="default"),
    source_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List all pipelines with optional source_type / status filters."""
    return _get_engine().list_pipelines(org_id, source_type=source_type, status=status)


@router.get("/pipelines/{pipeline_id}", dependencies=[Depends(api_key_auth)])
def get_pipeline(
    pipeline_id: str,
    org_id: str = Query(default="default"),
):
    """Fetch a single pipeline by ID."""
    result = _get_engine().get_pipeline(org_id, pipeline_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Pipeline {pipeline_id} not found")
    return result


@router.post("/pipelines/{pipeline_id}/runs", dependencies=[Depends(api_key_auth)], status_code=201)
def record_pipeline_run(
    pipeline_id: str,
    body: RecordRunRequest,
    org_id: str = Query(default="default"),
):
    """Record an execution run for a pipeline and update its throughput counters."""
    try:
        data = body.model_dump(exclude_none=False)
        if data.get("error_message") is None:
            data["error_message"] = ""
        return _get_engine().record_pipeline_run(org_id, pipeline_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording pipeline run")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/runs", dependencies=[Depends(api_key_auth)])
def list_runs(
    org_id: str = Query(default="default"),
    pipeline_id: Optional[str] = Query(default=None),
    run_status: Optional[str] = Query(default=None),
):
    """List pipeline runs, newest first, with optional pipeline_id / run_status filters."""
    return _get_engine().list_runs(org_id, pipeline_id=pipeline_id, run_status=run_status)


@router.patch("/pipelines/{pipeline_id}/status", dependencies=[Depends(api_key_auth)])
def update_pipeline_status(
    pipeline_id: str,
    body: UpdatePipelineStatusRequest,
    org_id: str = Query(default="default"),
):
    """Change the operational status of a pipeline (active/paused/error/stopped/testing)."""
    try:
        return _get_engine().update_pipeline_status(org_id, pipeline_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating pipeline status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_pipeline_stats(org_id: str = Query(default="default")):
    """Return aggregated stats: totals, throughput, error rate, by_source_type breakdown."""
    return _get_engine().get_pipeline_stats(org_id)
